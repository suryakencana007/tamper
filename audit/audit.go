// Package audit defines the append-only event log primitives for the
// v0.6 compliance work (closes the v0.4/v0.5-deferred non-goal).
//
// The package is two layers:
//
//   - audit.Event + audit.Logger — the wire-shaped event + the
//     interface the rest of Barista calls. NoopLogger is the test /
//     audit-disabled implementation.
//   - audit.SQLiteLogger (in audit_sqlite.go) — the production
//     implementation backed by a dedicated SQLite file with a
//     tamper-evident hash chain.
//
// Hash chain: each event's Hash field is sha256(PrevHash ||
// canonicalised payload). PrevHash for the first event is 32 zero
// bytes. Verify() walks the chain end-to-end and reports the first
// index where Hash diverges from the recomputed value — proves no
// event was deleted, edited, or reordered after the fact.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// HashSize is the byte length of the chained SHA-256 hash. PrevHash
// for the very first event is HashSize zero bytes.
const HashSize = sha256.Size

// Action is a stable, dotted string identifying the kind of mutation
// that produced the event. Convention: "<resource>.<verb>" — e.g.
// "project.create", "cluster.member.grant", "auth.login".
//
// The "system.audit." namespace (ReservedActionPrefix) is RESERVED for the
// chain machinery's own segment markers. A consumer that derives actions
// from untrusted input must reject that namespace at the boundary — see
// IsReservedAction for why the framework cannot enforce it at Log.
type Action string

// ResourceType narrows the resource_id column to a known kind so
// queries by (resource_type, resource_id) don't accidentally collide
// across types. Empty for actions that don't target a specific
// resource (e.g. auth.login carries the actor in Actor and leaves
// the resource fields blank).
type ResourceType string

// Common action / resource constants. Kept here so call-site typos
// surface at compile time rather than at the audit-log query.
const (
	ResourceProject    ResourceType = "project"
	ResourceApp        ResourceType = "app"
	ResourceDeployment ResourceType = "deployment"
	ResourceCluster    ResourceType = "cluster"
	ResourceUser       ResourceType = "user"
	ResourceMembership ResourceType = "membership"
	ResourceWebhook    ResourceType = "webhook"
	ResourceAuth       ResourceType = "auth"
)

// ActorType narrows the principal kind that produced an audit event.
// Defaulted to ActorTypeUser when the context has no actor (matches
// every pre-v1.0 emission site), set to ActorTypeServiceAccount by
// the RequireServiceAccount middleware (v1.0 task 01), and set to
// ActorTypeSystem by service code that emits an audit event in
// reaction to a background trigger (e.g. the bootstrap chain-restart
// row, future scheduled tasks).
//
// Persisted as a TEXT column on audit_event (default 'user' so v0.9
// rows that pre-date this field still verify under the v0.9 canonical
// shape). v1.0's canonical_version=2 events include it in the
// hash-chain canonical payload — see Event.Canonical.
type ActorType string

const (
	// ActorTypeUser is the default. Every authenticated HTTP request
	// gated by RequireAuth lands as ActorTypeUser. Backwards-compat
	// shape: ActorFromContext returns Actor{Type: ActorTypeUser} for
	// any context that lacks an explicit override, so v0.6+ emission
	// sites carry forward unchanged.
	ActorTypeUser ActorType = "user"
	// ActorTypeServiceAccount is set by RequireServiceAccount (v1.0
	// task 01). SCIM-driven mutations + future CI-runner emissions
	// land under this type. The Actor.ID carries the service account
	// row id; Actor.Name carries the human-readable name from the
	// service_accounts table.
	ActorTypeServiceAccount ActorType = "service_account"
	// ActorTypeSystem is set by service code reacting to a non-user
	// trigger — boot-path chain restart, retention pruner, future
	// scheduled jobs. The Actor.ID is the literal "system"; Actor.Name
	// names the subsystem (e.g. "barista", "retention").
	ActorTypeSystem ActorType = "system"
)

// Actor identifies who performed the action. Fields may be empty for
// system-actor events (e.g. the daily retention prune logs as actor
// "system" with empty user_id). Type defaults to ActorTypeUser via
// ActorFromContext + the SQLite column DEFAULT 'user'.
//
// Name is populated for ActorTypeServiceAccount + ActorTypeSystem
// emissions and identifies the SA / subsystem (e.g. "scim-provisioner",
// "barista", "retention"). User emissions leave Name empty — their
// Email is the right rendering already. The field landed in v1.1
// (closes TD-AUDIT-03 — v1.0 stuffed the name into the Email field as
// a backstop, which renders correctly via ActorPill's fallback chain
// but is cosmetically wrong on the wire). Hash-chain payload for v1.1+
// rows (CanonicalVersion3) includes Name; v1.0 rows
// (CanonicalVersion2) don't, so the v1.0 chain segment stays
// verifiable under its own canonical shape via `barista audit verify
// --legacy --canonical-version=2`.
type Actor struct {
	Type   ActorType
	UserID string
	Email  string
	Name   string `json:"name,omitempty"`
	IP     string

	// TenantID names the tenant the actor was acting in; "" is a
	// single-tenant deployment. Opaque and app-defined, as everywhere
	// else.
	//
	// CARRIED, NOT HASHED. canonicalPayloadV3 enumerates its fields
	// explicitly rather than marshalling this struct, so adding this
	// field does not move a single existing row's chain hash — verified
	// by the byte-parity tests, and the reason it was safe to add here.
	// Putting the tenant INTO the canonical row is slice 7i-1
	// (canonical_version=4), which is blocked on an undecided question:
	// one chain with the tenant in the row, or one chain per tenant.
	// This field does not pre-empt that answer; it only makes the value
	// available to an emitter before it is decided.
	TenantID string `json:"tenant_id,omitempty"`
}

// actorCtxKey is the context key used by WithActor + ActorFromContext.
// Defined as an unexported type to avoid context-key collisions per
// the stdlib `context` package guidance.
type actorCtxKey struct{}

// WithActor returns a derived context carrying the actor. Used by
// RequireServiceAccount (and any future principal-injecting
// middleware) to override the default ActorTypeUser shape that
// ActorFromContext returns when nothing was stashed.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

// ActorFromContext returns the actor stashed by WithActor, or a
// zero-valued Actor with Type=ActorTypeUser when nothing was stashed.
// The default-to-user shape keeps every v0.6+ emission site working
// without per-site changes — handlers that already pass userID +
// email + IP via audit.Actor{...} literals just need to omit the
// Type field; the value lands as ActorTypeUser via the SQLite
// column default at insert time.
func ActorFromContext(ctx context.Context) Actor {
	if v, ok := ctx.Value(actorCtxKey{}).(Actor); ok {
		if v.Type == "" {
			v.Type = ActorTypeUser
		}
		return v
	}
	return Actor{Type: ActorTypeUser}
}

// ActorService constructs an Actor for a service-account-driven
// request. Used by RequireServiceAccount. The SA's human-readable
// name lands in Name (v1.1 — TD-AUDIT-03); Email stays empty (SAs
// don't have email addresses).
func ActorService(saID, saName string) Actor {
	return ActorServiceInTenant(saID, saName, "")
}

// ActorServiceInTenant is ActorService for a pooled deployment: the same
// actor, plus the tenant the service account was acting in.
//
// The existing fields keep their exact meaning — UserID is still the
// service account's id, Name still its human-readable name. The tenant
// is additional context, not a redefinition, so an emitter that ignores
// it produces the row it always did.
func ActorServiceInTenant(saID, saName, tenantID string) Actor {
	return Actor{Type: ActorTypeServiceAccount, UserID: saID, Name: saName, TenantID: tenantID}
}

// clusterIDCaptureKey is the context key used by WithClusterIDCapture
// + clusterIDCaptureFromContext. v1.1 task 04 — lets the audit
// middleware learn a mutation's cluster_id AFTER the handler runs.
// Because http.Handler chains can't propagate context UP from the
// inner handler to the outer middleware, the standard trick is to
// stash a pointer-to-mutable-struct in context; the handler writes
// to it, the middleware reads after the handler returns.
type clusterIDCaptureKey struct{}

// ClusterIDCapture is a mutable slot the audit-mutation middleware
// installs on the request context before invoking the handler. The
// handler calls SetClusterID(ctx, id) to fill it in; the middleware
// reads cap.ID back when constructing the audit.Event after a 2xx
// response.
//
// Pointer-mutable because Go's request-scoped context can't propagate
// values UP the middleware chain — only down. Without the indirection,
// the middleware (outer) couldn't see what the handler (inner) had
// learned.
type ClusterIDCapture struct {
	// ID is the cluster_id the handler resolved for this mutation.
	// Empty when the mutation isn't cluster-scoped (auth.*,
	// retention prune, etc.) — those rows fall through to the
	// "visible to all callers" branch of the query-time filter.
	ID string
}

// WithClusterIDCapture returns a derived context carrying a fresh
// ClusterIDCapture slot, plus the slot itself so the middleware can
// read cap.ID once the handler has returned. The audit-mutation
// middleware calls this exactly once per mutation request.
func WithClusterIDCapture(ctx context.Context) (context.Context, *ClusterIDCapture) {
	cap := &ClusterIDCapture{}
	return context.WithValue(ctx, clusterIDCaptureKey{}, cap), cap
}

// SetClusterID writes id into the ClusterIDCapture stashed on ctx by
// WithClusterIDCapture. Handlers + services call this when they have
// the cluster_id in scope; the audit-mutation middleware stamps
// audit.Event.ClusterID from cap.ID on success. No-op when the
// context wasn't wrapped — the request flowed through a code path
// that doesn't install the capture (e.g. handler tests that exercise
// the service directly without the middleware), in which case the
// event ends up with empty ClusterID.
//
// Safe to call multiple times; the last writer wins. The middleware
// reads after the handler returns, so concurrent writes from inside a
// single request handler are sequenced by the handler's own flow.
func SetClusterID(ctx context.Context, id string) {
	if cap, ok := ctx.Value(clusterIDCaptureKey{}).(*ClusterIDCapture); ok && cap != nil {
		cap.ID = id
	}
}

// ClusterIDFromContext returns the cluster_id stashed by SetClusterID,
// or "" when nothing was stashed. Used by the audit middleware to read
// the value after the handler has returned. Service-direct emissions
// (GroupService, ServiceAccountService, SCIM handlers) that build
// audit.Event literals inline don't need this — they set ClusterID
// directly on the struct from the in-scope domain object.
func ClusterIDFromContext(ctx context.Context) string {
	if cap, ok := ctx.Value(clusterIDCaptureKey{}).(*ClusterIDCapture); ok && cap != nil {
		return cap.ID
	}
	return ""
}

// ActorSystem constructs an Actor for a system-driven event (chain
// restart, retention pruner, scheduled jobs). UserID is the literal
// "system"; Name carries the subsystem name (v1.1 — TD-AUDIT-03;
// v1.0 stuffed this into Email).
func ActorSystem(name string) Actor {
	return Actor{Type: ActorTypeSystem, UserID: "system", Name: name}
}

// CanonicalVersion identifies which hash-chain canonical-payload
// shape was used to compute this event's Hash.
//
//   - CanonicalVersion1 — v0.6 → v0.9 rows. Actor.Type NOT in the
//     payload.
//   - CanonicalVersion2 — v1.0 rows. Actor.Type added; v1.0 first
//     boot inserts a `system.audit.chain_restart` row at this
//     version as the chain genesis.
//   - CanonicalVersion3 — v1.1+ rows. Actor.Name added (closes
//     TD-AUDIT-03); v1.1 first boot inserts a second
//     `system.audit.chain_restart` row at this version as the new
//     chain genesis. `barista audit verify` walks forward from the
//     latest restart row (v3 if present, v2 otherwise) by default;
//     `--legacy --canonical-version=N` walks the prior segment.
//   - CanonicalVersion4 — Phase 7 rows. Adds the tenant to the hashed
//     payload (`tenant_id` + `actor.tenant_id`) and moves the PII
//     fields to stored salted commitments so a row can be redacted
//     without breaking the chain. Emitted only by a tenancy-configured
//     logger; a single-tenant deployment keeps writing v3 forever, so
//     its bytes are unchanged.
const (
	CanonicalVersion1 = 1
	CanonicalVersion2 = 2
	CanonicalVersion3 = 3
	CanonicalVersion4 = 4
)

// Event is the wire-shaped audit-log entry. Fields are deliberately
// ordered so the canonical-form encoding (used as input to the hash
// chain) is stable.
type Event struct {
	ID           string
	At           time.Time
	Actor        Actor
	Action       Action
	ResourceType ResourceType
	ResourceID   string
	RequestID    string
	// ClusterID is the per-cluster scope marker (v1.1 task 04).
	// Empty for non-cluster-scoped events (auth.login,
	// auth.register, auth.identity.link, retention prune, etc.) —
	// those are visible to every caller of /admin/audit. Non-empty
	// for app.*, deployment.*, cluster.*, cluster_acl.*,
	// group.role.*, webhook.* events. The query layer (ListScoped)
	// filters non-system-admin callers down to events whose
	// cluster_id is empty OR in their reachable-cluster set.
	//
	// NOT part of the canonical-payload hash — purely a query-time
	// filter, not part of integrity. The v1.1 chain genesis stays at
	// CanonicalVersion3 and existing v3 rows verify cleanly under
	// their stored hashes.
	ClusterID string
	// Before / After are arbitrary JSON snapshots of the resource
	// pre / post mutation. nil means "not applicable" (e.g. Before
	// for create, After for delete).
	Before json.RawMessage
	After  json.RawMessage
	// PrevHash is the prior event's Hash (or HashSize zero bytes
	// for the first event). Hash is sha256(PrevHash || canonical
	// payload). Both fields are populated by Logger.Log and are
	// not part of the wire-DTO surface.
	PrevHash []byte
	Hash     []byte
	// CanonicalVersion identifies which canonical-payload shape the
	// Hash was computed under. Defaulted to CanonicalVersion2 on new
	// emissions (Logger.Log fills this in); v0.6-v0.9 rows in the
	// DB carry CanonicalVersion1 and are walked under the v0.9
	// canonical shape by `barista audit verify --legacy`.
	CanonicalVersion int

	// --- Phase 7 (canonical_version=4) ---

	// TenantID is the row's SCOPE: the tenant whose log this event
	// belongs in. Empty on a single-tenant deployment and on every
	// pre-v4 row.
	//
	// DIFFERENT FROM Actor.TenantID, and conflating the two is a
	// correctness bug rather than a stylistic one. A support engineer
	// or an ActorTypeSystem actor belonging to tenant A, acting on
	// tenant B's resource, has Actor.TenantID=A and TenantID=B. A
	// tenant export filtered on the ACTOR's tenant silently omits
	// exactly the cross-tenant administrative actions a customer most
	// wants to see. Export filters on THIS field.
	//
	// Part of the hash at v4. Unlike ClusterID above — which is
	// documented as a query-time filter and deliberately outside
	// integrity — the tenant is the trust boundary, and an unhashed
	// tenant column could be re-attributed from one customer to
	// another without breaking anything.
	TenantID string

	// RowSalt is the per-row salt the Commitments were computed under.
	// 32 random bytes on a v4 row; nil on pre-v4 rows; ALL ZEROES on a
	// row whose PII has been redacted (see redaction.go).
	//
	// Not part of the hash. It is an input to the commitments, not to
	// the payload, which is what lets it be destroyed on erasure while
	// the payload stays reproducible.
	RowSalt []byte

	// Commitments are the salted hashes of the PII fields, and are what
	// canonicalPayloadV4 actually hashes in place of the plaintext.
	// Zero on pre-v4 rows.
	Commitments Commitments
}

// Filter narrows ListEvents queries. Zero-valued fields mean "any."
// Limit defaults to 50 when zero. Cursor is opaque — pass back the
// `next_cursor` from a prior page for the next page.
type Filter struct {
	Since        time.Time
	Until        time.Time
	ActorUserID  string
	ActorEmail   string
	Action       Action
	ResourceType ResourceType
	ResourceID   string
	RequestID    string
	Limit        int
	Cursor       string
}

// Page is the result of ListEvents. NextCursor is empty when the page
// is the last.
type Page struct {
	Events     []Event
	NextCursor string
}

// VerifyResult is the result of Logger.Verify. Tamper is true when at
// least one event's Hash didn't match the recomputed value;
// FirstBadIndex is the 0-based index in the chain (oldest first) where
// the divergence first appears. Total is the number of events walked.
type VerifyResult struct {
	Total         int64
	Tamper        bool
	FirstBadIndex int64
}

// Logger is the audit-log primitive consumed by middleware + service
// hooks. SQLiteLogger is the production implementation; NoopLogger is
// used when audit is disabled (chart value barista.audit.enabled=false)
// or in tests that don't care about the log.
type Logger interface {
	// Log appends a new event to the chain. The implementation
	// fills in PrevHash + Hash from the previous event's Hash. ID
	// and At should be pre-set by the caller (so the middleware can
	// use a request-scoped clock + UUID).
	Log(ctx context.Context, e Event) (Event, error)

	// List returns a page of events matching the filter, newest
	// first. Empty filter + zero limit returns the most-recent 50.
	List(ctx context.Context, f Filter) (Page, error)

	// ListScoped returns events filtered by the caller's reachable
	// cluster set (v1.1 task 04). Used by /api/audit for callers
	// who reach the admin gate without the system-cluster-admin role
	// (rare cluster-admin-but-not-system-admin user). Events with
	// empty cluster_id (auth.*, system.*) are visible to every
	// caller; cluster-scoped events are visible only when the row's
	// cluster_id matches one of clusterIDs.
	//
	// Empty clusterIDs collapses to non-cluster-scoped-only events
	// — the correct semantics for a caller with no ACL grants.
	ListScoped(ctx context.Context, clusterIDs []string, f Filter) (Page, error)

	// Verify walks the chain end-to-end and recomputes every Hash.
	// Returns the first index where the recomputed value diverges,
	// or Total + Tamper=false when the chain is intact.
	Verify(ctx context.Context) (VerifyResult, error)

	// PruneOlderThan deletes events with At < cutoff. Used by the
	// retention goroutine on a daily tick. Returns the number of
	// events removed.
	//
	// Pruning preserves the hash chain across the gap: the first
	// surviving event keeps its PrevHash field unchanged. Verify
	// only walks from the oldest surviving event forward, so a
	// pruned chain still verifies cleanly within the retained
	// window. (Operators who need long-term integrity proof should
	// archive the audit DB before pruning fires.)
	PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error)

	// CountByActionSince returns per-action counts of events strictly
	// newer than `since`, ordered by count desc + action asc. Used by
	// the v1.2 task 03 audit-digest scheduler to compose the daily
	// summary body. Returned slice is empty (non-nil) when no events
	// fall in the window.
	//
	// Counts are unscoped at v1.2 (cluster-admin digests only); a
	// future v1.3 scoped variant would add a cluster_id IN(...) filter
	// for cluster-deployer-tier digests.
	CountByActionSince(ctx context.Context, since time.Time) ([]ActionCount, error)

	// DeleteEventByID removes a single audit event by id. Used by the
	// v1.5+ fixture loader's ConflictForce policy (closes TD-INFRA-19).
	// Idempotent at the SQLite level: zero-row deletes are not errors.
	//
	// Not exposed via the HTTP surface — audit events are append-only
	// at runtime; this method exists solely for the operator-driven
	// `barista --load-fixture --on-conflict=force` re-load workflow.
	// WILL break chain integrity for any row whose hash was pointed at
	// by a later row's prev_hash — caller's responsibility to use only
	// on rows known-safe to delete (typically just-loaded fixture rows
	// whose chain hasn't been extended yet).
	//
	// NoopLogger returns nil. SQLiteLogger dispatches to the sqlc
	// DeleteEventByID query.
	DeleteEventByID(ctx context.Context, id string) error

	// Close releases the backing connection. NoopLogger.Close is a
	// no-op.
	Close() error
}

// ActionCount is a single (action, count) pair returned by
// Logger.CountByActionSince. The scheduler iterates these to format
// the digest body; the order reflects the SQL ORDER BY (count desc,
// action asc).
type ActionCount struct {
	Action Action
	Count  int64
}

// NoopLogger is the test / audit-disabled Logger. It accepts Log calls
// but never persists them; List always returns an empty page; Verify
// always reports Total=0, Tamper=false; PruneOlderThan returns 0.
type NoopLogger struct{}

// NewNoopLogger constructs a NoopLogger. Returned as the Logger
// interface so call sites stay implementation-agnostic.
func NewNoopLogger() Logger { return NoopLogger{} }

// Log echoes the event back unchanged so call sites that read the
// returned Event for its (caller-set) ID don't break in test setups.
func (NoopLogger) Log(_ context.Context, e Event) (Event, error) { return e, nil }

// List returns an empty page.
func (NoopLogger) List(_ context.Context, _ Filter) (Page, error) { return Page{}, nil }

// ListScoped returns an empty page. The clusterIDs argument is
// ignored; NoopLogger doesn't persist events so there's nothing to
// scope.
func (NoopLogger) ListScoped(_ context.Context, _ []string, _ Filter) (Page, error) {
	return Page{}, nil
}

// Verify reports an empty, intact chain.
func (NoopLogger) Verify(_ context.Context) (VerifyResult, error) { return VerifyResult{}, nil }

// PruneOlderThan reports zero events removed.
func (NoopLogger) PruneOlderThan(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

// CountByActionSince returns an empty (non-nil) slice. The NoopLogger
// doesn't persist events so there's nothing to count.
func (NoopLogger) CountByActionSince(_ context.Context, _ time.Time) ([]ActionCount, error) {
	return []ActionCount{}, nil
}

// DeleteEventByID is a no-op. NoopLogger doesn't persist events so
// there's nothing to delete. Matches the rest of NoopLogger's
// silently-succeed shape (consistent with Log, PruneOlderThan, etc.).
func (NoopLogger) DeleteEventByID(_ context.Context, _ string) error { return nil }

// Close is a no-op.
func (NoopLogger) Close() error { return nil }

// canonicalPayloadV3 encodes the v1.1+ (canonical_version=3) shape:
// every field length-prefixed, BigEndian u32 lengths, actor.name
// included between actor.email and actor.ip. This is the encoding
// used for every NEW row Logger.Log emits (closes v1.0's pipe-collision
// class on free-text fields).
//
// Layout:
//
//	u32 len("id") | bytes("id") | u32 len(id) | bytes(id)
//	... repeated for each field in order ...
//	u64 at_unix_nanos (length-prefixed)
//	u32 len(prev_hash) | bytes(prev_hash)
//
// JSON columns (Before/After) are length-prefixed too; nil → length 0.
// BigEndian for portability across the rare little/big-endian audit-DB
// transfer.
//
// Earlier canonical versions are walked by their own encoder:
// canonicalPayloadLegacyV2 reproduces v1.0's pipe-separated shape so
// v1.0 chain segments verify under `barista audit verify --legacy
// --canonical-version=2`. v0.6-v0.9 (canonical_version=1) rows do not
// have a v3 walker — the v1.0 bootstrap migration promoted them all to
// canonical_version=2 at v1.0 first boot, so they shouldn't exist on
// disk in a post-v1.0 install.
func canonicalPayloadV3(e Event, prevHash []byte) []byte {
	var buf []byte
	buf = appendStringField(buf, "id", e.ID)
	buf = appendInt64Field(buf, "at", e.At.UnixNano())
	buf = appendStringField(buf, "actor.user_id", e.Actor.UserID)
	buf = appendStringField(buf, "actor.email", e.Actor.Email)
	buf = appendStringField(buf, "actor.name", e.Actor.Name)
	buf = appendStringField(buf, "actor.ip", e.Actor.IP)
	t := string(e.Actor.Type)
	if t == "" {
		t = string(ActorTypeUser)
	}
	buf = appendStringField(buf, "actor.type", t)
	buf = appendStringField(buf, "action", string(e.Action))
	buf = appendStringField(buf, "resource_type", string(e.ResourceType))
	buf = appendStringField(buf, "resource_id", e.ResourceID)
	buf = appendStringField(buf, "request_id", e.RequestID)
	buf = appendBytesField(buf, "before", []byte(e.Before))
	buf = appendBytesField(buf, "after", []byte(e.After))
	buf = appendBytesField(buf, "prev_hash", prevHash)
	return buf
}

// canonicalPayloadForVersion dispatches to the canonical-payload
// encoder for the requested canonical_version. Used by the verify
// path (walkChain) so each row's stored Hash is re-checked under the
// encoding that produced it.
//
//   - version=2 → canonicalPayloadLegacyV2 (v1.0 pipe-separated shape).
//   - version=3 → canonicalPayloadV3 (v1.1+ length-prefixed shape).
//   - version=1 → error. v0.6-v0.9 rows should have been
//     bootstrap-migrated to canonical_version=2 at v1.0 first boot;
//     finding one in the wild means either the v1.0 bootstrap migration
//     didn't run on this DB or someone hand-edited the column. Fail
//     loud rather than silently walking under the wrong shape.
//   - other values → error so a row with a future / unknown
//     canonical_version fails fast.
func canonicalPayloadForVersion(e Event, prevHash []byte, version int) ([]byte, error) {
	switch version {
	case CanonicalVersion1:
		return nil, fmt.Errorf("audit: canonical_version=1 was never expected to survive v1.0 bootstrap migration; refusing to walk")
	case CanonicalVersion2:
		return canonicalPayloadLegacyV2(e, prevHash), nil
	case CanonicalVersion3:
		return canonicalPayloadV3(e, prevHash), nil
	case CanonicalVersion4:
		return canonicalPayloadV4(e, prevHash), nil
	default:
		return nil, fmt.Errorf("audit: unknown canonical_version=%d", version)
	}
}

// canonicalPayload is the version-dispatched helper used by Log + the
// verify path. Kept as a thin shim around canonicalPayloadForVersion
// so callers that want to compute the payload for a specific event
// (typically in tests) read one obvious function.
//
// Errors are intentionally swallowed at this layer — the only error
// canonicalPayloadForVersion returns is for unknown canonical_version,
// and callers of this shim are always passing CanonicalVersion3 or
// CanonicalVersion2 explicitly via e.CanonicalVersion. Tests that want
// to assert the error path use canonicalPayloadForVersion directly.
func canonicalPayload(e Event) []byte {
	v := e.CanonicalVersion
	if v == 0 {
		v = CanonicalVersion3
	}
	payload, err := canonicalPayloadForVersion(e, e.PrevHash, v)
	if err != nil {
		// Defensive: if a test ever calls canonicalPayload with a v1
		// or unknown-version event, return empty bytes rather than
		// panic. The verify path uses canonicalPayloadForVersion
		// directly so the error gets surfaced as Tamper there.
		return nil
	}
	return payload
}

func appendStringField(dst []byte, name, value string) []byte {
	dst = appendLP(dst, []byte(name))
	dst = appendLP(dst, []byte(value))
	return dst
}

func appendBytesField(dst []byte, name string, value []byte) []byte {
	dst = appendLP(dst, []byte(name))
	dst = appendLP(dst, value)
	return dst
}

func appendInt64Field(dst []byte, name string, value int64) []byte {
	dst = appendLP(dst, []byte(name))
	var n [8]byte
	// int64 → uint64 reinterprets the bit pattern; no overflow
	// possible. The hash treats the result as opaque bytes anyway.
	binary.BigEndian.PutUint64(n[:], uint64(value)) //nolint:gosec // int64 → uint64 is bit-pattern-only
	dst = appendLP(dst, n[:])
	return dst
}

func appendLP(dst, value []byte) []byte {
	var n [4]byte
	// Field names are short literals and JSON payloads are bounded
	// by the surrounding HTTP body limits. A >4 GiB single audit
	// field would have already failed JSON marshalling upstream;
	// the truncation is theoretical, not a real concern.
	binary.BigEndian.PutUint32(n[:], uint32(len(value))) //nolint:gosec // payloads bounded by HTTP body limits
	dst = append(dst, n[:]...)
	dst = append(dst, value...)
	return dst
}

// computeHash returns sha256(prevHash || canonicalPayloadForVersion(e, prevHash, version)).
// Callers populate e.PrevHash before calling and use the returned
// value as e.Hash. version selects the canonical-payload encoder so
// v1.0 (CanonicalVersion2) chain segments and v1.1+ (CanonicalVersion3)
// segments both round-trip cleanly under their stored hashes.
//
// version=0 defaults to CanonicalVersion3 — that's what Logger.Log
// uses for every new emission. Tests / fixture builders that want a
// v2-shape hash pass version=CanonicalVersion2 explicitly.
//
// Returns nil on encoder error (canonical_version=1 or unknown).
// Callers in the write path treat this as a programmer error; callers
// in the verify path (walkChain) surface it as Tamper via the per-row
// canonicalPayloadForVersion call site directly, so this path is only
// hit when computeHash is invoked outside walkChain (Logger.Log).
func computeHash(prevHash []byte, e Event, version int) []byte {
	if version == 0 {
		version = CanonicalVersion3
	}
	payload, err := canonicalPayloadForVersion(e, prevHash, version)
	if err != nil {
		return nil
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(payload)
	return h.Sum(nil)
}

// HashHex is a convenience for diagnostic logging — the bytes are
// sha256.Size = 32, hex.EncodedLen = 64. Empty input returns "".
func HashHex(h []byte) string {
	if len(h) == 0 {
		return ""
	}
	return hex.EncodeToString(h)
}

// errEmptyDBPath is returned by NewSQLiteLogger when its dbPath
// parameter is empty. Surfaced as a stable sentinel so callers can
// distinguish config errors from open errors.
var errEmptyDBPath = fmt.Errorf("audit: dbPath is empty")
