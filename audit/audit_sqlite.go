package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/suryakencana007/tamper/audit/sqlitestore"
)

// SQLiteLogger is the production audit.Logger backed by a dedicated
// SQLite file. The hash chain is serialised through mu so concurrent
// Log calls don't fork by picking the same prev_hash.
//
// Throughput note: the lock is held only for the duration of a single
// SELECT-latest + INSERT round trip on a local SQLite file (microseconds
// in normal operation). v0.6's expected event rate (low single-digit
// per second on a busy install) is comfortably within that envelope.
// If volume grows past tens of writes per second, switch to a single-
// writer goroutine + buffered channel before optimising further.
type SQLiteLogger struct {
	store *sqlitestore.Store
	opts  SQLiteLoggerOptions

	mu sync.Mutex
	// lastAt is the monotonic-at watermark (v1.8 follow-up #3).
	// Initialized to the DB's latest `at` on NewSQLiteLogger. Log()
	// under mu enforces e.At > lastAt by bumping by 1ns on
	// collision, then updates lastAt. Prevents same-at clock
	// collisions (Windows microsecond clock) from producing rows
	// whose chain-linkage order doesn't match ORDER BY (at,
	// canonical_version, id) — see Log() docs for the full
	// rationale.
	lastAt time.Time
}

// SQLiteLoggerOptions configures a SQLiteLogger at construction time.
// All fields are optional; the zero value of SQLiteLoggerOptions
// matches the v1.0 behavior (no email enrichment).
//
// EmailLookup is a v1.1 addition (closes TD-AUDIT-04). The
// `auditor.Mutation` middleware path resolves user_id → email at
// request time via its own EmailLookup, but service-direct audit
// emissions (e.g. GroupService.bootstrap, ServiceAccountService.Create)
// only carry a user_id from the RequireAuth-stashed Actor. When
// EmailLookup is non-nil, Log calls it at emit time for
// ActorTypeUser events with empty Email + non-empty UserID. Failures
// or (_, false) returns are silently tolerated — the audit row still
// records user_id, just not email.
//
// EmailLookup MUST be context-safe and reasonably fast (a single
// SELECT against the users table). Slow lookups block the Log call.
type SQLiteLoggerOptions struct {
	EmailLookup func(ctx context.Context, userID string) (email string, ok bool)

	// Tenancy switches new emissions to canonical_version=4: the tenant
	// enters the hashed payload and PII moves to redactable commitments
	// (Phase 7, 7i-1).
	//
	// FALSE IS THE DEFAULT AND IT IS BYTE-IDENTICAL TO PRE-7i-1. A
	// single-tenant deployment keeps writing v3 rows with v3 hashes
	// forever, no v4 anchor is emitted, and nothing about its audit DB
	// changes — which is invariant 1 of the phase, satisfied by not
	// participating rather than by careful equivalence.
	//
	// Existing rows are never rewritten either way. v4 applies to rows
	// written from here on; every older row keeps its own
	// canonical_version and its own hash, and the verify walk dispatches
	// per row exactly as it already does for v2 and v3.
	Tenancy bool
}

// NewSQLiteLogger opens (or creates) the audit DB at dbPath and
// returns a Logger backed by it. Empty dbPath returns errEmptyDBPath
// — call sites should construct NewNoopLogger() instead when audit
// is disabled, rather than passing an empty path through.
//
// opts is optional config — pass SQLiteLoggerOptions{} for the v1.0
// behavior, or supply an EmailLookup to enrich service-direct
// emissions (v1.1+ — TD-AUDIT-04).
func NewSQLiteLogger(dbPath string, opts SQLiteLoggerOptions) (Logger, error) {
	if dbPath == "" {
		return nil, errEmptyDBPath
	}
	store, err := sqlitestore.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &SQLiteLogger{store: store, opts: opts}
	// v1.8 follow-up #3: prime the monotonic-at watermark from the
	// DB so the first Log after a process restart picks up where the
	// prior process left off. sql.ErrNoRows on a fresh DB leaves
	// lastAt zero (which Log() treats as "no prior row, no bump").
	if latestAt, err := store.Queries.GetLatestAt(context.Background()); err == nil {
		l.lastAt = latestAt.UTC()
	} else if !errors.Is(err, sql.ErrNoRows) {
		_ = store.Close()
		return nil, fmt.Errorf("audit: prime lastAt watermark: %w", err)
	}
	return l, nil
}

// Log appends an event to the chain. The caller pre-sets ID + At so
// the audit middleware can use a request-scoped clock + UUID; this
// method fills in PrevHash + Hash. Returns the event with both hash
// fields populated.
//
// CanonicalVersion is defaulted to CanonicalVersion3 on every fresh
// emission (v1.1+ canonical shape — Actor.Type + Actor.Name
// included). The boot path's v1.1 chain-restart row also lands as
// CanonicalVersion3; v1.0 rows that pre-date this version carry
// CanonicalVersion2 and v0.9 rows carry CanonicalVersion1. Older
// segments are walkable via `audit verify --legacy
// --canonical-version=N`.
//
// EmailLookup enrichment (v1.1 — TD-AUDIT-04): when the actor is
// ActorTypeUser + Email is empty + UserID is non-empty + opts.EmailLookup
// is non-nil, Log resolves user_id → email at emit time. This closes
// the service-direct emission gap where the actor was stashed by
// RequireAuth with user_id but no email — only the `auditor.Mutation`
// middleware path used to enrich there.
func (l *SQLiteLogger) Log(ctx context.Context, e Event) (Event, error) {
	if e.ID == "" {
		return Event{}, errors.New("audit: event id is required")
	}
	if e.At.IsZero() {
		return Event{}, errors.New("audit: event at is required")
	}
	if e.Action == "" {
		return Event{}, errors.New("audit: event action is required")
	}
	if e.Actor.Type == "" {
		e.Actor.Type = ActorTypeUser
	}
	if e.CanonicalVersion == 0 {
		// A tenancy-configured logger writes v4; everyone else keeps
		// writing v3. An explicit CanonicalVersion on the event still
		// wins, which is what lets the boot bootstraps emit anchors at
		// a chosen version.
		if l.opts.Tenancy {
			e.CanonicalVersion = CanonicalVersion4
		} else {
			e.CanonicalVersion = CanonicalVersion3
		}
	}

	// v1.1 — service-direct emission email enrichment (TD-AUDIT-04).
	// Only triggers when the actor is a user with a user_id but no
	// email. SA + system actors don't have emails; user actors that
	// already have one are left alone. The lookup is best-effort:
	// (_, false) or a nil lookup leaves Email empty.
	if e.Actor.Type == ActorTypeUser &&
		e.Actor.Email == "" &&
		e.Actor.UserID != "" &&
		l.opts.EmailLookup != nil {
		if email, ok := l.opts.EmailLookup(ctx, e.Actor.UserID); ok {
			e.Actor.Email = email
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// THE CHAIN WRITE IS ONE SERIALISED TRANSACTION, not a mutex.
	//
	// Appending to a hash chain is read-latest-hash, compute, insert —
	// a read-modify-write, and it is only atomic if something makes it
	// so. Until this change the only thing was l.mu, which is
	// IN-PROCESS: two replicas sharing one audit DB both read the same
	// latest hash, both computed against it, and both inserted. The
	// result is two rows claiming the same predecessor — a forked chain
	// that the boot verify reports as tamper, on a database nobody
	// tampered with. Reproduced in
	// TestMultiWriter_ConcurrentLoggersKeepTheChainIntact, which failed
	// with stored_prev=000...0 before this transaction existed: one
	// writer saw an empty table while another had already inserted.
	//
	// BEGIN IMMEDIATE, not a plain BeginTx. SQLite's default deferred
	// transaction takes a READ lock and only tries to upgrade at the
	// INSERT — by which point another writer may hold the write lock,
	// and the upgrade fails with SQLITE_BUSY that no busy_timeout can
	// resolve (both sides hold read locks; neither can proceed).
	// IMMEDIATE takes the write lock up front, so the second writer
	// simply waits out its busy_timeout and then reads a latest hash
	// that already includes the first writer's row.
	//
	// On a dedicated *sql.Conn because BEGIN and COMMIT must land on the
	// SAME connection, and a pooled *sql.DB gives no such guarantee. The
	// SQL is written out rather than configured through a DSN flag
	// (_txlock=immediate) deliberately: an unrecognised DSN parameter is
	// ignored silently, and "the fix is present but inert" is the exact
	// failure mode this whole subsystem exists to make impossible.
	//
	// l.mu is kept. It costs nothing and keepssame-process writers off the
	// database lock entirely, so the transaction only ever contends
	// across processes.
	conn, err := l.store.DB.Conn(ctx)
	if err != nil {
		return Event{}, fmt.Errorf("audit: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return Event{}, fmt.Errorf("audit: begin chain-append transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// context.Background: the rollback must run even when ctx is
			// what failed, or the connection returns to the pool holding
			// a write lock and every later append blocks on it.
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	q := sqlitestore.New(conn)

	// v1.8 follow-up #3 — enforce strictly monotonic `at`. Two
	// time.Now() calls inside the boot bootstraps
	// (bootstrapAuditChainRestart's v=2 + v=3 emits +
	// bootstrapAuditChainMigrate's marker emit) can collide on
	// low-resolution clocks (Windows microsecond TEXT storage),
	// producing rows that share the same `at`. The verify-path
	// walker uses ORDER BY (at, canonical_version, id) ASC — when
	// two same-`at` rows ALSO share canonical_version, the id-ASC
	// tiebreak is arbitrary UUID ordering that may not match the
	// actual chain-linkage order. Bumping by 1ns on collision so
	// `at` is strictly increasing across all Log emissions makes
	// ORDER BY at ASC follow chain order naturally, regardless of
	// canonical_version or id collisions.
	//
	// PR #293 (Sprint 0 follow-up) + #300 (v1.8 follow-up #2)
	// fixed same-`at` ordering on the verify-path + write-path
	// SELECT queries respectively. This fix closes the
	// remaining class — v=3 vs v=3 same-`at` collisions where the
	// canonical_version tiebreak doesn't help.
	// The watermark is the LATER of the in-process one and the DB's, for
	// the same reason the hash read moved inside the transaction: the
	// in-process value knows nothing about another replica's writes. Max
	// rather than replace, so a single-writer deployment behaves exactly
	// as before — at open the two are primed equal and every append
	// advances both, so the DB value can only match or trail.
	watermark := l.lastAt
	if dbAt, aerr := q.GetLatestAt(ctx); aerr == nil {
		if dbAt = dbAt.UTC(); dbAt.After(watermark) {
			watermark = dbAt
		}
	} else if !errors.Is(aerr, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("audit: read at watermark: %w", aerr)
	}
	if !watermark.IsZero() && !e.At.After(watermark) {
		e.At = watermark.Add(time.Nanosecond)
	}

	// v4 rows commit to their PII before the payload is built, because
	// the payload hashes the COMMITMENTS rather than the values. Done
	// here, once, at write time — the verify path reads the stored
	// commitments back and never re-derives them, which is what lets a
	// redacted row still hash to what it hashed to originally.
	if e.CanonicalVersion == CanonicalVersion4 && len(e.RowSalt) == 0 {
		salt, serr := NewRowSalt()
		if serr != nil {
			return Event{}, serr
		}
		e.RowSalt = salt
		e.Commitments = ComputeCommitments(salt, e)
	}

	prev, err := latestHashFrom(ctx, q)
	if err != nil {
		return Event{}, err
	}
	e.PrevHash = prev
	// Hash under the event's stated canonical version. New rows
	// default to CanonicalVersion3 (set above); test fixtures that
	// emit v2-shape rows (chain-restart genesis at v1.0; replays of
	// v1.0 audit segments) get hashed under the v1.0 pipe-separated
	// encoder so the row's stored hash round-trips through
	// canonicalPayloadLegacyV2 in the verify path. CanonicalVersion1
	// rows are rejected at write time — the v1.0 bootstrap migration
	// promoted every v1 row to v2 long before this code path runs;
	// emitting a fresh v1 row is by definition anomalous.
	if e.CanonicalVersion == CanonicalVersion1 {
		return Event{}, fmt.Errorf("audit: refusing to write canonical_version=1 row; v1.0 bootstrap migration should have promoted all v1 rows to v2")
	}
	e.Hash = computeHash(prev, e, e.CanonicalVersion)
	if len(e.Hash) == 0 {
		return Event{}, fmt.Errorf("audit: computeHash returned empty hash for canonical_version=%d (unknown encoder)", e.CanonicalVersion)
	}

	// Update the watermark BEFORE the INSERT so a SQL error
	// doesn't leave lastAt behind the (uninserted) e.At — a
	// retry would then collide on the same at again. If INSERT
	// fails, the row never made it to disk; subsequent Log calls
	// will bump from this (slightly elevated) watermark, which is
	// safe: the chain stays monotonic from the perspective of
	// rows that DID land.
	l.lastAt = e.At.UTC()

	if err := q.InsertEvent(ctx, sqlitestore.InsertEventParams{
		ID:               e.ID,
		At:               e.At.UTC(),
		ActorUserID:      e.Actor.UserID,
		ActorEmail:       e.Actor.Email,
		ActorIp:          e.Actor.IP,
		ActorType:        string(e.Actor.Type),
		ActorName:        e.Actor.Name,
		Action:           string(e.Action),
		ResourceType:     string(e.ResourceType),
		ResourceID:       e.ResourceID,
		ClusterID:        e.ClusterID,
		RequestID:        e.RequestID,
		BeforeJson:       string(e.Before),
		AfterJson:        string(e.After),
		PrevHash:         e.PrevHash,
		Hash:             e.Hash,
		CanonicalVersion: int64(e.CanonicalVersion),
		TenantID:         e.TenantID,
		ActorTenantID:    e.Actor.TenantID,
		RowSalt:          nonNilBytes(e.RowSalt),
		CActorEmail:      nonNilBytes(e.Commitments.ActorEmail),
		CActorName:       nonNilBytes(e.Commitments.ActorName),
		CActorIp:         nonNilBytes(e.Commitments.ActorIP),
		CBefore:          nonNilBytes(e.Commitments.Before),
		CAfter:           nonNilBytes(e.Commitments.After),
	}); err != nil {
		return Event{}, fmt.Errorf("audit: insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Event{}, fmt.Errorf("audit: commit chain append: %w", err)
	}
	committed = true
	return e, nil
}

// latestHash returns the most-recent event's hash, or HashSize zero
// bytes when the table is empty (genesis prev_hash sentinel). Caller
// holds l.mu.
//
// Ordering tie-break rationale: the underlying GetLatestHash query
// orders by (at DESC, canonical_version DESC, id DESC) (v1.8
// follow-up #2). The canonical_version DESC middle key is required
// because two time.Now() calls inside the boot bootstraps
// (bootstrapAuditChainRestart's v=2 + v=3 anchor inserts, then
// bootstrapAuditChainMigrate's marker insert) can return identical
// at values on low-resolution clocks — observed on Windows in v1.9
// Task 00's harness boot. Without the canonical_version tiebreak,
// SELECT ORDER BY at DESC, id DESC would pick whichever UUID sorted
// lexically higher at a colliding at, sometimes returning the v=2
// chain_restart row's hash instead of the v=3 row's hash that was
// inserted later in chain order — corrupting the next row's
// prev_hash and tripping the v1.8 boot guard at next boot.
//
// PR #293 fixed the inverse case on the verify path
// (ListEventsForVerify ORDER BY at ASC, canonical_version ASC, id
// ASC). This is the write-path analog: at DESC means "most recent
// first," canonical_version DESC means "higher version is more
// recent at the same at" (since v=3 chain rows always follow v=2
// chain_restart in chain order).
func (l *SQLiteLogger) latestHash(ctx context.Context) ([]byte, error) {
	return latestHashFrom(ctx, l.store.Queries)
}

// latestHashFrom is latestHash against an explicit Queries, so the chain
// append can read it INSIDE its transaction.
//
// HONEST SCOPE, because the tempting claim is wrong. This is not what
// makes the append safe — BEGIN IMMEDIATE is. Once the write lock is
// held no other writer can commit, so even a read through the pooled
// handle would return the same value. Swapping this back for
// l.latestHash leaves every multi-writer test green, and that was
// checked rather than assumed.
//
// It is kept because it makes the invariant LOCAL: the read and the
// insert are visibly the same transaction, so the next person to touch
// this function cannot reintroduce the race by moving a line. Defensive
// clarity, not the load-bearing part.
func latestHashFrom(ctx context.Context, q *sqlitestore.Queries) ([]byte, error) {
	row, err := q.GetLatestHash(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return make([]byte, HashSize), nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: latest hash: %w", err)
	}
	if len(row) == 0 {
		// Defensive: NULL-as-empty-bytes from the driver. Treat as
		// genesis.
		return make([]byte, HashSize), nil
	}
	return row, nil
}

// ListScoped is the per-cluster-scoped variant of List (v1.1 task 04).
// Returns events whose cluster_id is empty (non-cluster-scoped:
// auth.*, retention prune, etc.) OR is in the caller's reachable
// cluster set. Used by /api/audit for non-system-cluster-admin
// callers — system-cluster-admin callers skip this method and hit
// List instead, getting the unscoped view.
//
// limit / cursor handling mirrors List's newest-first / cursor-paginate
// shape. Empty cursor returns the newest page; non-empty cursor walks
// older events.
//
// clusterIDs may be empty — in that case the query collapses to the
// non-cluster-scoped subset (only rows with empty cluster_id). That's
// the correct semantics for a caller with no ACL grants at all: they
// see their own auth events but nothing scoped to clusters they don't
// touch.
//
// sqlc/sqlite doesn't support `sqlc.slice` for parameterised IN
// clauses, so the query is built here against the underlying *sql.DB.
// The list of placeholders is generated from len(clusterIDs); the IDs
// themselves are bound as separate parameters, so this is safe against
// SQL injection.
func (l *SQLiteLogger) ListScoped(ctx context.Context, clusterIDs []string, f Filter) (Page, error) {
	limit := int64(f.Limit)
	if limit <= 0 {
		limit = 50
	}

	// Degenerate path: caller has no reachable clusters. The IN(...)
	// construction can't bind a zero-element slice in SQLite, so route
	// to the non-cluster-scoped-only query directly.
	if len(clusterIDs) == 0 {
		var rows []sqlitestore.Event
		var err error
		if f.Cursor != "" {
			cursorAt, cursorID, perr := parseCursor(f.Cursor)
			if perr != nil {
				return Page{}, fmt.Errorf("audit: parse cursor: %w", perr)
			}
			rows, err = l.store.Queries.ListEventsNonClusterScopedBefore(ctx, sqlitestore.ListEventsNonClusterScopedBeforeParams{
				At:    cursorAt,
				At_2:  cursorAt,
				ID:    cursorID,
				Limit: limit,
			})
		} else {
			rows, err = l.store.Queries.ListEventsNonClusterScoped(ctx, limit)
		}
		if err != nil {
			return Page{}, fmt.Errorf("audit: list scoped (no clusters): %w", err)
		}
		return pageFromRows(rows, limit), nil
	}

	// Build the IN(?, ?, ...) clause from len(clusterIDs). The strings
	// are bound as parameters, so concatenating the placeholder list is
	// safe against injection. Capacity = 2*N+1 placeholders worst case
	// (cursor variant); we always allocate the longer form.
	args := make([]any, 0, len(clusterIDs)+4)
	for _, id := range clusterIDs {
		args = append(args, id)
	}

	placeholders := strings.Repeat("?,", len(clusterIDs))
	placeholders = placeholders[:len(placeholders)-1] // trim trailing comma

	var query string
	if f.Cursor != "" {
		cursorAt, cursorID, perr := parseCursor(f.Cursor)
		if perr != nil {
			return Page{}, fmt.Errorf("audit: parse cursor: %w", perr)
		}
		query = fmt.Sprintf(
			"SELECT id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name, "+
				"action, resource_type, resource_id, cluster_id, request_id, "+
				"before_json, after_json, prev_hash, hash, canonical_version "+
				"FROM events "+
				"WHERE (cluster_id = '' OR cluster_id IN (%s)) "+
				"AND (at < ? OR (at = ? AND id < ?)) "+
				"ORDER BY at DESC, id DESC "+
				"LIMIT ?",
			placeholders,
		)
		args = append(args, cursorAt, cursorAt, cursorID, limit)
	} else {
		query = fmt.Sprintf(
			"SELECT id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name, "+
				"action, resource_type, resource_id, cluster_id, request_id, "+
				"before_json, after_json, prev_hash, hash, canonical_version "+
				"FROM events "+
				"WHERE (cluster_id = '' OR cluster_id IN (%s)) "+
				"ORDER BY at DESC, id DESC "+
				"LIMIT ?",
			placeholders,
		)
		args = append(args, limit)
	}

	rows, err := l.store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return Page{}, fmt.Errorf("audit: list scoped: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]sqlitestore.Event, 0, limit)
	for rows.Next() {
		var i sqlitestore.Event
		if err := rows.Scan(
			&i.ID, &i.At, &i.ActorUserID, &i.ActorEmail, &i.ActorIp,
			&i.ActorType, &i.ActorName, &i.Action, &i.ResourceType,
			&i.ResourceID, &i.ClusterID, &i.RequestID, &i.BeforeJson,
			&i.AfterJson, &i.PrevHash, &i.Hash, &i.CanonicalVersion,
		); err != nil {
			return Page{}, fmt.Errorf("audit: scan scoped row: %w", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("audit: iterate scoped rows: %w", err)
	}
	return pageFromRows(out, limit), nil
}

// pageFromRows projects sqlc rows onto Page, attaching NextCursor when
// the page is full (i.e. the caller likely has more rows older than
// the last visible one). Shared between ListScoped's two query
// branches.
func pageFromRows(rows []sqlitestore.Event, limit int64) Page {
	out := make([]Event, len(rows))
	for i, r := range rows {
		out[i] = fromRow(r)
	}
	page := Page{Events: out}
	if int64(len(rows)) == limit && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor = formatCursor(last.At, last.ID)
	}
	return page
}

// List dispatches to the appropriate sqlc query based on which filter
// fields are populated. The dispatch order favours the most-narrow
// index: request_id (unique-ish per request), resource_type+id,
// actor, then plain newest-first.
//
// The filter dispatch is intentionally simple — adding combinatorial
// AND-filtering would require a query builder. v0.6 stays with single-
// dimension filters; the SPA's UI exposes one filter at a time.
func (l *SQLiteLogger) List(ctx context.Context, f Filter) (Page, error) {
	limit := int64(f.Limit)
	if limit <= 0 {
		limit = 50
	}

	var rows []sqlitestore.Event
	var err error

	switch {
	case f.RequestID != "":
		rows, err = l.store.Queries.ListEventsByRequest(ctx, sqlitestore.ListEventsByRequestParams{
			RequestID: f.RequestID,
			Limit:     limit,
		})
	case f.ResourceType != "" && f.ResourceID != "":
		rows, err = l.store.Queries.ListEventsByResource(ctx, sqlitestore.ListEventsByResourceParams{
			ResourceType: string(f.ResourceType),
			ResourceID:   f.ResourceID,
			Limit:        limit,
		})
	case f.ActorUserID != "":
		rows, err = l.store.Queries.ListEventsByActor(ctx, sqlitestore.ListEventsByActorParams{
			ActorUserID: f.ActorUserID,
			Limit:       limit,
		})
	case f.Cursor != "":
		cursorAt, cursorID, perr := parseCursor(f.Cursor)
		if perr != nil {
			return Page{}, fmt.Errorf("audit: parse cursor: %w", perr)
		}
		rows, err = l.store.Queries.ListEventsBefore(ctx, sqlitestore.ListEventsBeforeParams{
			At:    cursorAt,
			At_2:  cursorAt,
			ID:    cursorID,
			Limit: limit,
		})
	default:
		rows, err = l.store.Queries.ListEventsAll(ctx, limit)
	}
	if err != nil {
		return Page{}, fmt.Errorf("audit: list: %w", err)
	}

	out := make([]Event, len(rows))
	for i, r := range rows {
		out[i] = fromRow(r)
	}

	page := Page{Events: out}
	// Only emit a NextCursor when the page is full — otherwise the
	// caller has already seen the tail.
	if int64(len(rows)) == limit && len(rows) > 0 {
		last := rows[len(rows)-1]
		page.NextCursor = formatCursor(last.At, last.ID)
	}
	return page, nil
}

// Verify walks every event in chain order and recomputes each hash.
// Returns the first index where the recomputed value diverges from
// the stored Hash, or Total + Tamper=false on a clean walk.
//
// Chain-restart handling: when a `system.audit.chain_restart` row
// exists, Verify walks forward from the most-recent one and re-hashes
// every row under that row's `canonical_version` (so the boot-path
// insert + everything emitted afterward verify under the v1.1+ shape
// when present, otherwise the v1.0 shape). Older segments at earlier
// canonical versions are walkable via VerifyLegacy.
//
// When no chain-restart row exists (pre-v1.0 install, or a fresh
// install before main.go inserts the genesis row), Verify falls back
// to walking from row 0 — keyed by each row's own
// `canonical_version` column so v0.9 fixture rows still verify
// correctly under the v0.9 shape.
//
// The first event's PrevHash is taken as the chain baseline rather
// than insisted upon — for an unpruned chain it equals HashSize zero
// bytes (genesis), but after a retention prune the first surviving
// event's PrevHash points at the deleted predecessor. Either is OK;
// the hash-recompute check still proves nobody edited the surviving
// events. Each subsequent event's PrevHash must equal the prior
// event's Hash (linkage check); a mismatch reports the same
// FirstBadIndex as a hash-recompute failure.
func (l *SQLiteLogger) Verify(ctx context.Context) (VerifyResult, error) {
	rows, canonicalVersion, err := l.verifyRows(ctx)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify list: %w", err)
	}
	return walkChain(rows, canonicalVersion), nil
}

// VerifyLegacy walks every row at the given canonical_version in
// chain-ascending order, re-hashing each row under that version's
// canonical shape. Used by `barista audit verify --legacy
// --canonical-version=N` to walk a v1.0-only (canonical_version=2)
// segment in isolation after v1.1 has restarted the chain.
//
// v1.4 shape (TD-AUDIT-10): the walker covers the ENTIRE v=N segment,
// not just the rows downstream of the latest chain-restart row. This
// lets fixture events loaded via `barista --load-fixture` with
// timestamps older than the bootstrap chain-restart row verify
// alongside the bootstrap row in one pass. (v1.1-v1.3 rooted the walk
// at the latest chain-restart, which made loaded older-fixture rows
// unreachable.)
//
// When canonicalVersion <= 0, the call is equivalent to Verify — walk
// the latest segment under its own canonical_version.
//
// When fromID is non-empty, narrows the walk to start at the specified
// row. The row's canonical_version must match canonicalVersion or an
// error is returned (operator typo / wrong-version anchor). The
// resulting walk still uses the chain-restart-rooted query shape
// underneath, so the anchor row + every later row whose
// canonical_version equals canonicalVersion is included.
//
// When no rows exist at the requested version, returns an empty
// (clean) VerifyResult. Operators interpret this as "no segment to
// walk at this version on this DB" rather than "tamper."
func (l *SQLiteLogger) VerifyLegacy(ctx context.Context, canonicalVersion int, fromID string) (VerifyResult, error) {
	if canonicalVersion <= 0 {
		return l.Verify(ctx)
	}

	// fromID narrows the walk to a specific anchor row + later. The
	// anchor's canonical_version must match the requested version so
	// operators don't accidentally walk a v=3 row's downstream under
	// the v=2 encoder (or vice versa).
	if fromID != "" {
		anchor, err := l.store.Queries.GetEventByID(ctx, fromID)
		if errors.Is(err, sql.ErrNoRows) {
			return VerifyResult{}, fmt.Errorf("audit: --from-id %q not found", fromID)
		}
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify legacy lookup: %w", err)
		}
		if int(anchor.CanonicalVersion) != canonicalVersion {
			return VerifyResult{}, fmt.Errorf("audit: --from-id %q has canonical_version=%d, want %d",
				fromID, anchor.CanonicalVersion, canonicalVersion)
		}
		rows, err := l.store.Queries.ListEventsForVerifyFromChainRestart(ctx, sqlitestore.ListEventsForVerifyFromChainRestartParams{
			At:   anchor.At,
			At_2: anchor.At,
			ID:   anchor.ID,
		})
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify legacy from-id list: %w", err)
		}
		// Trim trailing rows whose canonical_version moved past the
		// requested one — same shape as the v1.1-v1.3 implementation.
		// Operators walking the legacy segment want bytes-pure
		// isolation under the requested encoder.
		trimmed := make([]sqlitestore.Event, 0, len(rows))
		for _, r := range rows {
			if int(r.CanonicalVersion) != canonicalVersion {
				break
			}
			trimmed = append(trimmed, r)
		}
		return walkChain(trimmed, canonicalVersion), nil
	}

	// Default v1.4 path — walk the entire v=N segment regardless of
	// where the bootstrap chain-restart row sits in time.
	rows, err := l.store.Queries.ListEventsByCanonicalVersion(ctx, int64(canonicalVersion))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify legacy list: %w", err)
	}
	if len(rows) == 0 {
		// No rows at this version. Operators interpret this as "no
		// segment to walk here," not as tamper.
		return VerifyResult{}, nil
	}
	return walkChain(rows, canonicalVersion), nil
}

// verifyRows picks the chain segment Verify walks. When a chain-restart
// row exists, returns rows from the most-recent restart row forward
// (inclusive) in chain-asc order plus the canonical_version those rows
// were hashed under; otherwise walks every row in the table and
// returns 0 as the canonical_version (the per-row column is used in
// that fallback path).
func (l *SQLiteLogger) verifyRows(ctx context.Context) ([]sqlitestore.Event, int, error) {
	restart, err := l.store.Queries.GetLatestChainRestart(ctx, string(ActionAuditChainRestart))
	if errors.Is(err, sql.ErrNoRows) {
		all, lerr := l.store.Queries.ListEventsForVerify(ctx)
		if lerr != nil {
			return nil, 0, lerr
		}
		return all, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	rows, err := l.store.Queries.ListEventsForVerifyFromChainRestart(ctx, sqlitestore.ListEventsForVerifyFromChainRestartParams{
		At:   restart.At,
		At_2: restart.At,
		ID:   restart.ID,
	})
	if err != nil {
		return nil, 0, err
	}
	return rows, int(restart.CanonicalVersion), nil
}

// walkChain runs the verify-loop shape: linkage check + per-row
// canonical-payload re-hash. Each row is re-hashed under its OWN
// canonical_version column — that's the v1.2 task 04 dispatch
// (closes TD-AUDIT-05). A mixed-version segment with v1.0 (v=2)
// rows followed by v1.1+ (v=3) rows walks cleanly because each row's
// stored hash is recomputed under its own encoder.
//
// When canonicalVersion > 0, that explicit version overrides each
// row's column — used by VerifyLegacy(N) to walk a segment under a
// specific encoder + by the chain-restart-rooted Verify path (the
// genesis row + every successor share the genesis row's canonical
// version because the boot path emits them under that version
// deliberately).
//
// When canonicalVersion is 0, per-row dispatch is honoured — used by
// the pre-v1.0 fallback walk and by any future mixed-version DB shape
// where the chain-restart row no longer pins a single version across
// the segment.
//
// FirstBadIndex distinguishes the failure modes:
//
//   - Linkage break (row N's PrevHash != row N-1's Hash) → return at N.
//   - Hash mismatch (recomputed hash != stored Hash) → return at N.
//   - Encoder error (unknown canonical_version on the row) → return
//     at N (treated as Tamper — the row's claimed version is unmappable
//     so the row's integrity can't be proven).
func walkChain(rows []sqlitestore.Event, canonicalVersion int) VerifyResult {
	total := int64(len(rows))
	if total == 0 {
		return VerifyResult{}
	}

	var prev []byte
	for i, r := range rows {
		e := fromRow(r)
		version := e.CanonicalVersion
		if canonicalVersion > 0 {
			version = canonicalVersion
			e.CanonicalVersion = canonicalVersion
		}
		if i == 0 {
			prev = e.PrevHash
		} else if !bytesEqual(e.PrevHash, prev) {
			// Linkage check from event 1 onward.
			return VerifyResult{Total: total, Tamper: true, FirstBadIndex: int64(i)}
		}
		payload, err := canonicalPayloadForVersion(e, prev, version)
		if err != nil {
			// Unknown encoder on a stored row — fail loud (v1 row in
			// the wild, future canonical_version, etc.).
			return VerifyResult{Total: total, Tamper: true, FirstBadIndex: int64(i)}
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(payload)
		want := h.Sum(nil)
		if !bytesEqual(e.Hash, want) {
			return VerifyResult{Total: total, Tamper: true, FirstBadIndex: int64(i)}
		}
		prev = e.Hash
	}
	return VerifyResult{Total: total}
}

// PruneOlderThan deletes events strictly older than cutoff and returns
// the number of rows removed. Pruning preserves Verify on the
// surviving suffix because the first surviving event's PrevHash still
// points at the (now-deleted) predecessor's hash; Verify walks from
// that PrevHash forward, so the suffix verifies cleanly. Operators
// who need long-term integrity proof should archive the audit DB
// before pruning fires.
func (l *SQLiteLogger) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := l.store.Queries.PruneOlderThan(ctx, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("audit: prune: %w", err)
	}
	return n, nil
}

// CanonicalVersionCount is one row from CountEventsByCanonicalVersion.
// Used by `barista audit verify` to print the per-version row-count
// summary after a clean walk so operators can sanity-check what
// segment shapes their DB carries.
type CanonicalVersionCount struct {
	CanonicalVersion int
	Count            int64
}

// CountByCanonicalVersion returns one row per distinct canonical_version
// across the audit DB, sorted ASC. Used by `barista audit verify` to
// emit the distribution summary line after a clean walk (closes part of
// v1.2 task 04 — "log the verified canonical_version distribution at
// end-of-walk"). Empty DB returns an empty slice.
func (l *SQLiteLogger) CountByCanonicalVersion(ctx context.Context) ([]CanonicalVersionCount, error) {
	rows, err := l.store.Queries.CountEventsByCanonicalVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: count by canonical_version: %w", err)
	}
	out := make([]CanonicalVersionCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, CanonicalVersionCount{
			CanonicalVersion: int(r.CanonicalVersion),
			Count:            r.EventCount,
		})
	}
	return out, nil
}

// CountByActionSince returns per-action counts of audit events strictly
// newer than `since`, ordered by count desc + action asc. Used by the
// v1.2 task 03 digest scheduler. Empty result is non-nil so callers can
// range over it without nil-guarding.
func (l *SQLiteLogger) CountByActionSince(ctx context.Context, since time.Time) ([]ActionCount, error) {
	rows, err := l.store.Queries.CountAuditEventsByActionSince(ctx, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("audit: count by action: %w", err)
	}
	out := make([]ActionCount, len(rows))
	for i, r := range rows {
		out[i] = ActionCount{Action: Action(r.Action), Count: r.Count}
	}
	return out, nil
}

// HasChainRestartV2 reports whether the audit DB already contains a
// row at canonical_version=2 (i.e. the v1.0 chain-restart row has
// been inserted on a prior boot). Used by cmd/barista/main.go's boot
// path to decide whether to insert the genesis row on this boot.
func (l *SQLiteLogger) HasChainRestartV2(ctx context.Context) (bool, error) {
	n, err := l.store.Queries.CountChainRestartV2(ctx, int64(CanonicalVersion2))
	if err != nil {
		return false, fmt.Errorf("audit: count v2 rows: %w", err)
	}
	return n > 0, nil
}

// HasChainRestartV3 reports whether the audit DB already contains a
// row at canonical_version=3 (i.e. the v1.1 chain-restart row has
// been inserted on a prior boot). Used by cmd/barista/main.go's boot
// path to decide whether to insert the v1.1 genesis row on this boot.
// Idempotent — subsequent boots see HasChainRestartV3=true and skip.
func (l *SQLiteLogger) HasChainRestartV3(ctx context.Context) (bool, error) {
	n, err := l.store.Queries.CountChainRestartV2(ctx, int64(CanonicalVersion3))
	if err != nil {
		return false, fmt.Errorf("audit: count v3 rows: %w", err)
	}
	return n > 0, nil
}

// DeleteEventByID removes a single audit event row by id. Used by the
// v1.5+ fixture loader's ConflictForce policy (closes TD-INFRA-19).
// Idempotent: sqlc's :exec semantics return nil when zero rows match,
// matching the policy's "ensure no prior row exists" intent — nothing
// to delete is fine.
//
// Breaks chain integrity for any row downstream of the deleted id
// because the chain's hash linkage stops verifying past the gap. The
// fixture loader uses this only on rows it is about to re-insert via
// Logger.Log, so the chain is rebuilt immediately. Operators using this
// outside the fixture-load path should re-walk the chain with
// `barista audit verify` afterwards.
func (l *SQLiteLogger) DeleteEventByID(ctx context.Context, id string) error {
	if err := l.store.Queries.DeleteEventByID(ctx, id); err != nil {
		return fmt.Errorf("audit: delete event by id: %w", err)
	}
	return nil
}

// Close releases the audit DB connection. Safe to call on a nil
// SQLiteLogger.
func (l *SQLiteLogger) Close() error {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.Close()
}

// fromRow maps a sqlc-generated row to the public audit.Event.
// before_json / after_json are passed through as raw JSON when
// non-empty, nil otherwise (preserves "not applicable" semantics).
//
// Actor.Type defaults to ActorTypeUser when the row's column is
// empty — captures the v0.9 backfill where the migration filled
// existing rows with 'user'. Actor.Name is taken straight from the
// row (v1.1 migration 003 backfilled it from actor_email for
// pre-v1.1 system + service_account rows). CanonicalVersion is taken
// straight from the row.
func fromRow(r sqlitestore.Event) Event {
	t := ActorType(r.ActorType)
	if t == "" {
		t = ActorTypeUser
	}
	e := Event{
		ID:               r.ID,
		At:               r.At,
		Actor:            Actor{Type: t, UserID: r.ActorUserID, Email: r.ActorEmail, Name: r.ActorName, IP: r.ActorIp},
		Action:           Action(r.Action),
		ResourceType:     ResourceType(r.ResourceType),
		ResourceID:       r.ResourceID,
		ClusterID:        r.ClusterID,
		RequestID:        r.RequestID,
		PrevHash:         r.PrevHash,
		Hash:             r.Hash,
		CanonicalVersion: int(r.CanonicalVersion),
		TenantID:         r.TenantID,
		RowSalt:          r.RowSalt,
		Commitments: Commitments{
			ActorEmail: r.CActorEmail,
			ActorName:  r.CActorName,
			ActorIP:    r.CActorIp,
			Before:     r.CBefore,
			After:      r.CAfter,
		},
	}
	e.Actor.TenantID = r.ActorTenantID
	if r.BeforeJson != "" {
		e.Before = json.RawMessage(r.BeforeJson)
	}
	if r.AfterJson != "" {
		e.After = json.RawMessage(r.AfterJson)
	}
	return e
}

// parseCursor decodes the opaque "<rfc3339nano>|<id>" cursor format.
// Used by ListEventsBefore for cursor-paginated reads.
func parseCursor(s string) (time.Time, string, error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '|' {
			ts, err := time.Parse(time.RFC3339Nano, s[:i])
			if err != nil {
				return time.Time{}, "", fmt.Errorf("invalid timestamp: %w", err)
			}
			return ts, s[i+1:], nil
		}
	}
	return time.Time{}, "", errors.New("cursor missing | separator")
}

// formatCursor encodes (at, id) into the opaque cursor string.
// RFC3339Nano keeps the format human-readable; the | separator can't
// appear inside an RFC3339Nano timestamp or a UUID, so the split is
// unambiguous.
func formatCursor(at time.Time, id string) string {
	return at.UTC().Format(time.RFC3339Nano) + "|" + id
}

// bytesEqual is a constant-time-equivalent byte compare. We don't
// need the constant-time property here (the comparison is part of an
// integrity walk, not an auth path), but defining it locally avoids
// the bytes.Equal import and keeps the package's import set tight.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonNilBytes coerces a nil slice to an empty one.
//
// The v4 columns are NOT NULL DEFAULT x”, but a DEFAULT only applies
// when the column is OMITTED from the INSERT — driver-marshalled nil
// arrives as an explicit SQL NULL and trips the constraint. Every v3
// emission carries nil for all six, so without this a tenancy-disabled
// logger cannot write a row at all: the "" path breaking on the very
// migration that was supposed to leave it alone.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
