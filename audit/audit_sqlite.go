package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/suryakencana007/tamper/audit/internal/sqlitestore"
	"github.com/suryakencana007/tamper/audit/internal/sqlitestore/sqltypes"
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
	// lastAt is the monotonic-at watermark, primed from the DB's latest
	// `at` at open. Log, under mu, bumps a colliding or earlier e.At to
	// lastAt+1ns and then advances lastAt, so ORDER BY at follows the
	// order rows were chained in.
	lastAt time.Time
}

// SQLiteLoggerOptions configures a SQLiteLogger at construction time.
// All fields are optional.
type SQLiteLoggerOptions struct {
	// EmailLookup resolves a user id to an email at Log time, for an
	// ActorTypeUser event that carries a UserID and no Email — the shape
	// a service-direct emission has, where the actor came from the
	// request context rather than from the audit middleware. A nil
	// lookup or a (_, false) answer leaves the email empty.
	//
	// It runs inside Log, so it must be context-safe and fast.
	EmailLookup func(ctx context.Context, userID string) (email string, ok bool)
}

// NewSQLiteLogger opens (or creates) the audit DB at dbPath and
// returns a Logger backed by it. Empty dbPath returns errEmptyDBPath
// — call sites should construct NewNoopLogger() instead when audit
// is disabled, rather than passing an empty path through.
//
// It refuses a DB that holds a row at any canonical_version other than
// CanonicalVersion4, because such a row cannot be verified and nothing
// should be appended behind it. There are two ways a DB gets one, and
// the error names both rather than guessing: the file was written by an
// older version of this package, or a row's version was changed after
// it was written. The second is tampering, so the error never tells the
// operator to discard the file.
func NewSQLiteLogger(dbPath string, opts SQLiteLoggerOptions) (Logger, error) {
	if dbPath == "" {
		return nil, errEmptyDBPath
	}
	store, err := sqlitestore.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &SQLiteLogger{store: store, opts: opts}

	counts, err := store.Queries.CountEventsByCanonicalVersion(context.Background())
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("audit: check canonical versions: %w", err)
	}
	for _, c := range counts {
		if c.CanonicalVersion != CanonicalVersion4 {
			_ = store.Close()
			return nil, fmt.Errorf(
				"audit: %s holds %d row(s) at canonical_version=%d, which this version cannot "+
					"verify (it reads and writes canonical_version=%d only). Keep the file. If it was "+
					"written by an older version of tamper, archive it and point the application at "+
					"a new audit DB. If it was not, a row was altered after it was written",
				dbPath, c.EventCount, c.CanonicalVersion, CanonicalVersion4)
		}
	}

	// Prime the monotonic-at watermark so the first Log after a restart
	// picks up where the previous process left off. sql.ErrNoRows on a
	// fresh DB leaves lastAt zero, which Log treats as "no prior row".
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
// method fills in CanonicalVersion, RowSalt, Commitments, PrevHash and
// Hash, and returns the event as stored. A RowSalt, Commitments,
// PrevHash or Hash already on the event is replaced, never trusted.
//
// Every row is written at CanonicalVersion4. An event may leave
// CanonicalVersion zero or set it to CanonicalVersion4; any other value
// is an error. There is no way to write another version.
//
// When the actor is ActorTypeUser with a UserID and no Email, and
// opts.EmailLookup is set, Log resolves the email at emit time.
func (l *SQLiteLogger) Log(ctx context.Context, e Event) (Event, error) {
	if err := validateRequiredFields(e); err != nil {
		return Event{}, err
	}
	if e.Actor.Type == "" {
		e.Actor.Type = ActorTypeUser
	}
	switch e.CanonicalVersion {
	case 0:
		e.CanonicalVersion = CanonicalVersion4
	case CanonicalVersion4:
	default:
		// Refused rather than written. A row at another version has no
		// encoder: Verify would report it as tamper on every walk, and
		// the next open of this DB would refuse the whole file.
		return Event{}, fmt.Errorf(
			"audit: event requests canonical_version=%d; only canonical_version=%d is written "+
				"(leave Event.CanonicalVersion zero)", e.CanonicalVersion, CanonicalVersion4)
	}

	// Email enrichment: only for a user actor with a user_id and no
	// email. Best-effort — (_, false) or a nil lookup leaves it empty.
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
	// so. l.mu is IN-PROCESS: two replicas sharing one audit DB would
	// both read the same latest hash, both compute against it, and both
	// insert, giving two rows that claim the same predecessor — a
	// forked chain that verify reports as tamper on a database nobody
	// tampered with (TestMultiWriter_ConcurrentLoggersKeepTheChainIntact).
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
	// l.mu is kept. It costs nothing and keeps same-process writers off
	// the database lock entirely, so the transaction only ever contends
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

	// Enforce a strictly increasing `at`. The verify walks order rows by
	// `at`, so two rows sharing one would be walked in an order decided
	// by their ids rather than by how they were chained. A colliding or
	// earlier e.At is bumped to watermark+1ns.
	//
	// The watermark is the LATER of the in-process one and the DB's: the
	// in-process value knows nothing about another replica's writes.
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

	// The row commits to its PII before the payload is built, because
	// the payload hashes the COMMITMENTS rather than the values. Done
	// here, once, at write time — the verify path reads the stored
	// commitments back and never re-derives them, which is what lets a
	// redacted row still hash to what it hashed to originally.
	//
	// Always a fresh salt, and always commitments computed HERE, after
	// the email enrichment above. An event that arrives carrying its own
	// (a row read back from List and logged again, say) would otherwise
	// be stored with commitments to PII it no longer holds, or with an
	// all-zero salt that marks plaintext as redacted.
	salt, serr := NewRowSalt()
	if serr != nil {
		return Event{}, serr
	}
	e.RowSalt = salt
	e.Commitments = ComputeCommitments(salt, e)

	prev, err := latestHashFrom(ctx, q)
	if err != nil {
		return Event{}, err
	}
	e.PrevHash = prev
	e.Hash = hashChainLink(prev, canonicalPayloadV4(e, prev))

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
		RowSalt:          sqltypes.Blob(e.RowSalt),
		CActorEmail:      sqltypes.Blob(e.Commitments.ActorEmail),
		CActorName:       sqltypes.Blob(e.Commitments.ActorName),
		CActorIp:         sqltypes.Blob(e.Commitments.ActorIP),
		CBefore:          sqltypes.Blob(e.Commitments.Before),
		CAfter:           sqltypes.Blob(e.Commitments.After),
	}); err != nil {
		return Event{}, fmt.Errorf("audit: insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Event{}, fmt.Errorf("audit: commit chain append: %w", err)
	}
	committed = true
	return e, nil
}

// latestHashFrom returns the most-recent event's hash, or HashSize zero
// bytes when the table is empty (the genesis prev_hash). It takes an
// explicit Queries so the chain append reads it INSIDE its transaction.
//
// That is not what makes the append safe — BEGIN IMMEDIATE is: once the
// write lock is held no other writer can commit. Reading through the
// transaction makes the invariant LOCAL, so the read and the insert are
// visibly the same transaction and cannot be separated by moving a line.
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

// eventColumns is the column list of the hand-built list query, in the
// order its Scan reads them. It must name every column fromRow maps: an
// event returned without its tenant, salt and commitments cannot be
// verified or exported by the caller.
const eventColumns = "id, at, actor_user_id, actor_email, actor_ip, actor_type, actor_name, " +
	"action, resource_type, resource_id, cluster_id, request_id, " +
	"before_json, after_json, prev_hash, hash, canonical_version, " +
	"tenant_id, actor_tenant_id, row_salt, " +
	"c_actor_email, c_actor_name, c_actor_ip, c_before, c_after"

// ListScoped is the per-cluster-scoped variant of List. It returns events
// whose cluster_id is empty (not cluster-scoped: auth.*, retention prune,
// and so on) OR is in the caller's reachable cluster set, and applies
// the Filter on top exactly as List does.
//
// clusterIDs may be empty. The query then returns only the rows with an
// empty cluster_id, which is the right answer for a caller with no
// cluster grants: their own auth events, and nothing scoped to a
// cluster they cannot reach.
func (l *SQLiteLogger) ListScoped(ctx context.Context, clusterIDs []string, f Filter) (Page, error) {
	scope := "cluster_id = ''"
	args := make([]any, 0, len(clusterIDs))
	if len(clusterIDs) > 0 {
		// One placeholder per id; the ids themselves are bound, so
		// building the placeholder list by concatenation is safe.
		placeholders := strings.Repeat("?,", len(clusterIDs))
		scope = "(cluster_id = '' OR cluster_id IN (" + placeholders[:len(placeholders)-1] + "))"
		for _, id := range clusterIDs {
			args = append(args, id)
		}
	}
	return l.list(ctx, f, []string{scope}, args)
}

// List returns a page of events matching the filter, newest first.
func (l *SQLiteLogger) List(ctx context.Context, f Filter) (Page, error) {
	return l.list(ctx, f, nil, nil)
}

// list builds and runs the one query behind List and ListScoped.
//
// Every Filter field that is set becomes one condition, and the
// conditions are ANDed. where and args carry the conditions the caller
// already has (ListScoped's cluster scope); the filter's are appended.
//
// The query is assembled here rather than generated because the set of
// conditions varies per call. Only fixed column names and placeholders
// are concatenated; every value is bound as a parameter.
func (l *SQLiteLogger) list(ctx context.Context, f Filter, where []string, args []any) (Page, error) {
	limit := int64(f.Limit)
	if limit <= 0 {
		limit = 50
	}

	add := func(cond string, vals ...any) {
		where = append(where, cond)
		args = append(args, vals...)
	}
	if !f.Since.IsZero() {
		add("at >= ?", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		add("at < ?", f.Until.UTC())
	}
	if f.ActorUserID != "" {
		add("actor_user_id = ?", f.ActorUserID)
	}
	if f.ActorEmail != "" {
		add("actor_email = ?", f.ActorEmail)
	}
	if f.Action != "" {
		add("action = ?", string(f.Action))
	}
	if f.ResourceType != "" {
		add("resource_type = ?", string(f.ResourceType))
	}
	if f.ResourceID != "" {
		add("resource_id = ?", f.ResourceID)
	}
	if f.RequestID != "" {
		add("request_id = ?", f.RequestID)
	}
	if f.Cursor != "" {
		cursorAt, cursorID, perr := parseCursor(f.Cursor)
		if perr != nil {
			return Page{}, fmt.Errorf("audit: parse cursor: %w", perr)
		}
		add("(at < ? OR (at = ? AND id < ?))", cursorAt, cursorAt, cursorID)
	}

	query := "SELECT " + eventColumns + " FROM events"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	// gosec reads the concatenation above as possible injection. It is
	// not: query is built only from eventColumns, the fixed condition
	// strings passed to add, and "?" placeholders. Every caller-supplied
	// value is in args (TestList_FilterValuesAreBound).
	rows, err := l.store.DB.QueryContext(ctx, query, args...) //nolint:gosec // G202: fixed fragments and placeholders only; values are bound
	if err != nil {
		return Page{}, fmt.Errorf("audit: list: %w", err)
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
			&i.TenantID, &i.ActorTenantID, &i.RowSalt,
			&i.CActorEmail, &i.CActorName, &i.CActorIp, &i.CBefore, &i.CAfter,
		); err != nil {
			return Page{}, fmt.Errorf("audit: scan row: %w", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return pageFromRows(out, limit), nil
}

// pageFromRows projects rows onto Page, attaching NextCursor when the
// page is full (the caller likely has more rows older than the last
// visible one).
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

// Verify walks every event in chain order and recomputes each hash.
// Returns the first index where the recomputed value diverges from
// the stored Hash, or Total + Tamper=false on a clean walk.
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
	rows, err := l.store.Queries.ListEventsForVerify(ctx)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify list: %w", err)
	}
	return walkChain(rows), nil
}

// walkChain is the verify loop: the linkage check, then a re-hash of
// each row under the canonical_version stored on it.
//
// FirstBadIndex distinguishes nothing between the failure modes; all
// three report the row they were found at:
//
//   - Linkage break (row N's PrevHash != row N-1's Hash).
//   - Hash mismatch (recomputed hash != stored Hash).
//   - A canonical_version with no encoder. The version column is an
//     input to the check, so a row relabelled to another version is
//     caught here rather than trusted.
func walkChain(rows []sqlitestore.Event) VerifyResult {
	total := int64(len(rows))
	if total == 0 {
		return VerifyResult{}
	}

	var prev []byte
	for i, r := range rows {
		e := fromRow(r)
		if i == 0 {
			prev = e.PrevHash
		} else if !bytesEqual(e.PrevHash, prev) {
			return VerifyResult{Total: total, Tamper: true, FirstBadIndex: int64(i)}
		}
		payload, err := canonicalPayloadForVersion(e, prev, e.CanonicalVersion)
		if err != nil {
			return VerifyResult{Total: total, Tamper: true, FirstBadIndex: int64(i)}
		}
		if !bytesEqual(e.Hash, hashChainLink(prev, payload)) {
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
// empty. CanonicalVersion is taken straight from the row.
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
		RowSalt:          []byte(r.RowSalt),
		Commitments: Commitments{
			ActorEmail: []byte(r.CActorEmail),
			ActorName:  []byte(r.CActorName),
			ActorIP:    []byte(r.CActorIp),
			Before:     []byte(r.CBefore),
			After:      []byte(r.CAfter),
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

// insertEventDirect writes a row exactly as given, skipping the chain
// computation Log performs. It is the single implementation behind both the
// package's own fixture helpers and the exported InsertEventDirectForTest.
//
// It writes whatever it is handed, including a row that breaks the chain.
// Nothing here validates PrevHash/Hash, because the tamper-detection tests
// need to be able to write a bad row on purpose.
func (l *SQLiteLogger) insertEventDirect(ctx context.Context, e Event) error {
	beforeJSON := ""
	if len(e.Before) > 0 {
		beforeJSON = string(e.Before)
	}
	afterJSON := ""
	if len(e.After) > 0 {
		afterJSON = string(e.After)
	}
	return l.store.Queries.InsertEvent(ctx, sqlitestore.InsertEventParams{
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
		BeforeJson:       beforeJSON,
		AfterJson:        afterJSON,
		PrevHash:         e.PrevHash,
		Hash:             e.Hash,
		CanonicalVersion: int64(e.CanonicalVersion),
		TenantID:         e.TenantID,
		ActorTenantID:    e.Actor.TenantID,
		RowSalt:          sqltypes.Blob(e.RowSalt),
		CActorEmail:      sqltypes.Blob(e.Commitments.ActorEmail),
		CActorName:       sqltypes.Blob(e.Commitments.ActorName),
		CActorIp:         sqltypes.Blob(e.Commitments.ActorIP),
		CBefore:          sqltypes.Blob(e.Commitments.Before),
		CAfter:           sqltypes.Blob(e.Commitments.After),
	})
}

// IsUniqueViolation reports whether err is a SQLite UNIQUE or PRIMARY KEY
// constraint violation from the audit store.
//
// Exported because a consumer replaying fixture rows has to tell "this ID is
// already in the chain" apart from "the database fell over", and it must use
// the SQLite classifier specifically: the audit DB is always SQLite regardless
// of which driver the application's main store was built with, so a
// build-tag-dependent classifier would look for a Postgres SQLSTATE and miss
// this entirely.
//
// Previously callers reached into audit/sqlitestore for this. That package is
// now internal, and this is the only thing outside tamper ever legitimately
// needed from it.
func IsUniqueViolation(err error) bool {
	return sqlitestore.IsUniqueViolation(err)
}
