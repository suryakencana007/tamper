package tamper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

var (
	ctxA    = context.Background()
	acme    = tenant.New("acme")
	theUser = "u-1"
)

// captureLogger is an audit.Logger that keeps what it is given and can be told
// to fail.
type captureLogger struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

var _ audit.Logger = (*captureLogger)(nil)

func (c *captureLogger) Log(_ context.Context, e audit.Event) (audit.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return audit.Event{}, c.err
	}
	c.events = append(c.events, e)
	return e, nil
}

func (c *captureLogger) List(context.Context, audit.Filter) (audit.Page, error) {
	return audit.Page{}, nil
}
func (c *captureLogger) ListScoped(context.Context, []string, audit.Filter) (audit.Page, error) {
	return audit.Page{}, nil
}
func (c *captureLogger) Verify(context.Context) (audit.VerifyResult, error) {
	return audit.VerifyResult{}, nil
}
func (c *captureLogger) PruneOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (c *captureLogger) CountByActionSince(context.Context, time.Time) ([]audit.ActionCount, error) {
	return nil, nil
}
func (c *captureLogger) DeleteEventByID(context.Context, string) error { return nil }
func (c *captureLogger) Close() error                                  { return nil }

func (c *captureLogger) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// recordingAdmin records what the composer asked the tenant table to do, and can
// be told to fail a status write.
type recordingAdmin struct {
	mem          *tenant.MemStore
	setStatusErr error
	mu           sync.Mutex
	calls        []string
}

func (r *recordingAdmin) List(ctx context.Context) ([]tenant.Descriptor, error) {
	return r.mem.List(ctx)
}

func (r *recordingAdmin) Create(ctx context.Context, d tenant.Descriptor) error {
	return r.mem.Create(ctx, d)
}

func (r *recordingAdmin) SetStatus(ctx context.Context, id tenant.ID, status tenant.Status) error {
	r.mu.Lock()
	r.calls = append(r.calls, id.String()+"="+string(status))
	r.mu.Unlock()
	if r.setStatusErr != nil {
		return r.setStatusErr
	}
	return r.mem.SetStatus(ctx, id, status)
}

func (r *recordingAdmin) setStatusCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// failingRevoker is the identity store with one method that refuses.
type failingRevoker struct {
	*identity.MemStore
	err error
}

func (f failingRevoker) RevokeAllRefreshSessionsForTenant(context.Context, tenant.ID, time.Time) error {
	return f.err
}

// stack builds the three pieces the composer needs, with one live refresh
// session in acme.
func stack(t *testing.T, store *identity.MemStore, log audit.Logger) (*Admin, *recordingAdmin) {
	t.Helper()
	admin := &recordingAdmin{mem: tenant.NewMemStore()}
	if err := admin.mem.Create(ctxA, tenant.Descriptor{ID: "acme", Slug: "acme", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "tamper-admin-test-secret", TTL: time.Hour, Issuer: "tamper-test"})
	core, err := identity.New(store, jwt)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	if err := store.CreateRefreshSession(ctxA, identity.RefreshSession{
		ID: "s-1", UserID: theUser, TenantID: acme.String(), TokenHash: "h-1",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		AuthTime: time.Now(), ACR: crypto.ACRLocalPassword,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return NewAdmin(admin, core, log), admin
}

func operatorCtx(user, home string) context.Context {
	return audit.WithActor(context.Background(), audit.Actor{
		Type: audit.ActorTypeUser, UserID: user, TenantID: home,
	})
}

// ---------------------------------------------------------------------
// Construction (rule 6: the guard ships with a test that fires)
// ---------------------------------------------------------------------

func TestNewAdmin_PanicsOnMissingPiece(t *testing.T) {
	mem := identity.NewMemStore()
	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "x-test-secret", TTL: time.Hour, Issuer: "i"})
	core, err := identity.New(mem, jwt)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	admin := tenant.NewMemStore()
	log := &captureLogger{}

	cases := map[string]func(){
		"nil admin store": func() { NewAdmin(nil, core, log) },
		"nil core":        func() { NewAdmin(admin, nil, log) },
		"nil logger":      func() { NewAdmin(admin, core, nil) },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: want panic, got none", name)
				}
			}()
			call()
		})
	}
}

// ---------------------------------------------------------------------
// The happy path, and the audit row's two tenants
// ---------------------------------------------------------------------

func TestSuspend_SetsStatusRevokesAndAudits(t *testing.T) {
	mem := identity.NewMemStore()
	log := &captureLogger{}
	a, admin := stack(t, mem, log)

	if err := a.Suspend(operatorCtx("ops", "platform"), acme); err != nil {
		t.Fatalf("Suspend: %v", err)
	}

	// The tenant table was asked for exactly one thing, and it was the
	// suspension: the composer writes the status, not something else first.
	if calls := admin.setStatusCalls(); len(calls) != 1 || calls[0] != "acme=suspended" {
		t.Fatalf("tenant-table calls = %v, want exactly [acme=suspended]", calls)
	}
	// The tenant is suspended.
	if d, err := admin.mem.ByID(ctxA, "acme"); err != nil || d.Status != tenant.StatusSuspended {
		t.Fatalf("tenant = %+v, %v; want suspended", d, err)
	}
	// The sessions are gone.
	if n := mem.LiveSessionCount(theUser); n != 0 {
		t.Fatalf("live sessions = %d, want 0", n)
	}
	// One audit row, scoped to the SUSPENDED tenant, actor from the operator.
	evs := log.snapshot()
	if len(evs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.TenantID != acme.String() {
		t.Fatalf("event scope = %q, want the suspended tenant %q", ev.TenantID, acme)
	}
	if ev.Actor.TenantID != "platform" || ev.Actor.UserID != "ops" {
		t.Fatalf("actor = %+v, want ops@platform", ev.Actor)
	}
	if ev.Action != ActionSuspendTenant || ev.ResourceType != ResourceTypeTenant || ev.ResourceID != acme.String() {
		t.Fatalf("event = %s %s:%s, want %s %s:%s", ev.Action, ev.ResourceType, ev.ResourceID,
			ActionSuspendTenant, ResourceTypeTenant, acme)
	}
	if ev.Actor.Type != audit.ActorTypeUser {
		t.Fatalf("actor type = %q, want the subject type, never the admin level", ev.Actor.Type)
	}
}

// ---------------------------------------------------------------------
// Ordering and the partial states
// ---------------------------------------------------------------------

func TestSuspend_StatusFailureTouchesNothingElse(t *testing.T) {
	mem := identity.NewMemStore()
	log := &captureLogger{}
	a, admin := stack(t, mem, log)
	admin.setStatusErr = tenant.ErrNotFound

	err := a.Suspend(operatorCtx("ops", "platform"), acme)
	if !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if n := mem.LiveSessionCount(theUser); n != 1 {
		t.Fatalf("live sessions = %d, want 1 — a failed status write must not revoke", n)
	}
	if got := len(log.snapshot()); got != 0 {
		t.Fatalf("audit rows = %d, want 0 — nothing happened, nothing to record", got)
	}
}

func TestSuspend_RevokeFailureLeavesTenantSuspendedAndSaysSo(t *testing.T) {
	mem := identity.NewMemStore()
	broken := failingRevoker{MemStore: mem, err: errors.New("session table down")}
	log := &captureLogger{}
	a, admin := stack(t, mem, log)
	// Rebuild the composer over a core whose store refuses the revocation.
	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "tamper-admin-test-secret", TTL: time.Hour, Issuer: "tamper-test"})
	core, err := identity.New(broken, jwt)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	a = NewAdmin(admin, core, log)

	err = a.Suspend(operatorCtx("ops", "platform"), acme)
	if err == nil {
		t.Fatal("want a partial-state error, got nil")
	}
	if !errors.Is(err, broken.err) {
		t.Fatalf("err = %v, want it to wrap the revocation failure", err)
	}
	if !contains(err.Error(), "IS suspended") {
		t.Fatalf("err = %q, want it to say the tenant IS suspended", err)
	}
	if d, _ := admin.mem.ByID(ctxA, "acme"); d.Status != tenant.StatusSuspended {
		t.Fatalf("tenant = %+v, want suspended despite the revocation failure", d)
	}
	if n := mem.LiveSessionCount(theUser); n != 1 {
		t.Fatalf("live sessions = %d, want 1 — the revocation really did fail", n)
	}
}

func TestSuspend_AuditFailureIsReported(t *testing.T) {
	mem := identity.NewMemStore()
	log := &captureLogger{err: errors.New("audit chain down")}
	a, _ := stack(t, mem, log)

	err := a.Suspend(operatorCtx("ops", "platform"), acme)
	if err == nil {
		t.Fatal("want an error when the audit row cannot be written, got nil")
	}
	if !errors.Is(err, log.err) || !contains(err.Error(), "audit row is missing") {
		t.Fatalf("err = %q, want it to name the missing audit row", err)
	}
}

// A refusal propagates and revokes nothing.
func TestSuspend_RefusalsPropagateWithoutRevoking(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   tenant.ID
		want error
	}{
		{"single tenant", tenant.Single, tenant.ErrSingleTenant},
		{"unknown tenant", tenant.New("nope"), tenant.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := identity.NewMemStore()
			log := &captureLogger{}
			a, _ := stack(t, mem, log)

			err := a.Suspend(operatorCtx("ops", "platform"), tc.id)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if n := mem.LiveSessionCount(theUser); n != 1 {
				t.Fatalf("live sessions = %d, want 1", n)
			}
			if got := len(log.snapshot()); got != 0 {
				t.Fatalf("audit rows = %d, want 0", got)
			}
		})
	}
}

// A retried suspension is a normal retry: it succeeds and still revokes.
func TestSuspend_IsIdempotent(t *testing.T) {
	mem := identity.NewMemStore()
	log := &captureLogger{}
	a, _ := stack(t, mem, log)

	if err := a.Suspend(operatorCtx("ops", "platform"), acme); err != nil {
		t.Fatalf("first Suspend: %v", err)
	}
	if err := a.Suspend(operatorCtx("ops", "platform"), acme); err != nil {
		t.Fatalf("second Suspend: %v", err)
	}
	if got := len(log.snapshot()); got != 2 {
		t.Fatalf("audit rows = %d, want 2 — each attempt is recorded", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
