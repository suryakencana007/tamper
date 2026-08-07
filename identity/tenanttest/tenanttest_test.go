package tenanttest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/identity"
)

// --- the recorder -----------------------------------------------------
//
// RunLeakSuite takes *testing.T, so a leaky fixture cannot be driven
// through it without failing this package's own test run. runLeakSuite
// takes harnessT instead, and recorderT captures the verdict — which is
// what turns "a leaky fixture fails the suite" from a claim into a
// check.

type fatalPanic struct{}

type recorderT struct {
	failed   bool
	messages []string
}

func (r *recorderT) Helper() {}

func (r *recorderT) Errorf(format string, args ...any) {
	r.failed = true
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

// Fatalf must ABORT the case the way testing.T does, or a fixture that
// fails a seed would carry on and report misleading downstream errors.
func (r *recorderT) Fatalf(format string, args ...any) {
	r.failed = true
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
	panic(fatalPanic{})
}

func (r *recorderT) Run(name string, f func(harnessT)) bool {
	sub := &recorderT{}
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				if _, ok := rec.(fatalPanic); !ok {
					panic(rec) // a real bug in the suite, not a recorded failure
				}
			}
		}()
		f(sub)
	}()
	if sub.failed {
		r.failed = true
		for _, m := range sub.messages {
			r.messages = append(r.messages, name+": "+m)
		}
	}
	return !sub.failed
}

func (r *recorderT) report() string { return strings.Join(r.messages, "\n  ") }

// --- the fixture ------------------------------------------------------

type leakMode int

const (
	leakNone leakMode = iota
	leakUserByEmail        // ignores tenantID on the user read
	leakIdentity           // ignores tenantID on the identity read
	leakCount              // counts every tenant's users
	leakSessionTenant      // drops TenantID when returning a session
	leakRevokeAll          // revokes every tenant's sessions
	leakPermissionError    // returns a permission-shaped error instead of ErrNotFound
	leakZeroValueNilError  // returns a zero value with a nil error
	leakGlobalEmailUnique  // email unique globally rather than per tenant (blocker B1)
)

// errPermissionDenied is the shape a store might plausibly return
// instead of ErrNotFound — and which discloses that the row exists.
var errPermissionDenied = fmt.Errorf("permission denied: user belongs to another tenant")

// fixture is a two-tenant store whose isolation can be broken one seam
// at a time. Compliant when mode == leakNone; every other mode breaks
// exactly one property so each assertion in the suite is proven to bite
// on its own, rather than the whole suite going red for one reason.
type fixture struct {
	mu       sync.Mutex
	mode     leakMode
	users    map[string]identity.User
	idents   map[string]identity.Identity
	sessions map[string]identity.RefreshSession
	byHash   map[string]string
}

var _ identity.TenantScopedStore = (*fixture)(nil)

func newFixture(mode leakMode) *fixture {
	return &fixture{
		mode:     mode,
		users:    make(map[string]identity.User),
		idents:   make(map[string]identity.Identity),
		sessions: make(map[string]identity.RefreshSession),
		byHash:   make(map[string]string),
	}
}

// --- the tenant-scoped surface, where the leaks live ---

func (f *fixture) UserByEmailInTenant(_ context.Context, tenantID, email string) (identity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Email != email {
			continue
		}
		if f.mode == leakUserByEmail || u.TenantID == tenantID {
			return u, nil
		}
	}
	switch f.mode {
	case leakPermissionError:
		return identity.User{}, errPermissionDenied
	case leakZeroValueNilError:
		return identity.User{}, nil
	default:
		return identity.User{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, email)
	}
}

func (f *fixture) IdentityByProviderSubjectInTenant(_ context.Context, tenantID, provider, subject string) (identity.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, i := range f.idents {
		if i.Provider != provider || i.Subject != subject {
			continue
		}
		if f.mode == leakIdentity || i.TenantID == tenantID {
			return i, nil
		}
	}
	return identity.Identity{}, fmt.Errorf("%w: identity %s/%s", identity.ErrNotFound, provider, subject)
}

func (f *fixture) CountUsersInTenant(_ context.Context, tenantID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, u := range f.users {
		if f.mode == leakCount || u.TenantID == tenantID {
			n++
		}
	}
	return n, nil
}

func (f *fixture) RevokeAllRefreshSessionsForTenant(_ context.Context, tenantID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, s := range f.sessions {
		if f.mode == leakRevokeAll || s.TenantID == tenantID {
			s.RevokedAt = at
			f.sessions[id] = s
		}
	}
	return nil
}

// --- the inherited Store surface ---

func (f *fixture) CreateUser(_ context.Context, u identity.NewUser, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.users {
		sameTenant := existing.TenantID == u.TenantID
		if existing.Email == u.Email && (sameTenant || f.mode == leakGlobalEmailUnique) {
			return fmt.Errorf("%w: %s", identity.ErrEmailTaken, u.Email)
		}
	}
	f.users[u.ID] = identity.User{
		ID: u.ID, TenantID: u.TenantID, Email: u.Email,
		PasswordHash: u.PasswordHash, Active: true, CreatedAt: u.CreatedAt,
	}
	return nil
}

func (f *fixture) UserByID(_ context.Context, id string) (identity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return identity.User{}, fmt.Errorf("%w: user %s", identity.ErrNotFound, id)
	}
	return u, nil
}

func (f *fixture) UserByEmail(_ context.Context, email string) (identity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return identity.User{}, fmt.Errorf("%w: email %s", identity.ErrNotFound, email)
}

func (f *fixture) CountUsers(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.users)), nil
}

func (f *fixture) CreateRefreshSession(_ context.Context, s identity.RefreshSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[s.ID] = s
	f.byHash[s.TokenHash] = s.ID
	return nil
}

func (f *fixture) RefreshSessionByHash(_ context.Context, tokenHash string) (identity.RefreshSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byHash[tokenHash]
	if !ok {
		return identity.RefreshSession{}, fmt.Errorf("%w: session", identity.ErrNotFound)
	}
	s := f.sessions[id]
	if f.mode == leakSessionTenant {
		s.TenantID = "" // the row loses its tenant on the way out
	}
	return s, nil
}

func (f *fixture) RevokeRefreshSession(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[id]; ok && !s.Revoked() {
		s.RevokedAt = at
		f.sessions[id] = s
	}
	return nil
}

func (f *fixture) RevokeAllRefreshSessionsForUser(_ context.Context, userID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, s := range f.sessions {
		if s.UserID == userID && !s.Revoked() {
			s.RevokedAt = at
			f.sessions[id] = s
		}
	}
	return nil
}

func (f *fixture) InsertIdentity(_ context.Context, ni identity.NewIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, i := range f.idents {
		if i.Provider == ni.Provider && i.Subject == ni.Subject && i.TenantID == ni.TenantID {
			return fmt.Errorf("%w: %s/%s", identity.ErrIdentityTaken, ni.Provider, ni.Subject)
		}
	}
	// Explicit map, NOT identity.Identity(ni) — same reasoning as
	// identity/memstore.go: NewIdentity is a COMMAND, Identity is the
	// persisted ENTITY, and their coinciding field sets are incidental
	// rather than an invitation to couple the two types.
	f.idents[ni.ID] = identity.Identity{ //nolint:staticcheck // S1016: command->entity map, kept explicit on purpose
		ID: ni.ID, UserID: ni.UserID, TenantID: ni.TenantID,
		Provider: ni.Provider, Subject: ni.Subject,
		LinkedAt: ni.LinkedAt, LastLoginAt: ni.LastLoginAt,
	}
	return nil
}

func (f *fixture) IdentityByProviderSubject(_ context.Context, provider, subject string) (identity.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, i := range f.idents {
		if i.Provider == provider && i.Subject == subject {
			return i, nil
		}
	}
	return identity.Identity{}, fmt.Errorf("%w: identity", identity.ErrNotFound)
}

func (f *fixture) IdentityByID(_ context.Context, id string) (identity.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.idents[id]
	if !ok {
		return identity.Identity{}, fmt.Errorf("%w: identity %s", identity.ErrNotFound, id)
	}
	return i, nil
}

func (f *fixture) IdentitiesByUserID(_ context.Context, userID string) ([]identity.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]identity.Identity, 0)
	for _, i := range f.idents {
		if i.UserID == userID {
			out = append(out, i)
		}
	}
	return out, nil
}

func (f *fixture) CountIdentitiesByUserID(_ context.Context, userID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, i := range f.idents {
		if i.UserID == userID {
			n++
		}
	}
	return n, nil
}

func (f *fixture) TouchIdentityLastLogin(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.idents[id]
	if !ok {
		return fmt.Errorf("%w: identity %s", identity.ErrNotFound, id)
	}
	t := at
	i.LastLoginAt = &t
	f.idents[id] = i
	return nil
}

func (f *fixture) DeleteIdentity(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.idents, id)
	return nil
}

func (f *fixture) ProvisionUserWithIdentity(ctx context.Context, u identity.NewUser, ni identity.NewIdentity, first bool) (identity.User, identity.Identity, error) {
	if err := f.CreateUser(ctx, u, first); err != nil {
		return identity.User{}, identity.Identity{}, err
	}
	if err := f.InsertIdentity(ctx, ni); err != nil {
		return identity.User{}, identity.Identity{}, err
	}
	user, _ := f.UserByID(ctx, u.ID)
	ident, _ := f.IdentityByID(ctx, ni.ID)
	return user, ident, nil
}

// TOTP sub-surface: unexercised by the leak suite, present to satisfy
// the port.
func (f *fixture) TOTPState(context.Context, string) (identity.TOTPState, error) {
	return identity.TOTPState{}, nil
}
func (f *fixture) SetTOTPPending(context.Context, string, []byte, []string) error { return nil }
func (f *fixture) EnableTOTP(context.Context, string, []byte, []string, time.Time) error {
	return nil
}
func (f *fixture) SetRecoveryCodeHashes(context.Context, string, []string) error { return nil }
func (f *fixture) ClearTOTP(context.Context, string) error                       { return nil }

// --- the self-test ----------------------------------------------------

// TestRunLeakSuite_PassesAgainstCompliantStore runs through the REAL
// *testing.T, so a regression in the suite fails this package outright.
func TestRunLeakSuite_PassesAgainstCompliantStore(t *testing.T) {
	RunLeakSuite(t, func() identity.TenantScopedStore { return newFixture(leakNone) })
}

// TestRecorderReportsCompliantStoreAsGreen is the control for every
// test below it. If the recorder reported failure unconditionally, each
// leak case would pass vacuously and this whole file would prove
// nothing — the failure mode playbook step 5 is about.
func TestRecorderReportsCompliantStoreAsGreen(t *testing.T) {
	rec := &recorderT{}
	runLeakSuite(rec, func() identity.TenantScopedStore { return newFixture(leakNone) })
	if rec.failed {
		t.Fatalf("recorder reported the COMPLIANT store as failing; every leak case below is "+
			"therefore vacuous:\n  %s", rec.report())
	}
}

// TestRunLeakSuite_FailsAgainstLeakyStore is the proof the suite bites.
// One fixture per leak shape, each breaking exactly one property, and
// each asserted to fail the case that owns it — so a suite that went red
// for the wrong reason is caught too.
func TestRunLeakSuite_FailsAgainstLeakyStore(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     leakMode
		wantCase string
	}{
		{"user read ignores the tenant", leakUserByEmail, "UserByEmailInTenant"},
		{"identity read ignores the tenant", leakIdentity, "IdentityByProviderSubjectInTenant"},
		{"count spans every tenant", leakCount, "CountUsersInTenant"},
		{"session loses its tenant on read", leakSessionTenant, "RefreshSessionByHash"},
		{"revoke crosses the tenant boundary", leakRevokeAll, "RevokeAllRefreshSessionsForTenant"},
		{"permission error instead of not-found", leakPermissionError, "UserByEmailInTenant"},
		{"zero value with a nil error", leakZeroValueNilError, "UserByEmailInTenant"},
		{"email unique globally, not per tenant", leakGlobalEmailUnique, "UserByEmailInTenant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorderT{}
			runLeakSuite(rec, func() identity.TenantScopedStore { return newFixture(tc.mode) })
			if !rec.failed {
				t.Fatalf("the suite PASSED a store that leaks (%s) — the guard is pointed at nothing", tc.name)
			}
			if !strings.Contains(rec.report(), tc.wantCase) {
				t.Errorf("suite failed, but not in %s — it went red for the wrong reason:\n  %s",
					tc.wantCase, rec.report())
			}
		})
	}
}

// TestSuiteNeverSkips pins the amended invariant: no input may resolve
// to a skip. recorderT has no Skip method at all, so a t.Skip added to
// the suite would fail to compile against harnessT — this test states
// the intent the compiler enforces, and fails loudly if harnessT ever
// grows one.
func TestSuiteNeverSkips(t *testing.T) {
	var h harnessT = &recorderT{}
	if _, ok := h.(interface{ Skip(...any) }); ok {
		t.Error("harnessT exposes Skip; the suite must never skip, because a skipped case " +
			"reports green and guards nothing")
	}
	if _, ok := h.(interface{ Skipf(string, ...any) }); ok {
		t.Error("harnessT exposes Skipf; see above")
	}
}
