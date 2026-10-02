# Tech debt — reproduction tests

This file holds the tests that prove the sharp edges in
[`tech-debt.md`](tech-debt.md). They were run on 2026-10-02 against `main` at
`c1a9729` (`v0.6.0` plus the two docs commits).

Each test asserts the **wanted** behaviour. So a test **fails** while the
problem exists, and it passes after the fix. The same tests can later become
the regression tests of each fix.

The tests are **not** in the Go packages, because they fail and would turn CI
red. To run them again:

1. Copy each block below into the file named above it.
2. Run:

   ```
   go test -count=1 -v -run '^TestTD' . ./espresso ./identity
   ```

3. Delete the three files when you are done.

Check that the output has `=== RUN` lines. A `-run` pattern that matches
nothing also exits with success (see `PHASE7-HANDOFF.md`).

## Result

| Test | Proves | Result |
|---|---|---|
| `TestTD15_SCIMDefaultConfigIsTenantScoped` | TD-15 | FAIL (problem confirmed) |
| `TestTD08_AuditorStampsTenant` | TD-08, TD-17 | FAIL (problem confirmed) |
| `TestTD09_NewCanWriteAuditV4` | TD-09 | FAIL (problem confirmed) |
| `TestTD09_TenancyWithoutBootstrap` | TD-16 | FAIL (problem confirmed, but only for a DB that has an older anchor) |
| `TestTD10_PostTOTPMintCarriesTheUsersTenant` | TD-10, fails closed | FAIL (problem confirmed) |
| `TestTD10_PendingTokenCannotMintIntoAnotherTenant` | TD-10 fails open, TD-02 | FAIL (problem confirmed) |

## Re-run against the fixes

On 2026-10-02 the same six tests were run again against the fixes. The tests
were not changed. Five results below are from a branch that merged #39, #40,
#43 and the first versions of the two audit fixes. The audit fixes were then
redone (#45 replaces #41, and #42 was reduced), and the last row is from a
run with the `Verify` change of #45.

| Test | Result with the fixes | Why |
|---|---|---|
| `TestTD15_SCIMDefaultConfigIsTenantScoped` | PASS | All three requests now get `500` and the store is never called. |
| `TestTD08_AuditorStampsTenant` | PASS | The row has `Event.TenantID="acme"` and `Actor.TenantID="acme"`; the export has 1 row. |
| `TestTD10_PendingTokenCannotMintIntoAnotherTenant` | PASS | The mint is refused with `identity: not found`. |
| `TestTD10_PostTOTPMintCarriesTheUsersTenant` | still FAIL, expected | It calls the `tenant.Single` shim `Core.IssueTokensForUser`, which stays tenant-less by design. The fix is in the adapter, which must call `IssueTokensForUserInTenant`. The regression tests in #40 check that path. |
| `TestTD09_NewCanWriteAuditV4` | still FAIL, expected | It uses the default config. v4 is opt-in through `Audit.Tenancy: true`. The regression tests in #42 set the flag. |
| `TestTD09_TenancyWithoutBootstrap` | PASS with #45 | `Verify` hashes each row under its own version, so every case verifies clean with no anchor and no repair: the anchored v3 DB with a v4 row gives `tamper=false`. `HasChainRestartV4` still answers `true` and the late bootstrap still returns `emitted=false`; neither matters for `Verify` any more (TD-21). |

So the output below shows the state **before** the fixes.

## Output

The file names in the output are the temporary names used during the run.
Timings are removed.

```
=== RUN   TestTD09_NewCanWriteAuditV4
    zz_td_proof_test.go:37: row written through tamper.New: canonical_version=3
    zz_td_proof_test.go:41: BootstrapChainV4 on that logger: emitted=false err=<nil>
    zz_td_proof_test.go:43: RedactEvent(e1): redacted=false err=<nil>
    zz_td_proof_test.go:46: canonical_version = 3, want 4; tamper.Config has no way to ask for v4
--- FAIL: TestTD09_NewCanWriteAuditV4 
=== RUN   TestTD09_TenancyWithoutBootstrap
    zz_td_proof_test.go:81: fresh DB, Tenancy on, no bootstrap: Verify -> total=2 tamper=false firstBad=0 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:98: existing v3 DB, reopened with Tenancy on, no bootstrap: Verify -> total=3 tamper=false firstBad=0 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:102: late BootstrapChainV4: emitted=false err=<nil>
    zz_td_proof_test.go:104: same DB after a late bootstrap: Verify -> total=4 tamper=false firstBad=0 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:122: anchored v3 DB, before the switch: Verify -> total=2 tamper=false firstBad=0 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:129: anchored v3 DB, Tenancy on, no bootstrap: Verify -> total=3 tamper=true firstBad=2 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:131: HasChainRestartV4 with one ordinary v4 row and no anchor: true err=<nil>
    zz_td_proof_test.go:133: late BootstrapChainV4 on the anchored DB: emitted=false err=<nil>
    zz_td_proof_test.go:135: anchored v3 DB after the late bootstrap: Verify -> total=4 tamper=true firstBad=2 err=<nil> | VerifyChainPostMigration err=<nil>
    zz_td_proof_test.go:139: anchored v3 DB does not verify clean after Tenancy is switched on: before late bootstrap=true after=true
--- FAIL: TestTD09_TenancyWithoutBootstrap 
FAIL
FAIL	github.com/suryakencana007/tamper
=== RUN   TestTD15_SCIMDefaultConfigIsTenantScoped
    zz_td_proof_test.go:37: GET tenant-B user as tenant A    -> 200
    zz_td_proof_test.go:38: DELETE tenant-B group as tenant A -> 204
    zz_td_proof_test.go:39: LIST users as tenant A            -> 200
    zz_td_proof_test.go:40: store calls: [UNSCOPED UNSCOPED UNSCOPED UNSCOPED]
    zz_td_proof_test.go:44: the default SCIMConfig reached the UNSCOPED store: calls = [UNSCOPED UNSCOPED UNSCOPED UNSCOPED] (the principal's tenant "acme" was never passed down)
--- FAIL: TestTD15_SCIMDefaultConfigIsTenantScoped 
=== RUN   TestTD08_AuditorStampsTenant
    zz_td_proof_test.go:101: List(Filter{Action: "td.proof.mutation"}) returned 2 row(s), 1 with that action
    zz_td_proof_test.go:105: row written by Auditor: canonical_version=4 Event.TenantID="" Actor.TenantID="" Actor.UserID="user-1"
    zz_td_proof_test.go:118: ExportForTenant(acme): 0 row(s) for the action
    zz_td_proof_test.go:121: Event.TenantID = "", want "acme"
    zz_td_proof_test.go:124: Actor.TenantID = "", want "acme"
    zz_td_proof_test.go:127: acme's export holds 0 row(s) for its own mutation, want 1
--- FAIL: TestTD08_AuditorStampsTenant 
FAIL
FAIL	github.com/suryakencana007/tamper/espresso
=== RUN   TestTD10_PostTOTPMintCarriesTheUsersTenant
    zz_td_proof_test.go:50: user tenant="globex", token tid="", VerifyAccess(globex) err=auth: invalid token: token not valid
    zz_td_proof_test.go:53: token tid = "", want "globex" (the user's tenant)
--- FAIL: TestTD10_PostTOTPMintCarriesTheUsersTenant 
=== RUN   TestTD10_PendingTokenCannotMintIntoAnotherTenant
    zz_td_proof_test.go:82: IssueTokensForUserInTenant(globex user, acme) err=<nil>
    zz_td_proof_test.go:89: minted: tid="acme", VerifyAccess(acme) err=<nil>, refresh issued=true
    zz_td_proof_test.go:96: Refresh: succeeded, new token tid="acme"
    zz_td_proof_test.go:101: a user stored in tenant "globex" received a session with tid="acme"
--- FAIL: TestTD10_PendingTokenCannotMintIntoAnotherTenant 
FAIL
FAIL	github.com/suryakencana007/tamper/identity
FAIL
```

## Test sources

### `td_proof_test.go` — TD-09, TD-16

Put it in package `tamper_test` (repo root).

```go
package tamper_test

// TEMPORARY reproduction tests for tech-debt.md (TD-09).
// Not meant to be committed as-is.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	tamper "github.com/suryakencana007/tamper"
	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
)

// TD-09: a logger built by tamper.New must be able to write
// canonical_version=4 (tenant in the hash, PII redactable).
func TestTD09_NewCanWriteAuditV4(t *testing.T) {
	ctx := context.Background()
	p, err := tamper.New(tamper.Config{
		JWT:   crypto.JWTConfig{Secret: "td-proof-secret", TTL: time.Minute, Issuer: "td"},
		Audit: tamper.AuditConfig{DBPath: filepath.Join(t.TempDir(), "audit.db")},
	})
	if err != nil {
		t.Fatalf("tamper.New: %v", err)
	}
	defer p.Close()

	ev, err := p.Audit.Log(ctx, audit.Event{
		ID: "e1", At: time.Now().UTC(), Action: "td.proof", TenantID: "acme",
		Actor: audit.Actor{Type: audit.ActorTypeUser, UserID: "user-1", Email: "bob@acme.test", TenantID: "acme"},
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	t.Logf("row written through tamper.New: canonical_version=%d", ev.CanonicalVersion)

	sl := p.Audit.(*audit.SQLiteLogger)
	bootstrapped, berr := sl.BootstrapChainV4(ctx, time.Now().UTC(), "anchor-v4")
	t.Logf("BootstrapChainV4 on that logger: emitted=%v err=%v", bootstrapped, berr)
	redacted, rerr := sl.RedactEvent(ctx, "e1")
	t.Logf("RedactEvent(e1): redacted=%v err=%v", redacted, rerr)

	if ev.CanonicalVersion != audit.CanonicalVersion4 {
		t.Errorf("canonical_version = %d, want %d; tamper.Config has no way to ask for v4",
			ev.CanonicalVersion, audit.CanonicalVersion4)
	}
}

// TD-09 caveat: what happens when Tenancy is switched on WITHOUT calling
// BootstrapChainV4 first. Records the behaviour for a fresh DB and for a
// DB that already holds v3 rows.
func TestTD09_TenancyWithoutBootstrap(t *testing.T) {
	ctx := context.Background()
	log := func(l audit.Logger, id string) {
		t.Helper()
		if _, err := l.Log(ctx, audit.Event{
			ID: id, At: time.Now().UTC(), Action: "td.proof", TenantID: "acme",
			Actor: audit.Actor{Type: audit.ActorTypeUser, UserID: "user-1"},
		}); err != nil {
			t.Fatalf("Log(%s): %v", id, err)
		}
	}
	report := func(name string, l audit.Logger) (tamperFound bool) {
		t.Helper()
		vr, verr := l.Verify(ctx)
		_, berr := audit.VerifyChainPostMigration(ctx, l)
		t.Logf("%s: Verify -> total=%d tamper=%v firstBad=%d err=%v | VerifyChainPostMigration err=%v",
			name, vr.Total, vr.Tamper, vr.FirstBadIndex, verr, berr)
		return vr.Tamper || verr != nil || berr != nil
	}

	// (a) fresh DB, Tenancy on, no bootstrap.
	fresh, err := audit.NewSQLiteLogger(filepath.Join(t.TempDir(), "fresh.db"), audit.SQLiteLoggerOptions{Tenancy: true})
	if err != nil {
		t.Fatalf("open fresh: %v", err)
	}
	log(fresh, "f1")
	log(fresh, "f2")
	badFresh := report("fresh DB, Tenancy on, no bootstrap", fresh)
	_ = fresh.Close()

	// (b) existing v3 DB, then reopened with Tenancy on, no bootstrap.
	path := filepath.Join(t.TempDir(), "existing.db")
	v3, err := audit.NewSQLiteLogger(path, audit.SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("open v3: %v", err)
	}
	log(v3, "x1")
	log(v3, "x2")
	_ = v3.Close()
	v4, err := audit.NewSQLiteLogger(path, audit.SQLiteLoggerOptions{Tenancy: true})
	if err != nil {
		t.Fatalf("reopen v4: %v", err)
	}
	log(v4, "x3")
	badExisting := report("existing v3 DB, reopened with Tenancy on, no bootstrap", v4)

	// (c) same DB, bootstrap called late (after a v4 row already exists).
	emitted, berr := v4.(*audit.SQLiteLogger).BootstrapChainV4(ctx, time.Now().UTC(), "anchor-late")
	t.Logf("late BootstrapChainV4: emitted=%v err=%v", emitted, berr)
	log(v4, "x4")
	badLate := report("same DB after a late bootstrap", v4)
	_ = v4.Close()

	// (d) the shape an existing deployment has: a v3 chain-restart ANCHOR
	// (emitted by the application's boot), then Tenancy switched on.
	path2 := filepath.Join(t.TempDir(), "anchored.db")
	a3, err := audit.NewSQLiteLogger(path2, audit.SQLiteLoggerOptions{})
	if err != nil {
		t.Fatalf("open anchored v3: %v", err)
	}
	if _, err := a3.Log(ctx, audit.Event{
		ID: "anchor-v3", At: time.Now().UTC(), Actor: audit.ActorSystem("audit"),
		Action: audit.ActionAuditChainRestart, ResourceType: "audit_chain", ResourceID: "v3",
		CanonicalVersion: audit.CanonicalVersion3,
	}); err != nil {
		t.Fatalf("emit v3 anchor: %v", err)
	}
	log(a3, "y1")
	_ = report("anchored v3 DB, before the switch", a3)
	_ = a3.Close()
	a4, err := audit.NewSQLiteLogger(path2, audit.SQLiteLoggerOptions{Tenancy: true})
	if err != nil {
		t.Fatalf("reopen anchored with Tenancy: %v", err)
	}
	log(a4, "y2") // first v4 row, no v4 anchor yet
	badAnchored := report("anchored v3 DB, Tenancy on, no bootstrap", a4)
	has, herr := a4.(*audit.SQLiteLogger).HasChainRestartV4(ctx)
	t.Logf("HasChainRestartV4 with one ordinary v4 row and no anchor: %v err=%v", has, herr)
	emitted2, berr2 := a4.(*audit.SQLiteLogger).BootstrapChainV4(ctx, time.Now().UTC(), "anchor-late-2")
	t.Logf("late BootstrapChainV4 on the anchored DB: emitted=%v err=%v", emitted2, berr2)
	log(a4, "y3")
	badAnchoredLate := report("anchored v3 DB after the late bootstrap", a4)
	_ = a4.Close()

	if badAnchored || badAnchoredLate {
		t.Errorf("anchored v3 DB does not verify clean after Tenancy is switched on: "+
			"before late bootstrap=%v after=%v", badAnchored, badAnchoredLate)
	}
	if badFresh || badExisting || badLate {
		t.Errorf("a chain written with Tenancy on but no (or a late) BootstrapChainV4 does not verify clean: "+
			"fresh=%v existing=%v late=%v", badFresh, badExisting, badLate)
	}
}
```

### `espresso/td_proof_test.go` — TD-15, TD-08, TD-17

Put it in package `espresso` (it uses the fixtures in `espresso/scimtenant_test.go`).

```go
package espresso

// TEMPORARY reproduction tests for tech-debt.md (TD-15, TD-08).
// Each test asserts the DESIRED behaviour, so it fails while the sharp
// edge exists. Not meant to be committed as-is.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// TD-15: with the default SCIMConfig (Tenancy unset), tenant A's service
// account must not reach the unscoped store.
func TestTD15_SCIMDefaultConfigIsTenantScoped(t *testing.T) {
	store := newTenantSCIMStore()
	rt, err := NewSCIMRoutes(SCIMConfig{
		Prefix: "/scim/v2", BaseURL: "https://panel.test", MaxResults: 100,
		// Tenancy left at its default.
	}, store, groupSide{s: store})
	if err != nil {
		t.Fatalf("NewSCIMRoutes: %v", err)
	}

	// Tenant A's principal addresses tenant B's user and group.
	recUser := asTenant(rt.UsersGet, tenantA, http.MethodGet, "/scim/v2/Users/u-b", "")
	recGroup := asTenant(rt.GroupsDelete, tenantA, http.MethodDelete, "/scim/v2/Groups/g-b", "")
	recList := asTenant(rt.UsersList, tenantA, http.MethodGet, "/scim/v2/Users", "")

	t.Logf("GET tenant-B user as tenant A    -> %d", recUser.Code)
	t.Logf("DELETE tenant-B group as tenant A -> %d", recGroup.Code)
	t.Logf("LIST users as tenant A            -> %d", recList.Code)
	t.Logf("store calls: %v", store.calls)

	for _, got := range store.calls {
		if got == "UNSCOPED" {
			t.Fatalf("the default SCIMConfig reached the UNSCOPED store: calls = %v "+
				"(the principal's tenant %q was never passed down)", store.calls, tenantA)
		}
	}
}

// TD-08: a mutation made in tenant "acme" through RequireAuth ->
// RequireTenant -> Auditor.For must appear in acme's export, with the
// actor's tenant recorded.
func TestTD08_AuditorStampsTenant(t *testing.T) {
	ctx := context.Background()
	logger, err := audit.NewSQLiteLogger(filepath.Join(t.TempDir(), "audit.db"),
		audit.SQLiteLoggerOptions{Tenancy: true})
	if err != nil {
		t.Fatalf("NewSQLiteLogger: %v", err)
	}
	defer logger.Close()
	sl := logger.(*audit.SQLiteLogger)
	if _, err := sl.BootstrapChainV4(ctx, time.Now().UTC(), "anchor-v4"); err != nil {
		t.Fatalf("BootstrapChainV4: %v", err)
	}

	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "td-proof-secret", TTL: time.Minute, Issuer: "td"})
	acme := tenant.New("acme")
	tok, err := jwt.IssueAccess("user-1", acme, time.Now().Unix(), crypto.ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	const action = audit.Action("td.proof.mutation")
	auditor := NewAuditor(logger, nil)
	h := RequireAuth(jwt)(
		RequireTenant(func(*http.Request) string { return "acme" })(
			auditor.Mutation(action, audit.ResourceType("thing"), "")(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))))

	req := httptest.NewRequest(http.MethodPost, "/t/acme/things", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("request status = %d, want 204", rec.Code)
	}

	page, err := logger.List(ctx, audit.Filter{Action: action})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var ev audit.Event
	found := 0
	for _, e := range page.Events {
		if e.Action == action {
			ev, found = e, found+1
		}
	}
	t.Logf("List(Filter{Action: %q}) returned %d row(s), %d with that action", action, len(page.Events), found)
	if found != 1 {
		t.Fatalf("rows for the action = %d, want exactly 1", found)
	}
	t.Logf("row written by Auditor: canonical_version=%d Event.TenantID=%q Actor.TenantID=%q Actor.UserID=%q",
		ev.CanonicalVersion, ev.TenantID, ev.Actor.TenantID, ev.Actor.UserID)

	exp, err := sl.ExportForTenant(ctx, acme)
	if err != nil {
		t.Fatalf("ExportForTenant: %v", err)
	}
	inExport := 0
	for _, e := range exp.Events {
		if e.Action == action {
			inExport++
		}
	}
	t.Logf("ExportForTenant(acme): %d row(s) for the action", inExport)

	if ev.TenantID != "acme" {
		t.Errorf("Event.TenantID = %q, want %q", ev.TenantID, "acme")
	}
	if ev.Actor.TenantID != "acme" {
		t.Errorf("Actor.TenantID = %q, want %q", ev.Actor.TenantID, "acme")
	}
	if inExport != 1 {
		t.Errorf("acme's export holds %d row(s) for its own mutation, want 1", inExport)
	}
}
```

### `identity/td_proof_test.go` — TD-10, TD-02

Put it in package `identity_test`.

```go
package identity_test

// TEMPORARY reproduction tests for tech-debt.md (TD-10, TD-02).
// Each test asserts the DESIRED behaviour, so it fails while the sharp
// edge exists. Not meant to be committed as-is.

import (
	"context"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/identity"
	"github.com/suryakencana007/tamper/tenant"
)

func tdCore(t *testing.T) (*identity.Core, *crypto.JWTService) {
	t.Helper()
	jwt := crypto.NewJWTService(crypto.JWTConfig{Secret: "td-proof-secret", TTL: time.Minute, Issuer: "td"})
	core, err := identity.New(identity.NewMemStore(), jwt, identity.WithRefreshTTL(time.Hour))
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return core, jwt
}

// TD-10 (fails closed): the mint the TOTP route calls must carry the
// user's tenant.
func TestTD10_PostTOTPMintCarriesTheUsersTenant(t *testing.T) {
	ctx := context.Background()
	core, jwt := tdCore(t)
	globex := tenant.New("globex")

	u, _, err := core.Register(ctx, globex, "bob@globex.test", "correct-horse-battery")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// What espresso.AuthRoutes.VerifyTOTP ends up calling when the adapter
	// forwards IdentityService.IssueTokensForUser straight to the Core.
	tok, err := core.IssueTokensForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("IssueTokensForUser: %v", err)
	}
	claims, err := jwt.ParseAccess(tok.Access)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	_, pinErr := jwt.VerifyAccess(tok.Access, globex)
	t.Logf("user tenant=%q, token tid=%q, VerifyAccess(globex) err=%v", u.TenantID, claims.TenantID, pinErr)

	if claims.TenantID != "globex" {
		t.Errorf("token tid = %q, want %q (the user's tenant)", claims.TenantID, "globex")
	}
}

// TD-10 (fails open) + TD-02: a globex user's TOTP-pending token must
// not turn into a session in acme.
func TestTD10_PendingTokenCannotMintIntoAnotherTenant(t *testing.T) {
	ctx := context.Background()
	core, jwt := tdCore(t)
	globex, acme := tenant.New("globex"), tenant.New("acme")

	u, _, err := core.Register(ctx, globex, "bob@globex.test", "correct-horse-battery")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Password step done in globex; the pending token carries only the user id.
	pending, err := jwt.IssueTOTPPending(u.ID)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	// The token is replayed at ACME's /totp/verify.
	uid, err := jwt.VerifyTOTPPending(pending)
	if err != nil {
		t.Fatalf("VerifyTOTPPending: %v", err)
	}
	// An adapter that mints with the ROUTED tenant, without comparing it
	// to the user's stored tenant.
	tok, err := core.IssueTokensForUserInTenant(ctx, uid, acme, 0, "")
	t.Logf("IssueTokensForUserInTenant(globex user, acme) err=%v", err)
	if err != nil {
		return // desired: refused
	}

	claims, _ := jwt.ParseAccess(tok.Access)
	_, pinErr := jwt.VerifyAccess(tok.Access, acme)
	t.Logf("minted: tid=%q, VerifyAccess(acme) err=%v, refresh issued=%v",
		claims.TenantID, pinErr, tok.Refresh != "")

	// TD-02: the refresh session keeps working with no re-check.
	_, tok2, rerr := core.Refresh(ctx, tok.Refresh)
	if rerr == nil {
		c2, _ := jwt.ParseAccess(tok2.Access)
		t.Logf("Refresh: succeeded, new token tid=%q", c2.TenantID)
	} else {
		t.Logf("Refresh: %v", rerr)
	}

	t.Errorf("a user stored in tenant %q received a session with tid=%q", u.TenantID, claims.TenantID)
}
```
