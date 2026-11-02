package espresso

import (
	"net/http"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/audit"
	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

var (
	impAcme     = tenant.New("acme")
	impPlatform = tenant.New("platform")
)

// impToken mints an impersonated token: the request is bob@acme, the human is
// ops@platform.
func impToken(t *testing.T) string {
	t.Helper()
	j := tenantJWT(t)
	tok, err := j.IssueAccessImpersonated("bob", "ops", impAcme, impPlatform,
		time.Now().Unix(), crypto.ACRLocalPassword, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessImpersonated: %v", err)
	}
	return tok
}

// The three tenant gates, over one impersonated token.
func TestTenantGates_RefuseAnImpersonatedTokenByDefault(t *testing.T) {
	tok := impToken(t)
	j := tenantJWT(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		name string
		gate func(http.Handler) http.Handler
		want int
	}{
		{"RequireTenant", RequireTenant(scopeTo("acme")), http.StatusUnauthorized},
		{"RequireTenantAllowEntered", RequireTenantAllowEntered(scopeTo("acme")), http.StatusUnauthorized},
		{"RequireTenantAllowImpersonated", RequireTenantAllowImpersonated(scopeTo("acme")), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireAuth(j)(tc.gate(ok))
			if got := serveDecision(h, tok); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

// The decision gate: closed by default, and when open the subject's HOME is the
// routed tenant — the impersonated user is a user of the tenant being acted in.
func TestDecisionGate_ImpersonatedSubjectHomeIsTheRoutedTenant(t *testing.T) {
	tok := impToken(t)
	j := tenantJWT(t)

	t.Run("refused without AllowImpersonated", func(t *testing.T) {
		a := &recordingAuthorizer{allow: true}
		g := thingGate(a, "acme", false)
		h := RequireAuth(j)(RequireDecision(g)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		if got := serveDecision(h, tok); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got)
		}
		if len(a.scopes) != 0 {
			t.Fatalf("the authorizer was asked about a refused token: %v", a.scopes)
		}
	})

	t.Run("allowed, and asked with the routed tenant as the subject's home", func(t *testing.T) {
		a := &recordingAuthorizer{allow: true}
		g := thingGate(a, "acme", false)
		g.AllowImpersonated = true
		h := RequireAuth(j)(RequireDecision(g)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))
		if got := serveDecision(h, tok); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if len(a.subjects) == 0 {
			t.Fatal("the authorizer was never asked")
		}
		want := authz.Subject{Tenant: impAcme, Type: "user", ID: "bob"}
		if a.subjects[0] != want {
			t.Fatalf("subject = %+v, want %+v (home is the routed tenant, not htid)", a.subjects[0], want)
		}
		if a.scopes[0] != impAcme {
			t.Fatalf("scope = %q, want acme", a.scopes[0])
		}
	})
}

// Attribution: every audit row names the human, never the impersonated user.
func TestRequireAuth_AttributesToTheHuman(t *testing.T) {
	tok := impToken(t)
	j := tenantJWT(t)

	var actor audit.Actor
	var userID string
	h := RequireAuth(j)(RequireTenantAllowImpersonated(scopeTo("acme"))(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			actor = audit.ActorFromContext(r.Context())
			userID, _ = GetUserID(r.Context())
		})))
	serveDecision(h, tok)

	if userID != "bob" {
		t.Fatalf("GetUserID = %q, want bob (the request IS bob)", userID)
	}
	if actor.UserID != "ops" {
		t.Fatalf("audit actor = %q, want the human ops — a row naming bob blames the customer", actor.UserID)
	}
	if actor.TenantID != impPlatform.String() {
		t.Fatalf("audit actor tenant = %q, want the human's home", actor.TenantID)
	}
	if actor.Type != audit.ActorTypeUser {
		t.Fatalf("actor type = %q, want the subject type", actor.Type)
	}
}

func TestImpersonatedFromContext(t *testing.T) {
	tok := impToken(t)
	j := tenantJWT(t)

	var home tenant.ID
	var actorID string
	var ok, entered bool
	h := RequireAuth(j)(RequireTenantAllowImpersonated(scopeTo("acme"))(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			home, actorID, ok = ImpersonatedFromContext(r.Context())
			_, entered = EnteredFromContext(r.Context())
		})))
	serveDecision(h, tok)

	if !ok {
		t.Fatal("ImpersonatedFromContext did not report the impersonation")
	}
	if home != impPlatform || actorID != "ops" {
		t.Fatalf("got (%q, %q), want (platform, ops)", home, actorID)
	}
	if entered {
		t.Fatal("EnteredFromContext reported an impersonated token as entered")
	}
}

// An ordinary token is untouched by any of this.
func TestImpersonation_LeavesOrdinaryTokensAlone(t *testing.T) {
	tok := tokenFor(t, tenantJWT(t), impAcme)
	j := tenantJWT(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := RequireAuth(j)(RequireTenant(scopeTo("acme"))(ok))
	if got := serveDecision(h, tok); got != http.StatusOK {
		t.Fatalf("ordinary token = %d, want 200", got)
	}
}

// A route that accepts both shapes needs ONE gate with both flags. Stacking the
// two single-shape gates refuses every token, which is the trap the doc names.
func TestTenantGates_BothShapesNeedTheCombinedGate(t *testing.T) {
	j := tenantJWT(t)
	entered, err := j.IssueAccessEntered("ops", impAcme, impPlatform, time.Now().Unix(), crypto.ACRLocalPassword, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessEntered: %v", err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("stacked single-shape gates accept neither", func(t *testing.T) {
		h := RequireAuth(j)(
			RequireTenantAllowEntered(scopeTo("acme"))(
				RequireTenantAllowImpersonated(scopeTo("acme"))(ok)))
		for name, tok := range map[string]string{"entered": entered, "impersonated": impToken(t)} {
			if got := serveDecision(h, tok); got != http.StatusUnauthorized {
				t.Fatalf("%s token through stacked gates = %d, want 401 (intersection, not union)", name, got)
			}
		}
	})

	t.Run("the combined gate accepts both", func(t *testing.T) {
		h := RequireAuth(j)(RequireTenantAllowEnteredOrImpersonated(scopeTo("acme"))(ok))
		for name, tok := range map[string]string{
			"entered":      entered,
			"impersonated": impToken(t),
			"ordinary":     tokenFor(t, j, impAcme),
		} {
			if got := serveDecision(h, tok); got != http.StatusOK {
				t.Fatalf("%s token through the combined gate = %d, want 200", name, got)
			}
		}
	})
}
