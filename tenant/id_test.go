package tenant_test

import (
	"testing"

	"github.com/suryakencana007/tamper/tenant"
)

// TestID_ZeroValueIsInvalid is the property the whole type exists for. A
// caller who forgets to thread the tenant produces the zero value, and the
// zero value must never be mistaken for "single-tenant".
func TestID_ZeroValueIsInvalid(t *testing.T) {
	t.Parallel()

	var forgot tenant.ID
	if forgot.Valid() {
		t.Fatal("the zero ID reports Valid; a forgotten tenant would be accepted")
	}
	if forgot.IsSingle() {
		t.Fatal("the zero ID reports IsSingle; unset is not single-tenant, it is unset")
	}
}

// TestID_SingleIsValidAndDistinctFromZero pins the other half: "" IS legal,
// but only when said deliberately. If these two ever compare equal the type
// has stopped doing its job and a bare string would be just as good.
func TestID_SingleIsValidAndDistinctFromZero(t *testing.T) {
	t.Parallel()

	if !tenant.Single.Valid() {
		t.Fatal("Single must be valid — a single-tenant deployment has to be expressible")
	}
	if !tenant.Single.IsSingle() {
		t.Fatal("Single must report IsSingle")
	}
	if tenant.Single.String() != "" {
		t.Fatalf("Single.String() = %q, want empty", tenant.Single.String())
	}

	var zero tenant.ID
	if tenant.Single == zero {
		t.Fatal("Single equals the zero ID; explicit-empty and unset are indistinguishable again")
	}
}

// TestID_NewEmptyIsInvalidNotSingle guards the deliberate asymmetry. An empty
// string out of a tid claim, a header or a config lookup means the lookup
// produced nothing — it must deny, not silently select the single-tenant
// bucket. Only a literal tenant.Single may mean "".
func TestID_NewEmptyIsInvalidNotSingle(t *testing.T) {
	t.Parallel()

	got := tenant.New("")
	if got.Valid() {
		t.Fatal(`New("") is valid; an empty lookup result would select the single-tenant bucket`)
	}
	if got == tenant.Single {
		t.Fatal(`New("") equals Single; an absent tid claim would silently become single-tenant`)
	}
}

func TestID_NewRoundTrips(t *testing.T) {
	t.Parallel()

	id := tenant.New("acme")
	if !id.Valid() {
		t.Fatal("New(\"acme\") must be valid")
	}
	if id.IsSingle() {
		t.Fatal("a named tenant must not report IsSingle")
	}
	if id.String() != "acme" {
		t.Fatalf("String() = %q, want acme", id.String())
	}
}

// TestID_IsComparableForMapKeys pins that ID stays usable as a map key. The
// per-tenant OIDC and SAML registry caches are keyed by tenant; if ID ever
// gains a slice or map field it stops compiling as a key, and that would be
// found here rather than in the cache.
func TestID_IsComparableForMapKeys(t *testing.T) {
	t.Parallel()

	m := map[tenant.ID]string{
		tenant.New("acme"):   "a",
		tenant.New("globex"): "g",
		tenant.Single:        "s",
	}
	if m[tenant.New("acme")] != "a" {
		t.Fatal("equal IDs must hit the same map entry")
	}
	if m[tenant.Single] != "s" {
		t.Fatal("Single must be a usable key distinct from named tenants")
	}
	var zero tenant.ID
	if _, hit := m[zero]; hit {
		t.Fatal("the zero ID collided with a real key")
	}
}

// TestID_FromStoredTreatsEmptyAsSingle pins the deliberate asymmetry with
// New. A value coming back out of storage was written by a call that already
// passed the gate, so its emptiness is recorded rather than missing.
func TestID_FromStoredTreatsEmptyAsSingle(t *testing.T) {
	t.Parallel()

	if got := tenant.FromStored(""); got != tenant.Single {
		t.Fatalf(`FromStored("") = %#v, want Single — a persisted row's tenant must round-trip`, got)
	}
	if got := tenant.FromStored("acme"); got != tenant.New("acme") {
		t.Fatal("FromStored must round-trip a named tenant")
	}
	// The asymmetry is the point: the same "" means different things
	// depending on where it came from, and the two conversions say which.
	if tenant.New("") == tenant.FromStored("") {
		t.Fatal(`New("") and FromStored("") agree; untrusted empty would launder into Single`)
	}
}
