package tenant

import (
	"context"
	"testing"
)

func TestFromContext_BareContextReturnsEmptyFalse(t *testing.T) {
	id, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext(bare) reported a tenant; want none")
	}
	if id != "" {
		t.Errorf("FromContext(bare) id = %q, want empty", id)
	}
}

func TestWithTenant_RoundTrip(t *testing.T) {
	ctx := WithTenant(context.Background(), "acme")
	id, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext reported no tenant after WithTenant")
	}
	if id != "acme" {
		t.Errorf("id = %q, want %q", id, "acme")
	}
}

// TestWithTenant_NestedInnermostWins pins the shadowing semantics. A
// request that is re-scoped (an admin acting into a sub-tenant, a
// nested handler) must see the innermost tenant, never the outer one —
// an outer-wins bug reads as a cross-tenant action by the outer tenant.
func TestWithTenant_NestedInnermostWins(t *testing.T) {
	outer := WithTenant(context.Background(), "acme")
	inner := WithTenant(outer, "globex")

	if id, _ := FromContext(inner); id != "globex" {
		t.Errorf("inner id = %q, want %q", id, "globex")
	}
	// The outer context is unchanged — context derivation, not mutation.
	if id, _ := FromContext(outer); id != "acme" {
		t.Errorf("outer id = %q after nesting, want %q", id, "acme")
	}
}

// TestWithTenant_EmptyIDStoredVerbatim pins the documented distinction
// between ("", true) — a tenant was resolved and it is the
// single-tenant one — and ("", false) — nothing resolved a tenant.
// tamper does not canonicalize a tenant id (§4.1), so WithTenant must
// not quietly drop "" and turn the first fact into the second.
func TestWithTenant_EmptyIDStoredVerbatim(t *testing.T) {
	ctx := WithTenant(context.Background(), "")
	id, ok := FromContext(ctx)
	if !ok {
		t.Fatal(`WithTenant(ctx, "") did not record a tenant; want ("", true)`)
	}
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
}

// TestWithTenant_EmptyShadowsOuter follows from the two above: an inner
// empty tenant is still the innermost, and must not fall through to the
// outer one. Falling through would let a re-scope to "no tenant"
// silently keep acting as the outer tenant.
func TestWithTenant_EmptyShadowsOuter(t *testing.T) {
	ctx := WithTenant(WithTenant(context.Background(), "acme"), "")
	id, ok := FromContext(ctx)
	if !ok {
		t.Fatal("expected the inner empty tenant to be recorded")
	}
	if id != "" {
		t.Errorf("id = %q, want the inner empty value", id)
	}
}

// TestFromContext_ForeignValueIgnored pins that the unexported key type
// isolates this slot: a string key with the same shape stashed by other
// code must not be readable as a tenant.
func TestFromContext_ForeignValueIgnored(t *testing.T) {
	//nolint:staticcheck // SA1029: a string key is the collision this test exists to rule out.
	ctx := context.WithValue(context.Background(), "tenantCtxKey", "acme")
	if id, ok := FromContext(ctx); ok || id != "" {
		t.Errorf("FromContext read a foreign key: (%q, %v)", id, ok)
	}
}
