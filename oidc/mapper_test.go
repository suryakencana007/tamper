package oidc

import (
	"reflect"
	"testing"
)

// v1.0 Sprint 1 task 02 dropped the v0.9 RoleMapping evaluator
// (ResolveSystemRole / ResolveClusterGrants). The tests below
// exercise the surviving ExtractGroups helper.

func TestExtractGroups_SliceOfAny(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"barista-admins", "barista-users", ""},
	}
	got := ExtractGroups(claims, "groups")
	want := []string{"barista-admins", "barista-users"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractGroups_SliceOfString(t *testing.T) {
	claims := map[string]any{
		"groups": []string{" devs ", "ops", ""},
	}
	got := ExtractGroups(claims, "")
	want := []string{"devs", "ops"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractGroups_CommaString(t *testing.T) {
	claims := map[string]any{
		"groups": "barista-admins , barista-users",
	}
	got := ExtractGroups(claims, "groups")
	want := []string{"barista-admins", "barista-users"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractGroups_CustomClaimName(t *testing.T) {
	claims := map[string]any{
		"https://barista.io/groups": []any{"a", "b"},
	}
	got := ExtractGroups(claims, "https://barista.io/groups")
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExtractGroups_MissingClaim_ReturnsNil(t *testing.T) {
	claims := map[string]any{"other": "x"}
	if got := ExtractGroups(claims, "groups"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestExtractGroups_NilClaim_ReturnsNil(t *testing.T) {
	claims := map[string]any{"groups": nil}
	if got := ExtractGroups(claims, "groups"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestExtractGroups_NonStringPayload_ReturnsNil(t *testing.T) {
	claims := map[string]any{"groups": 42}
	if got := ExtractGroups(claims, "groups"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestExtractGroups_EmptyClaimsMap_ReturnsNil(t *testing.T) {
	if got := ExtractGroups(nil, "groups"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
