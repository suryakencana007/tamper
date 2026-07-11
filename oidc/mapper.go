package oidc

import (
	"strings"
)

// ExtractGroups normalises the raw claim value into a deduplicated
// list of group names. Handles the three IdP shapes that turn up in
// practice:
//
//   - []any{"a", "b", ...}      — Keycloak / Okta / Auth0 default.
//   - []string{"a", "b", ...}   — defensive (some test fixtures).
//   - "a,b,c"                   — comma-separated (rare; some Azure
//     AD app-roles configs).
//
// Anything else (missing claim, claim is map / number / nil) returns
// nil. Whitespace is trimmed; empty entries are dropped.
//
// claimName empty falls back to "groups" (the default per most IdPs).
// v1.0 Sprint 1 task 02 — the v0.9 RoleMapping evaluator
// (ResolveSystemRole / ResolveClusterGrants) is gone; this helper
// stays as the single normaliser the OIDC handler uses when
// gathering claims to pass into GroupService.ReconcileGroupMembership.
func ExtractGroups(claims map[string]any, claimName string) []string {
	if len(claims) == 0 {
		return nil
	}
	key := claimName
	if key == "" {
		key = "groups"
	}
	raw, ok := claims[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		return nil
	}
}
