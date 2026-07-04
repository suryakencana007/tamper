package crypto

import "time"

// JWTServiceTesting is the test-only handle on JWTService. Tests
// freeze the clock + verify freshness-gate behaviour deterministically
// via Testing().SetNow(...). Mirrors the v0.8 task 04 convention
// (CLAUDE.md §Core Pattern: AppState — "Service-internal test seams").
//
// The handle exists so production code can keep `now` unexported and
// race-safe — only tests reach the seam, and they reach it through a
// single, grep-able entry point rather than dozens of direct struct
// mutations.
type JWTServiceTesting struct {
	svc *JWTService
}

// Testing returns the test-only handle. Callers in production code
// MUST NOT call this; tests under internal/auth (and other packages)
// reach the clock seam via Testing().SetNow(...).
func (j *JWTService) Testing() *JWTServiceTesting {
	return &JWTServiceTesting{svc: j}
}

// SetNow replaces the JWTService clock source. Tests use this to
// freeze time deterministically so expiry + freshness-gate behaviour
// can be exercised without races.
func (t *JWTServiceTesting) SetNow(now func() time.Time) {
	t.svc.now = now
}
