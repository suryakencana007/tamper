package identity

import (
	"context"
	"time"
)

// Store is the persistence port for the identity core. Applications
// implement it over their own tables (Barista: the users +
// refresh_tokens sqlc queries, near-verbatim); MemStore is the
// reference implementation and test double.
//
// Sentinel contract: UserByID / UserByEmail / RefreshSessionByHash
// return an error matching ErrNotFound (errors.Is) when no row exists;
// CreateUser returns one matching ErrEmailTaken on the unique-email
// violation. Other errors propagate as-is and the core fails the
// operation (deny-by-default — a degraded identity read never widens
// access).
//
// Implementations MUST be safe for concurrent use.
type Store interface {
	// CreateUser inserts the identity-core row. firstUser reports
	// whether the store was empty at the core's decision time — the
	// application's bootstrap signal (Barista assigns the cluster-admin
	// system role AT INSERT when true, preserving its at-insert
	// semantics). Implementations with no bootstrap policy ignore it.
	// The race between the emptiness check and the insert is arbitrated
	// by the unique-email index, exactly as in Barista: two concurrent
	// first registrations both see firstUser=true, one loses on
	// ErrEmailTaken.
	CreateUser(ctx context.Context, u NewUser, firstUser bool) error

	UserByID(ctx context.Context, id string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	CountUsers(ctx context.Context) (int64, error)

	CreateRefreshSession(ctx context.Context, s RefreshSession) error
	RefreshSessionByHash(ctx context.Context, tokenHash string) (RefreshSession, error)
	// RevokeRefreshSession marks one session revoked at the given time.
	// Revoking an already-revoked session is not an error.
	RevokeRefreshSession(ctx context.Context, id string, at time.Time) error
	// RevokeAllRefreshSessionsForUser is the "sign out everywhere"
	// surface — marks every live session for the user revoked.
	RevokeAllRefreshSessionsForUser(ctx context.Context, userID string, at time.Time) error
}
