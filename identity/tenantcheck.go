package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/suryakencana007/tamper/tenant"
)

// Tenant-keyed lookups, added by Phase 13 slice 13b (TD-28).
//
// Before this, a method keyed by a bare user id — or by a bare refresh token —
// could not tell whether the thing it was acting on belonged to the tenant the
// request was routed to. The check lived in every adapter, and the Store port's own
// doc said so ("the callers that need a tenant check compare User.TenantID"); an
// adapter that forgot still compiled, which is what made it debt.
//
// Two properties are load-bearing here and each has a test:
//
//   - A miss and a mismatch are ONE branch, so they cannot drift into two
//     distinguishable errors. A distinguishable "this user exists, in another
//     tenant" is an existence oracle.
//   - The comparison is tenant.FromStored, not tenant.New: the value came out of
//     storage, so a stored "" is tenant.Single — a recorded fact — rather than the
//     zero ID that denies.

// userInTenant loads a user and refuses it unless it is stored in tenantID.
//
// Both failures answer ErrNotFound, the same error an id that does not exist gets.
func (c *Core) userInTenant(ctx context.Context, userID string, tenantID tenant.ID) (User, error) {
	user, err := c.store.UserByID(ctx, userID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return User{}, fmt.Errorf("identity: lookup user: %w", err)
	}
	if err != nil || tenant.FromStored(user.TenantID) != tenantID {
		return User{}, fmt.Errorf("%w: user %s", ErrNotFound, userID)
	}
	return user, nil
}

// sessionInTenant loads a refresh session by token hash and refuses it unless it
// belongs to tenantID.
//
// A MISS comes back as ErrNotFound (the store's own answer), and a routing MISMATCH
// as ErrInvalidSession, so the two callers can keep their different semantics:
// Refresh answers ErrInvalidSession for both, Logout treats an unknown token as
// already logged out but refuses a foreign one.
//
// A mismatch does NOT revoke the session. Refresh revokes when a session's tenant
// differs from its USER's — that is corrupt data, and it must not be retryable. A
// session whose tenant differs from the ROUTE's is a caller error, and revoking
// there would let a misconfigured route, or anyone holding a leaked token, destroy
// valid sessions. The two mismatches are different facts and get different
// treatment.
func (c *Core) sessionInTenant(ctx context.Context, hash string, tenantID tenant.ID) (RefreshSession, error) {
	session, err := c.store.RefreshSessionByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return RefreshSession{}, ErrNotFound
		}
		return RefreshSession{}, fmt.Errorf("identity: lookup session: %w", err)
	}
	if tenant.FromStored(session.TenantID) != tenantID {
		return RefreshSession{}, ErrInvalidSession
	}
	return session, nil
}
