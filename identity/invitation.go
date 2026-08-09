// Invitations — the non-SSO onboarding path.
//
// A tenant admin invites an address; the invitee follows a one-time link
// and sets a password. Until now tamper had no home for this: Register
// is self-service (anyone with the endpoint can create an account) and
// the federated paths need an IdP. A pooled deployment needs the middle
// case — "acme's admin adds bob, bob is not in any directory".
//
// The token is the whole security boundary. It is the only thing
// standing between a URL and an account inside someone's tenant, so it
// is high-entropy, stored only as a hash, single-use, and expiring.

package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/suryakencana007/tamper/crypto"
	"github.com/suryakencana007/tamper/tenant"
)

// Invitation is a pending (or spent) invitation to join a tenant.
//
// NEUTRAL RECORD, no table. tamper names no column here any more than it
// does for users or sessions (§6.5); the application maps this onto
// whatever it already has.
type Invitation struct {
	ID string

	// TenantID is the tenant being joined. "" is the single-tenant
	// deployment, exactly as everywhere else in this phase.
	TenantID string

	// Email is the address invited. The accepted account is created with
	// THIS address, never one supplied at accept time — otherwise an
	// invitation to bob@acme.com is a voucher to create any account at
	// all, which is a privilege-escalation path into the tenant.
	Email string

	// TokenHash is the SHA-256 hex of the invitation token. The
	// plaintext is returned once by Invite and never stored — the same
	// discipline as refresh tokens (crypto.HashRefreshToken).
	TokenHash string

	// ExpiresAt is when the link stops working.
	ExpiresAt time.Time

	// AcceptedAt is zero while pending. Set exactly once, by the store's
	// compare-and-set in MarkAccepted.
	AcceptedAt time.Time

	// InvitedBy is the inviting user's id. Carried for the application's
	// audit row; the core does not read it.
	InvitedBy string

	// CreatedAt is when the invitation was issued.
	CreatedAt time.Time
}

// Pending reports whether the invitation has not yet been accepted.
func (i Invitation) Pending() bool { return i.AcceptedAt.IsZero() }

// Expired reports whether the invitation is past its TTL at `now`.
//
// A zero ExpiresAt is EXPIRED, not eternal. The zero value of a struct
// an application fills in by hand must never be the permissive reading —
// a forgotten field would otherwise mint invitations that never die.
func (i Invitation) Expired(now time.Time) bool {
	return !i.ExpiresAt.After(now)
}

// Usable reports whether the invitation may still be accepted at `now`.
func (i Invitation) Usable(now time.Time) bool {
	return i.Pending() && !i.Expired(now)
}

// InvitationStore is the invitation persistence port.
//
// SEPARATE FROM Store, and optional, deliberately. Folding these three
// methods into Store would break every existing implementation the day
// this lands, for a feature most of them do not use. An application opts
// in by implementing this and passing WithInvitations; one that does not
// is unaffected, and the invitation verbs fail loudly with
// ErrNoInvitationStore rather than quietly doing nothing.
//
// Implementations MUST be safe for concurrent use.
type InvitationStore interface {
	// CreateInvitation persists a new invitation.
	//
	// Isolation contract. The implementation MUST constrain the query to
	// inv.TenantID and MUST return ErrNotFound — never a permission error
	// and never another tenant's row — when the addressed object belongs
	// to a different tenant. A "" tenantID selects the single-tenant
	// table shape. tamper cannot verify this; the cross-tenant leak suite
	// (§3.3) is the proof obligation that comes with implementing this
	// interface.
	CreateInvitation(ctx context.Context, inv Invitation) error

	// InvitationByHash resolves an invitation by its token hash.
	// ErrNotFound when no row matches.
	//
	// Deliberately NOT tenant-scoped, which is the one place in this
	// phase a lookup is not. The key is a 256-bit secret: there is no
	// enumeration to defend against, because anyone able to name the hash
	// already holds the token. Scoping it would also break the flow it
	// exists for — the invitee follows a link before anything has
	// established which tenant they are joining. The core compares the
	// tenant AFTER the fetch and collapses a mismatch into
	// ErrInvitationInvalid, so a wrong-tenant accept is indistinguishable
	// from a nonexistent one.
	//
	// Implementations MUST NOT filter on expiry or accepted-ness. The
	// core decides usability, so that "expired" and "already accepted"
	// reach the same collapsed error instead of one becoming a not-found
	// and the other something else.
	InvitationByHash(ctx context.Context, hash string) (Invitation, error)

	// MarkAccepted consumes the invitation, exactly once.
	//
	// THIS MUST BE AN ATOMIC COMPARE-AND-SET, not a read-then-write.
	// In SQL that is
	//
	//	UPDATE invitations SET accepted_at = $2
	//	 WHERE id = $1 AND accepted_at IS NULL
	//
	// and zero rows affected means someone else won: return
	// ErrInvitationConsumed. The check cannot live in the core, because
	// two concurrent accepts of one link would both read "pending" and
	// both proceed — two accounts from one invitation, which is the
	// failure this port shape exists to make impossible.
	//
	// Returns ErrInvitationConsumed if already accepted, ErrNotFound if
	// no such invitation.
	MarkAccepted(ctx context.Context, id string, at time.Time) error
}

// WithInvitations enables the invitation verbs.
//
// Panics on a nil store: a Core that believes it can invite but has
// nowhere to persist would fail on the first invitation an admin sends,
// which is both the least convenient moment and the hardest to
// reproduce. §6.4 — configuration fails at construction, never as a
// per-request denial.
func WithInvitations(s InvitationStore) Option {
	if s == nil {
		panic("identity: WithInvitations requires a non-nil InvitationStore")
	}
	return func(c *Core) { c.invitations = s }
}

// DefaultInvitationTTL is used when Invite is given a non-positive ttl.
//
// Bounded rather than unlimited, because the alternative reading — 0
// means "never expires" — turns a forgotten argument into a permanent
// credential. Seven days is long enough to survive a holiday and short
// enough that a link found in an old mailbox is dead.
const DefaultInvitationTTL = 7 * 24 * time.Hour

// Invite creates an invitation and returns it alongside the PLAINTEXT
// token, which is returned exactly once and never stored.
//
// The caller is responsible for delivering the token (the email, the
// link). tamper does not send mail.
//
// The returned Invitation carries only the hash, so logging the record —
// which is what an audit path will do — cannot leak the credential.
func (c *Core) Invite(ctx context.Context, tenantID tenant.ID, email, invitedBy string, ttl time.Duration) (Invitation, string, error) {
	if c.invitations == nil {
		return Invitation{}, "", ErrNoInvitationStore
	}
	if err := c.tenantGate(tenantID); err != nil {
		return Invitation{}, "", err
	}
	normalised, err := NormaliseEmail(email)
	if err != nil {
		return Invitation{}, "", err
	}
	if ttl <= 0 {
		ttl = DefaultInvitationTTL
	}

	// Same generator as refresh tokens: 32 random bytes, base64url. The
	// invariant is the entropy, not the encoding — this token is guessed
	// online against a lookup, so it must be infeasible to guess even
	// once.
	token, err := crypto.NewRefreshToken()
	if err != nil {
		return Invitation{}, "", fmt.Errorf("identity: generate invitation token: %w", err)
	}
	hash, err := crypto.HashRefreshToken(token)
	if err != nil {
		return Invitation{}, "", fmt.Errorf("identity: hash invitation token: %w", err)
	}

	now := c.now()
	inv := Invitation{
		ID:        c.newID(),
		TenantID:  tenantID.String(),
		Email:     normalised,
		TokenHash: hash,
		ExpiresAt: now.Add(ttl),
		InvitedBy: invitedBy,
		CreatedAt: now,
	}
	if err := c.invitations.CreateInvitation(ctx, inv); err != nil {
		return Invitation{}, "", fmt.Errorf("identity: create invitation: %w", err)
	}
	return inv, token, nil
}

// AcceptInvitation redeems a token: it consumes the invitation and
// creates the account, returning the user and a fresh session.
//
// The account is created with the INVITED address and the invited
// tenant. Neither is taken from the caller — an invitation that let its
// holder choose the address would be a voucher to create any account in
// someone else's tenant.
//
// EVERY REJECTION IS THE SAME ERROR. Unknown token, malformed token,
// expired, already accepted, or issued for a different tenant all return
// ErrInvitationInvalid, because the honest message for all of them is
// "this link no longer works". Distinguishing expired from accepted
// would tell whoever holds a stale link whether someone else used it,
// and distinguishing wrong-tenant from unknown would confirm that a
// token belongs to SOME tenant — the same 404-not-403 discipline the
// rest of the phase applies (§6.3).
func (c *Core) AcceptInvitation(ctx context.Context, tenantID tenant.ID, token, password string) (User, Tokens, error) {
	if c.invitations == nil {
		return User{}, Tokens{}, ErrNoInvitationStore
	}
	if err := c.tenantGate(tenantID); err != nil {
		return User{}, Tokens{}, err
	}
	// Validate the password BEFORE consuming the invitation. A weak
	// password would otherwise burn the link and leave the invitee
	// unable to retry — the failure mode is a support ticket per typo.
	if err := validatePassword(password); err != nil {
		return User{}, Tokens{}, err
	}

	hash, err := crypto.HashRefreshToken(token)
	if err != nil {
		// Malformed token: not base64url, or empty. Collapsed, so a
		// probe cannot tell "wrong shape" from "no such invitation".
		return User{}, Tokens{}, ErrInvitationInvalid
	}
	inv, err := c.invitations.InvitationByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return User{}, Tokens{}, ErrInvitationInvalid
		}
		return User{}, Tokens{}, fmt.Errorf("identity: lookup invitation: %w", err)
	}
	// Wrong tenant is a miss, not a permission error.
	if inv.TenantID != tenantID.String() {
		return User{}, Tokens{}, ErrInvitationInvalid
	}
	if !inv.Usable(c.now()) {
		return User{}, Tokens{}, ErrInvitationInvalid
	}

	// CONSUME FIRST, then create the account.
	//
	// The order is the single-use guarantee and it is not
	// interchangeable. Creating the user first means two concurrent
	// accepts both pass the usability check above and both insert; the
	// unique-email index arbitrates and one gets ErrEmailTaken, but only
	// because the emails happen to collide — and the invitation is still
	// pending afterwards. Consuming first makes the store's
	// compare-and-set the arbiter, which is the only thing here that is
	// actually atomic.
	//
	// The cost is real and accepted: if account creation fails after
	// this point the invitation is spent. That is recoverable — an admin
	// re-invites. Two accounts from one invitation is not.
	if err := c.invitations.MarkAccepted(ctx, inv.ID, c.now()); err != nil {
		if errors.Is(err, ErrInvitationConsumed) || errors.Is(err, ErrNotFound) {
			return User{}, Tokens{}, ErrInvitationInvalid
		}
		return User{}, Tokens{}, fmt.Errorf("identity: consume invitation: %w", err)
	}

	user, tokens, err := c.Register(ctx, tenant.FromStored(inv.TenantID), inv.Email, password)
	if err != nil {
		return User{}, Tokens{}, err
	}
	return user, tokens, nil
}
