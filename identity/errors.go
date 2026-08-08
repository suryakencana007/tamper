package identity

import (
	"errors"
	"time"
)

// Error taxonomy. The application maps these onto its own wire errors
// (Barista: domain.ErrUnauthorized / ErrAlreadyExists / ErrInvalid …).
// Store implementations MUST return the sentinels noted on the Store
// interface (wrapped is fine — the core matches with errors.Is).
var (
	// ErrInvalidCredentials is the single collapsed rejection for every
	// password-login failure mode — unknown email, malformed email, bad
	// password, federated-only account, deactivated account. One error
	// by design: distinguishing them would leak account existence.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrTOTPRequired signals that password verification SUCCEEDED but a
	// TOTP step must complete before tokens are issued (the user is
	// enrolled, or system-wide enforcement is on). Login returns the
	// user alongside it so the caller can mint its two-phase session
	// token.
	ErrTOTPRequired = errors.New("identity: totp verification required")

	// ErrInvalidSession is the single collapsed rejection for every
	// refresh failure mode — unknown, revoked, expired, malformed,
	// refresh disabled. Same anti-enumeration posture as
	// ErrInvalidCredentials.
	ErrInvalidSession = errors.New("identity: invalid refresh session")

	// ErrUserInactive is the one refresh failure deliberately NOT
	// collapsed into ErrInvalidSession: the caller needs to distinguish
	// it (Barista maps it to 401 USER_INACTIVE + a clear-cookie
	// response). The offending session is revoked before it is returned.
	ErrUserInactive = errors.New("identity: user is inactive")

	// ErrEmailTaken — registration against an already-registered email
	// (the store surfaces its unique-index violation as this).
	ErrEmailTaken = errors.New("identity: email is already registered")

	// ErrInvalidEmail — empty or shape-invalid email.
	ErrInvalidEmail = errors.New("identity: email is malformed")

	// ErrPasswordPolicy — password outside the accepted length bounds.
	ErrPasswordPolicy = errors.New("identity: password does not meet policy")

	// ErrNotFound — store sentinel for a missing row (user or session).
	ErrNotFound = errors.New("identity: not found")

	// ErrInvalidInput is the generic validation sentinel for inputs
	// the more specific sentinels (email shape, password policy)
	// don't cover — transport adapters map it to their
	// validation-error wire code.
	ErrInvalidInput = errors.New("identity: invalid input")

	// ErrNoTokenService — a token-minting flow was invoked on a Core
	// constructed without a JWT service (crypto-ops / bootstrap
	// instances are allowed to be token-less; minting from one is a
	// programmer error surfaced loudly).
	ErrNoTokenService = errors.New("identity: core has no token service")

	// ErrNoKeySet — a TOTP flow that seals/opens the secret envelope
	// was invoked on a Core constructed without a KeySet.
	ErrNoKeySet = errors.New("identity: core has no keyset")

	// ErrInvalidTOTP — code/recovery-code rejection (also covers
	// "phase 2 before phase 1": nothing to verify against, the caller
	// re-routes to phase 1).
	ErrInvalidTOTP = errors.New("identity: invalid totp code")

	// ErrTOTPAlreadyEnrolled / ErrTOTPNotEnrolled — enrollment
	// state-machine guards.
	ErrTOTPAlreadyEnrolled = errors.New("identity: totp already enrolled")
	ErrTOTPNotEnrolled     = errors.New("identity: totp not enrolled")

	// --- identity linking (Phase 2d) ---

	// ErrLinkConflict — the (provider, subject) is already linked to a
	// DIFFERENT user. (Same-user re-link is idempotent, not an error.)
	ErrLinkConflict = errors.New("identity: provider identity linked to another user")

	// ErrIdentityTaken — the (provider, subject) unique-index violation
	// surfaced by the store on insert (the identity analogue of
	// ErrEmailTaken). Used both directly and, on the race path, as the
	// signal to re-fetch and re-decide idempotent-vs-conflict.
	ErrIdentityTaken = errors.New("identity: provider identity already linked")

	// ErrLastAuthMethod — unlinking would leave a federated-only user
	// (empty password hash) with zero sign-in methods.
	ErrLastAuthMethod = errors.New("identity: cannot unlink the last authentication method")

	// --- tenancy (Phase 7) ---

	// ErrTenantRequired — a tenancy-enabled Core was asked to act with an
	// empty tenant id. Deny-by-default extends to tenancy: absent and
	// empty resolve to deny, never to "every tenant" (sketch §6.2).
	//
	// Deliberately NOT collapsed into ErrInvalidCredentials. That
	// collapse exists to stop attackers distinguishing facts ABOUT AN
	// ACCOUNT — unknown email, bad password, federated-only, deactivated.
	// This condition is decided from the tenantID argument alone, before
	// any store read, and is identical for every email and every account,
	// so it discloses nothing an attacker did not already supply. It is a
	// wiring bug in the deployment — the tenant-resolving middleware did
	// not run — and hiding it inside "invalid credentials" would send an
	// operator hunting a password problem that does not exist.
	//
	// Transport obligation: map it onto the SAME generic 401 envelope as
	// ErrInvalidCredentials. It is legible in logs, not on the wire.
	ErrTenantRequired = errors.New("identity: tenant id is required when tenancy is enabled")

	// ErrTenancyDisabled — a tenant id was supplied to a Core built
	// WITHOUT tenancy. Also a deny rather than a silent ignore: the store
	// has no tenant axis, so honouring the call would run an UNSCOPED
	// query while the caller believes it is scoped. That is precisely the
	// wildcard §6.2 forbids, and it fails open.
	ErrTenancyDisabled = errors.New("identity: tenant id supplied but tenancy is not enabled")

	// --- rate limiting (Phase 7, 7k-1) ---

	// ErrThrottled — the configured Throttle refused the attempt. Match
	// with errors.Is; the retry hint travels on *ThrottledError.
	//
	// Deliberately NOT collapsed into ErrInvalidCredentials, and this is
	// the case worth stating carefully because it looks like it should
	// be. The collapse hides facts about an ACCOUNT. This condition is
	// decided from the caller-supplied key alone, BEFORE any store read,
	// so it is identical whether the address exists, never existed, is
	// federated-only or is deactivated — it discloses nothing an attacker
	// did not just type. Collapsing it would also be actively harmful:
	// the honest client that backs off on a 429 would instead be told its
	// password was wrong and would keep trying.
	//
	// Transport obligation: 429 with Retry-After. A deployment that would
	// rather not admit to limiting at all may render the generic 401
	// envelope instead — that is a legitimate choice and it is safe,
	// because the error does not vary by account either way.
	ErrThrottled = errors.New("identity: too many attempts")

	// --- invitations (Phase 7, 7j-1) ---

	// ErrInvitationInvalid is the single collapsed rejection for every
	// invitation failure mode — unknown token, malformed token, expired,
	// already accepted, or issued for a different tenant.
	//
	// One error by design, the same posture as ErrInvalidCredentials and
	// ErrInvalidSession. Separating expired from accepted would tell
	// whoever holds a stale link whether somebody else used it — which
	// is a fact about another person's actions inside a tenant. The
	// honest message for all of them is "this link no longer works".
	ErrInvitationInvalid = errors.New("identity: invitation is not valid")

	// ErrInvitationConsumed is the STORE sentinel for a compare-and-set
	// that lost: MarkAccepted found the invitation already accepted.
	//
	// It exists so implementations have something precise to return, and
	// so the losing side of a concurrent accept is distinguishable from
	// an infrastructure failure. The core never surfaces it — it
	// collapses into ErrInvitationInvalid at the boundary.
	ErrInvitationConsumed = errors.New("identity: invitation already accepted")

	// ErrNoInvitationStore — an invitation verb was invoked on a Core
	// constructed without WithInvitations. A programmer error surfaced
	// loudly, exactly like ErrNoTokenService and ErrNoKeySet, rather
	// than a silent no-op that looks like a delivery problem.
	ErrNoInvitationStore = errors.New("identity: core has no invitation store")
)

// ThrottledError carries the retry hint alongside ErrThrottled.
//
// Its message is FIXED — no email, no user id, no key. The value that
// composed the key came from the caller, but the error crosses into logs
// and sometimes onto the wire, and a limiter that echoes the attempted
// address into either is how a rate limit becomes a credential-stuffing
// receipt.
type ThrottledError struct {
	// RetryAfter is how long until the attempt may be retried. It is a
	// property of the bucket, not of the account.
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string { return ErrThrottled.Error() }

// Unwrap makes errors.Is(err, ErrThrottled) match.
func (e *ThrottledError) Unwrap() error { return ErrThrottled }
