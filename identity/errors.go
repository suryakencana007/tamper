package identity

import "errors"

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
)
