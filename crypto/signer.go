package crypto

import (
	"github.com/golang-jwt/jwt/v5"
)

// Signer abstracts the JWT signing method so a deployment can move to
// asymmetric keys — and to a per-tenant `kid` — without touching a
// single call site. It is a SEAM: nothing in tamper selects a non-HS256
// signer, and the default construction path does not go through this
// interface at all.
//
// signingString is the JWS signing input, `base64url(header) + "." +
// base64url(claims)`. An implementation signs or verifies exactly those
// bytes and nothing else; it never sees, parses or trusts the claims.
//
// Implementations MUST be safe for concurrent use — one JWTService is
// shared across every request in the process.
type Signer interface {
	// Alg is the JWS `alg` header value ("HS256", "RS256", "ES256"…).
	// Verification requires the token's alg to equal this exactly, so an
	// implementation must never report an alg it does not enforce.
	Alg() string

	// KeyID is the JWS `kid` header value; "" means no kid header is
	// written, which is what keeps the default HS256 token byte-identical
	// to a pre-seam one.
	KeyID() string

	// Sign returns the raw (un-encoded) signature over signingString.
	Sign(signingString string) ([]byte, error)

	// Verify returns nil when sig is a valid signature over
	// signingString, and an error otherwise. It must not distinguish
	// failure modes to the caller — a signature that is wrong and one
	// that is malformed are the same answer.
	Verify(signingString string, sig []byte) error
}

// NewHS256Signer returns the HS256 Signer over secret — the same
// algorithm and the same key material the default path uses, expressed
// through the seam.
//
// Panics on an empty secret, the posture NewJWTService already takes: an
// HMAC key everyone can guess is not a weaker key, it is no key, and
// every token it signs is forgeable. The invariant that a supplied
// Signer bypasses the SECRET REQUIREMENT is about JWTConfig.Secret being
// allowed to be empty when signing is delegated — not about permitting
// an empty HMAC key here.
func NewHS256Signer(secret []byte) Signer {
	if len(secret) == 0 {
		panic("auth: NewHS256Signer requires a non-empty secret — an empty HMAC key forges trivially")
	}
	return hs256Signer{secret: secret}
}

type hs256Signer struct{ secret []byte }

func (h hs256Signer) Alg() string   { return jwt.SigningMethodHS256.Alg() }
func (h hs256Signer) KeyID() string { return "" }

func (h hs256Signer) Sign(signingString string) ([]byte, error) {
	return jwt.SigningMethodHS256.Sign(signingString, h.secret)
}

func (h hs256Signer) Verify(signingString string, sig []byte) error {
	return jwt.SigningMethodHS256.Verify(signingString, sig, h.secret)
}

// signerMethod adapts a Signer onto jwt.SigningMethod so the SIGNING
// side can keep using jwt.NewWithClaims, which owns the header/claims
// marshalling and the base64url encoding.
//
// It is deliberately NOT registered with jwt.RegisterSigningMethod.
// That call mutates a process-global map inside golang-jwt, so two
// JWTServices with different signers under one alg name would silently
// overwrite each other — new global mutable state, in someone else's
// package (sketch §6.6). The verification side therefore resolves the
// Signer itself and reuses jwt.NewValidator for claim checks, rather
// than going through the parser's global method lookup.
type signerMethod struct{ s Signer }

func (m signerMethod) Alg() string { return m.s.Alg() }

func (m signerMethod) Sign(signingString string, _ any) ([]byte, error) {
	return m.s.Sign(signingString)
}

func (m signerMethod) Verify(signingString string, sig []byte, _ any) error {
	return m.s.Verify(signingString, sig)
}
