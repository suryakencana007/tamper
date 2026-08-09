package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"github.com/suryakencana007/tamper/tenant"
	"strings"
	"testing"
	"time"
)

// Slice 7d-1 — the Signer seam. HS256 must not move by a byte; a
// non-HMAC signer must round-trip; an unknown kid must fail closed.

// --- a real asymmetric stub -----------------------------------------
//
// Ed25519 rather than a fake: the seam's whole claim is that a NON-HMAC
// key works through it, and a stub that secretly did HMAC would prove
// nothing. Stdlib only, no new dependency.

type ed25519Signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	kid  string
	alg  string
}

func newEd25519Signer(t *testing.T, kid string) ed25519Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return ed25519Signer{pub: pub, priv: priv, kid: kid, alg: "EdDSA"}
}

func (s ed25519Signer) Alg() string   { return s.alg }
func (s ed25519Signer) KeyID() string { return s.kid }

func (s ed25519Signer) Sign(signingString string) ([]byte, error) {
	return ed25519.Sign(s.priv, []byte(signingString)), nil
}

func (s ed25519Signer) Verify(signingString string, sig []byte) error {
	if !ed25519.Verify(s.pub, []byte(signingString), sig) {
		return errors.New("ed25519: bad signature")
	}
	return nil
}

var _ Signer = ed25519Signer{}

func pinnedClock(s *JWTService) {
	s.Testing().SetNow(func() time.Time { return time.Unix(pinnedNow, 0).UTC() })
}

// --- byte identity ---------------------------------------------------

// TestSignerSeam_DefaultHS256DidNotMove is the invariant. The expected
// value is the SAME token pinned in jwt_test.go — captured from the tree
// before either the tid claim or this seam existed. Introducing a
// signing abstraction is exactly the refactor that silently reorders a
// header, and a reordered header changes every token in the wild.
func TestSignerSeam_DefaultHS256DidNotMove(t *testing.T) {
	s := pinnedService(t)

	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if tok != pinnedPre7cToken {
		t.Errorf("default HS256 token moved:\n got: %s\nwant: %s\n"+
			"The Signer seam must not touch the default path.", tok, pinnedPre7cToken)
	}
	if got, want := strings.Split(tok, ".")[0], strings.Split(pinnedPre7cToken, ".")[0]; got != want {
		t.Errorf("header segment changed: %s", got)
	}
}

// TestSignerSeam_HS256SignerMatchesDefault: the same algorithm and key
// expressed THROUGH the seam produces the same bytes. If these differ,
// the seam is not a faithful re-expression of the default path.
func TestSignerSeam_HS256SignerMatchesDefault(t *testing.T) {
	def := pinnedService(t)
	viaSeam := NewJWTService(
		JWTConfig{Secret: pinnedSecret, TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(NewHS256Signer([]byte(pinnedSecret))),
	)
	pinnedClock(viaSeam)

	a, err := def.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	b, err := viaSeam.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("via seam: %v", err)
	}
	if a != b {
		t.Errorf("HS256 through the seam differs from the default path:\n  %s\n  %s", a, b)
	}
	if _, err := viaSeam.VerifyAccess(b, tenant.Single); err != nil {
		t.Errorf("seam-signed token failed seam verification: %v", err)
	}
}

// --- asymmetric round trip -------------------------------------------

func TestSignerSeam_AsymmetricRoundTrip(t *testing.T) {
	sig := newEd25519Signer(t, "tenant-acme-2026")
	// No secret at all: a supplied Signer bypasses the secret requirement.
	s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer}, WithSigner(sig))
	pinnedClock(s)

	tok, err := s.IssueAccess(pinnedSubject, tenant.New("acme"), pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("IssueAccessForTenant: %v", err)
	}
	claims, err := s.VerifyAccess(tok, tenant.New("acme"))
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Subject != pinnedSubject || claims.TenantID != "acme" {
		t.Errorf("claims did not survive the asymmetric round trip: %+v", claims)
	}

	header := decodeHeader(t, tok)
	// The kid rides in the header — what per-tenant keys will resolve on.
	if !strings.Contains(header, `"kid":"tenant-acme-2026"`) {
		t.Errorf("kid header missing: %s", header)
	}
	if !strings.Contains(header, `"alg":"EdDSA"`) {
		t.Errorf("alg header is not the signer's: %s", header)
	}
}

// TestSignerSeam_TOTPPendingAlsoRoutesThroughTheSeam: the seam covers
// every token this service signs, not only access tokens. A shape left
// on the old path would stay HS256 after a deployment moved to
// asymmetric keys, verifying against a key nobody rotated.
func TestSignerSeam_TOTPPendingAlsoRoutesThroughTheSeam(t *testing.T) {
	sig := newEd25519Signer(t, "k1")
	s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer}, WithSigner(sig))
	pinnedClock(s)

	tok, err := s.IssueTOTPPending(pinnedSubject)
	if err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	if h := decodeHeader(t, tok); !strings.Contains(h, `"alg":"EdDSA"`) {
		t.Errorf("totp-pending token did not use the signer: %s", h)
	}
	sub, err := s.VerifyTOTPPending(tok)
	if err != nil {
		t.Fatalf("VerifyTOTPPending: %v", err)
	}
	if sub != pinnedSubject {
		t.Errorf("sub = %q, want %q", sub, pinnedSubject)
	}
}

// --- kid resolution fails closed -------------------------------------

func TestSignerSeam_UnknownKidFailsClosed(t *testing.T) {
	live := newEd25519Signer(t, "k-live")
	retired := newEd25519Signer(t, "k-retired")

	// Signs with k-live, and knows only k-live.
	s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(live),
		WithVerifiers(map[string]Signer{"k-live": live}),
	)
	pinnedClock(s)

	good, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.VerifyAccess(good, tenant.Single); err != nil {
		t.Fatalf("a token signed by the live key did not verify: %v", err)
	}

	// Case 1 — unknown kid, DIFFERENT key. Refused, though note this
	// case alone cannot tell fail-closed apart from a fallback: a
	// fallback to the signing key would also fail, on the signature.
	other := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer}, WithSigner(retired))
	pinnedClock(other)
	foreign, err := other.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue foreign: %v", err)
	}
	if _, err := s.VerifyAccess(foreign, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown kid with a foreign key was accepted: err = %v, want ErrInvalidToken", err)
	}

	// Case 2 — unknown kid, RIGHT key. This is the case that actually
	// distinguishes the two behaviours, and the reason kid resolution has
	// to fail closed. The token is signed by key material the service
	// holds, but names a kid the service has not registered — a key
	// rotated out, or one that never existed. A fallback to the signing
	// key verifies it happily, which makes the kid header decorative at
	// exactly the moment it becomes load-bearing.
	rotatedOut := live
	rotatedOut.kid = "k-rotated-out"
	mintedUnderOldKid := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(rotatedOut))
	pinnedClock(mintedUnderOldKid)
	stale, err := mintedUnderOldKid.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue under the rotated-out kid: %v", err)
	}
	if _, err := s.VerifyAccess(stale, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token naming an UNREGISTERED kid was accepted because its signature "+
			"happened to check out against the signing key: err = %v, want ErrInvalidToken", err)
	}
}

// TestSignerSeam_AlgConfusionRejected: the token does not choose its own
// algorithm. A verifier that trusted the header's alg is the classic
// confusion attack.
func TestSignerSeam_AlgConfusionRejected(t *testing.T) {
	honest := newEd25519Signer(t, "k1")
	liar := honest // same keys, but writes HS256 in the header
	liar.alg = "HS256"

	signer := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer}, WithSigner(liar))
	pinnedClock(signer)
	tok, err := signer.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	verifier := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(honest), WithVerifiers(map[string]Signer{"k1": honest}))
	pinnedClock(verifier)

	if _, err := verifier.VerifyAccess(tok, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token whose alg header disagreed with its key was accepted: %v", err)
	}
}

// --- the secret requirement ------------------------------------------

func TestSignerSeam_EmptySecretStillPanicsOnTheDefaultPath(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewJWTService with an empty secret and no Signer did not panic")
		}
	}()
	_ = NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer})
}

func TestSignerSeam_SuppliedSignerBypassesTheSecret(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("a supplied Signer should bypass the secret requirement, but New panicked: %v", r)
		}
	}()
	if s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(newEd25519Signer(t, "k1"))); s == nil {
		t.Fatal("nil service")
	}
}

func TestNewHS256Signer_EmptySecretPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHS256Signer(nil) did not panic; an empty HMAC key forges trivially")
		}
	}()
	_ = NewHS256Signer(nil)
}

// TestWithVerifiers_MapIsCopied: a caller mutating its map after
// construction must not change what a running service accepts.
func TestWithVerifiers_MapIsCopied(t *testing.T) {
	live := newEd25519Signer(t, "k-live")
	m := map[string]Signer{"k-live": live}
	s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer},
		WithSigner(live), WithVerifiers(m))
	pinnedClock(s)

	delete(m, "k-live") // the caller reuses its map for something else

	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.VerifyAccess(tok, tenant.Single); err != nil {
		t.Errorf("verification broke when the caller mutated its map: %v", err)
	}
}

// TestSignerSeam_ExpiryStillEnforcedOnTheDelegatedPath proves the
// delegated path did not lose the claim validation the default path
// gets from jwt.ParseWithClaims. It reuses golang-jwt's own validator
// rather than re-implementing expiry, and this is the test that says so.
func TestSignerSeam_ExpiryStillEnforcedOnTheDelegatedPath(t *testing.T) {
	sig := newEd25519Signer(t, "k1")
	s := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: pinnedIssuer}, WithSigner(sig))
	pinnedClock(s)

	tok, err := s.IssueAccess(pinnedSubject, tenant.Single, pinnedAuthAt, ACRLocalPassword)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Move the clock past expiry.
	s.Testing().SetNow(func() time.Time { return time.Unix(pinnedNow, 0).UTC().Add(2 * time.Hour) })
	if _, err := s.VerifyAccess(tok, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token accepted on the delegated path: %v", err)
	}

	// And a wrong issuer is still refused.
	other := NewJWTService(JWTConfig{TTL: time.Hour, Issuer: "someone-else"}, WithSigner(sig))
	pinnedClock(other)
	if _, err := other.VerifyAccess(tok, tenant.Single); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token from another issuer accepted: %v", err)
	}
}

// decodeHeader returns the decoded JOSE header segment.
func decodeHeader(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	return string(raw)
}
