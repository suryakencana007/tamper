// Package crypto holds tamper's portable authentication primitives:
// bcrypt password hashing (+ timing-equalisation stub, here), HS256
// access tokens, random refresh tokens (SHA-256 at rest), RFC-6238
// TOTP, and the AES-GCM keyset/secretbox envelopes. Lifted near-verbatim
// from Barista's internal/auth; the package depends on nothing from a
// host application — callers compose these helpers.
package crypto

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidPassword is returned by VerifyPassword when the plain
// password does not match the stored hash, and by HashPassword when
// the input is rejected (e.g. empty). Handlers compare with errors.Is.
var ErrInvalidPassword = errors.New("auth: invalid password")

// Cost is the bcrypt work factor used by HashPassword. The auth service
// overrides this from config (BARISTA_AUTH_BCRYPT_COST) at startup;
// tests may drop it to bcrypt.MinCost to keep runtime bearable.
//
// 12 is the project default per /CLAUDE.md §Tech Stack. Values outside
// [bcrypt.MinCost, bcrypt.MaxCost] are clamped by the bcrypt package.
var Cost = 12

// HashPassword returns a bcrypt hash of plain. Empty passwords are
// rejected with ErrInvalidPassword; infra failures are returned as-is.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("%w: password is empty", ErrInvalidPassword)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), Cost)
	if err != nil {
		return "", fmt.Errorf("auth: bcrypt generate: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword returns nil iff plain matches hash. Any mismatch or
// malformed-hash error is returned as ErrInvalidPassword so callers
// don't need to distinguish (and handlers don't leak which side failed).
func VerifyPassword(hash, plain string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}
	return nil
}

var (
	stubHashOnce sync.Once
	stubHash     []byte
	stubHashErr  error
)

// stubHashBytes returns a bcrypt hash of a fixed dummy password, computed
// once at the current Cost. Callers use it to pay the bcrypt cost on
// authentication paths where no real hash exists yet — see VerifyStub.
//
// Cost is captured on first call; changes after that point have no effect.
// Callers are expected to finalise Cost at startup before the first auth.
func stubHashBytes() ([]byte, error) {
	stubHashOnce.Do(func() {
		stubHash, stubHashErr = bcrypt.GenerateFromPassword(
			[]byte("barista-stub-password-for-timing-equalisation"),
			Cost,
		)
	})
	return stubHash, stubHashErr
}

// ResetStubHashForTesting forces the next call to VerifyStub to
// regenerate the stub hash at the current Cost. Production code never
// calls this — Cost is finalised at startup before the first auth, so
// the sync.Once is the right guard. Tests that mutate Cost mid-run
// (notably TestLogin_MissingUserBranchPaysBcryptCost, which raises Cost
// to make bcrypt's runtime measurable) need to flush the cached stub
// or the missing-user branch keeps running at the cost the stub was
// first generated under, breaking the timing-symmetry assertion.
//
// Concurrency note: assignment of `stubHashOnce` is not atomic, but
// this helper is intended for serial test-setup use only.
func ResetStubHashForTesting() {
	stubHashOnce = sync.Once{}
	stubHash = nil
	stubHashErr = nil
}

// VerifyStub runs bcrypt against a fixed dummy hash and always returns
// ErrInvalidPassword. Authentication paths call this on the "user not
// found" branch so the request pays the same bcrypt cost whether or not
// the account exists — closing the timing side-channel that would
// otherwise leak user existence to a remote attacker.
//
// The stub hash is lazily computed at the current Cost on first call.
func VerifyStub(plain string) error {
	dummy, err := stubHashBytes()
	if err != nil {
		// Dummy-hash generation failed — possible only if Cost was
		// somehow set outside [MinCost, MaxCost], which the bcrypt
		// package clamps. Return the sentinel without leaking detail.
		return fmt.Errorf("%w: stub hash unavailable", ErrInvalidPassword)
	}
	// Ignore the outcome: plain will never match the fixed dummy, and
	// the caller only cares that bcrypt ran.
	_ = bcrypt.CompareHashAndPassword(dummy, []byte(plain))
	return fmt.Errorf("%w: user not found", ErrInvalidPassword)
}
