package crypto

import (
	"strings"
	"testing"
)

// TestMatchRecoveryCode_NormalisesInput exercises the v0.9 task 01
// TD-UX-10 normaliser: a stored canonical `XXXXX-XXXXX` hash should
// match any input that round-trips to the same string after stripping
// non-alphanumerics and uppercasing letters. The first six rows accept
// the canonical form; the last two are deliberately wrong length and
// must reject (the normaliser passes them through unchanged so bcrypt
// rejects them naturally).
func TestMatchRecoveryCode_NormalisesInput(t *testing.T) {
	const canonical = "ABCDE-FGHIJ"
	hashes, err := HashRecoveryCodes([]string{canonical})
	if err != nil {
		t.Fatalf("HashRecoveryCodes: %v", err)
	}

	cases := []struct {
		name      string
		candidate string
		wantOK    bool
	}{
		{"canonical", "ABCDE-FGHIJ", true},
		{"lowercase", "abcde-fghij", true},
		{"no hyphen", "ABCDEFGHIJ", true},
		{"lowercase no hyphen", "abcdefghij", true},
		{"spaces", "ABCDE FGHIJ", true},
		{"extra punctuation", "ABCDE-FGHIJ.", true},
		{"too short", "ABCDE", false},
		{"too long", "ABCDE-FGHIJ-X", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := MatchRecoveryCode(tc.candidate, hashes)
			if ok != tc.wantOK {
				t.Errorf("MatchRecoveryCode(%q) ok = %v, want %v", tc.candidate, ok, tc.wantOK)
			}
		})
	}
}

// TestNormaliseRecoveryCode_ReinsertsHyphenAtFive locks the placement
// of the hyphen for the canonical-length input — a regression here
// would mean the stored hashes don't round-trip even on
// well-formatted user input.
func TestNormaliseRecoveryCode_ReinsertsHyphenAtFive(t *testing.T) {
	got := normaliseRecoveryCode("abcdefghij")
	const want = "ABCDE-FGHIJ"
	if got != want {
		t.Errorf("normaliseRecoveryCode = %q, want %q", got, want)
	}
}

// TestNormaliseRecoveryCode_StripsNonAlphanumeric verifies the strip
// runs over the full Unicode range, not just ASCII punctuation. A
// pasted code surrounded by zero-width spaces (sometimes inserted by
// chat clients) should still normalise cleanly. U+200B is expressed
// via the explicit Go escape so the file stays free of invisible
// characters.
func TestNormaliseRecoveryCode_StripsNonAlphanumeric(t *testing.T) {
	const zwsp = "\u200b"
	got := normaliseRecoveryCode(zwsp + "abcde" + zwsp + "-fghij" + zwsp)
	const want = "ABCDE-FGHIJ"
	if got != want {
		t.Errorf("normaliseRecoveryCode = %q, want %q", got, want)
	}
}

// TestNormaliseRecoveryCode_KeepsDigits guards against an over-eager
// alpha-only filter that would strip out the digits some generators
// emit. Recovery codes use base32 (A-Z + 2-7), so a generator that
// happens to emit `34567-ABCDE` must survive normalisation as-is
// (modulo case).
func TestNormaliseRecoveryCode_KeepsDigits(t *testing.T) {
	got := normaliseRecoveryCode("34567-abcde")
	const want = "34567-ABCDE"
	if got != want {
		t.Errorf("normaliseRecoveryCode = %q, want %q", got, want)
	}
}

// TestNormaliseRecoveryCode_FallsThroughOnWrongLength documents the
// pass-through: an input whose stripped length isn't 10 keeps the
// uppercased alphanumeric subset. bcrypt rejects it naturally
// (stored hashes encode the 10+hyphen canonical form).
func TestNormaliseRecoveryCode_FallsThroughOnWrongLength(t *testing.T) {
	if got := normaliseRecoveryCode("abc"); got != "ABC" {
		t.Errorf("normaliseRecoveryCode(short) = %q, want %q", got, "ABC")
	}
	long := "abcde-fghij-klmno"
	want := strings.ToUpper(strings.ReplaceAll(long, "-", ""))
	if got := normaliseRecoveryCode(long); got != want {
		t.Errorf("normaliseRecoveryCode(long) = %q, want %q", got, want)
	}
}
