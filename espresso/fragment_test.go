package espresso

import "testing"

// TestIdpErrorFragment_DropsInjection is the TD-OIDC-FRAGMENT-ESCAPE
// regression. The IdP-rejection landing fragment must run its values
// through the same FragmentValue dropper as the success path, so a
// malicious IdP's ?error= cannot break out of its slot and inject a
// sibling fragment parameter the SPA landing route would then parse.
func TestIdpErrorFragment_DropsInjection(t *testing.T) {
	// "denied&code=injected" is what ?error=denied%26code=injected decodes
	// to. Without the dropper the raw '&' opens a second fragment param
	// (code=injected); the dropper deletes it, collapsing the attempt into
	// the error value.
	if got, want := idpErrorFragment("denied&code=injected", "test"), "#error=deniedcode=injected&provider=test"; got != want {
		t.Errorf("injection not dropped:\n got = %q\nwant = %q", got, want)
	}
	// '#' and '%' are dropped too (the full FragmentValue byte set).
	if got, want := idpErrorFragment("a#b%c", "test"), "#error=abc&provider=test"; got != want {
		t.Errorf("delimiters not dropped:\n got = %q\nwant = %q", got, want)
	}
	// A clean value + provider id pass through unchanged.
	if got, want := idpErrorFragment("access_denied", "google"), "#error=access_denied&provider=google"; got != want {
		t.Errorf("clean value altered:\n got = %q\nwant = %q", got, want)
	}
}
