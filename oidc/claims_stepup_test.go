package oidc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClaims_AuthTime(t *testing.T) {
	now := func() time.Time { return time.Unix(9999, 0) }

	// SECURITY: all three JSON number shapes must be honored — a
	// decoder's mode determines which lands, and missing json.Number
	// (UseNumber decoders) silently weakens the step-up boundary.
	cases := map[string]struct {
		raw  map[string]any
		want int64
	}{
		"float64":               {map[string]any{"auth_time": float64(1700)}, 1700},
		"int64":                 {map[string]any{"auth_time": int64(1800)}, 1800},
		"json.Number":           {map[string]any{"auth_time": json.Number("1900")}, 1900},
		"absent → fallback":     {map[string]any{}, 9999},
		"zero → fallback":       {map[string]any{"auth_time": float64(0)}, 9999},
		"negative → fallback":   {map[string]any{"auth_time": int64(-5)}, 9999},
		"wrong type → fallback": {map[string]any{"auth_time": "1700"}, 9999},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := (&Claims{Raw: c.raw}).AuthTime(now)
			if got != c.want {
				t.Errorf("AuthTime = %d, want %d", got, c.want)
			}
		})
	}

	// json.Number produced by a real UseNumber decoder (not a literal).
	dec := json.NewDecoder(strings.NewReader(`{"auth_time": 2000}`))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := (&Claims{Raw: m}).AuthTime(now); got != 2000 {
		t.Errorf("UseNumber-decoded auth_time = %d, want 2000", got)
	}

	// Nil receiver falls back safely.
	var nilClaims *Claims
	if got := nilClaims.AuthTime(now); got != 9999 {
		t.Errorf("nil receiver AuthTime = %d, want fallback", got)
	}
}

func TestClaims_ACR(t *testing.T) {
	if got := (&Claims{Raw: map[string]any{"acr": "urn:x:mfa"}}).ACR("fallback"); got != "urn:x:mfa" {
		t.Errorf("ACR = %q, want the claim", got)
	}
	if got := (&Claims{Raw: map[string]any{"acr": ""}}).ACR("fallback"); got != "fallback" {
		t.Errorf("empty acr ACR = %q, want fallback", got)
	}
	if got := (&Claims{Raw: map[string]any{}}).ACR("fallback"); got != "fallback" {
		t.Errorf("absent acr ACR = %q, want fallback", got)
	}
	var nilClaims *Claims
	if got := nilClaims.ACR("fallback"); got != "fallback" {
		t.Errorf("nil receiver ACR = %q, want fallback", got)
	}
}
