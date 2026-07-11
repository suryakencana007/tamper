package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// TestEndToEnd_AuthCodeFlow walks the full OIDC handshake against
// the testIdP fixture: discovery → authorization URL → token
// exchange via the IdP's token endpoint → ID token verification.
// The end-to-end shape mirrors the production handler path so any
// signature / nonce / audience regression surfaces here before
// the handler layer.
func TestEndToEnd_AuthCodeFlow(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")

	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	p, err := reg.Get("test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	flow, err := NewFlow()
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}

	// Sanity: the authorization URL carries every PKCE field.
	authURL := p.OAuth2.AuthCodeURL(flow.State,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", flow.Nonce),
		oauth2.S256ChallengeOption(flow.CodeVerifier),
	)
	for _, want := range []string{
		"response_type=code",
		"client_id=barista",
		"code_challenge=",
		"code_challenge_method=S256",
		"state=" + flow.State,
		"nonce=" + flow.Nonce,
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("authURL missing %q: %s", want, authURL)
		}
	}

	// Mint a code at the IdP carrying the expected claims.
	code := idp.MintCode(jwt.MapClaims{
		"sub":   "user-001",
		"email": "alice@example.com",
		"name":  "Alice Example",
		"nonce": flow.Nonce,
	})

	token, err := p.OAuth2.Exchange(context.Background(), code,
		oauth2.VerifierOption(flow.CodeVerifier),
	)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		t.Fatalf("no id_token returned")
	}

	verified, err := VerifyIDToken(context.Background(), p, rawIDToken, flow.Nonce)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if verified.Sub != "user-001" {
		t.Errorf("sub = %q, want user-001", verified.Sub)
	}
	if verified.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", verified.Email)
	}
	if verified.Name != "Alice Example" {
		t.Errorf("name = %q, want Alice Example", verified.Name)
	}
	if verified.Raw == nil {
		t.Errorf("raw claim map is nil; Task 03 mapper would have no source to read groups from")
	}
}

func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	p, _ := reg.Get("test")
	flow, _ := NewFlow()

	code := idp.MintCode(jwt.MapClaims{
		"sub":   "user-001",
		"email": "alice@example.com",
		"nonce": "WRONG-NONCE",
	})
	token, err := p.OAuth2.Exchange(context.Background(), code,
		oauth2.VerifierOption(flow.CodeVerifier),
	)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)

	_, err = VerifyIDToken(context.Background(), p, rawIDToken, flow.Nonce)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestVerifyIDToken_AudienceMismatch(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	p, _ := reg.Get("test")
	flow, _ := NewFlow()

	// Override the mint to emit an audience that doesn't match.
	idp.SetIDTokenMintOverride(func(c jwt.MapClaims) jwt.MapClaims {
		c["aud"] = "different-client"
		return c
	})

	code := idp.MintCode(jwt.MapClaims{
		"sub":   "user-002",
		"email": "bob@example.com",
		"nonce": flow.Nonce,
	})
	token, err := p.OAuth2.Exchange(context.Background(), code,
		oauth2.VerifierOption(flow.CodeVerifier),
	)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)

	_, err = VerifyIDToken(context.Background(), p, rawIDToken, flow.Nonce)
	if !errors.Is(err, ErrIDTokenInvalid) {
		t.Errorf("expected ErrIDTokenInvalid for audience mismatch, got %v", err)
	}
}

func TestVerifyIDToken_Expired(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	p, _ := reg.Get("test")
	flow, _ := NewFlow()

	// Override the mint to emit an exp in the past.
	idp.SetIDTokenMintOverride(func(c jwt.MapClaims) jwt.MapClaims {
		c["exp"] = time.Now().Add(-1 * time.Hour).Unix()
		return c
	})

	code := idp.MintCode(jwt.MapClaims{
		"sub":   "user-003",
		"email": "carol@example.com",
		"nonce": flow.Nonce,
	})
	token, err := p.OAuth2.Exchange(context.Background(), code,
		oauth2.VerifierOption(flow.CodeVerifier),
	)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)

	_, err = VerifyIDToken(context.Background(), p, rawIDToken, flow.Nonce)
	if !errors.Is(err, ErrIDTokenInvalid) {
		t.Errorf("expected ErrIDTokenInvalid for expired token, got %v", err)
	}
}

func TestVerifyIDToken_RawClaimsCarryGroups(t *testing.T) {
	// Forward-compat check for Task 03: the raw claim map MUST
	// carry whatever the IdP put on the wire, so the group-claim
	// role mapper can read configurable claim names (groups,
	// roles, custom Auth0 paths).
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	p, _ := reg.Get("test")
	flow, _ := NewFlow()

	code := idp.MintCode(jwt.MapClaims{
		"sub":    "user-004",
		"email":  "dave@example.com",
		"name":   "Dave",
		"nonce":  flow.Nonce,
		"groups": []string{"barista-admins", "ops"},
		// Azure-AD-like roles claim
		"roles": []string{"admin"},
		// Auth0-style URL claim
		"https://barista.io/groups": []string{"custom-group"},
	})
	token, err := p.OAuth2.Exchange(context.Background(), code,
		oauth2.VerifierOption(flow.CodeVerifier),
	)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)

	verified, err := VerifyIDToken(context.Background(), p, rawIDToken, flow.Nonce)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	for _, key := range []string{"groups", "roles", "https://barista.io/groups"} {
		if _, ok := verified.Raw[key]; !ok {
			t.Errorf("raw claims missing %q — Task 03 mapper can't read it", key)
		}
	}
}
