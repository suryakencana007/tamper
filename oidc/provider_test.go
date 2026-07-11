package oidc

import (
	"context"
	"errors"
	"testing"
)

func TestBuildRegistry_EmptyProviders(t *testing.T) {
	reg, err := BuildRegistryFromConfigs(context.Background(), nil, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs(empty): %v", err)
	}
	if reg != nil {
		t.Errorf("BuildRegistryFromConfigs(empty) returned non-nil registry; want nil to signal disabled OIDC")
	}
}

func TestBuildRegistry_DiscoveryAndLookup(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "test", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", ClientSecret: "secret", DisplayName: "Test IdP"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	if reg == nil {
		t.Fatalf("BuildRegistryFromConfigs returned nil; want a registry")
	}
	p, err := reg.Get("test")
	if err != nil {
		t.Fatalf("Get(test): %v", err)
	}
	if p.OAuth2 == nil || p.Verifier == nil {
		t.Errorf("provider has nil OAuth2 / Verifier")
	}
	if p.OAuth2.RedirectURL != "https://rp.example.local/callback" {
		t.Errorf("RedirectURL = %q, want the config-supplied redirect URL verbatim", p.OAuth2.RedirectURL)
	}

	_, err = reg.Get("missing")
	if !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("Get(missing) error = %v, want ErrUnknownProvider", err)
	}
}

func TestBuildRegistry_DuplicateID(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	_, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "dup", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback"},
		{ID: "dup", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback"},
	}, false)
	if err == nil {
		t.Fatalf("expected duplicate id error")
	}
}

func TestRegistry_List_OrderPreserved(t *testing.T) {
	idp := newTestIdP(t, "barista", "secret")
	reg, err := BuildRegistryFromConfigs(context.Background(), []ProviderConfig{
		{ID: "alpha", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", DisplayName: "Alpha"},
		{ID: "beta", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", DisplayName: "Beta"},
		{ID: "gamma", IssuerURL: idp.URL, ClientID: "barista", RedirectURL: "https://rp.example.local/callback", DisplayName: "Gamma"},
	}, false)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfigs: %v", err)
	}
	summaries := reg.List()
	if len(summaries) != 3 {
		t.Fatalf("List len = %d, want 3", len(summaries))
	}
	wantOrder := []string{"alpha", "beta", "gamma"}
	for i, want := range wantOrder {
		if summaries[i].ID != want {
			t.Errorf("List[%d].ID = %q, want %q", i, summaries[i].ID, want)
		}
	}
}

func TestBuildProvider_RejectsInvalidID(t *testing.T) {
	_, err := BuildProvider(context.Background(), ProviderConfig{
		ID:        "has spaces",
		IssuerURL: "https://example.com",
		ClientID:  "x",
	})
	if err == nil {
		t.Fatalf("expected invalid-id error")
	}
}

func TestBuildProvider_RejectsEmptyClientID(t *testing.T) {
	_, err := BuildProvider(context.Background(), ProviderConfig{
		ID:        "ok",
		IssuerURL: "https://example.com",
	})
	if err == nil {
		t.Fatalf("expected missing-clientID error")
	}
}

func TestNormaliseScopes(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, []string{"openid", "profile", "email"}},
		{[]string{}, []string{"openid", "profile", "email"}},
		{[]string{"openid", "groups"}, []string{"openid", "groups"}},
		// "openid" prepended when missing.
		{[]string{"groups"}, []string{"openid", "groups"}},
	}
	for _, c := range cases {
		got := normaliseScopes(c.in)
		if !sameSlice(got, c.want) {
			t.Errorf("normaliseScopes(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func sameSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
