package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"

	tampercrypto "github.com/suryakencana007/barista/packages/tamper/crypto"
)

const (
	mgrKEK1 = "0101010101010101010101010101010101010101010101010101010101010101"
	mgrKEK2 = "0202020202020202020202020202020202020202020202020202020202020202"
)

func mgrKeys(t *testing.T, entries ...tampercrypto.KEKEntry) *tampercrypto.KeySet {
	t.Helper()
	ks, err := tampercrypto.NewKeySet(entries, 0)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

// testCertKeyPEM mints a self-signed cert + matching RSA key as PEM.
func testCertKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

// fakeEntity is a minimal IdP metadata document with one Redirect
// SSO binding and one signing cert.
func fakeEntity(certPEM string) *crewjamsaml.EntityDescriptor {
	b64 := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(certPEM, "-----BEGIN CERTIFICATE-----"), "-----END CERTIFICATE-----\n"))
	b64 = strings.ReplaceAll(b64, "\n", "")
	return &crewjamsaml.EntityDescriptor{
		EntityID: "https://idp.example/realms/x",
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{{
			SSODescriptor: crewjamsaml.SSODescriptor{
				RoleDescriptor: crewjamsaml.RoleDescriptor{
					KeyDescriptors: []crewjamsaml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: crewjamsaml.KeyInfo{
							X509Data: crewjamsaml.X509Data{
								X509Certificates: []crewjamsaml.X509Certificate{{Data: b64}},
							},
						},
					}},
				},
			},
			SingleSignOnServices: []crewjamsaml.Endpoint{
				{Binding: crewjamsaml.HTTPPostBinding, Location: "https://idp.example/sso-post"},
				{Binding: crewjamsaml.HTTPRedirectBinding, Location: "https://idp.example/sso"},
			},
		}},
	}
}

func TestSAMLManager_CRUDSealsKeyAndRotates(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := testCertKeyPEM(t)
	store := NewMemProviderStore()
	m := NewManager(store, mgrKeys(t, tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1}))

	def := ProviderDefinition{
		ID: "kc", IdPMetadataURL: "https://idp.example/metadata", EntityID: "sp-entity",
		ACSURL: "https://panel.example/api/auth/saml/acs/kc", SPSigningCertPEM: certPEM,
		SPSigningKey: keyPEM, DisplayName: "KC", Enabled: true,
	}
	if err := m.Create(ctx, def); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec, _ := store.GetProvider(ctx, "kc")
	if string(rec.SealedSigningKey) == keyPEM || len(rec.SealedSigningKey) == 0 {
		t.Fatal("signing key must be sealed at rest")
	}
	got, err := m.Get(ctx, "kc")
	if err != nil || got.SPSigningKey != keyPEM {
		t.Fatalf("Get must open the key: err=%v", err)
	}
	if err := m.Create(ctx, def); !errors.Is(err, ErrProviderExists) {
		t.Fatalf("dup Create err=%v", err)
	}
	if err := m.Update(ctx, ProviderDefinition{ID: "ghost", SPSigningKey: "x"}); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("Update(ghost) err=%v", err)
	}

	// Rotate to a new write key.
	m2 := NewManager(store, mgrKeys(t,
		tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1}, tampercrypto.KEKEntry{ID: 2, Key: mgrKEK2}))
	res, err := m2.RotateSealedKeys(ctx)
	if err != nil || res.Scanned != 1 || res.Rotated != 1 {
		t.Fatalf("rotate: %+v err=%v", res, err)
	}
	rec, _ = store.GetProvider(ctx, "kc")
	if rec.SealedSigningKey[0] != 2 {
		t.Fatalf("envelope keyId=%d, want 2", rec.SealedSigningKey[0])
	}
	res, _ = m2.RotateSealedKeys(ctx)
	if res.Rotated != 0 {
		t.Fatalf("re-run must be a no-op: %+v", res)
	}
	if got, _ := m2.Get(ctx, "kc"); got.SPSigningKey != keyPEM {
		t.Fatal("post-rotate key must still open to the original plaintext")
	}
}

func TestSAMLManager_RegistryRebuildAndBadPEMOmission(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := testCertKeyPEM(t)
	store := NewMemProviderStore()
	m := NewManager(store, mgrKeys(t, tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1}),
		WithTTL(30*time.Second),
		WithSPMetadataURL(func(id, acsURL string) string { return "https://panel.example/api/auth/saml/metadata/" + id }),
		WithMetadataFetcher(func(_ context.Context, _ string) (*crewjamsaml.EntityDescriptor, error) {
			return fakeEntity(certPEM), nil
		}),
		WithAllowIDPInitiated(true),
	)
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return now })

	good := ProviderDefinition{
		ID: "good", IdPMetadataURL: "https://idp.example/md", EntityID: "sp",
		ACSURL: "https://panel.example/api/auth/saml/acs/good", SPSigningCertPEM: certPEM,
		SPSigningKey: keyPEM, DisplayName: "Good", Enabled: true,
	}
	bad := good
	bad.ID, bad.DisplayName, bad.SPSigningCertPEM = "bad", "Bad", "not-a-pem"
	bad.ACSURL = "https://panel.example/api/auth/saml/acs/bad"
	if err := m.Create(ctx, good); err != nil {
		t.Fatalf("Create good: %v", err)
	}
	if err := m.Create(ctx, bad); err != nil {
		t.Fatalf("Create bad: %v", err)
	}

	reg, err := m.GetRegistry(ctx)
	if err != nil || reg == nil {
		t.Fatalf("GetRegistry: reg=%v err=%v", reg, err)
	}
	if _, err := reg.Get("good"); err != nil {
		t.Fatalf("good provider must be in registry: %v", err)
	}
	if _, err := reg.Get("bad"); !errors.Is(err, ErrUnknownProvider) {
		t.Fatal("bad-PEM provider must be omitted, not fail the rebuild")
	}
	p, _ := reg.Get("good")
	if !p.SP.AllowIDPInitiated || p.Config.MetadataURL != "https://panel.example/api/auth/saml/metadata/good" {
		t.Fatalf("flow knobs / metadata URL not threaded: %+v", p.Config)
	}

	// Cache: same instance within ttl; mutation invalidates eagerly.
	reg2, _ := m.GetRegistry(ctx)
	if reg2 != reg {
		t.Fatal("within ttl the cached registry instance must be reused")
	}
	if err := m.Delete(ctx, "good"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, "bad"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	reg3, err := m.GetRegistry(ctx)
	if err != nil || reg3 != nil {
		t.Fatalf("empty store must yield the nil sentinel: %v %v", reg3, err)
	}
}

func TestSAMLManager_PinRegistryAndTestMetadata(t *testing.T) {
	ctx := context.Background()
	certPEM, _ := testCertKeyPEM(t)
	m := NewManager(NewMemProviderStore(), mgrKeys(t, tampercrypto.KEKEntry{ID: 1, Key: mgrKEK1}),
		WithMetadataFetcher(func(_ context.Context, url string) (*crewjamsaml.EntityDescriptor, error) {
			if url == "https://down.example/md" {
				return nil, ErrMetadataFetchFailed
			}
			return fakeEntity(certPEM), nil
		}),
	)

	pinned := &ProviderRegistry{providers: map[string]*Provider{}}
	m.PinRegistry(pinned)
	if got, err := m.GetRegistry(ctx); err != nil || got != pinned {
		t.Fatalf("pinned registry must be served with ttl=0: %v %v", got, err)
	}
	m.PinRegistry(nil)
	if got, err := m.GetRegistry(ctx); err != nil || got != nil {
		t.Fatalf("cleared pin: %v %v", got, err)
	}

	res, err := m.TestMetadata(ctx, "https://idp.example/md")
	if err != nil {
		t.Fatalf("TestMetadata: %v", err)
	}
	if res.EntityID != "https://idp.example/realms/x" ||
		res.SSOServiceBinding != crewjamsaml.HTTPRedirectBinding ||
		res.SSOServiceURL != "https://idp.example/sso" || res.SigningCertCount != 1 {
		t.Fatalf("TestMetadata result: %+v", res)
	}
	// The fetcher sentinel chain must survive for errors.Is callers.
	if _, err := m.TestMetadata(ctx, "https://down.example/md"); !errors.Is(err, ErrMetadataFetchFailed) {
		t.Fatalf("err=%v, want ErrMetadataFetchFailed chain", err)
	}
}
