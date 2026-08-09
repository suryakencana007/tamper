package saml

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/suryakencana007/tamper/tenant"
)

// assertionWith builds a *crewjamsaml.Assertion whose Subject carries one
// SubjectConfirmation per supplied InResponseTo value. Zero values => a
// Subject with no confirmations.
func assertionWith(id string, inResponseTos ...string) *crewjamsaml.Assertion {
	confs := make([]crewjamsaml.SubjectConfirmation, 0, len(inResponseTos))
	for _, v := range inResponseTos {
		confs = append(confs, crewjamsaml.SubjectConfirmation{
			SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{InResponseTo: v},
		})
	}
	a := &crewjamsaml.Assertion{ID: id}
	a.Issuer.Value = "https://idp.test"
	a.Subject = &crewjamsaml.Subject{SubjectConfirmations: confs}
	return a
}

// --- Layer 1: correlate — the security truth table ---

func TestCorrelate_TruthTable(t *testing.T) {
	const R = "authnreq-we-issued"
	cases := []struct {
		name       string
		expected   string   // request id THIS flow issued ("" = none)
		signed     []string // InResponseTo on the signed confirmations
		allowIDP   bool
		wantErrIs  error // nil = accept
		wantReason string
	}{
		{"SP-initiated correlated", R, []string{R}, false, nil, "answers our request"},
		{"answers a foreign flow", R, []string{"other"}, false, ErrUncorrelated, "different request"},
		{"correlator stripped mid-flow", R, []string{""}, false, ErrUncorrelated, "empty answers our issued request"},
		{"THE captured-assertion replay", "", []string{R}, true, ErrUncorrelated, "no flow, yet answers one — even with allowIDP=true"},
		{"THE replay, allowIDP false", "", []string{R}, false, ErrUncorrelated, "no flow, yet answers one"},
		{"genuine IdP-initiated, allowed", "", []string{""}, true, nil, "answers nothing, policy permits"},
		{"genuine IdP-initiated, disabled", "", []string{""}, false, ErrIdPInitiatedDisabled, "answers nothing, policy forbids"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := correlate(assertionWith("a1", c.signed...), c.expected, c.allowIDP)
			if c.wantErrIs == nil {
				if err != nil {
					t.Fatalf("want ACCEPT (%s), got %v", c.wantReason, err)
				}
				return
			}
			if !errors.Is(err, c.wantErrIs) {
				t.Fatalf("want %v (%s), got %v", c.wantErrIs, c.wantReason, err)
			}
		})
	}
}

// TestCorrelate_AllowIDPInitiatedDoesNotReopenReplay is the row-4 guard,
// pinned on its own because it is the whole point: enabling IdP-initiated
// SSO must NOT admit an assertion that answers a request the flow never
// issued.
func TestCorrelate_AllowIDPInitiatedDoesNotReopenReplay(t *testing.T) {
	err := correlate(assertionWith("a1", "someone-elses-request"), "", true)
	if !errors.Is(err, ErrUncorrelated) {
		t.Fatalf("allowIDPInitiated=true must still reject an assertion answering an unissued request; got %v", err)
	}
}

func TestSignedInResponseTo(t *testing.T) {
	t.Run("no subject", func(t *testing.T) {
		a := &crewjamsaml.Assertion{ID: "x"}
		if _, err := signedInResponseTo(a); !errors.Is(err, ErrNoSubjectConfirmation) {
			t.Fatalf("nil Subject must be ErrNoSubjectConfirmation, got %v", err)
		}
	})
	t.Run("no confirmations", func(t *testing.T) {
		if _, err := signedInResponseTo(assertionWith("x")); !errors.Is(err, ErrNoSubjectConfirmation) {
			t.Fatalf("zero confirmations must be ErrNoSubjectConfirmation, got %v", err)
		}
	})
	t.Run("single value", func(t *testing.T) {
		got, err := signedInResponseTo(assertionWith("x", "R"))
		if err != nil || got != "R" {
			t.Fatalf("got (%q,%v), want (R,nil)", got, err)
		}
	})
	t.Run("agreeing confirmations", func(t *testing.T) {
		got, err := signedInResponseTo(assertionWith("x", "R", "R"))
		if err != nil || got != "R" {
			t.Fatalf("got (%q,%v), want (R,nil)", got, err)
		}
	})
	t.Run("disagreeing confirmations are fatal (no splice)", func(t *testing.T) {
		if _, err := signedInResponseTo(assertionWith("x", "R", "R-prime")); !errors.Is(err, ErrUncorrelated) {
			t.Fatalf("disagreeing confirmations must be ErrUncorrelated, got %v", err)
		}
	})
}

// --- keying + expiry ---

func TestAssertionReplayKey(t *testing.T) {
	a := assertionWith("assertion-1", "R")

	k1, err := assertionReplayKey("prov-a", a)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if len(k1) != 64 { // sha256 hex
		t.Errorf("key len = %d, want 64 hex chars", len(k1))
	}
	// Determinism.
	k1b, _ := assertionReplayKey("prov-a", a)
	if k1 != k1b {
		t.Error("key must be deterministic for the same inputs")
	}
	// Namespaced by provider — same assertion, different provider => different key.
	k2, _ := assertionReplayKey("prov-b", a)
	if k1 == k2 {
		t.Error("key must namespace by provider id")
	}
	// Namespaced by issuer.
	other := assertionWith("assertion-1", "R")
	other.Issuer.Value = "https://evil.test"
	k3, _ := assertionReplayKey("prov-a", other)
	if k1 == k3 {
		t.Error("key must namespace by issuer")
	}
	// No boundary collision: ("ab","c") vs ("a","bc") separated by 0x00.
	x := assertionWith("c", "R")
	x.Issuer.Value = "ab"
	y := assertionWith("bc", "R")
	y.Issuer.Value = "a"
	kx, _ := assertionReplayKey("p", x)
	ky, _ := assertionReplayKey("p", y)
	if kx == ky {
		t.Error("0x00 separators must prevent (issuer,id) boundary collisions")
	}
}

func TestAssertionReplayKey_Unkeyable(t *testing.T) {
	if _, err := assertionReplayKey("p", nil); !errors.Is(err, ErrAssertionInvalid) {
		t.Errorf("nil assertion must error, got %v", err)
	}
	if _, err := assertionReplayKey("p", assertionWith("")); !errors.Is(err, ErrAssertionInvalid) {
		t.Errorf("missing assertion ID must error (never 'fresh'), got %v", err)
	}
	if _, err := assertionReplayKey("p", assertionWith("   ")); !errors.Is(err, ErrAssertionInvalid) {
		t.Errorf("whitespace-only assertion ID must error, got %v", err)
	}
}

func TestReplayExpiry(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	window := crewjamsaml.MaxIssueDelay + crewjamsaml.MaxClockSkew

	t.Run("floored at now+skew for a stale IssueInstant", func(t *testing.T) {
		stale := assertionWith("x", "R")
		stale.IssueInstant = now.Add(-time.Hour) // long past
		exp := replayExpiry(stale, now)
		// base=now (not the stale past), so exp = now + window.
		if want := now.Add(window); !exp.Equal(want) {
			t.Errorf("exp = %v, want %v (must not be already-expired)", exp, want)
		}
		if !exp.After(now) {
			t.Error("a stale IssueInstant must never yield an already-expired row")
		}
	})
	t.Run("future IssueInstant extends the row", func(t *testing.T) {
		future := assertionWith("x", "R")
		future.IssueInstant = now.Add(30 * time.Second)
		exp := replayExpiry(future, now)
		if want := future.IssueInstant.Add(window); !exp.Equal(want) {
			t.Errorf("exp = %v, want %v (base off the future IssueInstant)", exp, want)
		}
	})
}

// --- Layer 2: MemAssertionReplayStore ---

func TestMemAssertionReplayStore(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour)

	t.Run("fresh then replay", func(t *testing.T) {
		s := NewMemAssertionReplayStore()
		if fresh, err := s.ConsumeAssertion(ctx, "k1", future); err != nil || !fresh {
			t.Fatalf("first consume: got (%v,%v), want (true,nil)", fresh, err)
		}
		if fresh, err := s.ConsumeAssertion(ctx, "k1", future); err != nil || fresh {
			t.Fatalf("second consume: got (%v,%v), want (false,nil) = replay", fresh, err)
		}
		// A different key is independent.
		if fresh, _ := s.ConsumeAssertion(ctx, "k2", future); !fresh {
			t.Error("distinct key must be fresh")
		}
	})

	t.Run("expired prior entry is treated as absent", func(t *testing.T) {
		s := NewMemAssertionReplayStore()
		base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
		s.SetClock(func() time.Time { return base })
		// Consume with an expiry 1s out.
		if _, err := s.ConsumeAssertion(ctx, "k", base.Add(time.Second)); err != nil {
			t.Fatalf("seed consume: %v", err)
		}
		// Advance past the expiry; the key is now GC-eligible and must read fresh.
		s.SetClock(func() time.Time { return base.Add(2 * time.Second) })
		if fresh, err := s.ConsumeAssertion(ctx, "k", base.Add(3*time.Second)); err != nil || !fresh {
			t.Fatalf("expired entry must read fresh, got (%v,%v)", fresh, err)
		}
	})

	t.Run("concurrent consume yields exactly one winner", func(t *testing.T) {
		s := NewMemAssertionReplayStore()
		const n = 64
		var wins int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if fresh, _ := s.ConsumeAssertion(ctx, "hot", future); fresh {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			t.Errorf("exactly one caller must win the CAS, got %d", wins)
		}
	})
}

func TestNoReplayDefence_AlwaysFresh(t *testing.T) {
	var s AssertionReplayStore = NoReplayDefence{}
	for i := range 3 {
		if fresh, err := s.ConsumeAssertion(context.Background(), "same-key", time.Now()); err != nil || !fresh {
			t.Fatalf("iter %d: NoReplayDefence must always report fresh, got (%v,%v)", i, fresh, err)
		}
	}
}

// --- ParseAssertion guards that need no signature ---

func TestParseAssertion_NilReplayStoreFailsClosed(t *testing.T) {
	// A hand-built Provider literal with a nil ledger must fail closed at
	// parse — never a silent accept. (BuildProvider refuses nil up front;
	// this guards the literal path.)
	p := &Provider{Config: ProviderConfig{ID: "test"}, SP: &crewjamsaml.ServiceProvider{}}
	_, err := p.ParseAssertion(context.Background(), "x", "", "")
	if !errors.Is(err, ErrReplayStoreUnavailable) {
		t.Fatalf("nil replay store must fail closed with ErrReplayStoreUnavailable, got %v", err)
	}
}

func TestBuildProvider_RequiresReplayStore(t *testing.T) {
	certPEM, keyPEM := testCertKeyPEM(t)
	cert, key := parsePEMPair(t, certPEM, keyPEM)
	cfg := ProviderConfig{
		ID: "test", EntityID: "e", ACSURL: "https://p.test/acs",
		MetadataURL: "https://idp.test/md", SPCert: cert, SPKey: key,
	}
	if _, err := BuildProvider(cfg, fakeEntity(certPEM), nil); err == nil {
		t.Fatal("BuildProvider must refuse a nil AssertionReplayStore")
	}
	if _, err := BuildProvider(cfg, fakeEntity(certPEM), NoReplayDefence{}); err != nil {
		t.Fatalf("BuildProvider with NoReplayDefence must succeed (explicit opt-out): %v", err)
	}
	if _, err := BuildProvider(cfg, fakeEntity(certPEM), NewMemAssertionReplayStore()); err != nil {
		t.Fatalf("BuildProvider with a real store must succeed: %v", err)
	}
}

// TestManager_RequiresReplayStore pins the fail-closed contract on the
// Manager rebuild path (NewManager returns no error, so the check lands at
// first rebuild — same shape as the missing-SPMetadataURL check).
func TestManager_RequiresReplayStore(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := testCertKeyPEM(t)
	store := NewMemProviderStore()
	// One enabled provider so rebuild passes the empty-store early return.
	_ = store.InsertProvider(ctx, ProviderRecord{
		ID: "p", ACSURL: "https://p.test/acs", SPSigningCertPEM: certPEM,
		SealedSigningKey: nil, Enabled: true, DisplayName: "P",
	})
	m := NewManager(store, nil, // nil keyset: key opens as empty; fine, rebuild fails earlier on replay
		WithSPMetadataURL(func(id, acsURL string) string { return "https://p.test/md/" + id }),
		WithMetadataFetcher(func(context.Context, string) (*crewjamsaml.EntityDescriptor, error) {
			return fakeEntity(certPEM), nil
		}),
		// deliberately NO WithAssertionReplayStore
	)
	_ = keyPEM
	if _, err := m.GetRegistry(ctx, tenant.Single); err == nil {
		t.Fatal("a Manager rebuilding a non-empty registry with no replay store must error")
	}
}
