package oauth2social

import (
	"errors"
	"strings"
	"testing"
)

// discordProvider is a constructed Discord provider. Built through New
// so the tests exercise the same validation a real deployment does.
func discordProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Discord("client-id", "client-secret", "https://app.example/cb"))
	if err != nil {
		t.Fatalf("New(Discord): %v", err)
	}
	return p
}

// A realistic Discord /users/@me payload. Values are shaped like the
// real thing: snowflake as a STRING, verified as a bool.
func discordUserinfo() map[string]any {
	return map[string]any{
		"id":            "80351110224678912",
		"username":      "nelly",
		"global_name":   "Nelly",
		"email":         "nelly@example.com",
		"verified":      true,
		"discriminator": "0",
		"avatar":        "8342729096ea3675442027381ff50dfe",
	}
}

func TestClaimsFromUserinfo_DiscordHappyPath(t *testing.T) {
	p := discordProvider(t)
	claims, err := p.claimsFromUserinfo(discordUserinfo())
	if err != nil {
		t.Fatalf("claimsFromUserinfo: %v", err)
	}
	if claims.Sub != "80351110224678912" {
		t.Errorf("Sub = %q, want the snowflake", claims.Sub)
	}
	if claims.Email != "nelly@example.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	if claims.Name != "Nelly" || claims.PreferredUsername != "nelly" {
		t.Errorf("display fields: Name=%q PreferredUsername=%q", claims.Name, claims.PreferredUsername)
	}
	// Raw must carry the WHOLE document: a group/role mapper reading a
	// configurable claim name has to work identically across protocols.
	if claims.Raw["avatar"] != "8342729096ea3675442027381ff50dfe" {
		t.Error("Raw lost fields the typed struct does not model")
	}
}

// TestClaimsFromUserinfo_EmailFences pins the two refusals that make a
// social identity safe to hand to an application's collision veto.
//
// Mutation check: drop either fence and the matching subtest fails.
func TestClaimsFromUserinfo_EmailFences(t *testing.T) {
	p := discordProvider(t)

	t.Run("missing email is refused", func(t *testing.T) {
		// Discord's email is nullable EVEN WITH the scope granted. An
		// account with no address cannot be invited, cannot be matched
		// by the collision veto, and cannot be notified.
		raw := discordUserinfo()
		delete(raw, "email")
		if _, err := p.claimsFromUserinfo(raw); !errors.Is(err, ErrEmailRequired) {
			t.Fatalf("err = %v, want ErrEmailRequired", err)
		}
	})

	t.Run("null email is refused like a missing one", func(t *testing.T) {
		raw := discordUserinfo()
		raw["email"] = nil
		if _, err := p.claimsFromUserinfo(raw); !errors.Is(err, ErrEmailRequired) {
			t.Fatalf("err = %v, want ErrEmailRequired", err)
		}
	})

	t.Run("unverified email is refused", func(t *testing.T) {
		// The fence that matters most: an application keys its
		// collision veto on the address, so an unverified claim is an
		// assertion of "I am whoever I like".
		raw := discordUserinfo()
		raw["verified"] = false
		if _, err := p.claimsFromUserinfo(raw); !errors.Is(err, ErrEmailUnverified) {
			t.Fatalf("err = %v, want ErrEmailUnverified", err)
		}
	})

	t.Run("absent verification flag reads as unverified", func(t *testing.T) {
		// Fail closed: a missing flag is not evidence of verification.
		raw := discordUserinfo()
		delete(raw, "verified")
		if _, err := p.claimsFromUserinfo(raw); !errors.Is(err, ErrEmailUnverified) {
			t.Fatalf("err = %v, want ErrEmailUnverified", err)
		}
	})

	t.Run("a non-bool truthy value does NOT satisfy verification", func(t *testing.T) {
		// "1" and 1 are the shapes a sloppy provider or a hostile one
		// would send hoping a lenient parser accepts them.
		for _, v := range []any{1, 1.0, "yes", "TRUE ", map[string]any{}} {
			raw := discordUserinfo()
			raw["verified"] = v
			_, err := p.claimsFromUserinfo(raw)
			if v == "TRUE " {
				// ParseBool accepts "TRUE" and we trim, so this one is
				// genuinely a true. Pin that it is the ONLY string form
				// accepted, rather than silently allowing "yes".
				if err != nil {
					t.Errorf("verified=%v: %v (trimmed TRUE is a real true)", v, err)
				}
				continue
			}
			if !errors.Is(err, ErrEmailUnverified) {
				t.Errorf("verified=%v (%T): err = %v, want ErrEmailUnverified", v, v, err)
			}
		}
	})
}

// TestClaimsFromUserinfo_SubjectIsMandatory pins that a missing account
// key is fatal. There is nothing to fall back to: the subject IS the
// identity, and substituting a username would key accounts on a
// user-changeable, re-registerable handle.
func TestClaimsFromUserinfo_SubjectIsMandatory(t *testing.T) {
	p := discordProvider(t)
	raw := discordUserinfo()
	delete(raw, "id")
	if _, err := p.claimsFromUserinfo(raw); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
}

// TestDecodeUserinfo_LargeNumericIDSurvivesExactly is the sharpest test
// in this package, and it caught a real bug during development.
//
// encoding/json decodes numbers to float64 by default, and float64
// holds 53 bits of mantissa. A Discord snowflake is a full 64-bit
// integer, so 80351110224678912 came back as 80351110224678910 -- a
// DIFFERENT account key, produced silently, with no error anywhere.
//
// It is tested through the DECODER rather than a hand-built map because
// the bug lives in the decode, not the formatting: any test that
// constructs map[string]any itself has already chosen the type and
// cannot observe the loss.
func TestDecodeUserinfo_LargeNumericIDSurvivesExactly(t *testing.T) {
	p := discordProvider(t)

	// A provider sending the snowflake as a NUMBER -- the shape that
	// breaks under float64. (Discord sends a string today, which is
	// exactly why this needs pinning: the bug is invisible until some
	// other provider, or a Discord change, sends a number.)
	body := `{"id":80351110224678912,"email":"nelly@example.com","verified":true}`
	raw, err := decodeUserinfo(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decodeUserinfo: %v", err)
	}
	claims, err := p.claimsFromUserinfo(raw)
	if err != nil {
		t.Fatalf("claimsFromUserinfo: %v", err)
	}
	if claims.Sub != "80351110224678912" {
		t.Errorf("Sub = %q, want %q -- float64 rounding silently re-keys the account",
			claims.Sub, "80351110224678912")
	}

	// And the ordinary string form is untouched.
	raw, err = decodeUserinfo(strings.NewReader(`{"id":"80351110224678912","email":"n@example.com","verified":true}`))
	if err != nil {
		t.Fatalf("decodeUserinfo(string id): %v", err)
	}
	claims, err = p.claimsFromUserinfo(raw)
	if err != nil {
		t.Fatalf("claimsFromUserinfo(string id): %v", err)
	}
	if claims.Sub != "80351110224678912" {
		t.Errorf("string-form Sub = %q", claims.Sub)
	}
}

// TestDecodeUserinfo_RejectsGarbage pins that a hostile or broken
// provider body fails as ErrUserinfo rather than panicking or yielding
// a half-populated identity.
func TestDecodeUserinfo_RejectsGarbage(t *testing.T) {
	for _, body := range []string{``, `not json`, `[1,2,3]`, `{"id":`} {
		if _, err := decodeUserinfo(strings.NewReader(body)); !errors.Is(err, ErrUserinfo) {
			t.Errorf("body %q: err = %v, want ErrUserinfo", body, err)
		}
	}
}

// TestNew_RefusesConfigThatWouldDenyEveryLogin pins the construction
// guard. RejectUnverifiedEmail with no field to read it from is not a
// strict configuration — it is one that refuses every user forever,
// and finding that out at the first sign-in is far worse than at boot.
func TestNew_RefusesConfigThatWouldDenyEveryLogin(t *testing.T) {
	cfg := Discord("id", "secret", "https://app.example/cb")
	cfg.ClaimMap.EmailVerified = "" // no flag to read
	if _, err := New(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

// TestNew_RequiresHTTPSEndpoints pins the transport fence. The access
// token is spent as a bearer credential against the userinfo endpoint,
// and unlike an id_token nothing downstream would notice a tampered
// response, so there is no dev-mode http exemption here.
func TestNew_RequiresHTTPSEndpoints(t *testing.T) {
	for _, field := range []string{"auth", "token", "userinfo"} {
		t.Run(field, func(t *testing.T) {
			cfg := Discord("id", "secret", "https://app.example/cb")
			switch field {
			case "auth":
				cfg.AuthURL = "http://discord.example/authorize"
			case "token":
				cfg.TokenURL = "http://discord.example/token"
			case "userinfo":
				cfg.UserinfoURL = "http://discord.example/users/@me"
			}
			if _, err := New(cfg); !errors.Is(err, ErrConfig) {
				t.Fatalf("plain-http %s url accepted: err = %v", field, err)
			}
		})
	}
}

// TestDiscordPreset_ShapeIsTheDocumentedOne pins the preset against
// Discord's actual API, because every value here is a fact about their
// service rather than a taste decision -- and a wrong one fails only
// against the live provider, where it is expensive to diagnose.
func TestDiscordPreset_ShapeIsTheDocumentedOne(t *testing.T) {
	c := Discord("cid", "csec", "https://app.example/cb")

	if c.UserinfoURL != "https://discord.com/api/users/@me" {
		t.Errorf("userinfo = %q", c.UserinfoURL)
	}
	if c.ClaimMap.Subject != "id" {
		t.Errorf("subject field = %q, want the snowflake `id` (username is user-changeable)", c.ClaimMap.Subject)
	}
	if c.ClaimMap.EmailVerified != "verified" {
		t.Errorf("verified field = %q", c.ClaimMap.EmailVerified)
	}
	var hasEmailScope bool
	for _, s := range c.Scopes {
		if s == "email" {
			hasEmailScope = true
		}
	}
	if !hasEmailScope {
		t.Error("preset must request the email scope; `identify` alone returns no address and RequireEmail would refuse every sign-in")
	}
	if !c.ClaimMap.RequireEmail || !c.ClaimMap.RejectUnverifiedEmail {
		t.Error("preset must ship both email fences ON; relaxing them should be an explicit act by the application")
	}
}
