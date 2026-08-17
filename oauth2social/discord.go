package oauth2social

// Discord returns a ready [Config] for Discord sign-in.
//
// # Which Discord flow this is
//
// The classic web authorization-code flow against discord.com/api —
// NOT the Social SDK. That SDK is for game and console clients: it
// speaks a `sdk.social_layer` scope, expects loopback or app-scheme
// redirects, mints provisional accounts, and documents no identity
// retrieval path for a web backend. Its OIDC references describe
// Discord CONSUMING an external game identity provider, not Discord
// acting as one. A server-side web sign-in belongs on the flow below.
//
// The Social SDK docs are useful for one corroboration, though: they
// state plainly that public clients must send a code challenge and
// verifier, which is why PKCE is unconditional here rather than a knob.
//
// # Identity shape
//
//   - Scopes `identify email` — the minimum that yields an account key
//     plus an address. `identify` alone returns no email at all, which
//     RequireEmail would then refuse on every sign-in.
//   - `GET /users/@me` is the userinfo endpoint.
//   - `id` is a snowflake: a stable, opaque, never-reused 64-bit id,
//     delivered as a JSON STRING. It becomes the identity subject.
//   - `email` is NULLABLE even with the scope granted — an account can
//     exist without one — hence RequireEmail.
//   - `verified` is Discord's own flag for whether that address was
//     confirmed. It is the reason RejectUnverifiedEmail can be honoured
//     here at all.
//
// # Why the username is not the account key
//
// Discord usernames are user-changeable and were globally renumbered
// in the 2023 migration away from discriminators. Keying an account on
// one would hand over another user's account the day a handle is
// released and re-registered. The snowflake is the only stable value.
func Discord(clientID, clientSecret, redirectURL string) Config {
	return Config{
		ID:           "discord",
		DisplayName:  "Discord",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://discord.com/oauth2/authorize",
		TokenURL:     "https://discord.com/api/oauth2/token",
		UserinfoURL:  "https://discord.com/api/users/@me",
		Scopes:       []string{"identify", "email"},
		ClaimMap: ClaimMap{
			Subject:       "id",
			Email:         "email",
			EmailVerified: "verified",
			// global_name is the post-2023 display name; username is the
			// handle. Both display-only.
			Name:     "global_name",
			Username: "username",

			// Both fences ON by default. An application may relax them,
			// but it has to say so out loud — see the field docs for
			// what each one is standing in front of.
			RequireEmail:          true,
			RejectUnverifiedEmail: true,
		},
	}
}
