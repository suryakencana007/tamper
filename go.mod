module github.com/suryakencana007/tamper

go 1.26

// Pins the toolchain tamper's OWN builds and CI use, so they link a
// patched stdlib. Bare `go 1.26` resolves to the 1.26.0 stdlib, which
// carries 13 advisories reachable from this module (crypto/tls,
// crypto/x509, net/http, net/url, html/template, net/textproto); all are
// fixed by 1.26.5.
//
// The `go` line above stays at 1.26 on purpose. It is the floor adopters
// must meet, and raising it to 1.26.5 would force every consumer to bump
// (Barista, for one, is on go 1.26.0). A dependency's toolchain line is
// ignored when it is not the main module, so this pin costs consumers
// nothing.
//
// Bump this when a newer patch closes an advisory the CI govulncheck
// step reports — that step is the trigger.
toolchain go1.26.5

require (
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/crewjam/saml v0.5.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/pquerna/otp v1.5.0
	github.com/scim2/filter-parser/v2 v2.2.1
	github.com/suryakencana007/espresso/v2 v2.4.0
	golang.org/x/crypto v0.53.0
	golang.org/x/oauth2 v0.36.0
	modernc.org/sqlite v1.53.0
)

require (
	github.com/beevik/etree v1.6.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/di-wu/parser v0.2.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/zerolog v1.35.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	golang.org/x/sys v0.46.0 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
