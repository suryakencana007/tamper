package saml

// DefaultMaxSAMLResponseBytes bounds the SAML response ParseAssertion accepts.
//
// One mebibyte of base64, roughly 750 KiB of XML: far above any real assertion (a typical
// one with a certificate chain is 10-40 KiB) and low enough that the two parses this
// package performs before any signature check stay in the low tens of milliseconds.
//
// The bound exists because the ACS path is unauthenticated and the response is parsed
// twice — once to refuse foreign-namespace NameID values (GO-2026-6909), once by the
// library — so an unbounded body is an unauthenticated way to burn CPU and memory.
const DefaultMaxSAMLResponseBytes = 1 << 20

// WithMaxResponseBytes sets a bound other than the default. A value of zero or less leaves
// the documented default in place rather than removing the bound: removing it is a separate,
// named act (WithMaxResponseBytesUnbounded), because the earlier contract made
// WithMaxResponseBytes(0) — and, worse, the ZERO VALUE of the field — mean unbounded.
func WithMaxResponseBytes(n int) ProviderOption {
	return func(p *Provider) {
		if n > 0 {
			p.maxResponseBytes = n
		}
	}
}

// WithMaxResponseBytesUnbounded removes the bound for one provider, deliberately: it restores
// the unbounded pre-signature parse the default exists to prevent, so it is spelled out in a
// name a reviewer will see, and it is the only way to reach that state.
func WithMaxResponseBytesUnbounded() ProviderOption {
	return func(p *Provider) { p.maxResponseBytes = unboundedResponseBytes }
}

// unboundedResponseBytes is the field value that means "no bound". Negative, so that zero can
// stay available for the safe default — see responseLimit.
const unboundedResponseBytes = -1

// responseLimit resolves the effective bound for one provider. Zero means the documented
// default, which is what makes the field's zero value SAFE: a Provider literal — the shape the
// post-merge review found could silently restore unbounded parsing, since the default used to
// be applied only inside BuildProvider — now gets the same bound as one built by BuildProvider.
// Zero is returned to mean unbounded, matching the caller's `limit > 0` test.
func (p *Provider) responseLimit() int {
	switch {
	case p.maxResponseBytes < 0:
		return 0 // unbounded, and only WithMaxResponseBytesUnbounded set this
	case p.maxResponseBytes == 0:
		return DefaultMaxSAMLResponseBytes
	default:
		return p.maxResponseBytes
	}
}

// ProviderOption configures a Provider at construction.
type ProviderOption func(*Provider)
