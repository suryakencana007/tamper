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

// WithMaxResponseBytes overrides DefaultMaxSAMLResponseBytes for one provider. A value of
// zero or less disables the bound, which should be a deliberate act: it restores the
// unbounded pre-signature parse this default exists to prevent.
func WithMaxResponseBytes(n int) ProviderOption {
	return func(p *Provider) { p.maxResponseBytes = n }
}

// ProviderOption configures a Provider at construction.
type ProviderOption func(*Provider)
