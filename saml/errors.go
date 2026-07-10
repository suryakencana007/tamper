// Package saml implements a SAML 2.0 Service Provider (SP) substrate
// for Tamper consumers. Wraps github.com/crewjam/saml v0.5.x (SP-side
// metadata generation + AuthnRequest signing + assertion validation)
// behind a Provider / ProviderRegistry shape the app's HTTP layer can
// consume without owning the protocol mechanics.
//
// Route shapes stay the APP's concern: ProviderConfig carries the full
// ACS + SP-metadata URLs as data — the package never composes an
// endpoint path. State-cookie NAMES are likewise the app's (the app
// brands its cookies); this package owns the signed-claims format and
// its purpose discrimination.
//
// Why a third-party library: hand-rolling SAML XML signing /
// canonicalization / assertion validation is exactly the surface
// where security bugs hide. crewjam/saml is the most production-ready
// Go SAML library. License: BSD-2-Clause.
package saml

import "errors"

// ErrUnknownProvider surfaces from ProviderRegistry.Get when the
// requested id is not in the configured set. Callers should map to a
// 404 so an attacker probing for valid provider ids gets the same
// shape as a typo — id enumeration provides no useful signal.
var ErrUnknownProvider = errors.New("saml: unknown provider")

// ErrMetadataFetchFailed wraps any error from the IdP metadata fetch
// (network failure, malformed XML, non-200 status). Callers should map
// to a 503 so an IdP outage looks like a transient upstream failure
// rather than a 500.
var ErrMetadataFetchFailed = errors.New("saml: metadata fetch failed")

// ErrMetadataInvalid wraps parse errors where the IdP metadata XML
// is structurally invalid or missing the IDPSSODescriptor element.
// Distinct from ErrMetadataFetchFailed so operators see "the IdP
// responded but its metadata is wrong" vs "the IdP didn't respond".
var ErrMetadataInvalid = errors.New("saml: metadata invalid")
