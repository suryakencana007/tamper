package saml

import (
	"context"
	"fmt"
	"log"
)

// BuildRegistryFromConfigs builds a ProviderRegistry from the
// service-layer-supplied ProviderConfig list. Each entry runs
// fetcher(cfg.IdPMetadataURL) to retrieve IdP metadata, then
// BuildProvider to assemble the per-IdP Provider.
//
// partialOK softens the IdP metadata fetch failure mode:
//   - partialOK=false: any single provider whose metadata fetch
//     fails fails the whole construction. Fail-loud at boot when an
//     IdP is unreachable so the operator sees the bad provider id
//     immediately.
//   - partialOK=true: a failing entry logs a warning + is omitted
//     from the registry; rebuild succeeds with the remaining
//     providers. Login attempts for the missing provider should
//     surface as a 503 until the next rebuild finds the IdP healthy.
//     Suits a TTL-rebuild path so a transient IdP outage doesn't
//     cascade into a dead registry.
//
// Returns nil-and-nil for an empty input slice in either mode so
// callers can treat a nil registry as "SAML not configured".
//
// replay is the assertion-replay ledger threaded to every BuildProvider
// call — one instance shared across the registry (the ledger key
// namespaces by provider id). REQUIRED; a nil store fails every provider's
// construction. See BuildProvider.
func BuildRegistryFromConfigs(
	ctx context.Context,
	configs []ProviderConfig,
	fetcher MetadataFetcher,
	partialOK bool,
	replay AssertionReplayStore,
) (*ProviderRegistry, error) {
	if len(configs) == 0 {
		return nil, nil
	}
	if fetcher == nil {
		fetcher = DefaultMetadataFetcher
	}
	reg := &ProviderRegistry{
		providers: make(map[string]*Provider, len(configs)),
		order:     make([]string, 0, len(configs)),
	}
	for _, cfg := range configs {
		if _, dup := reg.providers[cfg.ID]; dup {
			return nil, fmt.Errorf("saml: duplicate provider id %q in provider list", cfg.ID)
		}
		entity, err := fetcher(ctx, cfg.IdPMetadataURL)
		if err != nil {
			if partialOK {
				log.Printf("saml: provider %q idp metadata fetch failed; omitting from registry until next reload: %v", cfg.ID, err)
				continue
			}
			return nil, fmt.Errorf("saml: provider %q: %w", cfg.ID, err)
		}
		p, err := BuildProvider(cfg, entity, replay)
		if err != nil {
			if partialOK {
				log.Printf("saml: provider %q construction failed; omitting from registry until next reload: %v", cfg.ID, err)
				continue
			}
			return nil, err
		}
		reg.providers[cfg.ID] = p
		reg.order = append(reg.order, cfg.ID)
	}
	return reg, nil
}
