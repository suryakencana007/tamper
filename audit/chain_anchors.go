package audit

// Chain-segment anchor actions. Unlike the caller-defined action /
// resource strings that ride through ordinary Event emissions, these two
// action values are load-bearing for the hash-chain machinery itself:
// the verify path (verify_boot.go / audit_sqlite.go) and the migration
// path (migration.go) recognise them as chain-segment boundaries.
//
// They were lifted out of Barista's Barista-specific event catalog
// (internal/audit/eventtypes.go, deliberately NOT lifted into Tamper) as
// the only two catalog constants the generic core depends on. Callers
// remain free to define their own action / resource vocabulary for every
// other Event; these two are reserved by the chain subsystem.
const (
	// ActionAuditChainRestart marks a hash-chain genesis row: PrevHash is
	// the HashSize zero-byte sentinel and the row opens a new canonical
	// payload segment. Verify() walks forward from the most-recent
	// chain-restart row, treating it as the segment anchor. A caller
	// emits one (via Logger.Log with Action=ActionAuditChainRestart and
	// an explicit CanonicalVersion) exactly once per chain segment —
	// typically at first boot after an encoder-version bump.
	ActionAuditChainRestart Action = "system.audit.chain_restart"

	// ActionAuditChainMigrate marks that an in-place chain rehash / encoder
	// migration ran against an existing segment (see
	// SQLiteLogger.MigrateLegacyV2Hashes / RehashChainInPlace). The row is
	// a logical segment boundary for the boot-time verify walk
	// (VerifyChainPostMigration) and its presence is the idempotency key
	// for HasChainMigrate so the migration doesn't re-run on every restart.
	ActionAuditChainMigrate Action = "system.audit.chain_migrate"
)
