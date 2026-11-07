# Architecture decisions

Each ADR records one decision, the forces behind it, and what was rejected. They are the
"why" behind the code — and where a decision was later revisited, the ADR says so rather
than being rewritten to look inevitable.

| ADR | Decision |
|---|---|
| [ADR-0001 — Tenant hierarchy: platform tenant, group, org](../adrs/ADR-0001-tenant-hierarchy-platform-tenantgroup-org) | The parentage model, and the rule that authorization never inherits while plans and IdPs do |

## Related reading

- **[Design](../design/TAMPER-DESIGN)** — the whole shape of the library: the ports, the
  boundaries, and the extraction playbook that produced it.
- **[Request flows](../design/flow)** — what happens on a login, a refresh, a step-up, and
  an entered request, function by function.
- **[Changelog](../changelog)** — what changed in each release.
- **[Migration guides](../migrations/MIGRATION-v0.9)** — the breaking releases, and what to
  do about them.
