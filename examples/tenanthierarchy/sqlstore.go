package tenanthierarchy

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/suryakencana007/tamper/authz"
	"github.com/suryakencana007/tamper/tenant"
)

// Schema is the SQL form of the in-memory model: one row table plus a per-row
// origin table. Two facts, two tables — that is what makes a revoke able to
// remove its own contribution and leave a direct grant on the same binding
// alone (provenance, slice 9a-1).
//
// It is app-owned: tamper names no table.
const Schema = `
CREATE TABLE IF NOT EXISTS authz_binding (
    tenant_scope   TEXT NOT NULL,
    subject_tenant TEXT NOT NULL,
    subject_type   TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    role           TEXT NOT NULL,
    PRIMARY KEY (tenant_scope, subject_tenant, subject_type, subject_id,
                 resource_type, resource_id, role)
);

CREATE TABLE IF NOT EXISTS authz_binding_origin (
    tenant_scope   TEXT NOT NULL,
    subject_tenant TEXT NOT NULL,
    subject_type   TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    role           TEXT NOT NULL,
    origin         TEXT NOT NULL,
    PRIMARY KEY (tenant_scope, subject_tenant, subject_type, subject_id,
                 resource_type, resource_id, role, origin)
);

-- ListSubjects / BindingsOnResource.
CREATE INDEX IF NOT EXISTS authz_binding_on_resource
    ON authz_binding (tenant_scope, resource_type, resource_id);

-- BindingsForSubject / the intent read.
CREATE INDEX IF NOT EXISTS authz_binding_for_subject
    ON authz_binding (tenant_scope, subject_tenant, subject_type, subject_id,
                      resource_type);

-- Reconcile: "which rows carry this origin".
CREATE INDEX IF NOT EXISTS authz_binding_origin_by_origin
    ON authz_binding_origin (origin, tenant_scope);
`

// bindingCols is the column list every row query selects, in scan order.
const bindingCols = `tenant_scope, subject_tenant, subject_type, subject_id,
                     resource_type, resource_id, role`

// SQLStore is the SQL adapter for the same ports the in-memory [Store]
// implements: authz.BindingStore, BindingWriter, BindingSource and
// IntentReader. Provisioning, reconciliation and derived membership accept it
// unchanged — they depend on the interfaces, not on the store.
//
// Every write runs in a transaction, and Apply is one transaction, so a
// provisioning operation is all-or-nothing exactly as it is in memory.
type SQLStore struct {
	db *sql.DB
}

var (
	_ authz.BindingStore = (*SQLStore)(nil)
	_ BindingWriter      = (*SQLStore)(nil)
	_ BindingSource      = (*SQLStore)(nil)
	_ IntentReader       = (*SQLStore)(nil)
)

// OpenSQLStore opens dsn with the "sqlite" driver and creates [Schema] if it is
// missing. Pass ":memory:" for an ephemeral store — note that a pooled
// *sql.DB may hold several connections, so a memory database needs
// "file:name?mode=memory&cache=shared" to be shared across them.
func OpenSQLStore(dsn string) (*SQLStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("tenanthierarchy: OpenSQLStore requires a dsn")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: open %q: %w", dsn, err)
	}
	if _, err := db.Exec(Schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tenanthierarchy: create schema in %q: %w", dsn, err)
	}
	return &SQLStore{db: db}, nil
}

// Close releases the database handle.
func (s *SQLStore) Close() error { return s.db.Close() }

// ---------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------

// Grant stores b with the OriginDirect contribution.
func (s *SQLStore) Grant(ctx context.Context, b authz.Binding) error {
	return s.GrantFrom(ctx, b, OriginDirect)
}

// GrantFrom stores b and records that origin justifies it. Idempotent on
// (key, origin): granting the same pair twice is one origin row.
func (s *SQLStore) GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error {
	if err := gate(b.Tenant, b.Subject); err != nil {
		return err
	}
	return s.Apply(ctx, func(tx Tx) error { return tx.GrantFrom(ctx, b, origin) })
}

// Revoke removes the OriginDirect contribution from the key's row.
func (s *SQLStore) Revoke(ctx context.Context, key BindingKey) error {
	return s.RevokeFrom(ctx, key, OriginDirect)
}

// RevokeFrom removes one origin. The row goes only when its last origin does,
// so a group revoke cannot take a direct grant with it.
func (s *SQLStore) RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error {
	if err := gate(key.Scope, key.Subject); err != nil {
		return err
	}
	return s.Apply(ctx, func(tx Tx) error { return tx.RevokeFrom(ctx, key, origin) })
}

// Apply runs fn in one transaction: commit on nil, rollback on any error.
func (s *SQLStore) Apply(ctx context.Context, fn func(tx Tx) error) error {
	dbtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("tenanthierarchy: begin: %w", err)
	}
	if err := fn(&sqlTx{tx: dbtx}); err != nil {
		_ = dbtx.Rollback()
		return err
	}
	if err := dbtx.Commit(); err != nil {
		return fmt.Errorf("tenanthierarchy: commit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------

// BindingsFor implements authz.BindingStore.
func (s *SQLStore) BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return queryBindings(ctx, s.db, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND subject_tenant = ? AND subject_type = ?
		  AND subject_id = ? AND resource_type = ? AND resource_id = ?
		ORDER BY role`,
		scope.String(), sub.Tenant.String(), sub.Type, sub.ID, res.Type, res.ID)
}

// BindingsForSubject implements authz.BindingStore (concrete resources only).
func (s *SQLStore) BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return queryBindings(ctx, s.db, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND subject_tenant = ? AND subject_type = ?
		  AND subject_id = ? AND resource_type = ? AND resource_id <> ''
		ORDER BY resource_id, role`,
		scope.String(), sub.Tenant.String(), sub.Type, sub.ID, resourceType)
}

// BindingsOnResource implements authz.BindingStore.
func (s *SQLStore) BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return queryBindings(ctx, s.db, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND resource_type = ? AND resource_id = ?
		ORDER BY subject_type, subject_id, role`,
		scope.String(), res.Type, res.ID)
}

// BindingsFrom returns the bindings in scope carrying origin.
func (s *SQLStore) BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return queryBindings(ctx, s.db, `
		SELECT `+bindingCols+` FROM authz_binding b
		WHERE b.tenant_scope = ? AND EXISTS (
			SELECT 1 FROM authz_binding_origin o
			WHERE o.tenant_scope = b.tenant_scope AND o.subject_tenant = b.subject_tenant
			  AND o.subject_type = b.subject_type AND o.subject_id = b.subject_id
			  AND o.resource_type = b.resource_type AND o.resource_id = b.resource_id
			  AND o.role = b.role AND o.origin = ?)
		ORDER BY subject_type, subject_id, role`,
		scope.String(), string(origin))
}

// IntentGroups lists every tenant-group holding an intent row.
func (s *SQLStore) IntentGroups(ctx context.Context) ([]tenant.ID, error) {
	return s.groupQuery(ctx, `
		SELECT DISTINCT b.tenant_scope FROM authz_binding b
		WHERE b.resource_type = ? AND EXISTS (
			SELECT 1 FROM authz_binding_origin o
			WHERE o.tenant_scope = b.tenant_scope AND o.subject_tenant = b.subject_tenant
			  AND o.subject_type = b.subject_type AND o.subject_id = b.subject_id
			  AND o.resource_type = b.resource_type AND o.resource_id = b.resource_id
			  AND o.role = b.role AND o.origin = ? || b.tenant_scope)
		ORDER BY b.tenant_scope`, ResourceTenantGroup, groupOriginPrefix)
}

// GroupOrigins lists every tenant-group some row's origin names, so a group
// whose intent row was lost is still reconciled.
func (s *SQLStore) GroupOrigins(ctx context.Context) ([]tenant.ID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT origin FROM authz_binding_origin WHERE origin LIKE ? ORDER BY origin`,
		groupOriginPrefix+"%")
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: query origins: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[tenant.ID]bool)
	var out []tenant.ID
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, fmt.Errorf("tenanthierarchy: scan origin: %w", err)
		}
		g, ok := groupOfOrigin(Origin(o))
		if !ok || !g.Valid() || g.IsSingle() || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenanthierarchy: iterate origins: %w", err)
	}
	return out, nil
}

// IntentGroupsForSubject lists the groups in which the subject holds an intent
// row. It is the read derived membership needs for MembershipsFor.
func (s *SQLStore) IntentGroupsForSubject(ctx context.Context, subjectType, userID string) ([]tenant.ID, error) {
	if userID == "" {
		return nil, nil
	}
	return s.groupQuery(ctx, `
		SELECT DISTINCT b.tenant_scope FROM authz_binding b
		WHERE b.subject_type = ? AND b.subject_id = ? AND b.resource_type = ? AND EXISTS (
			SELECT 1 FROM authz_binding_origin o
			WHERE o.tenant_scope = b.tenant_scope AND o.subject_tenant = b.subject_tenant
			  AND o.subject_type = b.subject_type AND o.subject_id = b.subject_id
			  AND o.resource_type = b.resource_type AND o.resource_id = b.resource_id
			  AND o.role = b.role AND o.origin = ? || b.tenant_scope)
		ORDER BY b.tenant_scope`, subjectType, userID, ResourceTenantGroup, groupOriginPrefix)
}

func (s *SQLStore) groupQuery(ctx context.Context, query string, args ...any) ([]tenant.ID, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: query groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []tenant.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("tenanthierarchy: scan group: %w", err)
		}
		out = append(out, tenant.FromStored(id))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenanthierarchy: iterate groups: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// The transaction view
// ---------------------------------------------------------------------

// sqlTx is the Tx an Apply callback works against: same writes and reads as the
// in-memory tx, all inside one database transaction. Reads see the
// transaction's own writes, which is what makes reconcile-then-repair atomic.
type sqlTx struct {
	tx *sql.Tx
}

func (t *sqlTx) Grant(ctx context.Context, b authz.Binding) error {
	return t.GrantFrom(ctx, b, OriginDirect)
}

func (t *sqlTx) GrantFrom(ctx context.Context, b authz.Binding, origin Origin) error {
	if err := gate(b.Tenant, b.Subject); err != nil {
		return err
	}
	const q = `INSERT INTO authz_binding
		(tenant_scope, subject_tenant, subject_type, subject_id, resource_type, resource_id, role)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`
	if _, err := t.tx.ExecContext(ctx, q,
		b.Tenant.String(), b.Subject.Tenant.String(), b.Subject.Type, b.Subject.ID,
		b.Resource.Type, b.Resource.ID, string(b.Role)); err != nil {
		return fmt.Errorf("tenanthierarchy: insert binding: %w", err)
	}
	const qo = `INSERT INTO authz_binding_origin
		(tenant_scope, subject_tenant, subject_type, subject_id, resource_type, resource_id, role, origin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`
	if _, err := t.tx.ExecContext(ctx, qo,
		b.Tenant.String(), b.Subject.Tenant.String(), b.Subject.Type, b.Subject.ID,
		b.Resource.Type, b.Resource.ID, string(b.Role), string(origin)); err != nil {
		return fmt.Errorf("tenanthierarchy: insert origin: %w", err)
	}
	return nil
}

func (t *sqlTx) Revoke(ctx context.Context, key BindingKey) error {
	return t.RevokeFrom(ctx, key, OriginDirect)
}

func (t *sqlTx) RevokeFrom(ctx context.Context, key BindingKey, origin Origin) error {
	if err := gate(key.Scope, key.Subject); err != nil {
		return err
	}
	const where = `tenant_scope = ? AND subject_tenant = ? AND subject_type = ?
	               AND subject_id = ? AND resource_type = ? AND resource_id = ? AND role = ?`
	args := []any{key.Scope.String(), key.Subject.Tenant.String(), key.Subject.Type,
		key.Subject.ID, key.Res.Type, key.Res.ID, string(key.Role)}

	if _, err := t.tx.ExecContext(ctx,
		`DELETE FROM authz_binding_origin WHERE `+where+` AND origin = ?`,
		append(args, string(origin))...); err != nil {
		return fmt.Errorf("tenanthierarchy: delete origin: %w", err)
	}
	// The row survives while any other origin still justifies it. The
	// subquery correlates on the outer row by table name, so it asks about
	// THIS key rather than re-comparing the parameters.
	if _, err := t.tx.ExecContext(ctx,
		`DELETE FROM authz_binding WHERE `+where+` AND NOT EXISTS (
			SELECT 1 FROM authz_binding_origin o
			WHERE o.tenant_scope = authz_binding.tenant_scope
			  AND o.subject_tenant = authz_binding.subject_tenant
			  AND o.subject_type = authz_binding.subject_type
			  AND o.subject_id = authz_binding.subject_id
			  AND o.resource_type = authz_binding.resource_type
			  AND o.resource_id = authz_binding.resource_id
			  AND o.role = authz_binding.role)`,
		args...); err != nil {
		return fmt.Errorf("tenanthierarchy: delete binding: %w", err)
	}
	return nil
}

func (t *sqlTx) BindingsFor(ctx context.Context, scope tenant.ID, sub authz.Subject, res authz.Resource) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return queryBindings(ctx, t.tx, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND subject_tenant = ? AND subject_type = ?
		  AND subject_id = ? AND resource_type = ? AND resource_id = ?
		ORDER BY role`,
		scope.String(), sub.Tenant.String(), sub.Type, sub.ID, res.Type, res.ID)
}

func (t *sqlTx) BindingsForSubject(ctx context.Context, scope tenant.ID, sub authz.Subject, resourceType string) ([]authz.Binding, error) {
	if err := gate(scope, sub); err != nil {
		return nil, err
	}
	return queryBindings(ctx, t.tx, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND subject_tenant = ? AND subject_type = ?
		  AND subject_id = ? AND resource_type = ? AND resource_id <> ''
		ORDER BY resource_id, role`,
		scope.String(), sub.Tenant.String(), sub.Type, sub.ID, resourceType)
}

func (t *sqlTx) BindingsOnResource(ctx context.Context, scope tenant.ID, res authz.Resource) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return queryBindings(ctx, t.tx, `
		SELECT `+bindingCols+` FROM authz_binding
		WHERE tenant_scope = ? AND resource_type = ? AND resource_id = ?
		ORDER BY subject_type, subject_id, role`,
		scope.String(), res.Type, res.ID)
}

func (t *sqlTx) BindingsFrom(ctx context.Context, scope tenant.ID, origin Origin) ([]authz.Binding, error) {
	if err := scopeGate(scope); err != nil {
		return nil, err
	}
	return queryBindings(ctx, t.tx, `
		SELECT `+bindingCols+` FROM authz_binding b
		WHERE b.tenant_scope = ? AND EXISTS (
			SELECT 1 FROM authz_binding_origin o
			WHERE o.tenant_scope = b.tenant_scope AND o.subject_tenant = b.subject_tenant
			  AND o.subject_type = b.subject_type AND o.subject_id = b.subject_id
			  AND o.resource_type = b.resource_type AND o.resource_id = b.resource_id
			  AND o.role = b.role AND o.origin = ?)
		ORDER BY subject_type, subject_id, role`,
		scope.String(), string(origin))
}

// querier is what both *sql.DB and *sql.Tx satisfy.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryBindings(ctx context.Context, q querier, query string, args ...any) ([]authz.Binding, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenanthierarchy: query bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []authz.Binding
	for rows.Next() {
		var (
			scope, subHome, subType, subID, resType, resID, role string
		)
		if err := rows.Scan(&scope, &subHome, &subType, &subID, &resType, &resID, &role); err != nil {
			return nil, fmt.Errorf("tenanthierarchy: scan binding: %w", err)
		}
		out = append(out, authz.Binding{
			Tenant:   tenant.FromStored(scope),
			Subject:  authz.Subject{Tenant: tenant.FromStored(subHome), Type: subType, ID: subID},
			Resource: authz.Resource{Type: resType, ID: resID},
			Role:     authz.Role(role),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenanthierarchy: iterate bindings: %w", err)
	}
	return out, nil
}
