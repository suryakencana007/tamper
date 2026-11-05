package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/suryakencana007/tamper/tenant"
)

// Phase 15 slice 15b (TD-11): Filter.TenantID and Filter.ActorTenantID.
//
// The two fields answer different questions — the row's SCOPE and the ACTOR's
// tenant — and the zero value means "no filter", never "the single tenant".

var (
	acmeT   = tenant.New("acme")
	globexT = tenant.New("globex")
	// platformT is a tenant whose staff act INSIDE other tenants.
	platformT = tenant.New("platform")
)

// seedTenants writes two rows per tenant plus one single-tenant row, so every
// filter below has something it must return and something it must not.
func seedTenants(t *testing.T, l Logger) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	rows := []struct {
		id       string
		scope    string
		actorTid string
		offset   int
	}{
		{"acme-1", "acme", "acme", 0},
		{"acme-2", "acme", "acme", 1},
		{"globex-1", "globex", "globex", 2},
		// A platform admin acting inside acme: scope acme, actor tenant platform.
		{"cross-1", "acme", "platform", 3},
		// The single-tenant deployment's own row: empty scope.
		{"single-1", "", "", 4},
	}
	for _, r := range rows {
		ev := makeEvent(r.id, base.Add(time.Duration(r.offset)*time.Second), "project.create")
		ev.TenantID = r.scope
		ev.Actor.TenantID = r.actorTid
		if _, err := l.Log(ctx, ev); err != nil {
			t.Fatalf("Log %s: %v", r.id, err)
		}
	}
}

func idsOf(p Page) []string {
	out := make([]string, 0, len(p.Events))
	for _, e := range p.Events {
		out = append(out, e.ID)
	}
	return out
}

func mustList(t *testing.T, l Logger, f Filter) []string {
	t.Helper()
	p, err := l.List(context.Background(), f)
	if err != nil {
		t.Fatalf("List(%+v): %v", f, err)
	}
	return idsOf(p)
}

// queryPlanWith is queryPlan plus an extra raw WHERE fragment, for the cursor shape.
func queryPlanWith(t *testing.T, l *SQLiteLogger, f Filter, extra string) string {
	t.Helper()
	where, args, err := filterWhere(f)
	if err != nil {
		t.Fatalf("filterWhere: %v", err)
	}
	where = append(where, extra)
	q := "EXPLAIN QUERY PLAN SELECT " + eventColumns + " FROM events WHERE " + strings.Join(where, " AND ") +
		" ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, int64(50))

	rows, err := l.store.DB.QueryContext(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		b.WriteString(detail)
		b.WriteString("\n")
	}
	return b.String()
}

func TestList_TenantIDReturnsOnlyThatTenantsRows(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	got := mustList(t, l, Filter{TenantID: acmeT})
	for _, id := range got {
		if strings.HasPrefix(id, "globex") || id == "single-1" {
			t.Fatalf("TenantID=acme returned %q — another tenant's row", id)
		}
	}
	if len(got) != 3 { // acme-1, acme-2, cross-1
		t.Fatalf("rows = %v, want the three scoped to acme", got)
	}
}

func TestList_TenantIDNeverSeesAnotherTenantEvenWhenOtherFiltersMatch(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	// globex-1 shares the action, resource type and actor user with everything else.
	got := mustList(t, l, Filter{TenantID: globexT, Action: "project.create"})
	if len(got) != 1 || got[0] != "globex-1" {
		t.Fatalf("rows = %v, want exactly [globex-1]", got)
	}
}

func TestList_TenantSingleSelectsTheEmptyScopeAndNotEverything(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	got := mustList(t, l, Filter{TenantID: tenant.Single})
	if len(got) != 1 || got[0] != "single-1" {
		t.Fatalf("rows = %v, want only the \"\"-scoped row — Single is not a wildcard", got)
	}
}

func TestList_ZeroTenantFilterReturnsEveryRow(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	if got := mustList(t, l, Filter{}); len(got) != 5 {
		t.Fatalf("rows = %v, want all five: zero means no filter", got)
	}
}

// The pair that motivates the second field: the SCOPE filter cannot find an
// admin's cross-tenant activity, and the ACTOR filter is what does.
func TestList_ActorTenantIDSeparatesActorFromScope(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	byScope := mustList(t, l, Filter{TenantID: platformT})
	if len(byScope) != 0 {
		t.Fatalf("TenantID=platform returned %v; platform has no scoped rows", byScope)
	}

	byActor := mustList(t, l, Filter{ActorTenantID: platformT})
	if len(byActor) != 1 || byActor[0] != "cross-1" {
		t.Fatalf("ActorTenantID=platform returned %v, want [cross-1] — what platform staff "+
			"did inside a customer tenant", byActor)
	}

	// And both together narrow rather than widen.
	both := mustList(t, l, Filter{TenantID: acmeT, ActorTenantID: platformT})
	if len(both) != 1 || both[0] != "cross-1" {
		t.Fatalf("both filters returned %v, want [cross-1]", both)
	}
}

func TestList_ActorTenantSingle(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	got := mustList(t, l, Filter{ActorTenantID: tenant.Single})
	if len(got) != 1 || got[0] != "single-1" {
		t.Fatalf("rows = %v, want only the row whose actor has no tenant", got)
	}
}

// The filter must survive paging: page 2 keeps narrowing to the same tenant.
func TestList_TenantFilterComposesWithCursor(t *testing.T) {
	l := newSQLiteLoggerForTest(t)

	// A foreign row OLDER than every acme row, so page 2 would reach it if the
	// filter were dropped once a cursor is present. It is logged FIRST: the chain
	// bumps an out-of-order At forward to preserve its own order, so writing it
	// later would make it the newest row instead of the oldest.
	old := makeEvent("globex-old", time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC), "project.create")
	old.TenantID = "globex"
	old.Actor.TenantID = "globex"
	if _, err := l.Log(context.Background(), old); err != nil {
		t.Fatalf("Log globex-old: %v", err)
	}
	seedTenants(t, l)

	first, err := l.List(context.Background(), Filter{TenantID: acmeT, Limit: 2})
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	if len(first.Events) != 2 {
		t.Fatalf("page 1 = %d rows, want 2", len(first.Events))
	}
	if first.NextCursor == "" {
		t.Fatal("no cursor after a full page")
	}
	second, err := l.List(context.Background(), Filter{TenantID: acmeT, Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	for _, id := range idsOf(second) {
		if strings.HasPrefix(id, "globex") || id == "single-1" {
			t.Fatalf("page 2 escaped the tenant filter with %q", id)
		}
	}
	if len(second.Events) != 1 {
		t.Fatalf("page 2 = %v, want the remaining acme row", idsOf(second))
	}
}

// A degraded plan returns the RIGHT rows, so no result assertion can catch it —
// which is why the plan is asserted directly (sketch §5, finding F1).
func TestListPlan_TenantFilterUsesThePartialIndex(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("logger is %T, want *SQLiteLogger", l)
	}
	seedTenants(t, l)

	plan := queryPlan(t, sl, Filter{TenantID: acmeT})
	if strings.Contains(plan, "SCAN events") {
		t.Fatalf("plan for a tenant filter is a full scan:\n%s\n"+
			"A partial index is only used when the WHERE implies its predicate, so the "+
			"query must carry the redundant AND tenant_id <> '' term.", plan)
	}
	if !strings.Contains(plan, "idx_events_tenant_id") {
		t.Fatalf("plan does not use idx_events_tenant_id:\n%s", plan)
	}
}

func TestListPlan_ActorTenantFilterUsesItsIndex(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("logger is %T, want *SQLiteLogger", l)
	}
	seedTenants(t, l)

	plan := queryPlan(t, sl, Filter{ActorTenantID: platformT})
	if !strings.Contains(plan, "idx_events_actor_tenant_id") {
		t.Fatalf("plan does not use idx_events_actor_tenant_id:\n%s\n"+
			"The console's cross-tenant question must not scan the log.", plan)
	}
}

// queryPlan runs EXPLAIN QUERY PLAN over exactly the WHERE the logger builds.
func queryPlan(t *testing.T, l *SQLiteLogger, f Filter) string {
	t.Helper()
	where, args, err := filterWhere(f)
	if err != nil {
		t.Fatalf("filterWhere: %v", err)
	}
	q := "EXPLAIN QUERY PLAN SELECT " + eventColumns + " FROM events"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, int64(5))

	rows, err := l.store.DB.QueryContext(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var b strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		b.WriteString(detail)
		b.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	return b.String()
}

// The positional bindings must stay aligned when a tenant term is added: a
// shifted argument matches the wrong column and returns wrong rows silently.
func TestList_TenantFilterKeepsBoundArgumentsAligned(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	seedTenants(t, l)

	since := time.Date(2026, 6, 1, 9, 0, 1, 0, time.UTC)
	got := mustList(t, l, Filter{
		TenantID:     acmeT,
		Since:        since,
		Action:       "project.create",
		ResourceType: ResourceProject,
	})
	// acme-2 and cross-1 are at/after `since`; acme-1 is before it.
	if len(got) != 2 {
		t.Fatalf("rows = %v, want [cross-1 acme-2]: every term must bind to its own column", got)
	}
	for _, id := range got {
		if strings.HasPrefix(id, "globex") || id == "single-1" || id == "acme-1" {
			t.Fatalf("rows = %v — a term bound to the wrong column", got)
		}
	}
}

// Phase 15 follow-up, issue #113 option 2: the tenant index is composite
// (tenant_id, at DESC, id DESC), so the page is served in index order — no sort of
// the whole matching set, and the cursor really prunes. Measured: 1844µs -> 13µs on a
// 20k-row tenant, for +13% file size (the single-column index is REPLACED, not joined).
func TestListPlan_TenantFilterIsServedInIndexOrder(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("logger is %T, want *SQLiteLogger", l)
	}
	seedTenants(t, l)

	plan := queryPlan(t, sl, Filter{TenantID: acmeT})
	if strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("plan still sorts:\n%s\n"+
			"The tenant index must be composite (tenant_id, at DESC, id DESC) so the "+
			"page comes out in order and LIMIT stops early.", plan)
	}
	if !strings.Contains(plan, "idx_events_tenant_id") {
		t.Fatalf("plan does not use idx_events_tenant_id:\n%s", plan)
	}
}

func TestListPlan_TenantCursorPrunesWithinTheIndex(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("logger is %T, want *SQLiteLogger", l)
	}
	seedTenants(t, l)

	// A cursor at the oldest seeded row: the plan must use `at<?` inside the index
	// rather than reading the tenant's rows and discarding them.
	// Parenthesised, exactly as filterWhere builds it: without the outer parens the
	// OR binds looser than the AND beside it and the predicate means something else.
	cursor := "(at < '2026-06-01 09:00:02' OR (at = '2026-06-01 09:00:02' AND id < 'x'))"
	plan := queryPlanWith(t, sl, Filter{TenantID: acmeT}, cursor)
	if !strings.Contains(plan, "at<?") && !strings.Contains(plan, "at<") {
		t.Fatalf("cursor does not prune inside the index:\n%s", plan)
	}
	if strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("cursor query still sorts:\n%s", plan)
	}
}

// The composite is PARTIAL over non-empty tenants, so a single-tenant page still
// scans. Recorded as a test so that a future change which fixes it (a non-partial
// index, issue #113 option 4) has to change this expectation deliberately.
func TestListPlan_TenantSingleStillScans(t *testing.T) {
	l := newSQLiteLoggerForTest(t)
	sl, ok := l.(*SQLiteLogger)
	if !ok {
		t.Fatalf("logger is %T, want *SQLiteLogger", l)
	}
	seedTenants(t, l)

	plan := queryPlan(t, sl, Filter{TenantID: tenant.Single})
	if !strings.Contains(plan, "SCAN events") {
		t.Fatalf("plan changed for tenant.Single:\n%s\n"+
			"If this is now an index search, the partial predicate was dropped: good news, "+
			"and issue #113 option 4 should be closed with this test updated.", plan)
	}
}
