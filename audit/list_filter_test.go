package audit

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// Every Filter field is applied, and the fields are ANDed. These tests
// exist because four of them (Since, Until, ActorEmail, Action) used to
// be declared and never read: a caller asking for "only this action"
// got every row back, with no error.

var filterBase = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// seedFilterRows writes six rows, one minute apart, that differ in every
// filterable field.
//
//	id  minute  actor       action          resource     request  cluster
//	a   0       alice/u-a   auth.login      user/u-a     req-1    -
//	b   1       alice/u-a   project.create  project/p-1  req-2    c-1
//	c   2       bob/u-b     project.create  project/p-2  req-3    c-2
//	d   3       bob/u-b     auth.login      user/u-b     req-4    -
//	e   4       alice/u-a   project.delete  project/p-1  req-5    c-1
//	f   5       bob/u-b     project.create  project/p-1  req-5    c-1
func seedFilterRows(t *testing.T) *SQLiteLogger {
	t.Helper()
	l := v4Logger(t)
	rows := []struct {
		id, user, email, action, rtype, rid, req, cluster string
	}{
		{"a", "u-a", "alice@example.com", "auth.login", "user", "u-a", "req-1", ""},
		{"b", "u-a", "alice@example.com", "project.create", "project", "p-1", "req-2", "c-1"},
		{"c", "u-b", "bob@example.com", "project.create", "project", "p-2", "req-3", "c-2"},
		{"d", "u-b", "bob@example.com", "auth.login", "user", "u-b", "req-4", ""},
		{"e", "u-a", "alice@example.com", "project.delete", "project", "p-1", "req-5", "c-1"},
		{"f", "u-b", "bob@example.com", "project.create", "project", "p-1", "req-5", "c-1"},
	}
	for i, r := range rows {
		if _, err := l.Log(context.Background(), Event{
			ID:           r.id,
			At:           filterBase.Add(time.Duration(i) * time.Minute),
			Actor:        Actor{Type: ActorTypeUser, UserID: r.user, Email: r.email},
			Action:       Action(r.action),
			ResourceType: ResourceType(r.rtype),
			ResourceID:   r.rid,
			RequestID:    r.req,
			ClusterID:    r.cluster,
		}); err != nil {
			t.Fatalf("Log %s: %v", r.id, err)
		}
	}
	return l
}

// ids returns the event ids of a page, sorted, as one string.
func ids(p Page) string {
	out := make([]string, 0, len(p.Events))
	for _, e := range p.Events {
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return strings.Join(out, "")
}

func TestList_AppliesEveryFilterField(t *testing.T) {
	ctx := context.Background()
	l := seedFilterRows(t)
	at := func(minute int) time.Time { return filterBase.Add(time.Duration(minute) * time.Minute) }

	for _, tc := range []struct {
		name string
		f    Filter
		want string
	}{
		{"no filter", Filter{}, "abcdef"},
		{"action", Filter{Action: "project.create"}, "bcf"},
		{"actor email", Filter{ActorEmail: "alice@example.com"}, "abe"},
		{"actor user id", Filter{ActorUserID: "u-b"}, "cdf"},
		{"resource type alone", Filter{ResourceType: "project"}, "bcef"},
		{"resource type and id", Filter{ResourceType: "project", ResourceID: "p-1"}, "bef"},
		{"resource id alone", Filter{ResourceID: "p-1"}, "bef"},
		{"request id", Filter{RequestID: "req-5"}, "ef"},
		// Since is inclusive, Until is exclusive.
		{"since", Filter{Since: at(3)}, "def"},
		{"until", Filter{Until: at(2)}, "ab"},
		{"since and until", Filter{Since: at(1), Until: at(4)}, "bcd"},
		{"empty window", Filter{Since: at(2), Until: at(2)}, ""},
		// Fields are ANDed, in any combination.
		{"action and actor", Filter{Action: "project.create", ActorUserID: "u-b"}, "cf"},
		{"action and email", Filter{Action: "auth.login", ActorEmail: "alice@example.com"}, "a"},
		{"request and action", Filter{RequestID: "req-5", Action: "project.delete"}, "e"},
		{"resource, actor and window", Filter{ResourceType: "project", ResourceID: "p-1", ActorUserID: "u-a", Since: at(2)}, "e"},
		{"contradiction", Filter{Action: "auth.login", ResourceType: "project"}, ""},
		{"unknown action", Filter{Action: "no.such.action"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := l.List(ctx, tc.f)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if got := ids(page); got != tc.want {
				t.Errorf("List(%+v) returned %q, want %q", tc.f, got, tc.want)
			}
		})
	}
}

// Newest first, whatever the filter.
func TestList_FilteredResultsAreNewestFirst(t *testing.T) {
	page, err := seedFilterRows(t).List(context.Background(), Filter{Action: "project.create"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, e := range page.Events {
		got = append(got, e.ID)
	}
	if strings.Join(got, "") != "fcb" {
		t.Errorf("order = %v, want f, c, b (newest first)", got)
	}
}

// The cursor pages WITHIN the filter: every matching row once, and no
// row that does not match.
func TestList_CursorPagesWithinTheFilter(t *testing.T) {
	ctx := context.Background()
	l := seedFilterRows(t)
	f := Filter{ResourceType: "project", Limit: 2}

	var seen []string
	for page := 0; page < 5; page++ {
		p, err := l.List(ctx, f)
		if err != nil {
			t.Fatalf("List page %d: %v", page, err)
		}
		for _, e := range p.Events {
			seen = append(seen, e.ID)
		}
		if p.NextCursor == "" {
			break
		}
		f.Cursor = p.NextCursor
	}
	if got := strings.Join(seen, ""); got != "fecb" {
		t.Errorf("paged through %q, want f, e, c, b — each project row once, newest first", got)
	}
}

// ListScoped applies the same filter on top of its cluster scope.
func TestListScoped_AppliesTheFilter(t *testing.T) {
	ctx := context.Background()
	l := seedFilterRows(t)

	for _, tc := range []struct {
		name     string
		clusters []string
		f        Filter
		want     string
	}{
		{"scope only, one cluster", []string{"c-1"}, Filter{}, "abdef"},
		{"scope only, no clusters", nil, Filter{}, "ad"},
		{"scope and action", []string{"c-1"}, Filter{Action: "project.create"}, "bf"},
		{"scope and email", []string{"c-1", "c-2"}, Filter{ActorEmail: "bob@example.com"}, "cdf"},
		{"no clusters and action", nil, Filter{Action: "auth.login", ActorUserID: "u-b"}, "d"},
		{"scope and window", []string{"c-2"}, Filter{Since: filterBase.Add(2 * time.Minute), Until: filterBase.Add(4 * time.Minute)}, "cd"},
		{"filter cannot widen the scope", []string{"c-2"}, Filter{ResourceID: "p-1"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := l.ListScoped(ctx, tc.clusters, tc.f)
			if err != nil {
				t.Fatalf("ListScoped: %v", err)
			}
			if got := ids(page); got != tc.want {
				t.Errorf("ListScoped(%v, %+v) returned %q, want %q", tc.clusters, tc.f, got, tc.want)
			}
		})
	}
}

// A filter value is data, never SQL.
func TestList_FilterValuesAreBound(t *testing.T) {
	ctx := context.Background()
	l := seedFilterRows(t)

	page, err := l.List(ctx, Filter{Action: Action("x' OR '1'='1")})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Events) != 0 {
		t.Fatalf("a quote in a filter value matched %d rows; the value reached the SQL text", len(page.Events))
	}
	if all, err := l.List(ctx, Filter{}); err != nil || len(all.Events) != 6 {
		t.Fatalf("the table changed: %d rows, err=%v", len(all.Events), err)
	}
}

// A malformed cursor is an error, not an unfiltered first page.
func TestList_BadCursorIsAnError(t *testing.T) {
	if _, err := seedFilterRows(t).List(context.Background(), Filter{Cursor: "not-a-cursor"}); err == nil {
		t.Fatal("List accepted a malformed cursor")
	}
}
