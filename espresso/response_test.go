package espresso

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirect_WriteResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	r := Redirect{
		URL: "https://idp.example/authorize?x=1",
		Cookies: []*http.Cookie{
			{Name: "app_state", Value: "s1", Path: "/api/auth", HttpOnly: true},
			nil, // nil entries are skipped
		},
	}
	if err := r.WriteResponse(rec); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://idp.example/authorize?x=1" {
		t.Fatalf("Location = %q", got)
	}
	if sc := rec.Result().Cookies(); len(sc) != 1 || sc[0].Name != "app_state" || sc[0].Value != "s1" {
		t.Fatalf("Set-Cookie = %+v, want one app_state cookie", sc)
	}
}

func TestXML_WriteResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := (XML{Body: []byte("<md/>")}).WriteResponse(rec); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("default Content-Type = %q", ct)
	}
	if rec.Body.String() != "<md/>" {
		t.Fatalf("body = %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	_ = (XML{Body: []byte("<x/>"), ContentType: "application/xml"}).WriteResponse(rec)
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
		t.Fatalf("explicit Content-Type = %q", ct)
	}
}

func TestStepUpSatisfied(t *testing.T) {
	const silver = "urn:mace:incommon:iap:silver"
	cases := []struct {
		name          string
		maxAge        int64
		acrs          []string
		deliveredTime int64
		deliveredACR  string
		now           int64
		want          bool
	}{
		{"nothing requested", 0, nil, 100, silver, 200, false},
		{"maxage fresh", 300, nil, 100, "", 200, true},
		{"maxage stale", 300, nil, 100, "", 500, false},
		{"maxage but no delivered auth_time", 300, nil, 0, "", 200, false},
		{"maxage negative age ok", 300, nil, 250, "", 200, true},
		{"acr matched", 0, []string{silver}, 100, silver, 200, true},
		{"acr unmatched", 0, []string{silver}, 100, "weak", 200, false},
		{"acr one-of matched", 0, []string{"a", silver, "b"}, 100, silver, 200, true},
		{"both satisfied", 300, []string{silver}, 100, silver, 200, true},
		{"maxage ok but acr wrong", 300, []string{silver}, 100, "weak", 200, false},
		{"acr ok but stale", 300, []string{silver}, 100, silver, 500, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StepUpSatisfied(c.maxAge, c.acrs, c.deliveredTime, c.deliveredACR, c.now); got != c.want {
				t.Errorf("StepUpSatisfied = %v, want %v", got, c.want)
			}
		})
	}
}
