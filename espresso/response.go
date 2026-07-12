package espresso

import "net/http"

// Redirect is an IntoResponse that emits a 302 to URL with an
// optional cookie list — the shape federation flows need (state
// cookie set on start, cleared on exchange/ACS) that Espresso v2's
// typed-error path can't express (it carries no Set-Cookie, and there
// is no built-in redirect response type). Filed upstream as an
// Espresso v2.5 request; until it lands this is the canonical shape
// tamper consumers return.
type Redirect struct {
	URL     string
	Cookies []*http.Cookie
}

// WriteResponse implements espresso.IntoResponse: cookies first (so
// they land in the header block before the status line), then the
// Location header, then the 302.
func (r Redirect) WriteResponse(w http.ResponseWriter) error {
	for _, c := range r.Cookies {
		if c == nil {
			continue
		}
		http.SetCookie(w, c)
	}
	w.Header().Set("Location", r.URL)
	w.WriteHeader(http.StatusFound)
	return nil
}

// XML is an IntoResponse that emits an XML body with a caller-chosen
// content type (SP metadata uses application/samlmetadata+xml). The
// zero ContentType defaults to that SAML-metadata MIME so the common
// case needs no field.
type XML struct {
	Body        []byte
	ContentType string
}

// WriteResponse implements espresso.IntoResponse.
func (x XML) WriteResponse(w http.ResponseWriter) error {
	ct := x.ContentType
	if ct == "" {
		ct = "application/samlmetadata+xml"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(x.Body)
	return err
}
