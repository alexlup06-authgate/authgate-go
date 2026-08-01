package authara

import (
	"context"
	"net/http"
	"testing"
)

func TestGeneratedCallRefreshSessionForwardsContractAuth(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != RefreshPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("audience"); got != "admin" {
			t.Fatalf("unexpected audience: %s", got)
		}
		if cookie, err := r.Cookie("authara_refresh"); err != nil || cookie.Value != "refresh-token" {
			t.Fatalf("expected refresh cookie, got %+v, %v", cookie, err)
		}
		if cookie, err := r.Cookie(CSRFCookieName); err != nil || cookie.Value != "csrf-token" {
			t.Fatalf("expected csrf cookie, got %+v, %v", cookie, err)
		}
		if got := r.Header.Get(CSRFHeaderName); got != "csrf-token" {
			t.Fatalf("expected csrf header, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	})

	client, _ := newTestClient(t, handler)
	req := newIncomingRequestWithCookies(
		&http.Cookie{Name: "authara_refresh", Value: "refresh-token"},
		&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"},
	)

	if err := client.CallRefreshSession(context.Background(), req, "admin"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newIncomingRequestWithCookies(cookies ...*http.Cookie) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req
}
