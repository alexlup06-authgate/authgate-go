package authgate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestSDK(t *testing.T) *SDK {
	t.Helper()

	sdk, err := New(Config{
		Issuer:   "https://auth.example.com",
		Audience: "app",
		Keys: map[string][]byte{
			"test-kid": []byte("secret"),
		},
	})
	if err != nil {
		t.Fatalf("failed to create sdk: %v", err)
	}

	return sdk
}

func TestRequireAuth_NoCookie_Redirects(t *testing.T) {
	sdk := newTestSDK(t)

	called := false
	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("handler should not have been called")
	}

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, LoginPath) {
		t.Fatalf("expected redirect to start with %q, got %q", LoginPath, loc)
	}
}

func TestRequireAuth_HTMXRedirect(t *testing.T) {
	sdk := newTestSDK(t)

	handler := sdk.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("HX-Request", "true")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if got := rec.Header().Get("HX-Redirect"); got == "" {
		t.Fatal("expected HX-Redirect header to be set")
	}
}

func TestTryAuth_NoCookie_AllowsThrough(t *testing.T) {
	sdk := newTestSDK(t)

	called := false
	handler := sdk.TryAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/optional", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler should have been called")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
