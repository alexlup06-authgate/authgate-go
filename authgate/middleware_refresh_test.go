package authgate

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestSDKWithRefresh(t *testing.T, authGateBaseURL string, hc *http.Client) (*SDK, map[string][]byte) {
	t.Helper()

	key := []byte("super-secret")
	keys := map[string][]byte{"test-kid": key}

	sdk, err := New(Config{
		Issuer:   "https://auth.example.com",
		Audience: "app",
		Keys:     keys,
	})
	if err != nil {
		t.Fatalf("failed to create sdk: %v", err)
	}

	sdk.authGateBaseURL = strings.TrimRight(authGateBaseURL, "/")
	if hc != nil {
		sdk.httpClient = hc
	} else {
		sdk.httpClient = http.DefaultClient
	}

	return sdk, keys
}

func signAccessToken(t *testing.T, keys map[string][]byte, userID uuid.UUID, roles []string, expiresIn time.Duration) string {
	t.Helper()

	now := time.Now()

	claims := accessClaims{
		SessionID: "session-123",
		Roles:     roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  []string{"app"},
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "test-kid"

	s, err := token.SignedString(keys["test-kid"])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return s
}

/* -------------------- RequireAuthWithRefresh -------------------- */

func TestRequireAuthWithRefresh_ValidAccessCookie_SkipsRefresh(t *testing.T) {
	refreshHit := false
	authGate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshHit = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(authGate.Close)

	sdk, keys := newTestSDKWithRefresh(t, authGate.URL, authGate.Client())

	userID := uuid.New()
	access := signAccessToken(t, keys, userID, []string{"authgate:user"}, time.Hour)

	called := false
	h := sdk.RequireAuthWithRefresh(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		gotID, ok := UserIDFromContext(r.Context())
		if !ok || gotID != userID {
			t.Fatalf("expected userID %v, got %v (ok=%v)", userID, gotID, ok)
		}

		gotRoles, ok := RolesFromContext(r.Context())
		if !ok || len(gotRoles) != 1 || gotRoles[0] != "authgate:user" {
			t.Fatalf("unexpected roles: %v (ok=%v)", gotRoles, ok)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: access})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler should have been called")
	}
	if refreshHit {
		t.Fatal("refresh endpoint should not have been called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireAuthWithRefresh_MissingAccess_RefreshOK_ForwardsSetCookie_AuthenticatesRequest(t *testing.T) {
	userID := uuid.New()

	var gotCookieHeader string
	var gotCSRFHeader string

	authGate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic contract checks
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != RefreshPath {
			t.Fatalf("expected path %q, got %q", RefreshPath, r.URL.Path)
		}
		if got := r.URL.Query().Get("audience"); got != "app" {
			t.Fatalf("expected audience=app, got %q", got)
		}

		gotCookieHeader = r.Header.Get("Cookie")
		gotCSRFHeader = r.Header.Get(CSRFHeaderName)

		// Issue new cookies
		// (Access token must be valid per sdk verifier to allow THIS request through.)
		// We'll sign with the same test key used in SDK.
		// Note: the SDK reads AccessCookieName from resp.Cookies(), so this must parse.
		access := signAccessToken(t, map[string][]byte{"test-kid": []byte("super-secret")}, userID, []string{"authgate:user"}, time.Hour)

		http.SetCookie(w, &http.Cookie{
			Name:     AccessCookieName,
			Value:    access,
			Path:     "/",
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "authgate_refresh",
			Value:    "rotated-refresh",
			Path:     "/",
			HttpOnly: true,
		})

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authGate.Close)

	sdk, _ := newTestSDKWithRefresh(t, authGate.URL, authGate.Client())

	called := false
	h := sdk.RequireAuthWithRefresh(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		gotID, ok := UserIDFromContext(r.Context())
		if !ok || gotID != userID {
			t.Fatalf("expected userID %v, got %v (ok=%v)", userID, gotID, ok)
		}

		gotRoles, ok := RolesFromContext(r.Context())
		if !ok || len(gotRoles) != 1 || gotRoles[0] != "authgate:user" {
			t.Fatalf("unexpected roles: %v (ok=%v)", gotRoles, ok)
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/protected?action=save", nil)
	req.Header.Set("Accept", "text/html")

	// Incoming cookies: refresh + csrf (and no access)
	req.AddCookie(&http.Cookie{Name: "authgate_refresh", Value: "rt1", Path: "/"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf123", Path: "/"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler should have been called after successful refresh")
	}

	// Ensure cookies were forwarded to AuthGate refresh call
	if !strings.Contains(gotCookieHeader, "authgate_refresh=rt1") {
		t.Fatalf("expected refresh cookie forwarded, got Cookie=%q", gotCookieHeader)
	}

	// Ensure CSRF header was forwarded
	if gotCSRFHeader != "csrf123" {
		t.Fatalf("expected CSRF header %q, got %q", "csrf123", gotCSRFHeader)
	}

	// Ensure Set-Cookie headers from refresh response are forwarded to client response
	setCookies := rec.Result().Header.Values("Set-Cookie")
	if len(setCookies) < 2 {
		t.Fatalf("expected at least 2 Set-Cookie headers, got %v", setCookies)
	}

	hasAccess := false
	hasRefresh := false
	for _, sc := range setCookies {
		if strings.HasPrefix(sc, AccessCookieName+"=") {
			hasAccess = true
		}
		if strings.HasPrefix(sc, "authgate_refresh=") {
			hasRefresh = true
		}
	}
	if !hasAccess {
		t.Fatalf("expected access Set-Cookie forwarded, got %v", setCookies)
	}
	if !hasRefresh {
		t.Fatalf("expected refresh Set-Cookie forwarded, got %v", setCookies)
	}
}

func TestRequireAuthWithRefresh_InvalidAccess_RefreshFails_FallsBack_API401(t *testing.T) {
	authGate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate refresh failure (expired/invalid refresh token)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(authGate.Close)

	sdk, _ := newTestSDKWithRefresh(t, authGate.URL, authGate.Client())

	h := sdk.RequireAuthWithRefresh(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when refresh fails")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")

	// Provide an invalid access cookie to force refresh path.
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: "not-a-jwt"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthWithRefresh_RefreshDisabled_FallsBack_BrowserRedirect(t *testing.T) {
	sdk := newTestSDK(t) // refresh disabled because baseURL not configured

	h := sdk.RequireAuthWithRefresh(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected?x=1", nil)
	req.Header.Set("Accept", "text/html")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header to be set")
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	if u.Path != LoginPath {
		t.Fatalf("expected redirect to %q, got %q", LoginPath, u.Path)
	}
	if rt := u.Query().Get("return_to"); rt != "/protected?x=1" {
		t.Fatalf("expected return_to to preserve path+query, got %q", rt)
	}
}
