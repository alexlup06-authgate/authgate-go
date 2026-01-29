package authgate

import (
	"net/http"
	"net/url"
)

// RequireAuth returns middleware that enforces authentication.
//
// If no valid access token is present, the request is redirected to the
// AuthGate login page with a return_to parameter pointing back to the
// original request URL.
//
// For HTMX requests (HX-Request: true), the middleware responds with
// status 200 and sets the HX-Redirect header instead of issuing a
// standard HTTP redirect.
//
// On successful authentication, the user's ID and roles are injected
// into the request context before calling the next handler.
func (s *SDK) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(AccessCookieName)
		if err != nil {
			loginURL := LoginPath + "?return_to=" + url.QueryEscape(buildReturnTo(r))

			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", loginURL)
				w.WriteHeader(http.StatusOK)
				return
			}

			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		userID, roles, err := s.verifier.verify(cookie.Value)
		if err != nil {
			loginURL := LoginPath + "?return_to=" + url.QueryEscape(buildReturnTo(r))

			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", loginURL)
				w.WriteHeader(http.StatusOK)
				return
			}

			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		ctx := withUserID(r.Context(), userID)
		ctx = withRoles(ctx, roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TryAuth returns middleware that attempts authentication if an access
// token is present, but does not enforce it.
//
// If a valid access token is found, the user's ID and roles are injected
// into the request context. If no token is present or verification fails,
// the request continues without authentication data.
//
// This middleware never redirects and is suitable for routes where
// authentication is optional.
func (s *SDK) TryAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(AccessCookieName)
		if err == nil {
			userID, roles, err := s.verifier.verify(cookie.Value)
			if err == nil {
				ctx := withUserID(r.Context(), userID)
				ctx = withRoles(ctx, roles)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// buildReturnTo constructs the return_to value for redirects by
// preserving the request path and query string.
//
// This ensures users are redirected back to the exact URL they originally
// requested after authentication.
func buildReturnTo(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}
