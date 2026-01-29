package authgate

import (
	"net/http"
	"net/url"
)

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

func buildReturnTo(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}
