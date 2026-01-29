package authgate

import "time"

const (
	// AccessCookieName is the name of the cookie that stores the AuthGate
	// access token (JWT).
	//
	// This cookie is read by the SDK to authenticate incoming requests.
	AccessCookieName = "authgate_access"

	// LoginPath is the path to the AuthGate login endpoint.
	//
	// Unauthenticated users are redirected to this path, with an optional
	// return_to query parameter appended.
	LoginPath = "/auth/login"

	// clockSkew defines the allowed clock skew when validating JWT timestamps.
	//
	// This accounts for small differences between the AuthGate server's clock
	// and the application server's clock.
	clockSkew = 2 * time.Minute

	// CSRFCookieName is the name of the cookie that stores the CSRF token.
	//
	// The CSRF token is issued by AuthGate and used for CSRF protection via
	// the double-submit cookie pattern.
	CSRFCookieName = "authgate_csrf"

	// CSRFHeaderName is the HTTP header used to forward the CSRF token in
	// state-changing requests (e.g. POST, PUT, DELETE).
	CSRFHeaderName = "X-CSRF-Token"

	// CSRFFormField is the name of the hidden form field used to submit the
	// CSRF token in server-rendered (SSR) applications.
	CSRFFormField = "csrf_token"
)
