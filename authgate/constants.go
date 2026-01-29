package authgate

import "time"

const (
	AccessCookieName = "authgate_access"
	LoginPath        = "/auth/login"

	clockSkew = 2 * time.Minute

	CSRFCookieName = "authgate_csrf"
	CSRFHeaderName = "X-CSRF-Token"
	CSRFFormField  = "csrf_token"
)
