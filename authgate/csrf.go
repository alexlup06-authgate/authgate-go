package authgate

import "net/http"

func CSRFToken(req *http.Request) (string, bool) {
	c, err := req.Cookie(CSRFCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func AttachCSRF(req *http.Request, token string) {
	if token == "" {
		return
	}
	req.Header.Set(CSRFHeaderName, token)
}

func CSRFTokenOrPanic(req *http.Request) string {
	token, ok := CSRFToken(req)
	if !ok {
		panic("authgate: CSRF token missing from request")
	}
	return token
}
