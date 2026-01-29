package authgate

import "net/http"

type LogoutFormData struct {
	Action    string
	Method    string
	CSRFName  string
	CSRFValue string
}

func LogoutFormDataFromRequest(r *http.Request) (LogoutFormData, bool) {
	token, ok := CSRFToken(r)
	if !ok {
		return LogoutFormData{}, false
	}

	return LogoutFormData{
		Action:    "/auth/logout",
		Method:    http.MethodPost,
		CSRFName:  CSRFFormField,
		CSRFValue: token,
	}, true
}

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
