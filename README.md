# AuthGate Go SDK

A minimal Go SDK for integrating applications with an AuthGate server.

This SDK is intentionally small. It exists to verify AuthGate-issued access
tokens and expose authentication facts to your application.

---

## What this SDK does

- Verifies AuthGate access tokens (JWT)
- Validates:
  - issuer
  - audience
  - expiry
  - signature
- Injects authentication facts into `context.Context`
- Provides optional HTTP middleware
- Exposes CSRF forwarding helpers

---

## What this SDK does NOT do

- Does NOT authenticate users
- Does NOT manage sessions
- Does NOT refresh tokens
- Does NOT set or clear cookies
- Does NOT enforce authorization or roles
- Does NOT validate CSRF tokens

All security enforcement lives in **AuthGate**, not in this SDK.

---

## Installation

```bash
go get github.com/alexlup06/authgate-go
```

---

## Configuration

```go
sdk, err := authgate.New(authgate.Config{
	Issuer:   "https://example.com/auth",
	Audience: "app",
	Keys: map[string][]byte{
		"key-id": []byte("secret"),
	},
})
if err != nil {
	// handle error
}
```

All fields are required.

---

## HTTP Middleware

### Require authentication

```go
r.Use(sdk.RequireAuth)
```

Unauthenticated users are redirected to `/auth/login`.

### Optional authentication

```go
r.Use(sdk.TryAuth)
```

Attaches user context if present, otherwise continues.

---

## Reading authentication data

```go
userID, ok := authgate.UserIDFromContext(r.Context())
roles, _ := authgate.RolesFromContext(r.Context())
```

The SDK exposes **facts only**.  
Your application decides what roles mean.

---

## CSRF helpers

```go
token, ok := authgate.CSRFToken(r)
if ok {
	authgate.AttachCSRF(req, token)
}
```

CSRF creation and validation are handled by AuthGate.

---

## Compatibility

This SDK is compatible with AuthGate v1.x.

Public APIs follow semantic versioning.
