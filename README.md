# AuthGate Go SDK

A minimal Go SDK for integrating backend applications with an **AuthGate**
authentication server.

This SDK is intentionally small and infrastructure-focused. Its sole
responsibility is to **verify AuthGate-issued access tokens** and expose
authentication facts to your application in a safe, explicit way.

It does not perform authentication itself and does not own session or security
policy.

---

## What this SDK does

- Verifies AuthGate-issued access tokens (JWT)
- Validates token properties:
  - issuer (`iss`)
  - audience (`aud`)
  - expiry (`exp`)
  - signature and key ID (`kid`)
- Injects authentication facts into `context.Context`
- Provides HTTP middleware for common auth patterns
- Exposes CSRF forwarding helpers for browser-based flows

---

## What this SDK does NOT do

- Does **not** authenticate users
- Does **not** manage sessions
- Does **not** refresh tokens
- Does **not** set, clear, or modify cookies
- Does **not** validate CSRF tokens
- Does **not** make network calls to AuthGate

All security enforcement, session management, CSRF validation, and refresh logic
live exclusively in **AuthGate itself**, not in this SDK.

---

## Installation

```bash
go get github.com/alexlup06-authgate/authgate-go
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
	// handle configuration error
}
```

All fields are required:

- `Issuer` must exactly match the issuer configured in AuthGate
- `Audience` must match the intended token audience
- `Keys` maps JWT `kid` values to their signing secrets

Multiple keys may be provided to support key rotation.

---

## HTTP middleware

### Require authentication

```go
r.Use(sdk.RequireAuth)
```

`RequireAuth` enforces authentication and behaves differently depending on the
request type:

- **Browser navigations (`Accept: text/html`)**  
  Redirects to `/auth/login` with a `return_to` parameter

- **HTMX requests (`HX-Request: true`)**  
  Responds with `HX-Redirect` to trigger a full navigation

- **API / SPA requests**  
  Responds with `401 Unauthorized` (no redirect)

On success, authentication facts are injected into the request context.

---

### Optional authentication

```go
r.Use(sdk.TryAuth)
```

`TryAuth` attempts to authenticate the request if a valid access token is
present, but **never blocks or redirects**.

- If authenticated - user facts are attached to the context
- If unauthenticated - the request proceeds unchanged

This is useful for optional personalization.

---

## Reading authentication facts

```go
userID, ok := authgate.UserIDFromContext(r.Context())
roles, _ := authgate.RolesFromContext(r.Context())
```

The SDK exposes **facts only**:

- user identity
- session-derived roles

Your application decides what these facts mean and how to enforce authorization.

---

## CSRF helpers

```go
token, ok := authgate.CSRFToken(r)
if ok {
	authgate.AttachCSRF(req, token)
}
```

These helpers:

- read the AuthGate-issued CSRF token from the incoming request
- attach it to outgoing requests when needed

CSRF token generation and validation are fully owned by AuthGate.

---

## Compatibility

- Compatible with AuthGate v1.x
- Safe for SSR, HTMX, and API-based applications
- Public APIs follow semantic versioning

---

## License

MIT
