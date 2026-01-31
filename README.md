# AuthGate Go SDK

A minimal Go SDK for integrating backend and SSR applications with an **AuthGate**
authentication server.

This SDK is intentionally small and infrastructure-focused. Its primary
responsibility is to **verify AuthGate-issued access tokens** and expose
authentication facts to your application in a safe, explicit way.

It does not perform authentication itself and does not own session or security
policy.

---

## Scope and design philosophy

This SDK is designed to:

- expose **facts**, not policy
- avoid hidden behavior
- avoid implicit network calls
- keep authentication and authorization concerns separate

AuthGate itself remains the single source of truth for authentication,
sessions, refresh logic, CSRF enforcement, and security invariants.

---

## What this SDK does

### Token verification & middleware

- Verifies AuthGate-issued access tokens (JWT)
- Validates token properties:
  - issuer (`iss`)
  - audience (`aud`)
  - expiry (`exp`)
  - signature and key ID (`kid`)
- Injects authentication facts into `context.Context`
- Provides HTTP middleware for common auth patterns
- Exposes helpers for reading authentication facts from context

### Backend client helpers (optional)

- Provides **explicit, side-effect-free HTTP helpers** for calling AuthGate
  endpoints from backend or SSR applications
- Forwards existing authentication context (access cookie) only
- Exposes identity data via dedicated helpers (e.g. `GetCurrentUser`)
- Offers a generic escape-hatch helper for user-defined AuthGate endpoints

These helpers are **strict by design**:
- no token refresh
- no retries
- no cookie mutation
- no redirect behavior

---

## What this SDK does NOT do

- Does **not** authenticate users
- Does **not** manage sessions
- Does **not** refresh tokens
- Does **not** set, clear, or modify cookies
- Does **not** validate CSRF tokens
- Does **not** enforce authorization policy
- Does **not** perform background or implicit network calls

All authentication, session management, refresh logic, and CSRF enforcement live
exclusively in **AuthGate itself**, not in this SDK.

---

## Installation

```bash
go get github.com/alexlupatsiy/authgate-go
```

---

## Configuration (token verification)

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

- If authenticated → user facts are attached to the context
- If unauthenticated → the request proceeds unchanged

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

## Backend client helpers

The SDK provides an optional backend client for calling AuthGate endpoints from
server-side or SSR code.

### Creating a client

```go
client := authgate.NewClient("https://auth.example.com")
```

A custom `http.Client` may be provided if needed:

```go
client := authgate.NewClient(
	"https://auth.example.com",
	authgate.WithHTTPClient(customHTTPClient),
)
```

---

### Fetching the current user

```go
user, err := client.GetCurrentUser(ctx, r)
if err != nil {
	// unexpected error
}

if user == nil {
	// not authenticated
}
```

`GetCurrentUser`:

- forwards the AuthGate access cookie from the incoming request
- does **not** refresh tokens
- returns `(nil, nil)` if the request is unauthenticated
- returns an error only for unexpected failures

---

### Generic request helper (escape hatch)

```go
var result MyResponse

resp, err := authgate.DoJSONRequest(
	ctx,
	client,
	http.MethodGet,
	"/auth/admin/custom-endpoint",
	r,
	&result,
)
if err != nil {
	// transport or decode error
}

if resp.StatusCode != http.StatusOK {
	// caller-defined handling
}
```

This helper:

- performs a raw HTTP request against AuthGate
- forwards authentication context if present
- decodes JSON **only for successful (2xx) responses**
- does **not** implement AuthGate semantics

Callers are responsible for interpreting HTTP status codes.

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

---

## License

MIT
