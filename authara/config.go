package authara

import "net/http"

// Config defines the configuration required to initialize the Authara SDK.
//
// All fields are required. The SDK performs strict validation when calling
// New and will return an error if any required field is missing or invalid.
type Config struct {
	// Issuer is the expected issuer (iss claim) of Authara-issued access tokens.
	//
	// This must exactly match the issuer configured in the Authara server,
	// including scheme and host (e.g. "https://example.com").
	Issuer string

	// Audience is the expected audience (aud claim) of access tokens.
	//
	// Typical values are application identifiers such as "app" or "admin".
	// Tokens with a different audience will be rejected.
	Audience string

	// Keys maps key IDs (kid) to their corresponding HMAC secrets.
	//
	// The key ID must match the "kid" header of the JWT. Multiple keys may be
	// provided to support key rotation.
	Keys map[string][]byte

	// AutharaBaseURL enables refresh behavior in RequireAuth.
	//
	// Example: "https://example.com", or if you use Docker, e.g.: "authara:3000"
	// If empty, RequireAuth will NOT attempt refresh and will behave as today.
	AutharaBaseURL string

	// InternalAPIToken authorizes calls to /auth/internal/v1.
	//
	// It must match AUTHARA_INTERNAL_API_TOKEN configured in Authara.
	InternalAPIToken string

	// HTTPClient is used for outbound calls to Authara (refresh).
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// AccessTokenRevocationEnabled makes middleware reject access tokens that
	// Authara Core has revoked in Redis. Checks fail closed if Redis is
	// unavailable.
	AccessTokenRevocationEnabled bool

	// Redis configures the shared Redis used by Authara Core for access-token
	// revocations. It is only used when AccessTokenRevocationEnabled is true.
	Redis RedisConfig
}

// RedisConfig configures the Redis connection used for access-token revocation
// checks.
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}
