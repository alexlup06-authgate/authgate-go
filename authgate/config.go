package authgate

// Config defines the configuration required to initialize the AuthGate SDK.
//
// All fields are required. The SDK performs strict validation when calling
// New and will return an error if any required field is missing or invalid.
type Config struct {
	// Issuer is the expected issuer (iss claim) of AuthGate-issued access tokens.
	//
	// This must exactly match the issuer configured in the AuthGate server,
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
}
