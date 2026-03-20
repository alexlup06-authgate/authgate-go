package authara

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// VerifyWebhookSignature verifies that a webhook request was signed by Authara.
//
// It computes an HMAC-SHA256 signature of the request body using the provided
// secret and compares it to the value from the X-Authara-Signature header.
//
// The expected header format is:
//
//	sha256=<hex-encoded-hmac>
//
// Returns true if the signature is valid, otherwise false.
//
// This function should be called before trusting or processing any webhook data.
func VerifyWebhookSignature(secret string, body []byte, header string) bool {
	// Reject if required inputs are missing.
	if secret == "" || header == "" {
		return false
	}

	const prefix = "sha256="

	// Ensure the header uses the expected format.
	if !strings.HasPrefix(header, prefix) {
		return false
	}

	// Compute HMAC-SHA256 over the request body using the shared secret.
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := prefix + hex.EncodeToString(mac.Sum(nil))

	// Compare signatures using constant-time comparison to prevent timing attacks.
	return hmac.Equal([]byte(expected), []byte(header))
}
