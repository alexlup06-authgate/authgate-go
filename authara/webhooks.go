package authara

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var (
	// ErrWebhookInvalidSignature indicates that the webhook signature
	// verification failed.
	//
	// This usually means the request did not originate from a trusted
	// Authara instance or the shared secret is incorrect.
	ErrWebhookInvalidSignature = errors.New("invalid webhook signature")

	// ErrWebhookInvalidBody indicates that the request body could not be read.
	//
	// This may happen if the request is malformed or prematurely closed.
	ErrWebhookInvalidBody = errors.New("invalid webhook body")

	// ErrWebhookInvalidEvent indicates that the webhook payload could not
	// be parsed into a valid WebhookEvent.
	ErrWebhookInvalidEvent = errors.New("invalid webhook event")
)

// WebhookHandler provides a high-level helper for handling Authara webhooks.
//
// It performs:
//
//   - request body reading
//   - signature verification
//   - event parsing
//
// Applications can use this to reduce boilerplate when implementing webhook endpoints.
type WebhookHandler struct {
	// Secret is the shared webhook secret used to verify request signatures.
	//
	// It must match AUTHARA_WEBHOOK_SECRET configured in Authara.
	Secret string
}

// Handle processes an incoming webhook HTTP request.
//
// It verifies the signature, parses the event, and returns a WebhookEvent
// if successful.
//
// On failure, it writes an appropriate HTTP error response and returns
// a corresponding error.
//
// Typical usage:
//
//	evt, err := handler.Handle(w, r)
//	if err != nil {
//	    return
//	}
func (h *WebhookHandler) Handle(w http.ResponseWriter, r *http.Request) (*WebhookEvent, error) {
	// Ensure request and body are present.
	if r == nil || r.Body == nil {
		http.Error(w, ErrWebhookInvalidBody.Error(), http.StatusBadRequest)
		return nil, ErrWebhookInvalidBody
	}
	defer r.Body.Close()

	// Read the full request body.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, ErrWebhookInvalidBody.Error(), http.StatusBadRequest)
		return nil, ErrWebhookInvalidBody
	}

	// Verify webhook signature.
	signature := r.Header.Get(WebhookSignatureHeader)
	if !VerifyWebhookSignature(h.Secret, body, signature) {
		http.Error(w, ErrWebhookInvalidSignature.Error(), http.StatusUnauthorized)
		return nil, ErrWebhookInvalidSignature
	}

	// Parse the webhook event.
	evt, err := ParseWebhookEvent(body)
	if err != nil {
		http.Error(w, ErrWebhookInvalidEvent.Error(), http.StatusBadRequest)
		return nil, ErrWebhookInvalidEvent
	}

	return evt, nil
}

// ParseWebhookEvent parses a raw JSON webhook payload into a WebhookEvent.
//
// It does not perform signature verification and should only be used
// after the request has been validated.
func ParseWebhookEvent(body []byte) (*WebhookEvent, error) {
	var evt WebhookEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		return nil, err
	}
	return &evt, nil
}

// DecodeWebhookData decodes the Data field of a WebhookEvent into a typed struct.
//
// The type parameter T should match the expected payload for the event type.
//
// Example:
//
//	data, err := DecodeWebhookData[UserCreatedData](evt)
func DecodeWebhookData[T any](evt *WebhookEvent) (*T, error) {
	var out T

	// Ensure event is present.
	if evt == nil {
		return nil, ErrWebhookInvalidEvent
	}

	// Decode raw JSON payload into the provided type.
	if err := json.Unmarshal(evt.Data, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
