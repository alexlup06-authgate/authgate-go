package authara

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1","type":"user.created","created_at":"2026-03-20T12:00:00Z","data":{"user_id":"123"}}`)

	header := signedHeader(secret, body)

	if !VerifyWebhookSignature(secret, body, header) {
		t.Fatal("expected signature to be valid")
	}
}

func TestVerifyWebhookSignature_Invalid(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1"}`)

	if VerifyWebhookSignature(secret, body, "sha256=wrong") {
		t.Fatal("expected signature to be invalid")
	}
}

func TestParseWebhookEvent(t *testing.T) {
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}

	if evt.ID != "evt_1" {
		t.Fatalf("expected id evt_1, got %q", evt.ID)
	}
	if evt.Type != WebhookEventUserCreated {
		t.Fatalf("expected type %q, got %q", WebhookEventUserCreated, evt.Type)
	}
}

func TestDecodeWebhookData(t *testing.T) {
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	evt, err := ParseWebhookEvent(body)
	if err != nil {
		t.Fatalf("ParseWebhookEvent failed: %v", err)
	}

	data, err := DecodeWebhookData[UserCreatedData](evt)
	if err != nil {
		t.Fatalf("DecodeWebhookData failed: %v", err)
	}

	if data.UserID != "123" {
		t.Fatalf("expected user_id 123, got %q", data.UserID)
	}
}

func TestWebhookHandler_Handle_Success(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{
		"id":"evt_1",
		"type":"user.created",
		"created_at":"2026-03-20T12:00:00Z",
		"data":{"user_id":"123"}
	}`)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/authara", bytes.NewReader(body))
	req.Header.Set(WebhookSignatureHeader, signedHeader(secret, body))
	rr := httptest.NewRecorder()

	handler := &WebhookHandler{Secret: secret}

	evt, err := handler.Handle(rr, req)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event")
	}
	if rr.Code != 200 {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}

func TestWebhookHandler_Handle_InvalidSignature(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"id":"evt_1"}`)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/authara", bytes.NewReader(body))
	req.Header.Set(WebhookSignatureHeader, "sha256=wrong")
	rr := httptest.NewRecorder()

	handler := &WebhookHandler{Secret: secret}

	evt, err := handler.Handle(rr, req)
	if err == nil {
		t.Fatal("expected error")
	}
	if evt != nil {
		t.Fatal("expected nil event")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func signedHeader(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return WebhookSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
