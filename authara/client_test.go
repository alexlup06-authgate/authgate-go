package authara

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func newTestClient(t *testing.T, handler http.Handler, opts ...ClientOption) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	opts = append([]ClientOption{WithHTTPClient(srv.Client())}, opts...)
	return NewClient(srv.URL, opts...), srv
}

func TestGeneratedCallForwardsCookiesAndCSRF(t *testing.T) {
	orgID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/auth/api/v1/organizations/"+orgID.String()+"/switch" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("audience"); got != "app" {
			t.Fatalf("unexpected audience: %q", got)
		}
		if _, err := r.Cookie(AccessCookieName); err != nil {
			t.Fatal("expected access cookie")
		}
		if c, err := r.Cookie(CSRFCookieName); err != nil || c.Value != "csrf123" {
			t.Fatalf("expected csrf cookie, got %v (err=%v)", c, err)
		}
		if got := r.Header.Get(CSRFHeaderName); got != "csrf123" {
			t.Fatalf("expected csrf header, got %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"access","refresh_token":"refresh"}`))
	})

	client, _ := newTestClient(t, handler)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: "access-token"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf123"})

	tokens, err := client.CallSwitchOrganization(context.Background(), req, orgID, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "access" || tokens.RefreshToken != "refresh" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestGeneratedInternalCallSendsBearerToken(t *testing.T) {
	orgID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	actorID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	invitationID := uuid.MustParse("44444444-4444-4444-4444-444444444444")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/internal/v1/organizations/"+orgID.String()+"/invitations" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization: %q", got)
		}
		var body APIInternalCreateInvitationRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Role == nil || *body.Role != APIOrganizationInvitationRoleAdmin || body.Metadata == nil {
			t.Fatalf("unexpected request body: %+v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"invitation": {
				"id": "` + invitationID.String() + `",
				"organization_id": "` + orgID.String() + `",
				"email": "teammate@example.com",
				"role": "admin",
				"metadata": {"baufunk":{"role":"manager"}},
				"status": "pending",
				"expires_at": "2026-01-08T12:00:00Z"
			}
		}`))
	})

	client, _ := newTestClient(t, handler, WithInternalAPIToken(" token "))
	role := APIOrganizationInvitationRoleAdmin
	metadata := map[string]any{"baufunk": map[string]any{"role": "manager"}}

	invitation, err := client.CallCreateInternalOrganizationInvitation(
		context.Background(),
		orgID,
		APIInternalCreateInvitationRequest{
			ActorUserID: actorID,
			Email:       "teammate@example.com",
			Role:        &role,
			Metadata:    &metadata,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if invitation.Invitation.ID != invitationID {
		t.Fatalf("unexpected invitation: %+v", invitation)
	}
	if invitation.Invitation.Role != APIOrganizationRoleAdmin || invitation.Invitation.Metadata == nil {
		t.Fatalf("unexpected invitation role or metadata: %+v", invitation.Invitation)
	}
}

func TestGeneratedInternalLifecycleCallSendsActor(t *testing.T) {
	orgID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	actorID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/auth/internal/v1/organizations/"+orgID.String() {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization: %q", got)
		}
		var body APIInternalOrganizationActorRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.ActorUserID != actorID {
			t.Fatalf("unexpected actor: %s", body.ActorUserID)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	client, _ := newTestClient(t, handler, WithInternalAPIToken("token"))
	if err := client.CallDeleteInternalOrganization(context.Background(), orgID, APIInternalOrganizationActorRequest{ActorUserID: actorID}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGeneratedCallDecodesAPIError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"code":"unauthorized","message":"No session"}}`))
	})

	client, _ := newTestClient(t, handler)
	_, err := client.CallGetCurrentUser(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized || apiErr.Code != "unauthorized" {
		t.Fatalf("unexpected api error: %+v", apiErr)
	}
}
