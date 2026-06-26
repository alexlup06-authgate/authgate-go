package authara

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// helper to create a client pointing at a test server
func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := NewClient(
		srv.URL,
		WithHTTPClient(srv.Client()),
	)

	return client, srv
}

func TestGetCurrentUser_OK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/user" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "11111111-1111-1111-1111-111111111111",
			"email": "user@example.com",
			"username": "user",
			"roles": ["authara:user"],
			"organization": {
				"id": "22222222-2222-2222-2222-222222222222",
				"name": "Example Org",
				"role": "owner"
			}
		}`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	user, err := client.GetCurrentUser(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user == nil {
		t.Fatal("expected user, got nil")
	}

	if user.ID.String() != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("unexpected id: %s", user.ID)
	}
	if user.Email != "user@example.com" {
		t.Errorf("unexpected email: %s", user.Email)
	}
	if user.Username != "user" {
		t.Errorf("unexpected username: %s", user.Username)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "authara:user" {
		t.Fatalf("unexpected roles: %v", user.Roles)
	}
	if user.Organization == nil || user.Organization.ID.String() != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("unexpected organization: %+v", user.Organization)
	}
}

func TestGetCurrentUser_Unauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestGetCurrentUser_UnexpectedStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if user != nil {
		t.Fatalf("expected nil user on error, got %+v", user)
	}
}

func TestGetCurrentUser_MalformedJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{ not valid json`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := client.GetCurrentUser(context.Background(), req)
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}

	if user != nil {
		t.Fatalf("expected nil user on error, got %+v", user)
	}
}

func TestGetCurrentUser_ForwardsAccessCookie(t *testing.T) {
	var sawCookie bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(AccessCookieName)
		if err == nil {
			sawCookie = true
		}

		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	_, _ = client.GetCurrentUser(context.Background(), req)

	if !sawCookie {
		t.Fatal("expected access cookie to be forwarded")
	}
}

func TestGetCurrentUser_NilIncomingRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	client, _ := newTestClient(t, handler)

	user, err := client.GetCurrentUser(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestDoJSONRequest_OK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":"ok"}`))
	})

	client, _ := newTestClient(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessCookieName,
		Value: "access-token",
	})

	type Response struct {
		Value string `json:"value"`
	}

	var out Response

	resp, err := DoJSONRequest[Response](
		context.Background(),
		client,
		http.MethodGet,
		"/custom",
		req,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	if out.Value != "ok" {
		t.Fatalf("unexpected value: %s", out.Value)
	}
}

func TestListCurrentOrganizationMembers_DecodesUserFields(t *testing.T) {
	memberID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/organizations/current/members" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if _, err := r.Cookie(AccessCookieName); err != nil {
			t.Fatal("expected access cookie")
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"members": [{
				"user_id": "` + memberID.String() + `",
				"email": "teammate@example.com",
				"username": "teammate",
				"role": "admin",
				"created_at": "2026-01-08T12:00:00Z"
			}]
		}`))
	})

	client, _ := newTestClient(t, handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: "access-token"})

	members, err := client.ListCurrentOrganizationMembers(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("unexpected members: %+v", members)
	}
	if members[0].UserID != memberID ||
		members[0].Email != "teammate@example.com" ||
		members[0].Username != "teammate" ||
		members[0].Role != "admin" ||
		members[0].CreatedAt.IsZero() {
		t.Fatalf("unexpected member: %+v", members[0])
	}
}

func TestSwitchOrganization_ForwardsCookieAndCSRF(t *testing.T) {
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

	tokens, err := client.SwitchOrganization(context.Background(), req, orgID, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "access" || tokens.RefreshToken != "refresh" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func TestGetCapabilities_SendsInternalToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/internal/v1/capabilities" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer internal-secret" {
			t.Fatalf("unexpected authorization: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"organization_mode":"multi",
			"has_visible_organizations":true,
			"allows_invitations":true,
			"allows_org_switching":true,
			"allows_user_created_team_orgs":true,
			"allows_organization_leave":true
		}`))
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, WithHTTPClient(srv.Client()), WithInternalAPIToken(" internal-secret "))

	caps, err := client.GetCapabilities(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caps.OrganizationMode != "multi" || !caps.AllowsInvitations {
		t.Fatalf("unexpected capabilities: %+v", caps)
	}
}

func TestListOrganizationMembers_DecodesInternalMemberFields(t *testing.T) {
	orgID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	memberID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/internal/v1/organizations/"+orgID.String()+"/members" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"members": [{
				"organization_id": "` + orgID.String() + `",
				"user_id": "` + memberID.String() + `",
				"email": "teammate@example.com",
				"username": "teammate",
				"role": "admin",
				"created_at": "2026-01-08T12:00:00Z",
				"updated_at": "2026-01-09T12:00:00Z",
				"disabled": true
			}]
		}`))
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, WithHTTPClient(srv.Client()), WithInternalAPIToken("token"))

	members, err := client.ListOrganizationMembers(context.Background(), orgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("unexpected members: %+v", members)
	}
	if members[0].OrganizationID != orgID ||
		members[0].UserID != memberID ||
		members[0].Email != "teammate@example.com" ||
		members[0].Username != "teammate" ||
		members[0].Role != "admin" ||
		members[0].CreatedAt.IsZero() ||
		members[0].UpdatedAt.IsZero() ||
		!members[0].Disabled {
		t.Fatalf("unexpected member: %+v", members[0])
	}
}

func TestCreateOrganizationInvitation_SendsInternalBody(t *testing.T) {
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

		var body struct {
			ActorUserID string `json:"actor_user_id"`
			Email       string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.ActorUserID != actorID.String() || body.Email != "teammate@example.com" {
			t.Fatalf("unexpected body: %+v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"invitation": {
				"id": "` + invitationID.String() + `",
				"organization_id": "` + orgID.String() + `",
				"email": "teammate@example.com",
				"role": "member",
				"status": "pending",
				"expires_at": "2026-01-08T12:00:00Z",
				"invite_url": "https://example.com/auth/invitations/accept?token=x"
			}
		}`))
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, WithHTTPClient(srv.Client()), WithInternalAPIToken("token"))

	invitation, err := client.CreateOrganizationInvitation(context.Background(), orgID, actorID, "teammate@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if invitation.ID != invitationID || invitation.InviteURL == "" || invitation.ExpiresAt.IsZero() {
		t.Fatalf("unexpected invitation: %+v", invitation)
	}
}
