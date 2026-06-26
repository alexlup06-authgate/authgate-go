package authara

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ClientOption configures a Client.
//
// Client options are applied at construction time via NewClient and allow
// callers to customize transport-level behavior (e.g. HTTP client, timeouts)
// without changing Client semantics.
type ClientOption func(*Client)

// WithHTTPClient configures the Client to use a custom http.Client.
//
// This is useful for setting timeouts, proxies, tracing, or test transports.
// The provided client is used for all outbound requests to Authara.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithInternalAPIToken configures bearer auth for /auth/internal/v1 helpers.
func WithInternalAPIToken(token string) ClientOption {
	return func(c *Client) {
		c.internalAPIToken = strings.TrimSpace(token)
	}
}

// Client is a backend-facing Authara HTTP client.
//
// It is intended for server-side and SSR use cases and provides strict,
// side-effect-free helpers for calling Authara endpoints.
//
// The Client:
//   - never refreshes tokens
//   - never mutates authentication state
//   - forwards existing authentication context only
//   - treats "not authenticated" as a valid state
type Client struct {
	baseURL          string
	internalAPIToken string
	httpClient       *http.Client
}

// NewClient creates a new Authara backend client.
//
// baseURL must point to the Authara HTTP endpoint (e.g. "https://auth.example.com").
// The base URL is normalized by trimming any trailing slash.
//
// Optional ClientOptions may be provided to customize transport behavior.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type requestOption func(*http.Request)

func withIncomingRequest(incoming *http.Request) requestOption {
	return func(req *http.Request) {
		forwardAccessAuth(req, incoming)
	}
}

func withCSRFToken(token string) requestOption {
	return func(req *http.Request) {
		if strings.TrimSpace(token) != "" {
			AttachCSRF(req, token)
		}
	}
}

func withInternalAuth(token string) requestOption {
	return func(req *http.Request) {
		if strings.TrimSpace(token) != "" {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
		}
	}
}

func (c *Client) doJSONBody(
	ctx context.Context,
	method string,
	path string,
	body any,
	out any,
	opts ...requestOption,
) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
		reader = &buf
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, decodeAPIError(resp)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return resp, err
		}
	}

	return resp, nil
}

// forwardAccessAuth forwards Authara cookies needed to preserve request auth.
//
// This preserves the caller's authentication and CSRF context without
// inspecting, validating, or modifying token values.
//
// If the incoming request is nil or does not contain Authara cookies,
// no authentication information is forwarded.
func forwardAccessAuth(req *http.Request, incoming *http.Request) {
	if incoming == nil {
		return
	}

	for _, name := range []string{AccessCookieName, CSRFCookieName} {
		if c, err := incoming.Cookie(name); err == nil {
			req.AddCookie(c)
		}
	}
}

// DoJSONRequest performs a raw HTTP request against the Authara API and
// optionally decodes a successful JSON response into out.
//
// This function is a low-level transport helper intended as an escape hatch
// for calling Authara endpoints that do not yet have first-class helpers.
//
// Behavior and guarantees:
//   - Forwards Authara access/CSRF cookies from the incoming request, if present
//   - Does NOT refresh tokens
//   - Does NOT retry requests
//   - Does NOT interpret HTTP status codes
//   - Decodes JSON only for successful (2xx) responses
//
// Callers are responsible for inspecting the returned HTTP status code and
// deciding how to handle non-2xx responses.
//
// This helper intentionally provides no Authara-specific semantics.
func DoJSONRequest[T any](
	ctx context.Context,
	client *Client,
	method string,
	path string,
	incoming *http.Request,
	out *T,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		method,
		client.baseURL+path,
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	forwardAccessAuth(req, incoming)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

// CurrentUser represents the authenticated user and current authorization facts.
//
// This struct mirrors the response of the Authara `/auth/api/v1/user` endpoint.
type CurrentUser struct {
	ID           uuid.UUID     `json:"id"`
	Email        string        `json:"email"`
	Username     string        `json:"username"`
	Roles        []string      `json:"roles"`
	Organization *Organization `json:"organization,omitempty"`
	Disabled     bool          `json:"disabled"`
	CreatedAt    time.Time     `json:"created_at"`
}

type Organization struct {
	ID              uuid.UUID  `json:"id"`
	CreatedAt       time.Time  `json:"created_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at,omitempty"`
	Name            string     `json:"name"`
	Kind            string     `json:"kind,omitempty"`
	Role            string     `json:"role,omitempty"`
	CreatedByUserID *uuid.UUID `json:"created_by_user_id,omitempty"`
}

type Membership struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         uuid.UUID `json:"user_id"`
	Email          string    `json:"email"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Disabled       bool      `json:"disabled"`
}

type CurrentOrganizationMember struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type MembershipWithOrganization struct {
	Organization Organization `json:"organization"`
	Membership   Membership   `json:"membership"`
}

type Invitation struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
	InviteURL      string    `json:"invite_url,omitempty"`
}

type Capabilities struct {
	OrganizationMode          string `json:"organization_mode"`
	HasVisibleOrganizations   bool   `json:"has_visible_organizations"`
	AllowsInvitations         bool   `json:"allows_invitations"`
	AllowsOrgSwitching        bool   `json:"allows_org_switching"`
	AllowsUserCreatedTeamOrgs bool   `json:"allows_user_created_team_orgs"`
	AllowsOrganizationLeave   bool   `json:"allows_organization_leave"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type OrganizationWithMembership struct {
	Organization Organization `json:"organization"`
	Membership   *Membership  `json:"membership,omitempty"`
}

type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// APIError is returned by high-level client helpers for non-2xx Authara responses.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("authara: %s (%s)", e.Code, e.Message)
	}
	return fmt.Sprintf("authara: unexpected status %d", e.StatusCode)
}

func decodeAPIError(resp *http.Response) error {
	var errResp ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error.Code != "" {
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       errResp.Error.Code,
			Message:    errResp.Error.Message,
		}
	}
	return &APIError{StatusCode: resp.StatusCode}
}

// GetCurrentUser retrieves the identity of the currently authenticated user.
//
// The authentication context is forwarded from the incoming request using the
// Authara access cookie. This method does not refresh tokens or retry requests.
//
// Return values:
//   - (*CurrentUser, nil): the request is authenticated and the user exists
//   - (nil, nil): the request is not authenticated (401 Unauthorized)
//   - (nil, error): an unexpected failure occurred
func (c *Client) GetCurrentUser(ctx context.Context, incoming *http.Request) (*CurrentUser, error) {
	var user CurrentUser

	resp, err := c.doJSONBody(
		ctx,
		http.MethodGet,
		"/auth/api/v1/user",
		nil,
		&user,
		withIncomingRequest(incoming),
	)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

type csrfResponse struct {
	CSRFToken string `json:"csrf_token"`
}

func (c *Client) GetCSRFToken(ctx context.Context) (string, error) {
	var out csrfResponse
	_, err := c.doJSONBody(ctx, http.MethodGet, "/auth/api/v1/csrf", nil, &out)
	if err != nil {
		return "", err
	}
	return out.CSRFToken, nil
}

type organizationsResponse struct {
	Organizations []Organization `json:"organizations"`
}

func (c *Client) GetOrganizations(ctx context.Context, incoming *http.Request) ([]Organization, error) {
	var out organizationsResponse
	resp, err := c.doJSONBody(
		ctx,
		http.MethodGet,
		"/auth/api/v1/organizations",
		nil,
		&out,
		withIncomingRequest(incoming),
	)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return nil, nil
	}
	return out.Organizations, err
}

func (c *Client) GetCurrentOrganization(ctx context.Context, incoming *http.Request) (*Organization, error) {
	var out Organization
	resp, err := c.doJSONBody(
		ctx,
		http.MethodGet,
		"/auth/api/v1/organizations/current",
		nil,
		&out,
		withIncomingRequest(incoming),
	)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

type currentMembersResponse struct {
	Members []CurrentOrganizationMember `json:"members"`
}

func (c *Client) ListCurrentOrganizationMembers(ctx context.Context, incoming *http.Request) ([]CurrentOrganizationMember, error) {
	var out currentMembersResponse
	resp, err := c.doJSONBody(
		ctx,
		http.MethodGet,
		"/auth/api/v1/organizations/current/members",
		nil,
		&out,
		withIncomingRequest(incoming),
	)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return nil, nil
	}
	return out.Members, err
}

func (c *Client) SwitchOrganization(ctx context.Context, incoming *http.Request, organizationID uuid.UUID, audience string) (*Tokens, error) {
	var out Tokens
	path := "/auth/api/v1/organizations/" + url.PathEscape(organizationID.String()) + "/switch?audience=" + url.QueryEscape(audienceOrApp(audience))
	opts := []requestOption{withIncomingRequest(incoming)}
	if token, ok := CSRFToken(incoming); ok {
		opts = append(opts, withCSRFToken(token))
	}
	_, err := c.doJSONBody(ctx, http.MethodPost, path, nil, &out, opts...)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RefreshTokens(ctx context.Context, refreshToken string, audience string) (*Tokens, error) {
	var out Tokens
	_, err := c.doJSONBody(
		ctx,
		http.MethodPost,
		"/auth/api/v1/tokens/refresh",
		struct {
			RefreshToken string `json:"refresh_token"`
			Audience     string `json:"audience"`
		}{
			RefreshToken: refreshToken,
			Audience:     audienceOrApp(audience),
		},
		&out,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) internalJSON(ctx context.Context, method string, path string, body any, out any) error {
	if c.internalAPIToken == "" {
		return errors.New("authara: internal API token is required")
	}
	_, err := c.doJSONBody(ctx, method, path, body, out, withInternalAuth(c.internalAPIToken))
	return err
}

func (c *Client) GetCapabilities(ctx context.Context) (*Capabilities, error) {
	var out Capabilities
	if err := c.internalJSON(ctx, http.MethodGet, "/auth/internal/v1/capabilities", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateOrganization(ctx context.Context, name string, createdByUserID uuid.UUID) (*OrganizationWithMembership, error) {
	var out OrganizationWithMembership
	err := c.internalJSON(
		ctx,
		http.MethodPost,
		"/auth/internal/v1/organizations",
		struct {
			Name            string    `json:"name"`
			CreatedByUserID uuid.UUID `json:"created_by_user_id"`
		}{Name: name, CreatedByUserID: createdByUserID},
		&out,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetOrganization(ctx context.Context, organizationID uuid.UUID) (*Organization, error) {
	var out OrganizationWithMembership
	err := c.internalJSON(ctx, http.MethodGet, internalOrganizationPath(organizationID), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out.Organization, nil
}

func (c *Client) UpdateOrganization(ctx context.Context, organizationID uuid.UUID, name string) (*Organization, error) {
	var out OrganizationWithMembership
	err := c.internalJSON(
		ctx,
		http.MethodPatch,
		internalOrganizationPath(organizationID),
		struct {
			Name string `json:"name"`
		}{Name: name},
		&out,
	)
	if err != nil {
		return nil, err
	}
	return &out.Organization, nil
}

type membersResponse struct {
	Members []Membership `json:"members"`
}

func (c *Client) ListOrganizationMembers(ctx context.Context, organizationID uuid.UUID) ([]Membership, error) {
	var out membersResponse
	err := c.internalJSON(ctx, http.MethodGet, internalOrganizationPath(organizationID)+"/members", nil, &out)
	return out.Members, err
}

type memberResponse struct {
	Member Membership `json:"member"`
}

func (c *Client) GetOrganizationMember(ctx context.Context, organizationID uuid.UUID, userID uuid.UUID) (*Membership, error) {
	var out memberResponse
	path := internalOrganizationPath(organizationID) + "/members/" + url.PathEscape(userID.String())
	err := c.internalJSON(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return nil, err
	}
	return &out.Member, nil
}

type invitationsResponse struct {
	Invitations []Invitation `json:"invitations"`
}

func (c *Client) ListOrganizationInvitations(ctx context.Context, organizationID uuid.UUID) ([]Invitation, error) {
	var out invitationsResponse
	err := c.internalJSON(ctx, http.MethodGet, internalOrganizationPath(organizationID)+"/invitations", nil, &out)
	return out.Invitations, err
}

type invitationResponse struct {
	Invitation Invitation `json:"invitation"`
}

func (c *Client) CreateOrganizationInvitation(ctx context.Context, organizationID uuid.UUID, actorUserID uuid.UUID, email string) (*Invitation, error) {
	var out invitationResponse
	err := c.internalJSON(
		ctx,
		http.MethodPost,
		internalOrganizationPath(organizationID)+"/invitations",
		struct {
			ActorUserID uuid.UUID `json:"actor_user_id"`
			Email       string    `json:"email"`
		}{ActorUserID: actorUserID, Email: email},
		&out,
	)
	if err != nil {
		return nil, err
	}
	return &out.Invitation, nil
}

func (c *Client) GetOrganizationInvitation(ctx context.Context, organizationID uuid.UUID, invitationID uuid.UUID) (*Invitation, error) {
	var out invitationResponse
	path := internalOrganizationPath(organizationID) + "/invitations/" + url.PathEscape(invitationID.String())
	err := c.internalJSON(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return nil, err
	}
	return &out.Invitation, nil
}

func (c *Client) ResendOrganizationInvitation(ctx context.Context, organizationID uuid.UUID, invitationID uuid.UUID) (*Invitation, error) {
	var out invitationResponse
	path := internalOrganizationPath(organizationID) + "/invitations/" + url.PathEscape(invitationID.String()) + "/resend"
	err := c.internalJSON(ctx, http.MethodPost, path, nil, &out)
	if err != nil {
		return nil, err
	}
	return &out.Invitation, nil
}

func (c *Client) RevokeOrganizationInvitation(ctx context.Context, organizationID uuid.UUID, invitationID uuid.UUID, revokedByUserID *uuid.UUID) (*Invitation, error) {
	var body any
	if revokedByUserID != nil {
		body = struct {
			RevokedByUserID uuid.UUID `json:"revoked_by_user_id"`
		}{RevokedByUserID: *revokedByUserID}
	}

	var out invitationResponse
	path := internalOrganizationPath(organizationID) + "/invitations/" + url.PathEscape(invitationID.String()) + "/revoke"
	err := c.internalJSON(ctx, http.MethodPost, path, body, &out)
	if err != nil {
		return nil, err
	}
	return &out.Invitation, nil
}

type membershipsResponse struct {
	Memberships []MembershipWithOrganization `json:"memberships"`
}

func (c *Client) ListUserMemberships(ctx context.Context, userID uuid.UUID) ([]MembershipWithOrganization, error) {
	var out membershipsResponse
	path := "/auth/internal/v1/users/" + url.PathEscape(userID.String()) + "/memberships"
	err := c.internalJSON(ctx, http.MethodGet, path, nil, &out)
	return out.Memberships, err
}

func internalOrganizationPath(organizationID uuid.UUID) string {
	return "/auth/internal/v1/organizations/" + url.PathEscape(organizationID.String())
}

func audienceOrApp(audience string) string {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "app"
	}
	return audience
}
