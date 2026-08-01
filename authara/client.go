package authara

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ClientOption func(*Client)

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

func WithInternalAPIToken(token string) ClientOption {
	return func(c *Client) {
		c.internalAPIToken = strings.TrimSpace(token)
	}
}

type Client struct {
	baseURL          string
	internalAPIToken string
	httpClient       *http.Client
}

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

func withCSRFToken(token string) requestOption {
	return func(req *http.Request) {
		AttachCSRF(req, strings.TrimSpace(token))
	}
}

func withInternalAuth(token string) requestOption {
	return func(req *http.Request) {
		if token = strings.TrimSpace(token); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
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

func (c *Client) internalJSON(ctx context.Context, method string, path string, body any, out any) error {
	if c.internalAPIToken == "" {
		return errors.New("authara: internal API token is required")
	}
	_, err := c.doJSONBody(ctx, method, path, body, out, withInternalAuth(c.internalAPIToken))
	return err
}

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
	var errResp APIErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error.Code != "" {
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       errResp.Error.Code,
			Message:    errResp.Error.Message,
		}
	}
	return &APIError{StatusCode: resp.StatusCode}
}

func audienceOrApp(audience string) string {
	if audience = strings.TrimSpace(audience); audience != "" {
		return audience
	}
	return "app"
}
