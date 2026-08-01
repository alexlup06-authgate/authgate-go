package main

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestMethodUsesAmpersandForAdditionalQueryParams(t *testing.T) {
	src := generator{}.method(operation{
		Method:      "GET",
		Path:        "/auth/api/v1/example",
		OperationID: "listExamples",
		QueryParams: []parameter{
			{Name: "audience", Type: "string"},
			{Name: "cursor", Type: "string"},
		},
	})

	if !strings.Contains(src, `path += "?audience=" + url.QueryEscape(audienceOrApp(audience))`) {
		t.Fatalf("missing first query param with ?: %s", src)
	}
	if !strings.Contains(src, `path += "&cursor=" + url.QueryEscape(cursor)`) {
		t.Fatalf("missing second query param with &: %s", src)
	}
}

func TestMethodUsesAuthModeInsteadOfPath(t *testing.T) {
	internal := generator{}.method(operation{
		Path:         "/auth/api/v2/organizations",
		OperationID:  "createInternalOrganization",
		Auth:         authInternalBearer,
		NeedsRequest: false,
	})
	if !strings.Contains(internal, "c.internalJSON") {
		t.Fatalf("internal bearer operation did not use internal auth: %s", internal)
	}

	public := generator{}.method(operation{
		Path:        "/auth/internal/v1/public",
		OperationID: "publicOperation",
		Auth:        authPublic,
	})
	if strings.Contains(public, "c.internalJSON") {
		t.Fatalf("public operation used internal auth: %s", public)
	}
}

func TestSecurityUsesInternalBearerScheme(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"customBearer": securitySchemeRef(&openapi3.SecurityScheme{
			Type:   "http",
			Scheme: "bearer",
			Extensions: map[string]any{
				authModeExtension: string(authInternalBearer),
			},
		}),
	})

	mode, cookies, csrf, err := g.security(operationSecurity(openapi3.SecurityRequirement{
		"customBearer": {},
	}))
	if err != nil {
		t.Fatalf("security: %v", err)
	}
	if mode != authInternalBearer || len(cookies) != 0 || csrf {
		t.Fatalf("unexpected auth mode: mode=%q cookies=%v csrf=%t", mode, cookies, csrf)
	}
}

func TestSecurityUsesExplicitPublicRequirement(t *testing.T) {
	g := generatorWithSecuritySchemes(nil)

	mode, cookies, csrf, err := g.security(operationSecurity(openapi3.SecurityRequirement{}))
	if err != nil {
		t.Fatalf("security: %v", err)
	}
	if mode != authPublic || len(cookies) != 0 || csrf {
		t.Fatalf("unexpected auth mode: mode=%q cookies=%v csrf=%t", mode, cookies, csrf)
	}
}

func TestSecurityRejectsBearerWithoutAuthMode(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"internalBearer": securitySchemeRef(&openapi3.SecurityScheme{Type: "http", Scheme: "bearer"}),
	})

	_, _, _, err := g.security(operationSecurity(openapi3.SecurityRequirement{
		"internalBearer": {},
	}))
	if err == nil || !strings.Contains(err.Error(), `security scheme "internalBearer" is unsupported`) {
		t.Fatalf("expected unsupported bearer scheme error, got %v", err)
	}
}

func TestSecurityInheritsTopLevelRequirement(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"accessCookie": securitySchemeRef(&openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: "authara_access"}),
	})
	g.doc.Security = openapi3.SecurityRequirements{
		{"accessCookie": {}},
	}

	mode, cookies, csrf, err := g.security(&openapi3.Operation{})
	if err != nil {
		t.Fatalf("security: %v", err)
	}
	if mode != authCookie || len(cookies) != 1 || cookies[0] != "authara_access" || csrf {
		t.Fatalf("unexpected auth mode: mode=%q cookies=%v csrf=%t", mode, cookies, csrf)
	}
}

func TestSecurityOperationRequirementOverridesTopLevel(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"accessCookie": securitySchemeRef(&openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: "authara_access"}),
	})
	g.doc.Security = openapi3.SecurityRequirements{
		{"accessCookie": {}},
	}

	mode, cookies, csrf, err := g.security(operationSecurity(openapi3.SecurityRequirement{}))
	if err != nil {
		t.Fatalf("security: %v", err)
	}
	if mode != authPublic || len(cookies) != 0 || csrf {
		t.Fatalf("operation-level public security did not override top-level security: mode=%q cookies=%v csrf=%t", mode, cookies, csrf)
	}
}

func TestSecurityForwardsCookieSchemesAndCSRF(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"customCookie": securitySchemeRef(&openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: "custom_auth"}),
		"customHeader": securitySchemeRef(&openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-CSRF-Token"}),
	})

	mode, cookies, csrf, err := g.security(operationSecurity(openapi3.SecurityRequirement{
		"customCookie": {},
		"customHeader": {},
	}))
	if err != nil {
		t.Fatalf("security: %v", err)
	}
	if mode != authCookie || len(cookies) != 1 || cookies[0] != "custom_auth" || !csrf {
		t.Fatalf("unexpected auth mode: mode=%q cookies=%v csrf=%t", mode, cookies, csrf)
	}
}

func TestSecurityRejectsUnsupportedScheme(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"oauth": securitySchemeRef(&openapi3.SecurityScheme{Type: "oauth2"}),
	})

	_, _, _, err := g.security(operationSecurity(openapi3.SecurityRequirement{"oauth": {}}))
	if err == nil || !strings.Contains(err.Error(), `security scheme "oauth" is unsupported`) {
		t.Fatalf("expected unsupported security scheme error, got %v", err)
	}
}

func TestSecurityRejectsUnsupportedAuthMode(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"customCookie": securitySchemeRef(&openapi3.SecurityScheme{
			Type: "apiKey",
			In:   "cookie",
			Name: "custom_auth",
			Extensions: map[string]any{
				authModeExtension: "session_cookie",
			},
		}),
	})

	_, _, _, err := g.security(operationSecurity(openapi3.SecurityRequirement{"customCookie": {}}))
	if err == nil || !strings.Contains(err.Error(), `security scheme "customCookie" has unsupported auth mode "session_cookie"`) {
		t.Fatalf("expected unsupported auth mode error, got %v", err)
	}
}

func TestSecurityRejectsAlternativeRequirements(t *testing.T) {
	g := generatorWithSecuritySchemes(map[string]*openapi3.SecuritySchemeRef{
		"accessCookie":   securitySchemeRef(&openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: "authara_access"}),
		"internalBearer": securitySchemeRef(&openapi3.SecurityScheme{Type: "http", Scheme: "bearer"}),
	})

	_, _, _, err := g.security(operationSecurity(
		openapi3.SecurityRequirement{"accessCookie": {}},
		openapi3.SecurityRequirement{"internalBearer": {}},
	))
	if err == nil || !strings.Contains(err.Error(), "multiple alternative security requirements") {
		t.Fatalf("expected alternative security requirement error, got %v", err)
	}
}

func generatorWithSecuritySchemes(schemes map[string]*openapi3.SecuritySchemeRef) generator {
	return generator{doc: &openapi3.T{Components: &openapi3.Components{SecuritySchemes: schemes}}}
}

func securitySchemeRef(scheme *openapi3.SecurityScheme) *openapi3.SecuritySchemeRef {
	return &openapi3.SecuritySchemeRef{Value: scheme}
}

func operationSecurity(requirements ...openapi3.SecurityRequirement) *openapi3.Operation {
	security := openapi3.SecurityRequirements(requirements)
	return &openapi3.Operation{Security: &security}
}
