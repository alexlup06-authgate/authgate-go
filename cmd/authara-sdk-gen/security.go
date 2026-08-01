package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func (g generator) security(op *openapi3.Operation) (authMode, []string, bool, error) {
	requirements := g.doc.Security
	if op.Security != nil {
		requirements = *op.Security
	}
	if len(requirements) == 0 {
		return authPublic, nil, false, nil
	}
	if len(requirements) != 1 {
		return "", nil, false, fmt.Errorf("multiple alternative security requirements are unsupported")
	}

	requirement := requirements[0]
	if len(requirement) == 0 {
		return authPublic, nil, false, nil
	}

	names := make([]string, 0, len(requirement))
	for name := range requirement {
		names = append(names, name)
	}
	sort.Strings(names)

	mode := authPublic
	var cookies []string
	seen := map[string]bool{}
	needsCSRF := false
	for _, name := range names {
		schemeRef := g.doc.Components.SecuritySchemes[name]
		if schemeRef == nil || schemeRef.Value == nil {
			return "", nil, false, fmt.Errorf("security scheme %q is missing or unresolved", name)
		}
		scheme := schemeRef.Value
		if len(requirement[name]) > 0 {
			return "", nil, false, fmt.Errorf("security scheme %q has unsupported scopes", name)
		}
		modeName, err := securityMode(scheme)
		if err != nil {
			return "", nil, false, fmt.Errorf("security scheme %q: %w", name, err)
		}
		if modeName != authPublic && modeName != authInternalBearer {
			return "", nil, false, fmt.Errorf("security scheme %q has unsupported auth mode %q", name, modeName)
		}

		switch {
		case modeName == authInternalBearer:
			if scheme.Type != "http" || !strings.EqualFold(scheme.Scheme, "bearer") {
				return "", nil, false, fmt.Errorf("must be an HTTP bearer scheme")
			}
			if mode != authPublic {
				return "", nil, false, fmt.Errorf("security scheme %q cannot be combined with other authentication", name)
			}
			mode = authInternalBearer
		case scheme.Type == "apiKey" && scheme.In == "header":
			if !strings.EqualFold(scheme.Name, "X-CSRF-Token") {
				return "", nil, false, fmt.Errorf("must be the X-CSRF-Token header")
			}
			if mode == authInternalBearer {
				return "", nil, false, fmt.Errorf("security scheme %q cannot be combined with internal bearer authentication", name)
			}
			mode = authCookie
			needsCSRF = true
		case scheme.Type == "apiKey" && scheme.In == "cookie":
			if scheme.Name == "" {
				return "", nil, false, fmt.Errorf("cookie security scheme %q has no cookie name", name)
			}
			if mode == authInternalBearer {
				return "", nil, false, fmt.Errorf("cookie security scheme %q cannot be combined with internal bearer authentication", name)
			}
			mode = authCookie
			if !seen[scheme.Name] {
				cookies = append(cookies, scheme.Name)
				seen[scheme.Name] = true
			}
		default:
			return "", nil, false, fmt.Errorf("security scheme %q is unsupported", name)
		}
	}
	sort.Strings(cookies)
	return mode, cookies, needsCSRF, nil
}

func securityMode(scheme *openapi3.SecurityScheme) (authMode, error) {
	if scheme.Extensions == nil {
		return authPublic, nil
	}
	value, ok := scheme.Extensions[authModeExtension]
	if !ok {
		return authPublic, nil
	}
	mode, ok := value.(string)
	if !ok || strings.TrimSpace(mode) == "" {
		return authPublic, fmt.Errorf("%s must be a non-empty string", authModeExtension)
	}
	return authMode(strings.TrimSpace(mode)), nil
}
