package main

import (
	"strings"
	"testing"
)

func TestMethodUsesAmpersandForAdditionalQueryParams(t *testing.T) {
	src, err := (generator{}).method(operation{
		Method:      "GET",
		Path:        "/auth/api/v1/example",
		OperationID: "listExamples",
		QueryParams: []parameter{
			{Name: "audience", Type: "string"},
			{Name: "cursor", Type: "string"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(src, `query.Set("audience", audienceOrApp(audience))`) {
		t.Fatalf("missing first query param with ?: %s", src)
	}
	if !strings.Contains(src, `query.Set("cursor", cursor)`) {
		t.Fatalf("missing second query param with &: %s", src)
	}
	if !strings.Contains(src, `path += "?" + query.Encode()`) {
		t.Fatalf("missing encoded query: %s", src)
	}
}

func TestMethodUsesAuthModeInsteadOfPath(t *testing.T) {
	internal, err := (generator{}).method(operation{
		Path:         "/auth/api/v2/organizations",
		OperationID:  "createInternalOrganization",
		Auth:         authInternalBearer,
		NeedsRequest: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(internal, "c.internalJSON") {
		t.Fatalf("internal bearer operation did not use internal auth: %s", internal)
	}

	public, err := (generator{}).method(operation{
		Path:        "/auth/internal/v1/public",
		OperationID: "publicOperation",
		Auth:        authPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(public, "c.internalJSON") {
		t.Fatalf("public operation used internal auth: %s", public)
	}
}
