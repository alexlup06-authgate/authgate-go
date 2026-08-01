package main

import (
	"strings"
	"testing"
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
