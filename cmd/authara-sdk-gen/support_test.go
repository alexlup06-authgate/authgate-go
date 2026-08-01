package main

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestValidateSupportRejectsInlineObject(t *testing.T) {
	object := &openapi3.Schema{
		Type:                 typesPtr("object"),
		AdditionalProperties: openapi3.AdditionalProperties{Has: boolPtr(false)},
		Properties: openapi3.Schemas{
			"profile": {Value: &openapi3.Schema{
				Type: typesPtr("object"),
				Properties: openapi3.Schemas{
					"timezone": {Value: &openapi3.Schema{Type: typesPtr("string")}},
				},
			}},
		},
	}

	err := (generator{schemas: map[string]*openapi3.SchemaRef{
		"User": {Value: object},
	}}).validateSupport()
	if err == nil || !strings.Contains(err.Error(), "inline objects with properties are unsupported") {
		t.Fatalf("expected inline object error, got %v", err)
	}
}

func TestValidateSupportRejectsCompositionsAndNullable(t *testing.T) {
	for name, schema := range map[string]*openapi3.Schema{
		"oneOf": {
			Type:  typesPtr("string"),
			OneOf: openapi3.SchemaRefs{{Value: &openapi3.Schema{Type: typesPtr("string")}}},
		},
		"nullable": {Type: typesPtr("string"), Nullable: true},
	} {
		err := (generator{schemas: map[string]*openapi3.SchemaRef{
			name: {Value: schema},
		}}).validateSupport()
		if err == nil {
			t.Fatalf("expected %s schema to be rejected", name)
		}
	}
}

func TestValidateSupportAllowsOpaqueAndTypedMaps(t *testing.T) {
	for name, schema := range map[string]*openapi3.Schema{
		"Opaque": {
			Type:                 typesPtr("object"),
			AdditionalProperties: openapi3.AdditionalProperties{Has: boolPtr(true)},
		},
		"Typed": {
			Type: typesPtr("object"),
			AdditionalProperties: openapi3.AdditionalProperties{Schema: &openapi3.SchemaRef{
				Value: &openapi3.Schema{Type: typesPtr("string")},
			}},
		},
	} {
		if err := (generator{schemas: map[string]*openapi3.SchemaRef{
			name: {Value: schema},
		}}).validateSupport(); err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
	}
}

func TestGoTypePreservesIntegerFormats(t *testing.T) {
	for format, want := range map[string]string{
		"int32": "int32",
		"int64": "int64",
		"":      "int",
	} {
		got := (generator{}).goType(&openapi3.SchemaRef{Value: &openapi3.Schema{
			Type:   typesPtr("integer"),
			Format: format,
		}})
		if got != want {
			t.Fatalf("format %q: got %q, want %q", format, got, want)
		}
	}
}

func TestOptionalCollectionsPreservePresence(t *testing.T) {
	if got := optionalType("[]string"); got != "*[]string" {
		t.Fatalf("optional slice type: got %q", got)
	}
	if got := optionalType("map[string]any"); got != "*map[string]any" {
		t.Fatalf("optional map type: got %q", got)
	}
}

func TestTypesFileEmitsEnumConstants(t *testing.T) {
	schema := &openapi3.Schema{
		Type:                 typesPtr("object"),
		AdditionalProperties: openapi3.AdditionalProperties{Has: boolPtr(false)},
		Properties: openapi3.Schemas{
			"status": {Value: &openapi3.Schema{
				Type: typesPtr("string"),
				Enum: []any{"active", "disabled"},
			}},
		},
	}

	src := string((generator{schemas: map[string]*openapi3.SchemaRef{
		"User": {Value: schema},
	}}).typesFile())
	for _, want := range []string{
		`const APIUserStatusActive = "active"`,
		`const APIUserStatusDisabled = "disabled"`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("generated types are missing %q: %s", want, src)
		}
	}
}

func boolPtr(value bool) *bool {
	return &value
}
