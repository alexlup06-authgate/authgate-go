package main

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestMethodSerializesTypedParameters(t *testing.T) {
	intParam := testParameter("id", "path", "integer", "", "int")
	dateTimeParam := testParameter("when", "path", "string", "date-time", "time.Time")
	uuidParam := testParameter("requestID", "path", "string", "uuid", "uuid.UUID")
	boolParam := testParameter("active", "query", "boolean", "", "bool")
	regionParam := testParameter("region", "query", "string", "", "APIRegion")

	src, err := (generator{}).method(operation{
		Path:        "/things/{id}/{when}/{requestID}",
		OperationID: "getThing",
		PathParams:  []parameter{intParam, dateTimeParam, uuidParam},
		QueryParams: []parameter{boolParam, regionParam},
		Auth:        authPublic,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		`url.PathEscape(strconv.FormatInt(int64(iD), 10))`,
		`url.PathEscape(when.Format(time.RFC3339Nano))`,
		`url.PathEscape(requestID.String())`,
		`query.Set("active", strconv.FormatBool(bool(active)))`,
		`query.Set("region", string(region))`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("generated method is missing %q: %s", want, src)
		}
	}
}

func TestMethodSerializesQueryArrays(t *testing.T) {
	items := &openapi3.SchemaRef{Value: &openapi3.Schema{Type: typesPtr("string")}}
	arraySchema := &openapi3.SchemaRef{Value: &openapi3.Schema{
		Type:  typesPtr("array"),
		Items: items,
	}}
	explode := false

	src, err := (generator{}).method(operation{
		Path:        "/things",
		OperationID: "listThings",
		QueryParams: []parameter{
			{
				Name:    "tags",
				Type:    "[]string",
				In:      "query",
				Schema:  arraySchema,
				Style:   "form",
				Explode: &explode,
			},
			{
				Name:   "labels",
				Type:   "[]string",
				In:     "query",
				Schema: arraySchema,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		`for i, queryItem0 := range tags`,
		`queryValues0[i] = queryItem0`,
		`query.Set("tags", strings.Join(queryValues0, ","))`,
		`for i, queryItem1 := range labels`,
		`query.Add("labels", value)`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("generated array query is missing %q: %s", want, src)
		}
	}
}

func TestClientImportsParameterSerializationDependencies(t *testing.T) {
	src := (generator{}).clientImports([]operation{{
		PathParams: []parameter{
			testParameter("id", "path", "string", "uuid", "uuid.UUID"),
			testParameter("when", "path", "string", "date-time", "time.Time"),
		},
		QueryParams: []parameter{
			testParameter("limit", "query", "integer", "", "int"),
		},
	}})

	for _, want := range []string{"\"net/url\"", "\"strconv\"", "\"time\"", "\"github.com/google/uuid\""} {
		if !strings.Contains(src, want) {
			t.Fatalf("generated imports are missing %q: %s", want, src)
		}
	}
}

func testParameter(name, in, schemaType, format, goType string) parameter {
	ref := &openapi3.SchemaRef{Value: &openapi3.Schema{
		Type:   typesPtr(schemaType),
		Format: format,
	}}
	if strings.HasPrefix(goType, "API") {
		ref.Ref = "#/components/schemas/" + strings.TrimPrefix(goType, "API")
	}
	return parameter{Name: name, Type: goType, In: in, Schema: ref}
}

func typesPtr(value string) *openapi3.Types {
	types := openapi3.Types{value}
	return &types
}
