package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// validateSupport checks the subset of OpenAPI that this generator can map
// without silently weakening the generated Go API.
func (g generator) validateSupport() error {
	for _, name := range sortedSchemaNames(g.schemas) {
		ref := g.schemas[name]
		if ref == nil {
			return fmt.Errorf("schema %q: missing schema reference", name)
		}
		if err := g.validateSchema(ref, "#/components/schemas/"+name, true, map[*openapi3.Schema]bool{}); err != nil {
			return err
		}
	}

	if g.doc == nil || g.doc.Paths == nil {
		return nil
	}
	paths := g.doc.Paths.Map()
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	for _, path := range pathNames {
		pathItem := paths[path]
		if pathItem == nil {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
			op := pathItem.GetOperation(method)
			if op == nil || op.OperationID == "" {
				continue
			}
			location := fmt.Sprintf("%s %s (%s)", method, path, op.OperationID)
			if err := g.validateParameters(pathItem.Parameters, location+" path-level parameter"); err != nil {
				return err
			}
			if err := g.validateParameters(op.Parameters, location+" parameter"); err != nil {
				return err
			}
			if err := g.validateRequestSchema(op, location); err != nil {
				return err
			}
			if err := g.validateResponseSchemas(op, location); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedSchemaNames(schemas map[string]*openapi3.SchemaRef) []string {
	names := make([]string, 0, len(schemas))
	for name := range schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (g generator) validateParameters(parameters openapi3.Parameters, location string) error {
	for _, ref := range parameters {
		if ref == nil || ref.Value == nil {
			return fmt.Errorf("%s: unresolved parameter reference", location)
		}
		parameter := ref.Value
		if parameter.Schema == nil {
			return fmt.Errorf("%s %q: parameter content is unsupported", location, parameter.Name)
		}
		path := fmt.Sprintf("%s %q schema", location, parameter.Name)
		if err := g.validateSchema(parameter.Schema, path, false, map[*openapi3.Schema]bool{}); err != nil {
			return err
		}
	}
	return nil
}

func (g generator) validateRequestSchema(op *openapi3.Operation, location string) error {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	content := op.RequestBody.Value.Content.Get("application/json")
	if content == nil {
		return nil
	}
	if content.Schema == nil {
		return fmt.Errorf("%s request body: application/json schema is missing", location)
	}
	return g.validateSchema(content.Schema, location+" request body", false, map[*openapi3.Schema]bool{})
}

func (g generator) validateResponseSchemas(op *openapi3.Operation, location string) error {
	if op.Responses == nil {
		return nil
	}
	statuses := op.Responses.Keys()
	sort.Strings(statuses)
	for _, status := range statuses {
		if !strings.HasPrefix(status, "2") {
			continue
		}
		response := op.Responses.Value(status)
		if response == nil || response.Value == nil {
			return fmt.Errorf("%s response %s: unresolved response reference", location, status)
		}
		content := response.Value.Content.Get("application/json")
		if content == nil {
			continue
		}
		if content.Schema == nil {
			return fmt.Errorf("%s response %s: application/json schema is missing", location, status)
		}
		if err := g.validateSchema(content.Schema, fmt.Sprintf("%s response %s", location, status), false, map[*openapi3.Schema]bool{}); err != nil {
			return err
		}
	}
	return nil
}

func (g generator) validateSchema(ref *openapi3.SchemaRef, path string, allowStruct bool, seen map[*openapi3.Schema]bool) error {
	if ref == nil {
		return fmt.Errorf("%s: schema is missing", path)
	}
	if ref.Ref != "" {
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(ref.Ref, prefix) {
			return fmt.Errorf("%s: schema reference %q is unsupported", path, ref.Ref)
		}
		name := strings.TrimPrefix(ref.Ref, prefix)
		if _, ok := g.schemas[name]; !ok {
			return fmt.Errorf("%s: schema reference %q is unresolved", path, ref.Ref)
		}
		return nil
	}

	schema := ref.Value
	if schema == nil {
		return fmt.Errorf("%s: schema is unresolved", path)
	}
	if seen[schema] {
		return nil
	}
	seen[schema] = true

	if len(schema.OneOf) > 0 || len(schema.AnyOf) > 0 || len(schema.AllOf) > 0 {
		return fmt.Errorf("%s: oneOf, anyOf, and allOf are unsupported", path)
	}
	if schema.Not != nil {
		return fmt.Errorf("%s: not is unsupported", path)
	}
	if schema.Nullable || schema.Type.IncludesNull() {
		return fmt.Errorf("%s: nullable schemas are unsupported", path)
	}

	types := schema.Type.Slice()
	if len(types) != 1 {
		return fmt.Errorf("%s: schema must have exactly one supported type", path)
	}

	switch types[0] {
	case "string", "boolean", "integer", "number":
		if len(schema.Enum) > 0 {
			for index, value := range schema.Enum {
				if _, ok := enumLiteral(value); !ok {
					return fmt.Errorf("%s enum value %d cannot be represented as a Go constant", path, index)
				}
			}
		}
		return nil
	case "array":
		if schema.Items == nil {
			return fmt.Errorf("%s: array items are missing", path)
		}
		return g.validateSchema(schema.Items, path+" items", false, seen)
	case "object":
		if len(schema.Properties) > 0 {
			if !allowStruct {
				return fmt.Errorf("%s: inline objects with properties are unsupported", path)
			}
			if schema.AdditionalProperties.Schema != nil || schema.AdditionalProperties.Has == nil || *schema.AdditionalProperties.Has {
				return fmt.Errorf("%s: object structs must disallow additional properties", path)
			}
			props := make([]string, 0, len(schema.Properties))
			for prop := range schema.Properties {
				props = append(props, prop)
			}
			sort.Strings(props)
			for _, prop := range props {
				if err := g.validateSchema(schema.Properties[prop], path+" property "+prop, false, seen); err != nil {
					return err
				}
			}
			return nil
		}
		if schema.AdditionalProperties.Schema != nil {
			return g.validateSchema(schema.AdditionalProperties.Schema, path+" values", false, seen)
		}
		if schema.AdditionalProperties.Has != nil && !*schema.AdditionalProperties.Has {
			return fmt.Errorf("%s: empty closed objects are unsupported", path)
		}
		// A property-less object is intentionally represented as opaque JSON.
		return nil
	default:
		return fmt.Errorf("%s: schema type %q is unsupported", path, types[0])
	}
}
