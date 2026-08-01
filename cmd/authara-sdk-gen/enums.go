package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type enumConstant struct {
	name     string
	typeName string
	literal  string
}

func (g generator) enumConstants() []enumConstant {
	var constants []enumConstant
	seen := map[string]bool{}
	add := func(prefix, typeName string, values []any) {
		for index, value := range values {
			literal, ok := enumLiteral(value)
			if !ok {
				continue
			}
			name := prefix + enumValueName(value, index)
			if seen[name] {
				continue
			}
			seen[name] = true
			constants = append(constants, enumConstant{name: name, typeName: typeName, literal: literal})
		}
	}

	var walk func(*openapi3.SchemaRef, string, string)
	walk = func(ref *openapi3.SchemaRef, prefix, typeName string) {
		if ref == nil || ref.Ref != "" || ref.Value == nil {
			return
		}
		schema := ref.Value
		if len(schema.Enum) > 0 {
			add(prefix, typeName, schema.Enum)
		}
		types := schema.Type.Slice()
		if len(types) != 1 {
			return
		}
		switch types[0] {
		case "array":
			walk(schema.Items, prefix+"Item", "")
		case "object":
			props := make([]string, 0, len(schema.Properties))
			for prop := range schema.Properties {
				props = append(props, prop)
			}
			sort.Strings(props)
			for _, prop := range props {
				walk(schema.Properties[prop], prefix+goName(prop), "")
			}
			if schema.AdditionalProperties.Schema != nil {
				walk(schema.AdditionalProperties.Schema, prefix+"Value", "")
			}
		}
	}

	for _, name := range sortedSchemaNames(g.schemas) {
		walk(g.schemas[name], apiTypeName(name), apiTypeName(name))
	}
	if g.doc != nil && g.doc.Components != nil {
		parameterNames := make([]string, 0, len(g.doc.Components.Parameters))
		for name := range g.doc.Components.Parameters {
			parameterNames = append(parameterNames, name)
		}
		sort.Strings(parameterNames)
		for _, name := range parameterNames {
			ref := g.doc.Components.Parameters[name]
			if ref != nil && ref.Value != nil {
				walk(ref.Value.Schema, apiTypeName(name), "")
			}
		}
	}
	if g.doc != nil && g.doc.Paths != nil {
		for _, path := range g.doc.Paths.Map() {
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
				op := path.GetOperation(method)
				if op == nil || op.OperationID == "" {
					continue
				}
				prefix := apiTypeName(op.OperationID)
				for _, ref := range op.Parameters {
					if ref != nil && ref.Value != nil {
						walk(ref.Value.Schema, prefix+goName(ref.Value.Name), "")
					}
				}
				if op.RequestBody != nil && op.RequestBody.Value != nil {
					if content := op.RequestBody.Value.Content.Get("application/json"); content != nil {
						walk(content.Schema, prefix+"Request", "")
					}
				}
				if op.Responses != nil {
					for _, status := range op.Responses.Keys() {
						if !strings.HasPrefix(status, "2") {
							continue
						}
						if response := op.Responses.Value(status); response != nil && response.Value != nil {
							if content := response.Value.Content.Get("application/json"); content != nil {
								walk(content.Schema, prefix+"Response", "")
							}
						}
					}
				}
			}
		}
	}

	sort.Slice(constants, func(i, j int) bool {
		return constants[i].name < constants[j].name
	})
	return constants
}

func enumLiteral(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	literal, err := json.Marshal(value)
	if err != nil || string(literal) == "null" {
		return "", false
	}
	return string(literal), true
}

func enumValueName(value any, index int) string {
	name := strings.TrimSpace(fmt.Sprint(value))
	if name == "" {
		return fmt.Sprintf("Value%d", index)
	}
	return goName(name)
}
