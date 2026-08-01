package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func (g generator) typesFile() []byte {
	var b bytes.Buffer
	b.WriteString(g.header())
	b.WriteString("import (\n")
	b.WriteString("\t\"time\"\n\n")
	b.WriteString("\t\"github.com/google/uuid\"\n")
	b.WriteString(")\n\n")

	names := make([]string, 0, len(g.schemas))
	for name := range g.schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		schema := g.schemas[name].Value
		if schema == nil {
			continue
		}
		typeName := apiTypeName(name)
		if len(schema.Type.Slice()) == 1 && schema.Type.Slice()[0] == "object" && len(schema.Properties) > 0 {
			b.WriteString("type " + typeName + " struct {\n")
			required := map[string]bool{}
			for _, field := range schema.Required {
				required[field] = true
			}
			props := make([]string, 0, len(schema.Properties))
			for prop := range schema.Properties {
				props = append(props, prop)
			}
			sort.Strings(props)
			for _, prop := range props {
				propSchema := schema.Properties[prop]
				fieldType := g.goType(propSchema)
				jsonName := prop
				if !required[prop] {
					jsonName += ",omitempty"
					fieldType = optionalType(fieldType)
				}
				b.WriteString(fmt.Sprintf("\t%s %s `json:\"%s\"`\n", goName(prop), fieldType, jsonName))
			}
			b.WriteString("}\n\n")
			continue
		}
		b.WriteString(fmt.Sprintf("type %s %s\n\n", typeName, g.goType(g.schemas[name])))
	}
	return b.Bytes()
}

func (g generator) goType(ref *openapi3.SchemaRef) string {
	if ref == nil {
		return "any"
	}
	if ref.Ref != "" {
		const prefix = "#/components/schemas/"
		if strings.HasPrefix(ref.Ref, prefix) {
			return apiTypeName(strings.TrimPrefix(ref.Ref, prefix))
		}
	}
	schema := ref.Value
	if schema == nil {
		return "any"
	}
	types := schema.Type.Slice()
	if len(types) == 0 {
		return "any"
	}
	switch types[0] {
	case "string":
		switch schema.Format {
		case "uuid":
			return "uuid.UUID"
		case "date-time":
			return "time.Time"
		default:
			return "string"
		}
	case "boolean":
		return "bool"
	case "integer":
		return "int"
	case "number":
		return "float64"
	case "array":
		return "[]" + g.goType(schema.Items)
	case "object":
		if schema.AdditionalProperties.Has != nil && *schema.AdditionalProperties.Has {
			return "map[string]any"
		}
		return "map[string]any"
	default:
		return "any"
	}
}

func optionalType(t string) string {
	if strings.HasPrefix(t, "[]") || strings.HasPrefix(t, "map[") {
		return t
	}
	return "*" + t
}
