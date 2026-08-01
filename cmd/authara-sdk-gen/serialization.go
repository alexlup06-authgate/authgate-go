package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func (g generator) pathCode(op operation) (string, error) {
	if len(op.PathParams) == 0 {
		return "\tpath := " + fmt.Sprintf("%q", op.Path) + "\n", nil
	}
	expr := fmt.Sprintf("%q", op.Path)
	var prelude strings.Builder
	for i, p := range op.PathParams {
		needle := "{" + p.Name + "}"
		parts := strings.Split(expr, needle)
		if err := validateParameterSerialization(p, "path"); err != nil {
			return "", err
		}
		value := lowerName(p.Name)
		if parameterIsArray(p) {
			valuesName := fmt.Sprintf("pathValues%d", i)
			itemName := fmt.Sprintf("pathItem%d", i)
			itemExpr, err := g.parameterItemStringExpr(p, itemName)
			if err != nil {
				return "", err
			}
			prelude.WriteString(fmt.Sprintf("\t%s := make([]string, len(%s))\n", valuesName, value))
			prelude.WriteString(fmt.Sprintf("\tfor i, %s := range %s {\n", itemName, value))
			prelude.WriteString(fmt.Sprintf("\t\t%s[i] = %s\n", valuesName, itemExpr))
			prelude.WriteString("\t}\n")
			value = fmt.Sprintf("strings.Join(%s, \",\")", valuesName)
		} else {
			var err error
			value, err = g.parameterStringExpr(p, value)
			if err != nil {
				return "", err
			}
		}
		expr = strings.Join(parts, "\" + url.PathEscape("+value+") + \"")
	}
	return prelude.String() + "\tpath := " + expr + "\n", nil
}

func (g generator) writeQueryParameter(b *bytes.Buffer, p parameter, index int) error {
	if err := validateParameterSerialization(p, "query"); err != nil {
		return err
	}
	value := lowerName(p.Name)
	if parameterIsArray(p) {
		valuesName := fmt.Sprintf("queryValues%d", index)
		itemName := fmt.Sprintf("queryItem%d", index)
		itemExpr, err := g.parameterItemStringExpr(p, itemName)
		if err != nil {
			return err
		}
		b.WriteString(fmt.Sprintf("\t%s := make([]string, len(%s))\n", valuesName, value))
		b.WriteString(fmt.Sprintf("\tfor i, %s := range %s {\n", itemName, value))
		b.WriteString(fmt.Sprintf("\t\t%s[i] = %s\n", valuesName, itemExpr))
		b.WriteString("\t}\n")

		style, explode := parameterSerialization(p, "query")
		if style == "form" && explode {
			b.WriteString(fmt.Sprintf("\tfor _, value := range %s {\n", valuesName))
			b.WriteString(fmt.Sprintf("\t\tquery.Add(%q, value)\n", p.Name))
			b.WriteString("\t}\n")
			return nil
		}
		delimiter, ok := queryArrayDelimiter(style)
		if !ok {
			return fmt.Errorf("query parameter %q uses unsupported array style %q", p.Name, style)
		}
		b.WriteString(fmt.Sprintf("\tquery.Set(%q, strings.Join(%s, %q))\n", p.Name, valuesName, delimiter))
		return nil
	}

	value, err := g.parameterStringExpr(p, value)
	if err != nil {
		return err
	}
	if p.Name == "audience" {
		value = "audienceOrApp(" + value + ")"
	}
	b.WriteString(fmt.Sprintf("\tquery.Set(%q, %s)\n", p.Name, value))
	return nil
}

func parameterSerialization(p parameter, in string) (string, bool) {
	style := p.Style
	if style == "" {
		if in == "path" {
			return "simple", false
		}
		return "form", true
	}
	if p.Explode != nil {
		return style, *p.Explode
	}
	return style, style == "form"
}

func validateParameterSerialization(p parameter, in string) error {
	style, _ := parameterSerialization(p, in)
	if in == "path" {
		if style != "simple" {
			return fmt.Errorf("path parameter %q uses unsupported style %q", p.Name, style)
		}
		return nil
	}
	if parameterIsArray(p) {
		if _, ok := queryArrayDelimiter(style); !ok {
			return fmt.Errorf("query parameter %q uses unsupported array style %q", p.Name, style)
		}
		return nil
	}
	if style != "form" {
		return fmt.Errorf("query parameter %q uses unsupported scalar style %q", p.Name, style)
	}
	return nil
}

func queryArrayDelimiter(style string) (string, bool) {
	switch style {
	case "form":
		return ",", true
	case "spaceDelimited":
		return " ", true
	case "pipeDelimited":
		return "|", true
	default:
		return "", false
	}
}

func queryArrayNeedsJoin(p parameter) bool {
	style, explode := parameterSerialization(p, "query")
	return !(style == "form" && explode)
}

func parameterIsArray(p parameter) bool {
	if schemaType, _ := parameterSchemaType(p); schemaType != "" {
		return schemaType == "array"
	}
	return strings.HasPrefix(p.Type, "[]")
}

func parameterSchemaType(p parameter) (string, string) {
	if p.Schema == nil || p.Schema.Value == nil || p.Schema.Value.Type == nil {
		return "", ""
	}
	types := p.Schema.Value.Type.Slice()
	if len(types) == 0 {
		return "", p.Schema.Value.Format
	}
	return types[0], p.Schema.Value.Format
}

func (g generator) parameterItemStringExpr(p parameter, value string) (string, error) {
	if p.Schema != nil && p.Schema.Value != nil && p.Schema.Value.Items != nil {
		return g.schemaStringExpr(p.Schema.Value.Items, g.goType(p.Schema.Value.Items), value)
	}
	if strings.HasPrefix(p.Type, "[]") {
		return scalarTypeStringExpr(strings.TrimPrefix(p.Type, "[]"), "", value)
	}
	return "", fmt.Errorf("array parameter %q has no item schema", p.Name)
}

func (g generator) parameterStringExpr(p parameter, value string) (string, error) {
	if parameterIsArray(p) {
		return "", fmt.Errorf("parameter %q is an array", p.Name)
	}
	if p.Schema != nil {
		return g.schemaStringExpr(p.Schema, p.Type, value)
	}
	return scalarTypeStringExpr(p.Type, "", value)
}

func (g generator) schemaStringExpr(ref *openapi3.SchemaRef, goType, value string) (string, error) {
	if ref == nil || ref.Value == nil {
		return scalarTypeStringExpr(goType, "", value)
	}
	schemaType, schemaFormat := parameterSchemaType(parameter{Schema: ref})
	if schemaType == "" {
		return scalarTypeStringExpr(goType, schemaFormat, value)
	}
	if schemaType == "array" || schemaType == "object" {
		return "", fmt.Errorf("unsupported non-scalar parameter schema type %q", schemaType)
	}
	return scalarTypeStringExpr(goType, schemaFormat, value, schemaType)
}

func scalarTypeStringExpr(goType, format, value string, schemaTypes ...string) (string, error) {
	schemaType := ""
	if len(schemaTypes) > 0 {
		schemaType = schemaTypes[0]
	}
	if schemaType == "" {
		switch goType {
		case "string":
			schemaType = "string"
		case "bool":
			schemaType = "boolean"
		case "int", "int32", "int64":
			schemaType = "integer"
		case "float64":
			schemaType = "number"
		case "uuid.UUID", "time.Time":
			schemaType = "string"
		default:
			return "", fmt.Errorf("unsupported parameter type %q", goType)
		}
	}

	switch schemaType {
	case "string":
		switch format {
		case "uuid":
			if goType == "uuid.UUID" {
				return value + ".String()", nil
			}
			return "uuid.UUID(" + value + ").String()", nil
		case "date-time":
			if goType == "time.Time" {
				return value + ".Format(time.RFC3339Nano)", nil
			}
			return "time.Time(" + value + ").Format(time.RFC3339Nano)", nil
		default:
			if goType == "string" {
				return value, nil
			}
			return "string(" + value + ")", nil
		}
	case "boolean":
		return "strconv.FormatBool(bool(" + value + "))", nil
	case "integer":
		return "strconv.FormatInt(int64(" + value + "), 10)", nil
	case "number":
		return "strconv.FormatFloat(float64(" + value + "), 'g', -1, 64)", nil
	default:
		return "", fmt.Errorf("unsupported parameter schema type %q", schemaType)
	}
}
