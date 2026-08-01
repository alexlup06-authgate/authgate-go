package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/getkin/kin-openapi/openapi3"
)

type generator struct {
	doc     *openapi3.T
	schemas map[string]*openapi3.SchemaRef
}

type operation struct {
	Method       string
	Path         string
	OperationID  string
	RequestType  string
	ResponseType string
	Internal     bool
	NeedsRequest bool
	NeedsCSRF    bool
	Cookies      []string
	PathParams   []parameter
	QueryParams  []parameter
}

type parameter struct {
	Name string
	Type string
}

func main() {
	openapiPath := flag.String("openapi", "contract/openapi.yaml", "OpenAPI contract path")
	outDir := flag.String("out", "", "SDK authara package directory")
	flag.Parse()
	if strings.TrimSpace(*outDir) == "" {
		log.Fatal("-out is required")
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(*openapiPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		log.Fatal(err)
	}

	g := generator{
		doc:     doc,
		schemas: doc.Components.Schemas,
	}

	if err := writeGenerated(filepath.Join(*outDir, "openapi_types.gen.go"), g.typesFile()); err != nil {
		log.Fatal(err)
	}
	if err := writeGenerated(filepath.Join(*outDir, "openapi_client.gen.go"), g.clientFile()); err != nil {
		log.Fatal(err)
	}
}

func writeGenerated(path string, src []byte) error {
	if !strings.HasSuffix(path, ".gen.go") {
		return fmt.Errorf("refusing to write non-generated file %s", path)
	}
	formatted, err := format.Source(src)
	if err != nil {
		return fmt.Errorf("format %s: %w\n%s", path, err, src)
	}
	return os.WriteFile(path, formatted, 0o644)
}

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

func (g generator) clientFile() []byte {
	var b bytes.Buffer
	b.WriteString(g.header())
	b.WriteString("import (\n")
	b.WriteString("\t\"context\"\n")
	b.WriteString("\t\"net/http\"\n")
	b.WriteString("\t\"net/url\"\n")
	b.WriteString("\n\t\"github.com/google/uuid\"\n")
	b.WriteString(")\n\n")
	b.WriteString(`func apiRequestOptions(incoming *http.Request, cookies []string, csrf bool) []requestOption {
	var opts []requestOption
	if len(cookies) > 0 {
		opts = append(opts, func(req *http.Request) {
			if incoming == nil {
				return
			}
			for _, name := range cookies {
				if cookie, err := incoming.Cookie(name); err == nil {
					req.AddCookie(cookie)
				}
			}
		})
	}
	if csrf {
		if token, ok := CSRFToken(incoming); ok {
			opts = append(opts, withCSRFToken(token))
		}
	}
	return opts
}

`)

	for _, op := range g.operations() {
		b.WriteString(g.method(op))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func (g generator) method(op operation) string {
	var b bytes.Buffer
	name := "Call" + goName(op.OperationID)
	params := []string{"ctx context.Context"}
	if op.NeedsRequest {
		params = append(params, "incoming *http.Request")
	}
	for _, p := range op.PathParams {
		params = append(params, lowerName(p.Name)+" "+p.Type)
	}
	for _, p := range op.QueryParams {
		params = append(params, lowerName(p.Name)+" "+p.Type)
	}
	if op.RequestType != "" {
		params = append(params, "body "+op.RequestType)
	}

	resultType := "error"
	if op.ResponseType != "" {
		resultType = "(*" + op.ResponseType + ", error)"
	}
	b.WriteString(fmt.Sprintf("func (c *Client) %s(%s) %s {\n", name, strings.Join(params, ", "), resultType))
	if op.ResponseType != "" {
		b.WriteString("\tvar out " + op.ResponseType + "\n")
	}
	b.WriteString("\tpath := " + pathExpr(op) + "\n")
	if len(op.QueryParams) > 0 {
		separator := "?"
		for _, p := range op.QueryParams {
			value := lowerName(p.Name)
			if p.Name == "audience" {
				value = "audienceOrApp(" + value + ")"
			}
			b.WriteString(fmt.Sprintf("\tpath += \"%s%s=\" + url.QueryEscape(%s)\n", separator, p.Name, value))
			separator = "&"
		}
	}
	body := "nil"
	if op.RequestType != "" {
		body = "body"
	}
	out := "nil"
	if op.ResponseType != "" {
		out = "&out"
	}
	if op.Internal {
		b.WriteString(fmt.Sprintf("\terr := c.internalJSON(ctx, %s, path, %s, %s)\n", methodConst(op.Method), body, out))
	} else if op.NeedsRequest {
		b.WriteString(fmt.Sprintf("\t_, err := c.doJSONBody(ctx, %s, path, %s, %s, apiRequestOptions(incoming, %#v, %t)...)\n", methodConst(op.Method), body, out, op.Cookies, op.NeedsCSRF))
	} else {
		b.WriteString(fmt.Sprintf("\t_, err := c.doJSONBody(ctx, %s, path, %s, %s)\n", methodConst(op.Method), body, out))
	}
	b.WriteString("\tif err != nil {\n")
	if op.ResponseType != "" {
		b.WriteString("\t\treturn nil, err\n")
	} else {
		b.WriteString("\t\treturn err\n")
	}
	b.WriteString("\t}\n")
	if op.ResponseType != "" {
		b.WriteString("\treturn &out, nil\n")
	} else {
		b.WriteString("\treturn nil\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (g generator) operations() []operation {
	var ops []operation
	paths := g.doc.Paths.Map()
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	for _, path := range pathNames {
		pathItem := paths[path]
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
			op := pathItem.GetOperation(method)
			if op == nil || op.OperationID == "" {
				continue
			}
			operation := operation{
				Method:      method,
				Path:        path,
				OperationID: op.OperationID,
				Internal:    strings.HasPrefix(path, "/auth/internal/"),
			}
			operation.PathParams, operation.QueryParams = g.parameters(pathItem.Parameters, op.Parameters)
			operation.RequestType = g.requestType(op)
			operation.ResponseType = g.responseType(op)
			operation.Cookies, operation.NeedsCSRF = g.security(op)
			operation.NeedsRequest = !operation.Internal && (len(operation.Cookies) > 0 || operation.NeedsCSRF)
			ops = append(ops, operation)
		}
	}
	return ops
}

func (g generator) parameters(groups ...openapi3.Parameters) ([]parameter, []parameter) {
	var pathParams, queryParams []parameter
	for _, group := range groups {
		for _, ref := range group {
			if ref == nil || ref.Value == nil {
				continue
			}
			p := parameter{Name: ref.Value.Name, Type: g.goType(ref.Value.Schema)}
			switch ref.Value.In {
			case "path":
				pathParams = append(pathParams, p)
			case "query":
				queryParams = append(queryParams, p)
			}
		}
	}
	return pathParams, queryParams
}

func (g generator) requestType(op *openapi3.Operation) string {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return ""
	}
	content := op.RequestBody.Value.Content.Get("application/json")
	if content == nil || content.Schema == nil {
		return ""
	}
	return g.goType(content.Schema)
}

func (g generator) responseType(op *openapi3.Operation) string {
	statuses := op.Responses.Keys()
	sort.Strings(statuses)
	for _, status := range statuses {
		if !strings.HasPrefix(status, "2") {
			continue
		}
		resp := op.Responses.Value(status)
		if resp == nil || resp.Value == nil {
			continue
		}
		content := resp.Value.Content.Get("application/json")
		if content == nil || content.Schema == nil {
			return ""
		}
		return g.goType(content.Schema)
	}
	return ""
}

func (g generator) security(op *openapi3.Operation) ([]string, bool) {
	var cookies []string
	seen := map[string]bool{}
	needsCSRF := false
	if op.Security == nil {
		return cookies, needsCSRF
	}
	for _, requirement := range *op.Security {
		for name := range requirement {
			switch name {
			case "csrfHeader":
				needsCSRF = true
			case "accessCookie", "refreshCookie", "csrfCookie", "oauthNonceCookie":
				scheme := g.doc.Components.SecuritySchemes[name]
				if scheme != nil && scheme.Value != nil && scheme.Value.Name != "" && !seen[scheme.Value.Name] {
					cookies = append(cookies, scheme.Value.Name)
					seen[scheme.Value.Name] = true
				}
			}
		}
	}
	sort.Strings(cookies)
	return cookies, needsCSRF
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

func pathExpr(op operation) string {
	if len(op.PathParams) == 0 {
		return fmt.Sprintf("%q", op.Path)
	}
	expr := fmt.Sprintf("%q", op.Path)
	for _, p := range op.PathParams {
		needle := "{" + p.Name + "}"
		parts := strings.Split(expr, needle)
		value := lowerName(p.Name)
		if p.Type == "uuid.UUID" {
			value += ".String()"
		}
		expr = strings.Join(parts, "\" + url.PathEscape("+value+") + \"")
	}
	return expr
}

func methodConst(method string) string {
	switch method {
	case http.MethodGet:
		return "http.MethodGet"
	case http.MethodPost:
		return "http.MethodPost"
	case http.MethodPatch:
		return "http.MethodPatch"
	case http.MethodPut:
		return "http.MethodPut"
	case http.MethodDelete:
		return "http.MethodDelete"
	default:
		return fmt.Sprintf("%q", method)
	}
}

func (g generator) header() string {
	return "// Code generated by authara-sdk-gen from authara-core/contract/openapi.yaml; DO NOT EDIT.\n\npackage authara\n\n"
}

func apiTypeName(name string) string {
	return "API" + goName(name)
}

func goName(s string) string {
	words := splitIdentifier(s)
	var out strings.Builder
	for _, word := range words {
		lower := strings.ToLower(word)
		if initialism, ok := initialisms[lower]; ok {
			out.WriteString(initialism)
			continue
		}
		out.WriteString(strings.ToUpper(lower[:1]) + lower[1:])
	}
	if out.Len() == 0 {
		panic(errors.New("empty Go identifier"))
	}
	return out.String()
}

func lowerName(s string) string {
	name := goName(s)
	return strings.ToLower(name[:1]) + name[1:]
}

func splitIdentifier(s string) []string {
	var words []string
	for _, segment := range strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		runes := []rune(segment)
		start := 0
		for i := 1; i < len(runes); i++ {
			prev := runes[i-1]
			curr := runes[i]
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			split := unicode.IsDigit(prev) != unicode.IsDigit(curr) ||
				(unicode.IsUpper(curr) && (unicode.IsLower(prev) || unicode.IsDigit(prev))) ||
				(unicode.IsUpper(prev) && unicode.IsUpper(curr) && next != 0 && unicode.IsLower(next))
			if split {
				words = append(words, string(runes[start:i]))
				start = i
			}
		}
		words = append(words, string(runes[start:]))
	}
	return words
}

var initialisms = map[string]string{
	"api":   "API",
	"csrf":  "CSRF",
	"id":    "ID",
	"json":  "JSON",
	"oauth": "OAuth",
	"url":   "URL",
}
