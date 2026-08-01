package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func (g generator) operations() ([]operation, error) {
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
			}
			operation.PathParams, operation.QueryParams = g.parameters(pathItem.Parameters, op.Parameters)
			operation.RequestType = g.requestType(op)
			operation.ResponseType = g.responseType(op)
			var err error
			operation.Auth, operation.Cookies, operation.NeedsCSRF, err = g.security(op)
			if err != nil {
				return nil, fmt.Errorf("operation %s %s (%s): %w", method, path, op.OperationID, err)
			}
			operation.NeedsRequest = operation.Auth == authCookie
			ops = append(ops, operation)
		}
	}
	return ops, nil
}

func (g generator) parameters(groups ...openapi3.Parameters) ([]parameter, []parameter) {
	var pathParams, queryParams []parameter
	for _, group := range groups {
		for _, ref := range group {
			if ref == nil || ref.Value == nil {
				continue
			}
			p := parameter{
				Name:    ref.Value.Name,
				Type:    g.goType(ref.Value.Schema),
				In:      ref.Value.In,
				Schema:  ref.Value.Schema,
				Style:   ref.Value.Style,
				Explode: ref.Value.Explode,
			}
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
