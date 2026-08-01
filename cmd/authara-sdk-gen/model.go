package main

import "github.com/getkin/kin-openapi/openapi3"

type generator struct {
	doc     *openapi3.T
	schemas map[string]*openapi3.SchemaRef
}

type authMode string

const (
	authPublic         authMode = ""
	authCookie         authMode = "cookie"
	authInternalBearer authMode = "internal_bearer"
)

const authModeExtension = "x-authara-auth-mode"

type operation struct {
	Method       string
	Path         string
	OperationID  string
	RequestType  string
	ResponseType string
	Auth         authMode
	NeedsRequest bool
	NeedsCSRF    bool
	Cookies      []string
	PathParams   []parameter
	QueryParams  []parameter
}

type parameter struct {
	Name    string
	Type    string
	In      string
	Schema  *openapi3.SchemaRef
	Style   string
	Explode *bool
}
