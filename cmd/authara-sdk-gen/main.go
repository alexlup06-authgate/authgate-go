package main

import (
	"context"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

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

	clientSrc, err := g.clientFile()
	if err != nil {
		log.Fatal(err)
	}
	if err := writeGenerated(filepath.Join(*outDir, "openapi_types.gen.go"), g.typesFile()); err != nil {
		log.Fatal(err)
	}
	if err := writeGenerated(filepath.Join(*outDir, "openapi_client.gen.go"), clientSrc); err != nil {
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
