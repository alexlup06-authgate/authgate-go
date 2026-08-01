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
	if err := g.validateSupport(); err != nil {
		log.Fatal(err)
	}

	clientSrc, err := g.clientFile()
	if err != nil {
		log.Fatal(err)
	}
	if err := writeGeneratedFiles(
		generatedFile{path: filepath.Join(*outDir, "openapi_types.gen.go"), src: g.typesFile()},
		generatedFile{path: filepath.Join(*outDir, "openapi_client.gen.go"), src: clientSrc},
	); err != nil {
		log.Fatal(err)
	}
}

type generatedFile struct {
	path string
	src  []byte
}

type stagedFile struct {
	path string
	temp string
}

func writeGeneratedFiles(files ...generatedFile) (err error) {
	formatted := make([]generatedFile, len(files))
	for i, file := range files {
		if !strings.HasSuffix(file.path, ".gen.go") {
			return fmt.Errorf("refusing to write non-generated file %s", file.path)
		}
		formatted[i] = generatedFile{path: file.path, src: file.src}
		formatted[i].src, err = format.Source(file.src)
		if err != nil {
			return fmt.Errorf("format %s: %w\n%s", file.path, err, file.src)
		}
	}

	staged := make([]stagedFile, 0, len(formatted))
	defer func() {
		if err == nil {
			return
		}
		for _, file := range staged {
			_ = os.Remove(file.temp)
		}
	}()

	for _, file := range formatted {
		temp, createErr := os.CreateTemp(filepath.Dir(file.path), ".authara-sdk-gen-*")
		if createErr != nil {
			return fmt.Errorf("stage %s: %w", file.path, createErr)
		}
		staged = append(staged, stagedFile{path: file.path, temp: temp.Name()})
		if chmodErr := temp.Chmod(0o644); chmodErr != nil {
			_ = temp.Close()
			return fmt.Errorf("stage %s: %w", file.path, chmodErr)
		}
		if _, writeErr := temp.Write(file.src); writeErr != nil {
			_ = temp.Close()
			return fmt.Errorf("stage %s: %w", file.path, writeErr)
		}
		if closeErr := temp.Close(); closeErr != nil {
			return fmt.Errorf("stage %s: %w", file.path, closeErr)
		}
	}

	for _, file := range staged {
		if renameErr := os.Rename(file.temp, file.path); renameErr != nil {
			return fmt.Errorf("replace %s: %w", file.path, renameErr)
		}
	}
	return nil
}
