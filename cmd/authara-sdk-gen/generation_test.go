package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteGeneratedFilesDoesNotPartiallyReplaceOnFormatError(t *testing.T) {
	dir := t.TempDir()
	typesPath := filepath.Join(dir, "openapi_types.gen.go")
	clientPath := filepath.Join(dir, "openapi_client.gen.go")
	oldTypes := []byte("package authara\n\ntype OldTypes struct{}\n")
	oldClient := []byte("package authara\n\nfunc OldClient() {}\n")
	if err := os.WriteFile(typesPath, oldTypes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, oldClient, 0o644); err != nil {
		t.Fatal(err)
	}

	err := writeGeneratedFiles(
		generatedFile{path: typesPath, src: []byte("package authara\n\ntype NewTypes struct{}\n")},
		generatedFile{path: clientPath, src: []byte("package authara\n\nfunc {")},
	)
	if err == nil {
		t.Fatal("expected client formatting error")
	}

	gotTypes, err := os.ReadFile(typesPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotTypes) != string(oldTypes) {
		t.Fatalf("types file was partially replaced: %s", gotTypes)
	}
	gotClient, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotClient) != string(oldClient) {
		t.Fatalf("client file changed: %s", gotClient)
	}
}
