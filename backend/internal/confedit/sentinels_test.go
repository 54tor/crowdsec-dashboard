package confedit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The sidecar maps Sentinels() to wire codes. A sentinel declared in the
// package but missing from the list would silently degrade to a generic
// failure for remote editors, so the declared and listed counts must match.
func TestSentinelsListsEveryExportedErrorVariable(testContext *testing.T) {
	directoryEntries, readError := os.ReadDir(".")
	if readError != nil {
		testContext.Fatalf("read dir: %v", readError)
	}
	declaredNames := map[string]bool{}
	for _, directoryEntry := range directoryEntries {
		isProductionFile := strings.HasSuffix(directoryEntry.Name(), ".go") && !strings.HasSuffix(directoryEntry.Name(), "_test.go")
		if !isProductionFile {
			continue
		}
		parsedFile, parseError := parser.ParseFile(token.NewFileSet(), directoryEntry.Name(), nil, 0)
		if parseError != nil {
			testContext.Fatalf("parse %s: %v", directoryEntry.Name(), parseError)
		}
		for _, declaration := range parsedFile.Decls {
			generalDeclaration, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || generalDeclaration.Tok != token.VAR {
				continue
			}
			for _, specification := range generalDeclaration.Specs {
				for _, name := range specification.(*ast.ValueSpec).Names {
					if strings.HasPrefix(name.Name, "Err") {
						declaredNames[name.Name] = true
					}
				}
			}
		}
	}

	listedSentinels := Sentinels()

	if len(listedSentinels) != len(declaredNames) {
		testContext.Errorf("declared %d exported Err variables %v, Sentinels() lists %d", len(declaredNames), declaredNames, len(listedSentinels))
	}
}
