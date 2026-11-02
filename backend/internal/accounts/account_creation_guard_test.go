package accounts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// backendRoot is the module root seen from this package directory
// (backend/internal/accounts).
const backendRoot = "../.."

// accountCreators lists the only production functions allowed to insert an
// account, with the call that guarantees the account is never left without a
// second factor outside its setup window: CreateAccount opens the window in
// the same transaction, Enrollment.Complete saves the confirmed factor.
var accountCreators = map[string]string{
	"CreateAccount": "OpenSecondFactorSetup",
	"Complete":      "SaveSetup",
}

type productionFunction struct {
	path        string
	declaration *ast.FuncDecl
}

// productionFunctions parses every non-test Go file of the module.
func productionFunctions(testContext *testing.T) []productionFunction {
	testContext.Helper()
	var functions []productionFunction
	fileSet := token.NewFileSet()
	walkError := filepath.WalkDir(backendRoot, func(path string, entry fs.DirEntry, entryError error) error {
		if entryError != nil {
			return entryError
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsedFile, parseError := parser.ParseFile(fileSet, path, nil, 0)
		if parseError != nil {
			return parseError
		}
		for _, declaration := range parsedFile.Decls {
			if functionDeclaration, isFunction := declaration.(*ast.FuncDecl); isFunction {
				functions = append(functions, productionFunction{path: path, declaration: functionDeclaration})
			}
		}
		return nil
	})
	if walkError != nil {
		testContext.Fatal(walkError)
	}
	return functions
}

func insertsAccountRow(body ast.Node) bool {
	foundInsert := false
	ast.Inspect(body, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING {
			return true
		}
		literalText, unquoteError := strconv.Unquote(literal.Value)
		if unquoteError != nil {
			literalText = literal.Value
		}
		if strings.Contains(strings.Join(strings.Fields(literalText), " "), "INSERT INTO account ") {
			foundInsert = true
		}
		return true
	})
	return foundInsert
}

func callsFunction(body ast.Node, functionName string) bool {
	foundCall := false
	ast.Inspect(body, func(node ast.Node) bool {
		callExpression, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch callee := callExpression.Fun.(type) {
		case *ast.Ident:
			foundCall = foundCall || callee.Name == functionName
		case *ast.SelectorExpr:
			foundCall = foundCall || callee.Sel.Name == functionName
		}
		return true
	})
	return foundCall
}

func TestNoProductionCodeCreatesFactorlessAccountOutsideSetupWindow(testContext *testing.T) {
	functions := productionFunctions(testContext)
	inserterNames := map[string]bool{}
	for _, function := range functions {
		if function.declaration.Body != nil && insertsAccountRow(function.declaration.Body) {
			inserterNames[function.declaration.Name.Name] = true
		}
	}
	if len(inserterNames) != 1 || !inserterNames["insertPasswordAccount"] {
		testContext.Fatalf("only insertPasswordAccount may insert an account row, found %v", inserterNames)
	}

	foundCreators := map[string]bool{}
	for _, function := range functions {
		body := function.declaration.Body
		if body == nil || !callsFunction(body, "insertPasswordAccount") {
			continue
		}
		functionName := function.declaration.Name.Name
		requiredCall, isAllowedCreator := accountCreators[functionName]
		if !isAllowedCreator {
			testContext.Errorf("%s: %s inserts an account but is not an allowed creator", function.path, functionName)
			continue
		}
		if !callsFunction(body, requiredCall) {
			testContext.Errorf("%s: %s inserts an account without calling %s", function.path, functionName, requiredCall)
		}
		foundCreators[functionName] = true
	}
	for creatorName := range accountCreators {
		if !foundCreators[creatorName] {
			testContext.Errorf("expected %s to create accounts through insertPasswordAccount", creatorName)
		}
	}
}
