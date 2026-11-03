package hush

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The module uses only the standard library (ADR-001 section 2; HSH-5/D16
// moved this test here from cmd/hush).
func TestGoModHasNoRequire(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal("cannot read go.mod")
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require") { // also "require(", which Go accepts
			t.Errorf("go.mod line %d: require", i+1)
		}
	}
	if _, err := os.Stat("go.sum"); err == nil {
		t.Error("go.sum exists")
	}
	leak(t, string(data))
}

// undocumented returns every exported identifier in f without a doc comment:
// functions, methods of exported types, types, constants, variables and
// struct fields. A field or a value in a group may carry a line comment
// instead, and a value spec in a documented group needs none of its own.
func undocumented(f *ast.File) []string {
	var missing []string
	exportedRecv := func(fd *ast.FuncDecl) bool {
		if fd.Recv == nil {
			return true
		}
		typ := fd.Recv.List[0].Type
		if st, ok := typ.(*ast.StarExpr); ok {
			typ = st.X
		}
		id, ok := typ.(*ast.Ident)
		return ok && id.IsExported()
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() && exportedRecv(d) && d.Doc == nil {
				missing = append(missing, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					if sp.Name.IsExported() && sp.Doc == nil && (d.Doc == nil || len(d.Specs) > 1) {
						missing = append(missing, sp.Name.Name)
					}
					if st, ok := sp.Type.(*ast.StructType); ok && sp.Name.IsExported() {
						for _, fld := range st.Fields.List {
							for _, n := range fld.Names {
								if n.IsExported() && fld.Doc == nil && fld.Comment == nil {
									missing = append(missing, sp.Name.Name+"."+n.Name)
								}
							}
						}
					}
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						if n.IsExported() && sp.Doc == nil && sp.Comment == nil && d.Doc == nil {
							missing = append(missing, n.Name)
						}
					}
				}
			}
		}
	}
	return missing
}

// ADR-001 section 7 and the issue's second criterion: every exported identifier
// of package hush has a doc comment.
func TestDocComments(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("cannot parse %s", name)
		}
		n++
		if f.Doc == nil && name == "hush.go" {
			t.Error("the package has no doc comment")
		}
		for _, id := range undocumented(f) {
			t.Errorf("%s: %s has no doc comment", name, id)
		}
	}
	if n < 5 {
		t.Fatalf("checked only %d files", n)
	}
}

// The check behind TestDocComments reports each kind of identifier it covers
// when its comment is missing.
func TestDocCommentsPlanted(t *testing.T) {
	src := `package p
// Doc is documented.
type Doc struct {
	A int // documented
	B int
	c int
}
func F() {}
func (Doc) M() {}
func (*Doc) N() {}
type hidden struct{ X int }
func (hidden) P() {}
const C = 1
var (
	V1 = 1 // documented
	V2 = 2
)
type (
	// T1 is documented.
	T1 int
	T2 int
)
`
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(undocumented(f), " ")
	if got != "Doc.B F M N C V2 T2" {
		t.Errorf("got %q", got)
	}
}
