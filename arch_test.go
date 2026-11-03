package hush

import (
	"encoding"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nonhumanhq/hush/internal/termset"
)

// The architecture tests of ADR-001 sections 2 and 6.6 (HSH-11/T25, D61).
// Each check reads the module's sources with go/parser, as the build sees
// them (build constraints applied), or walks package hush's types with
// reflect, and each has a planted violation it must report, so a check that
// stops looking fails too.

// srcFile is one parsed Go file: its package's import path and whether it is
// a test file.
type srcFile struct {
	pkg, name string
	test      bool
	file      *ast.File
}

// The module's packages, by import path.
const (
	pkgRoot   = modulePath
	pkgCLI    = modulePath + "/cmd/hush"
	pkgHooks  = modulePath + "/internal/hooks"
	pkgGHWrap = modulePath + "/internal/ghwrap"
	pkgTarget = modulePath + "/internal/target"
	pkgLeak   = modulePath + "/internal/leakcheck"
	pkgSchema = modulePath + "/internal/schema"
)

// moduleFiles parses every Go file of the module that the default build
// context builds, skipping .work, reference, testdata and docs, which hold no
// package of the module.
var moduleFiles = sync.OnceValues(func() (*token.FileSet, []srcFile) {
	fset := token.NewFileSet()
	var files []srcFile
	filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "reference" || d.Name() == "testdata" || d.Name() == "docs") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if ok, err := build.Default.MatchFile(filepath.Dir(path), d.Name()); err != nil || !ok {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		pkg := modulePath
		if dir := filepath.ToSlash(filepath.Dir(path)); dir != "." {
			pkg += "/" + dir
		}
		files = append(files, srcFile{pkg: pkg, name: filepath.ToSlash(path), test: strings.HasSuffix(path, "_test.go"), file: f})
		return nil
	})
	return fset, files
})

// planted parses src as the file name of package pkg, for a planted violation.
func planted(t *testing.T, pkg, name, src string) srcFile {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("planted %s: %v", name, err)
	}
	return srcFile{pkg: pkg, name: name, test: strings.HasSuffix(name, "_test.go"), file: f}
}

// imports maps each import's local name in f to its path.
func imports(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, is := range f.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if is.Name != nil {
			name = is.Name.Name
		}
		m[name] = p
	}
	return m
}

// funcName returns the name of fd as "Recv.Name" or "Name".
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// call is one call of a package-level function, PKG.NAME, in a non-test file.
type call struct {
	f    srcFile
	fn   string // the enclosing function, "" at package level
	path string // the import path of PKG
	name string
	expr *ast.CallExpr
}

// calls returns every call of an imported package's function in the
// non-test files of files.
func calls(files []srcFile) []call {
	var out []call
	for _, f := range files {
		if f.test {
			continue
		}
		imp := imports(f.file)
		visit := func(fn string, n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if se, ok := ce.Fun.(*ast.SelectorExpr); ok {
					if id, ok := se.X.(*ast.Ident); ok && imp[id.Name] != "" && id.Obj == nil {
						out = append(out, call{f, fn, imp[id.Name], se.Sel.Name, ce})
					}
				}
				return true
			})
		}
		for _, d := range f.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				visit(funcName(fd), fd)
			} else {
				visit("", d)
			}
		}
	}
	return out
}

// importViolations: cmd/hush imports no package of the module but hush,
// internal/hooks and internal/ghwrap; those two import none but hush; and the
// test-only packages are imported by test files only (ADR-001 section 2).
func importViolations(files []srcFile) []string {
	var bad []string
	for _, f := range files {
		for _, p := range imports(f.file) {
			if !strings.HasPrefix(p, modulePath) {
				continue
			}
			switch {
			case (p == pkgLeak || p == pkgSchema) && !f.test:
				bad = append(bad, f.name+" imports the test-only "+p)
			case f.test:
			case f.pkg == pkgCLI && p != pkgRoot && p != pkgHooks && p != pkgGHWrap:
				bad = append(bad, f.name+" imports "+p)
			case (f.pkg == pkgHooks || f.pkg == pkgGHWrap) && p != pkgRoot:
				bad = append(bad, f.name+" imports "+p)
			}
		}
	}
	return bad
}

// envAllowed names the functions that may read the environment or hand it
// on, by package: the CLI's git-hook handling (GIT_INDEX_FILE and GIT_DIR in
// index mode; the installer's own path, found on PATH; the installer's git,
// with the caller's configuration), and gh's one launch (ADR-001 negative
// test 3; HSH-11/D59).
var envAllowed = map[string][]string{
	pkgCLI:    {"indexFile", "gitDir", "hushPath"},
	pkgHooks:  {"hookGit"},
	pkgGHWrap: {"launch"},
}

// envViolations: no environment read, write or pass-through outside
// envAllowed. A child process with no Env set inherits the environment, so
// a function that starts one must set Env.
func envViolations(files []srcFile) []string {
	reads := map[string]bool{"os.Getenv": true, "os.LookupEnv": true, "os.Environ": true, "os.ExpandEnv": true,
		"os.Setenv": true, "os.Unsetenv": true, "os.Clearenv": true, "syscall.Getenv": true, "syscall.Environ": true,
		"syscall.Setenv": true, "os/exec.LookPath": true}
	starts := map[string]bool{"os/exec.Command": true, "os/exec.CommandContext": true}
	var bad []string
	setsEnv := map[string]bool{} // FILE FUNC that assigns X.Env
	for _, f := range files {
		for _, d := range f.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok {
					for _, l := range as.Lhs {
						if se, ok := l.(*ast.SelectorExpr); ok && se.Sel.Name == "Env" {
							setsEnv[f.name+" "+funcName(fd)] = true
						}
					}
				}
				return true
			})
		}
	}
	for _, c := range calls(files) {
		key := c.path + "." + c.name
		allowed := slices.Contains(envAllowed[c.f.pkg], c.fn)
		switch {
		case reads[key] && !allowed:
			bad = append(bad, c.f.name+": "+c.fn+" calls "+key)
		case starts[key] && !allowed && !setsEnv[c.f.name+" "+c.fn]:
			bad = append(bad, c.f.name+": "+c.fn+" starts a process with the inherited environment")
		}
	}
	return bad
}

// processViolations: git, run by internal/target for scans and by
// internal/hooks for the installer, always by the literal name "git", and gh,
// run once by internal/ghwrap's launch from the path LookPath gives for "gh",
// are the only child processes (ADR-001 sections 2 and 6.6).
func processViolations(files []srcFile) []string {
	starts := map[string]bool{"os/exec.Command": true, "os/exec.CommandContext": true, "os.StartProcess": true,
		"syscall.Exec": true, "syscall.ForkExec": true, "syscall.StartProcess": true}
	var bad []string
	for _, c := range calls(files) {
		key := c.path + "." + c.name
		if !starts[key] {
			if key == "os/exec.LookPath" && c.f.pkg == pkgGHWrap && !isLiteral(c.expr.Args[0], "gh") {
				bad = append(bad, c.f.name+": "+c.fn+" looks up a program other than gh")
			}
			continue
		}
		prog := 0
		if c.name == "CommandContext" {
			prog = 1
		}
		switch {
		case !strings.HasPrefix(key, "os/exec."):
			bad = append(bad, c.f.name+": "+c.fn+" calls "+key)
		case (c.f.pkg == pkgTarget || c.f.pkg == pkgHooks) && isLiteral(c.expr.Args[prog], "git"):
		case c.f.pkg == pkgGHWrap && c.fn == "launch" && isIdent(c.expr.Args[prog]):
		default:
			bad = append(bad, c.f.name+": "+c.fn+" starts a child process hush does not allow")
		}
	}
	return bad
}

func isLiteral(e ast.Expr, s string) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && lit.Value == strconv.Quote(s)
}

func isIdent(e ast.Expr) bool { _, ok := e.(*ast.Ident); return ok }

// outputViolations: no log output and no goroutine of hush's own; from
// log/slog only the guards' Value and StringValue; the standard streams only
// in cmd/hush; and a regular expression's source is always a literal, so no
// term enters one (ADR-001 section 6.6).
func outputViolations(files []srcFile) []string {
	var bad []string
	for _, f := range files {
		if f.test || f.pkg == pkgLeak || f.pkg == pkgSchema {
			continue
		}
		imp := imports(f.file)
		for _, p := range imp {
			if p == "log" {
				bad = append(bad, f.name+" imports log")
			}
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt:
				bad = append(bad, f.name+" starts a goroutine")
			case *ast.SelectorExpr:
				id, ok := n.X.(*ast.Ident)
				if !ok || id.Obj != nil {
					break
				}
				switch path := imp[id.Name]; {
				case path == "log/slog" && n.Sel.Name != "Value" && n.Sel.Name != "StringValue":
					bad = append(bad, f.name+" uses slog."+n.Sel.Name)
				case path == "os" && (n.Sel.Name == "Stdout" || n.Sel.Name == "Stderr" || n.Sel.Name == "Stdin") && f.pkg != pkgCLI:
					bad = append(bad, f.name+" uses os."+n.Sel.Name)
				}
			}
			return true
		})
	}
	for _, c := range calls(files) {
		if c.path == "regexp" && strings.Contains(c.name, "Compile") && c.f.pkg != pkgLeak && c.f.pkg != pkgSchema {
			if lit, ok := c.expr.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
				bad = append(bad, c.f.name+": "+c.fn+" compiles a pattern that is not a literal")
			}
		}
	}
	return bad
}

// recoverViolations: every exported function and method of package hush that
// returns an error defers recoverError first, so a panic becomes the fixed
// internal error (ADR-001 section 6.6; HSH-11/D41). The guards' encoders,
// which only return a fixed error, are the exception.
func recoverViolations(files []srcFile) []string {
	guards := map[string]bool{"MarshalJSON": true, "MarshalText": true, "GobEncode": true}
	var bad []string
	for _, f := range files {
		if f.test || f.pkg != pkgRoot {
			continue
		}
		for _, d := range f.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || guards[fd.Name.Name] || fd.Type.Results == nil || fd.Body == nil {
				continue
			}
			if fd.Recv != nil {
				if name := funcName(fd); !ast.IsExported(name[:strings.Index(name, ".")]) {
					continue
				}
			}
			returnsError := false
			for _, r := range fd.Type.Results.List {
				if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
					returnsError = true
				}
			}
			if !returnsError {
				continue
			}
			ok = false
			if len(fd.Body.List) > 0 {
				if ds, isDefer := fd.Body.List[0].(*ast.DeferStmt); isDefer {
					if id, isIdent := ds.Call.Fun.(*ast.Ident); isIdent && id.Name == "recoverError" {
						ok = true
					}
				}
			}
			if !ok {
				bad = append(bad, f.name+": "+funcName(fd)+" does not recover a panic first")
			}
		}
	}
	return bad
}

// sourceImporter type-checks imported packages from source, the module's own
// included, once for every check.
var sourceImporter = sync.OnceValues(func() (*token.FileSet, types.Importer) {
	fset := token.NewFileSet()
	return fset, importer.ForCompiler(fset, "source", nil)
})

// errorViolations type-checks each non-test package of files and reports
// every place that formats an error from outside the module: Error() called
// on a value of interface type, such an error passed to a fmt function, and
// fmt.Errorf. Foreign errors are converted where they occur and dropped
// (ADR-001 section 6.6).
func errorViolations(t *testing.T, files []srcFile) []string {
	t.Helper()
	fset, imp := sourceImporter()
	byPkg := map[string][]*ast.File{}
	names := map[*ast.File]string{}
	for _, f := range files {
		if f.test || f.pkg == pkgLeak || f.pkg == pkgSchema {
			continue
		}
		// Reparse into the importer's file set, so positions agree.
		src, err := os.ReadFile(f.name)
		if err != nil {
			src = []byte(nodeSource(f))
		}
		af, err := parser.ParseFile(fset, f.name, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		byPkg[f.pkg] = append(byPkg[f.pkg], af)
		names[af] = f.name
	}
	errIface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	foreign := func(tv types.Type) bool {
		if tv == nil || !types.Implements(tv, errIface) {
			return false
		}
		if types.IsInterface(tv) {
			return true
		}
		if p, ok := tv.(*types.Pointer); ok {
			tv = p.Elem()
		}
		n, ok := tv.(*types.Named)
		return !ok || n.Obj().Pkg() == nil || !strings.HasPrefix(n.Obj().Pkg().Path(), modulePath) && !strings.HasPrefix(n.Obj().Pkg().Path(), "planted")
	}
	var bad []string
	for _, pkg := range slices.Sorted(func(yield func(string) bool) {
		for p := range byPkg {
			if !yield(p) {
				return
			}
		}
	}) {
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{},
			Uses: map[*ast.Ident]types.Object{}}
		conf := types.Config{Importer: imp}
		if _, err := conf.Check(pkg, fset, byPkg[pkg], info); err != nil {
			t.Fatalf("type-checking %s: %v", pkg, err)
		}
		for _, af := range byPkg[pkg] {
			ast.Inspect(af, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				se, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel := info.Selections[se]; sel != nil && se.Sel.Name == "Error" && sel.Kind() == types.MethodVal &&
					foreign(sel.Recv()) && !moduleVar(info, se.X) {
					bad = append(bad, names[af]+": calls Error on an error from outside the module")
				}
				if fn, ok := info.Uses[se.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "fmt" {
					if fn.Name() == "Errorf" {
						bad = append(bad, names[af]+": calls fmt.Errorf")
					}
					for _, a := range ce.Args {
						if foreign(info.Types[a].Type) {
							bad = append(bad, names[af]+": formats an error from outside the module")
						}
					}
				}
				return true
			})
		}
	}
	return bad
}

// moduleVar reports whether e names a package-level variable of the module,
// such as hush.ErrInterrupted: an error of the module's own table, whose
// static type is the interface.
func moduleVar(info *types.Info, e ast.Expr) bool {
	var id *ast.Ident
	switch e := e.(type) {
	case *ast.Ident:
		id = e
	case *ast.SelectorExpr:
		id = e.Sel
	default:
		return false
	}
	v, ok := info.Uses[id].(*types.Var)
	return ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && strings.HasPrefix(v.Pkg().Path(), modulePath)
}

// nodeSource is the source of a planted file, which has no file on disk.
var plantedSources = map[string]string{}

func nodeSource(f srcFile) string { return plantedSources[f.name] }

// guardTypes lists every exported type of package hush. TestArchitecture
// checks the list against the sources, so a new type is not missed.
var guardTypes = []any{Config{}, Coverage(0), Tier(0), Scanner{}, Code(""), Error{}, FindingsError{},
	Destination{}, TermSets{}, Identities{}, Kind(0), Part(0), Counts{}, Finding{}, Report{}, RefSelector(0),
	Range{}, Repo{}, Target(0)}

// printable lists the exported types that hold unexported fields but only
// values that may print, so they carry no guards (HSH-11/D38).
var printable = map[reflect.Type]string{
	reflect.TypeOf(Error{}): "a code, a fixed message, an argument position, a line and a commit id",
}

var guardIfaces = []reflect.Type{
	reflect.TypeOf((*fmt.Formatter)(nil)).Elem(), reflect.TypeOf((*fmt.GoStringer)(nil)).Elem(),
	reflect.TypeOf((*slog.LogValuer)(nil)).Elem(), reflect.TypeOf((*json.Marshaler)(nil)).Elem(),
	reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem(), reflect.TypeOf((*gob.GobEncoder)(nil)).Elem(),
}

// guarded reports whether the value type t implements every guard, so fmt,
// slog and the encoders meet a guard at the top level and through exported
// fields, and through a pointer to t as well.
func guarded(t reflect.Type) bool {
	for _, i := range guardIfaces {
		if !t.Implements(i) {
			return false
		}
	}
	return true
}

// guardViolations walks each root type transitively: through pointers,
// slices, arrays, maps and struct fields. A struct type with an unexported
// field, reached from a root through exported fields only, must carry the
// guards with value receivers, unless it is printable (ADR-001 section 6.6).
// What lies behind a guarded type or an unexported field is the guard's.
func guardViolations(roots []reflect.Type) []string {
	var bad []string
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for {
			switch t.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Array:
				t = t.Elem()
				continue
			case reflect.Map:
				walk(t.Key())
				t = t.Elem()
				continue
			}
			break
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		hidden := false
		for i := 0; i < t.NumField(); i++ {
			hidden = hidden || !t.Field(i).IsExported()
		}
		if hidden && printable[t] == "" && !guarded(t) {
			bad = append(bad, t.String()+" holds unexported fields and lacks a guard")
		}
		if guarded(t) {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				walk(t.Field(i).Type)
			}
		}
	}
	for _, r := range roots {
		walk(r)
	}
	return bad
}

// plantedGuardless holds term sets with no guard; plantedPointerGuards has
// the guards on its pointer only, which fmt does not reach for a value.
type plantedGuardless struct{ sets *termset.Sets }

type plantedPointerGuards struct{ label string }

func (*plantedPointerGuards) Format(f fmt.State, _ rune)   { fmt.Fprint(f, "x") }
func (*plantedPointerGuards) GoString() string             { return "x" }
func (*plantedPointerGuards) LogValue() slog.Value         { return slog.StringValue("x") }
func (*plantedPointerGuards) MarshalJSON() ([]byte, error) { return nil, ErrInternal }
func (*plantedPointerGuards) MarshalText() ([]byte, error) { return nil, ErrInternal }
func (*plantedPointerGuards) GobEncode() ([]byte, error)   { return nil, ErrInternal }

// plantedHolder reaches a guardless type through an exported field.
type plantedHolder struct{ Inner plantedGuardless }

func TestArchitecture(t *testing.T) {
	_, files := moduleFiles()
	if len(files) < 50 {
		t.Fatalf("read only %d files", len(files))
	}
	for _, c := range []struct {
		name  string
		check func([]srcFile) []string
		plant []srcFile
	}{
		{"imports", importViolations, []srcFile{
			planted(t, pkgCLI, "cmd/hush/planted.go", "package main\nimport _ \""+pkgTarget+"\"\n"),
			planted(t, pkgGHWrap, "internal/ghwrap/planted.go", "package ghwrap\nimport _ \""+modulePath+"/internal/rule\"\n"),
			planted(t, pkgHooks, "internal/hooks/planted.go", "package hooks\nimport _ \""+pkgTarget+"\"\n"),
			planted(t, pkgRoot, "planted.go", "package hush\nimport _ \""+pkgLeak+"\"\n"),
		}},
		{"environment", envViolations, []srcFile{
			planted(t, pkgRoot, "planted.go", "package hush\nimport \"os\"\nfunc f() string { return os.Getenv(\"HUSH_TERMS\") }\n"),
			planted(t, pkgTarget, "internal/target/planted.go", "package target\nimport \"os/exec\"\nfunc f() { exec.Command(\"git\").Run() }\n"),
			planted(t, pkgCLI, "cmd/hush/planted.go", "package main\nimport x \"os\"\nfunc scanCommand() { _, _ = x.LookupEnv(\"HOME\") }\n"),
			planted(t, pkgGHWrap, "internal/ghwrap/planted.go", "package ghwrap\nimport \"os\"\nfunc Run() []string { return os.Environ() }\n"),
		}},
		{"child processes", processViolations, []srcFile{
			planted(t, pkgRoot, "planted.go", "package hush\nimport \"os/exec\"\nfunc f() { c := exec.Command(\"git\"); c.Env = nil }\n"),
			planted(t, pkgTarget, "internal/target/planted.go", "package target\nimport \"os/exec\"\nfunc f(p string) { exec.Command(p) }\n"),
			planted(t, pkgGHWrap, "internal/ghwrap/planted.go", "package ghwrap\nimport \"os/exec\"\nfunc launch() { exec.LookPath(\"sh\") }\n"),
			planted(t, pkgHooks, "internal/hooks/planted.go", "package hooks\nimport \"syscall\"\nfunc f() { syscall.Exec(\"/bin/sh\", nil, nil) }\n"),
		}},
		{"output", outputViolations, []srcFile{
			planted(t, pkgRoot, "planted.go", "package hush\nimport \"log/slog\"\nfunc f() { slog.Info(\"x\") }\n"),
			planted(t, pkgTarget, "internal/target/planted.go", "package target\nimport \"log\"\nfunc f() { log.Print(\"x\") }\n"),
			planted(t, pkgRoot, "planted.go", "package hush\nfunc f() { go func() {}() }\n"),
			planted(t, pkgGHWrap, "internal/ghwrap/planted.go", "package ghwrap\nimport \"os\"\nfunc f() { os.Stderr.WriteString(\"x\") }\n"),
			planted(t, modulePath+"/internal/termset", "internal/termset/planted.go", "package termset\nimport \"regexp\"\nfunc f(term string) { regexp.MustCompile(term) }\n"),
		}},
		{"recovery", recoverViolations, []srcFile{
			planted(t, pkgRoot, "planted.go", "package hush\nfunc Planted() error { return nil }\n"),
			planted(t, pkgRoot, "planted.go", "package hush\nfunc (s *Scanner) Planted() (int, error) { defer func() {}(); return 0, nil }\n"),
		}},
	} {
		if bad := c.check(files); len(bad) > 0 {
			t.Errorf("%s: %s", c.name, strings.Join(bad, "; "))
		}
		for _, p := range c.plant {
			if bad := c.check([]srcFile{p}); len(bad) == 0 {
				t.Errorf("%s: the planted violation in %s is not reported", c.name, p.name)
			}
		}
	}

	// Errors, through the type checker.
	if bad := errorViolations(t, files); len(bad) > 0 {
		t.Errorf("errors: %s", strings.Join(bad, "; "))
	}
	for _, src := range []string{
		"package planted\nimport \"os\"\nfunc F() string { _, err := os.Open(\"x\"); return err.Error() }\n",
		"package planted\nimport (\"fmt\"; \"strconv\")\nfunc F() string { _, err := strconv.Atoi(\"x\"); return fmt.Sprint(err) }\n",
		"package planted\nimport \"fmt\"\nfunc F() error { return fmt.Errorf(\"x\") }\n",
	} {
		name := "planted/" + strconv.Itoa(len(plantedSources)) + ".go"
		plantedSources[name] = src
		if bad := errorViolations(t, []srcFile{planted(t, "planted", name, src)}); len(bad) == 0 {
			t.Errorf("errors: the planted violation in %s is not reported", name)
		}
	}

	// Formatting guards, through reflect.
	var roots []reflect.Type
	declared := map[string]bool{}
	for _, v := range guardTypes {
		roots = append(roots, reflect.TypeOf(v))
		declared[reflect.TypeOf(v).Name()] = true
	}
	for _, f := range files {
		if f.pkg != pkgRoot || f.test {
			continue
		}
		for _, d := range f.file.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				for _, s := range gd.Specs {
					if name := s.(*ast.TypeSpec).Name.Name; ast.IsExported(name) && !declared[name] {
						t.Errorf("guards: the exported type %s is not in guardTypes", name)
					}
				}
			}
		}
	}
	if bad := guardViolations(roots); len(bad) > 0 {
		t.Errorf("guards: %s", strings.Join(bad, "; "))
	}
	for _, v := range []any{plantedGuardless{}, plantedPointerGuards{}, plantedHolder{}} {
		if bad := guardViolations([]reflect.Type{reflect.TypeOf(v)}); len(bad) == 0 {
			t.Errorf("guards: the planted %T is not reported", v)
		}
	}
}
