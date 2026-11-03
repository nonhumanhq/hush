package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
	"github.com/nonhumanhq/hush/internal/schema"
)

// start runs the built hush with h's fixed environment in dir, with the
// given standard input and output, and returns the command, started, and its
// standard error.
func (h *hookEnv) start(dir string, stdin, stdout *os.File, args ...string) (*exec.Cmd, *bytes.Buffer) {
	h.t.Helper()
	c := exec.Command(h.hush, args...)
	var errs bytes.Buffer
	c.Dir, c.Env, c.Stdin, c.Stdout, c.Stderr = dir, h.env, stdin, stdout, &errs
	if err := c.Start(); err != nil {
		h.t.Fatal(err)
	}
	return c, &errs
}

// wait waits for c, at most 20 seconds, and returns its exit status, -1 when
// a signal ended it.
func wait(t *testing.T, c *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(20 * time.Second):
		c.Process.Kill()
		t.Fatal("no result after 20s")
	}
	return -1
}

// ADR-001 negative test 16: a scan whose output cannot be written exits 2
// with the output message, whether standard output is /dev/full or a pipe
// whose reader has exited; a clean scan writes its JSON document, and a scan
// with findings writes them, so both fail.
func TestWriteFailures(t *testing.T) {
	h := newHookEnv(t)
	dir := filepath.Join(h.root, "tree")
	h.write(filepath.Join(dir, "clean.md"), "clean\n")
	h.write(filepath.Join(dir, "bad.md"), "see "+lc.Bad+"\n")
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/full")
	}
	defer full.Close()
	for _, args := range [][]string{
		{"scan", "--format", "json", "--destination", "public", "--generic-only", "clean.md"},
		{"scan", "--destination", "public", "--generic-only", "bad.md"},
		{"scan", "--format", "json", "--destination", "public", "--generic-only", "bad.md"},
		{"scan", "--format", "json", "--destination", "public", "missing.md"}, // an error's document
		{"--help"},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		for _, out := range []*os.File{full, w} {
			c, errs := h.start(dir, nil, out, args...)
			code := wait(t, c)
			if code != 2 || errs.String() != "hush: cannot write output\n" {
				t.Errorf("%q to %s: exit %d, stderr %q", args, out.Name(), code, errs.String())
			}
			lc.Check(t, errs.String())
		}
		w.Close()
	}
}

// ADR-001 section 5, "The process": INT, TERM, HUP and QUIT each end a scan
// with exit 2 and the interrupted message, and with the JSON document when it
// is owed, even while hush waits on standard input that never ends (D44).
func TestSignals(t *testing.T) {
	h := newHookEnv(t)
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		for _, json := range []bool{false, true} {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.CreateTemp(h.root, "out")
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"scan", "--destination", "public", "--generic-only", "--stdin"}
			if json {
				args = append([]string{"scan", "--format", "json"}, args[1:]...)
			}
			c, errs := h.start(h.root, r, out, args...)
			r.Close()
			// More than a pipe holds: once the write returns, hush is reading
			// standard input, so its signal handling is in place.
			if _, err := w.WriteString(strings.Repeat("a line\n", 64<<10)); err != nil {
				t.Fatal(err)
			}
			c.Process.Signal(sig)
			code := wait(t, c)
			w.Close()
			stdout, _ := os.ReadFile(out.Name())
			out.Close()
			if code != 2 || errs.String() != "hush: interrupted\n" {
				t.Errorf("%s, JSON %t: exit %d, stderr %q", sig, json, code, errs.String())
			}
			switch {
			case !json && len(stdout) != 0:
				t.Errorf("%s: standard output %q", sig, stdout)
			case json:
				if err := schema.CheckLine(string(stdout)); err != nil ||
					!strings.Contains(string(stdout), `"error":{"code":"interrupted","message":"interrupted"}}`) {
					t.Errorf("%s in JSON: %v, %s", sig, err, stdout)
				}
			}
			lc.Check(t, errs.String(), string(stdout))
		}
	}
}

// ADR-001 section 5, "The process": a signal ends hush with exit 2 and the
// interrupted line even while it writes a report to a pipe that nobody
// reads, which blocks the write (HSH-11/D44).
func TestSignalsDuringBlockedWrite(t *testing.T) {
	h := newHookEnv(t)
	dir := filepath.Join(h.root, "tree")
	h.write(filepath.Join(dir, "bad.md"), strings.Repeat("see "+lc.Bad+"\n", 20000))
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		for _, json := range []bool{false, true} {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"scan", "--destination", "public", "--generic-only", "bad.md"}
			if json {
				args = append([]string{"scan", "--format", "json"}, args[1:]...)
			}
			c, errs := h.start(dir, nil, w, args...)
			w.Close()
			// One byte read shows the write has begun; the rest, far more than
			// a pipe holds, keeps it blocked.
			r.SetReadDeadline(time.Now().Add(20 * time.Second))
			if _, err := r.Read(make([]byte, 1)); err != nil {
				c.Process.Kill()
				t.Fatalf("no output: %v", err)
			}
			c.Process.Signal(sig)
			code := wait(t, c)
			r.Close()
			if code != 2 || errs.String() != "hush: interrupted\n" {
				t.Errorf("%s, JSON %t: exit %d, stderr %q", sig, json, code, errs.String())
			}
			lc.Check(t, errs.String())
		}
	}
}

// ADR-001 section 7, "Panics": a panic before the result is claimed writes
// the internal error, and its JSON document when one is owed; a panic after
// it is claimed, before the claimant has written anything, still writes the
// internal line. Either way the exit is 2 with exactly one line.
func TestPanicRecovered(t *testing.T) {
	isolate(t)
	defer func() { testHook = nil }()
	for _, claimed := range []bool{false, true} {
		testHook = func(c bool) {
			if c == claimed {
				panic("injected")
			}
		}
		for _, json := range []bool{false, true} {
			args := []string{"--destination", "public", "--generic-only", "--stdin"}
			if json {
				args = append([]string{"--format", "json"}, args...)
			}
			code, out, errs := scan(t, "clean\n", args...)
			if code != 2 || errs != "hush: internal error; output withheld\n" {
				t.Errorf("claimed %t, JSON %t: exit %d, stderr %q", claimed, json, code, errs)
			}
			switch {
			case json && !claimed:
				if c, m, _, _ := errorDoc(t, out); c != "internal" || m != "internal error; output withheld" {
					t.Errorf("claimed %t: document %s", claimed, out)
				}
			case out != "":
				t.Errorf("claimed %t, JSON %t: standard output %q", claimed, json, out)
			}
		}
	}
}
