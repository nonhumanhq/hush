package hush

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"testing"

	lc "github.com/nonhumanhq/hush/internal/leakcheck"
)

// ADR-001 section 4: the destinations, the client label grammar, and that a
// Destination prints its class only.
func TestDestination(t *testing.T) {
	good := []string{"k7", "a", "0", "clients-k7", "a_b", strings.Repeat("z", 32), lc.LabelA}
	bad := []string{"", "K7", "-k7", "_k7", "k 7", "k:7", "k.7", "public", "private", strings.Repeat("z", 33), "k7\n", "kä"}
	for _, l := range good {
		d, err := Client(l)
		if err != nil || d.String() != "client" || d.clientLabel() != l {
			t.Errorf("Client(%q) failed", l)
		}
		if p, err := ParseDestination("client:" + l); err != nil || p != d {
			t.Errorf("ParseDestination(client:%q) failed", l)
		}
	}
	for _, l := range bad {
		_, err := Client(l)
		wantError(t, err, CodeDestination)
		_, err = ParseDestination("client:" + l)
		wantError(t, err, CodeDestination)
		if err != nil && strings.Contains(err.Error(), "client:") {
			t.Error("the error echoes the destination")
		}
	}
	for s, want := range map[string]Destination{"public": Public(), "private": Private()} {
		if d, err := ParseDestination(s); err != nil || d != want || d.String() != s {
			t.Errorf("ParseDestination(%q) failed", s)
		}
	}
	// ADR-001 negative test 10, in the API: an unknown destination is refused
	// and not echoed.
	for _, s := range []string{"publc", "", "Public", "client", "client:", " public", lc.Quorvel} {
		_, err := ParseDestination(s)
		wantError(t, err, CodeDestination)
		if s != "" && strings.Contains(err.Error(), s) {
			t.Error("the error echoes the value")
		}
	}
	if (Destination{}).String() != "invalid" {
		t.Error("the zero Destination does not print as invalid")
	}
}

// ADR-001 section 6.6: Destination's guards print the class, never the label
// (negative test 8's last point, for Destination).
func TestDestinationGuards(t *testing.T) {
	d := client(t, lc.LabelA)
	var log strings.Builder
	slog.New(slog.NewTextHandler(&log, nil)).Info("scan", "destination", d)
	j, jerr := json.Marshal(d)
	txt, terr := d.MarshalText()
	g, gerr := d.GobEncode()
	var gb strings.Builder
	gob.NewEncoder(&gb).Encode(struct{ D Destination }{d})
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s %q %x %d", d, d, d, d, d, d, d), string(j), string(txt), string(g), log.String(), gb.String()} {
		if strings.Contains(s, lc.LabelA) || !strings.Contains(s, "client") {
			t.Errorf("formatted destination: %d bytes, without the class or with the label", len(s))
		}
	}
	if jerr != nil || terr != nil || gerr != nil {
		t.Error("encoding a destination failed")
	}
	leak(t, d, &d, []Destination{d}, map[string]Destination{"d": d}, log.String(), string(j), gb.String())
}

// ADR-002 section 5.4: the identity allowance's form, and its guards.
func TestIdentities(t *testing.T) {
	ids, err := NewIdentities([]string{lc.Identity, strings.ToUpper(lc.Identity2)})
	if err != nil || ids.Len() != 2 || (*ids.addrs.get())[1] != lc.Identity2 {
		t.Fatalf("NewIdentities failed: %v", err)
	}
	bad := [][]string{nil, {}, {""}, {"@"}, {"alice@"}, {"@acme.internal"}, {"alice"}, {lc.Identity, ""},
		{"alice " + lc.Identity[5:]}, {lc.Identity + "\t"}, {"<" + lc.Identity + ">"}, {lc.Identity + ">"},
		{lc.Identity + "," + lc.Identity2}}
	for i, list := range bad {
		got, err := NewIdentities(list)
		if got != nil {
			t.Errorf("case %d: got identities", i)
		}
		wantError(t, err, CodeUsage)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "acme") {
			t.Errorf("case %d: the error echoes an address", i)
		}
	}
	_, err = NewIdentities([]string{lc.Identity, "x"})
	if err == nil || err.Error() != "identities: address 2 is malformed" {
		t.Errorf("the error does not cite the position: %v", err)
	}
}

// TestIdentitiesGuards: no formatting, logging or encoding of an Identities, a
// Config holding one, or a Scanner built from one prints an address.
func TestIdentitiesGuards(t *testing.T) {
	ids, err := NewIdentities([]string{lc.Identity})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Destination: Public(), GenericOnly: true, Identities: ids}
	s := scanner(t, cfg)
	var log strings.Builder
	slog.New(slog.NewJSONHandler(&log, nil)).Info("scan", "ids", ids, "config", cfg, "scanner", s)
	texts := []string{log.String()}
	for _, v := range []any{ids, *ids, cfg, &cfg, s, *s, []*Identities{ids}} {
		texts = append(texts, fmt.Sprintf("%v %+v %#v %s %q %x", v, v, v, v, v, v))
	}
	if _, err := json.Marshal(ids); err == nil {
		t.Error("json.Marshal(*Identities) succeeded")
	}
	if _, err := json.Marshal(cfg); err == nil {
		t.Error("json.Marshal(Config) succeeded")
	}
	if _, err := ids.MarshalText(); err == nil {
		t.Error("MarshalText succeeded")
	}
	if err := gob.NewEncoder(&strings.Builder{}).Encode(cfg); err == nil {
		t.Error("gob encoding a Config succeeded")
	}
	for _, s := range texts {
		if strings.Contains(strings.ToLower(s), "acme") || strings.Contains(s, "alice") {
			t.Error("an address was printed")
		}
	}
	if !strings.Contains(texts[1], "hush.Identities(1 addresses)") {
		t.Error("the summary is missing")
	}
	leak(t, ids, *ids, cfg, &cfg, s, *s, []*Identities{ids}, struct{ C Config }{cfg})
}

// Destinations compare with ==: the label is a unique.Handle (HSH-11/D38),
// one pointer per distinct label.
func TestDestinationEqual(t *testing.T) {
	a1, a2, b := client(t, lc.LabelA), client(t, lc.LabelA), client(t, lc.LabelB)
	p, _ := ParseDestination("client:" + lc.LabelA)
	if a1 != a2 || a1 != p || a1 == b || a1 == Public() || Public() != Public() || Private() == Public() {
		t.Error("== does not compare destinations")
	}
}

// A label's entry is freed once no destination holds it: making many distinct
// client destinations and dropping them leaves the heap about where it was
// (HSH-11/D38, review round 2).
func TestDestinationLabelsFreed(t *testing.T) {
	heap := func() uint64 {
		var m runtime.MemStats
		for range 3 {
			runtime.GC()
		}
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	for i := range 200_000 {
		if _, err := Client("label-" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if after := heap(); after > before+8<<20 {
		t.Errorf("200000 dropped labels kept %d MB", (after-before)>>20)
	}
}
