package sbom

import (
	"reflect"
	"strings"
	"testing"
)

func TestCleanLocations(t *testing.T) {
	got := cleanLocations([]RawLocation{
		{Path: "/usr/share/doc/a/copyright", Evidence: "supporting"},
		{Path: " /var/lib/dpkg/status ", Evidence: "primary"},
		{Path: "/var/lib/dpkg/status", Evidence: "supporting"},
		{Path: "/app/a.jar", AccessPath: "/app/a.jar", Layer: "sha256:1"},
		{Path: "/opt/lib/a.jar", AccessPath: "/app/lib/a.jar"},
		{Path: ""},
		{Path: "/bad\x00path"},
		{Path: "/" + strings.Repeat("x", MaxLocationLen)},
		{Path: "/b", Layer: strings.Repeat("l", MaxLocationLayer+1)},
	})
	want := []Location{
		{Path: "/app/a.jar", Layer: "sha256:1"},
		{Path: "/b"},
		{Path: "/opt/lib/a.jar", AccessPath: "/app/lib/a.jar"},
		{Path: "/var/lib/dpkg/status"},
		{Path: "/usr/share/doc/a/copyright", Supporting: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("emplacements\n got %+v\nwant %+v", got, want)
	}
	if cleanLocations(nil) != nil || cleanLocations([]RawLocation{{Path: " "}}) != nil {
		t.Error("liste vide attendue nil")
	}
}

func TestCleanLocationsBound(t *testing.T) {
	var in []RawLocation
	for i := range MaxLocations + 5 {
		in = append(in, RawLocation{Path: "/s/" + strings.Repeat("z", i), Evidence: "supporting"})
	}
	in = append(in, RawLocation{Path: "/zzz/main"})
	got := cleanLocations(in)
	if len(got) != MaxLocations || got[0] != (Location{Path: "/zzz/main"}) {
		t.Fatalf("borne : %d emplacements, premier %+v", len(got), got[0])
	}
}

func TestNormalizeMergesLocations(t *testing.T) {
	doc := Normalize(RawDocument{Components: []RawComponent{
		{PURL: "pkg:maven/org.a/b@1", Locations: []RawLocation{{Path: "/app/lib/b.jar"}}},
		{PURL: "pkg:maven/org.a/b@1", Locations: []RawLocation{{Path: "/opt/b.jar"}, {Path: "/app/lib/b.jar"}}},
	}})
	want := []Location{{Path: "/app/lib/b.jar"}, {Path: "/opt/b.jar"}}
	if len(doc.Components) != 1 || !reflect.DeepEqual(doc.Components[0].Locations, want) {
		t.Fatalf("fusion : %+v", doc.Components)
	}
}

func TestMainLocations(t *testing.T) {
	main := []Location{{Path: "/a"}, {Path: "/b"}}
	sup := []Location{{Path: "/c", Supporting: true}}
	if got := MainLocations(append(main, sup...)); !reflect.DeepEqual(got, main) {
		t.Errorf("principaux : %+v", got)
	}
	if got := MainLocations(sup); !reflect.DeepEqual(got, sup) {
		t.Errorf("tous secondaires : %+v", got)
	}
	if MainLocations(nil) != nil {
		t.Error("vide")
	}
}

func TestParseLocations(t *testing.T) {
	ls := []Location{{Path: "/a", AccessPath: "/b", Layer: "sha256:1", Supporting: true}}
	if got := ParseLocations([]byte(`[{"path":"/a","access_path":"/b","layer":"sha256:1","supporting":true}]`)); !reflect.DeepEqual(got, ls) {
		t.Errorf("relecture : %+v", got)
	}
	if ParseLocations(nil) != nil || ParseLocations([]byte(`{`)) != nil {
		t.Error("valeur absente ou illisible")
	}
}
