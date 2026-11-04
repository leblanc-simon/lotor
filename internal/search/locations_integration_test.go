//go:build integration

package search

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"testing"

	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// TestSearchLocations : une occurrence porte les emplacements de son composant dans
// l'inventaire courant (écran, API, export CSV et JSON).
func TestSearchLocations(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	res := f.run(f.a, "q=pkg:golang/github.com/burntsushi/toml")
	if len(res.Groups) != 1 || len(res.Groups[0].Hits) != 1 {
		t.Fatalf("occurrences %v", occurrences(res))
	}
	want := []sbom.Location{{Path: "/go.mod"}}
	if got := res.Groups[0].Hits[0].Locations; !reflect.DeepEqual(got, want) {
		t.Fatalf("emplacements %+v", got)
	}
	req := f.request("q=pkg:golang/github.com/burntsushi/toml")
	var csvOut bytes.Buffer
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), req, FormatCSV, &csvOut); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&csvOut).ReadAll()
	if err != nil || len(records) != 2 || records[1][len(exportColumns)-1] != "/go.mod" {
		t.Fatalf("CSV : %v, %v", records, err)
	}
	var jsonOut bytes.Buffer
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), req, FormatJSON, &jsonOut); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Results []struct {
			Locations []sbom.Location `json:"locations"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &doc); err != nil || len(doc.Results) != 1 || !reflect.DeepEqual(doc.Results[0].Locations, want) {
		t.Fatalf("JSON : %s, %v", jsonOut.String(), err)
	}
	// Recherche par vulnérabilité : l'élément courant du composant, ici sans emplacement.
	for _, g := range f.run(f.a, "q=CVE-2021-44228").Groups {
		for _, h := range g.Hits {
			if h.Locations != nil {
				t.Errorf("%s : emplacements inattendus %+v", h.PURL, h.Locations)
			}
		}
	}
}
