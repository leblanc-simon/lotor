//go:build integration

package inventory

import (
	"context"
	"reflect"
	"testing"
	"time"

	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// TestStoreLocations : les emplacements d'un composant sont rangés sur l'élément
// d'ensemble, relus par la liste d'un instantané et par l'usage d'un composant, et un
// changement d'emplacement seul donne un nouvel ensemble.
func TestStoreLocations(t *testing.T) {
	t.Parallel()
	d := newDB(t)
	f := newFixture(t, d.App)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour).UTC()
	withLocations := func(paths ...string) []sbom.Component {
		raw := sbom.RawDocument{Format: sbom.FormatSyft, Components: []sbom.RawComponent{
			{PURL: "pkg:maven/org.example/lib@1.0", Locations: []sbom.RawLocation{
				{Path: "/usr/share/doc/lib/copyright", Evidence: "supporting"},
			}},
			{PURL: "pkg:npm/sans-emplacement@1.0"},
		}}
		for _, p := range paths {
			raw.Components[0].Locations = append(raw.Components[0].Locations,
				sbom.RawLocation{Path: p, AccessPath: "/srv" + p, Layer: "sha256:01", Evidence: "primary"})
		}
		return sbom.Normalize(raw).Components
	}
	first := f.store(t, f.hostRecord(withLocations("/opt/app/lib.jar"), t0))
	want := []sbom.Location{
		{Path: "/opt/app/lib.jar", AccessPath: "/srv/opt/app/lib.jar", Layer: "sha256:01"},
		{Path: "/usr/share/doc/lib/copyright", Supporting: true},
	}

	page, _, err := NewService(d.App).Items(ctx, f.org, first.SetID, ItemFilter{}, "", 10)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("composants %+v, %v", page, err)
	}
	if got := page.Items[0].Locations; !reflect.DeepEqual(got, want) {
		t.Errorf("emplacements relus %+v", got)
	}
	if page.Items[1].Locations != nil {
		t.Errorf("composant sans emplacement : %+v", page.Items[1].Locations)
	}
	c, usage, err := NewService(d.App).Component(ctx, f.org, tenant.AllTeams(), page.Items[0].ComponentID)
	if err != nil || len(usage) != 1 || !reflect.DeepEqual(usage[0].Locations, want) {
		t.Fatalf("usage de %s : %+v, %v", c.PURL, usage, err)
	}

	// Même inventaire, même emplacement : l'instantané ne fait qu'avancer. Le paquet
	// déplacé change l'ensemble.
	if same := f.store(t, f.hostRecord(withLocations("/opt/app/lib.jar"), t0.Add(time.Minute))); same.Outcome != OutcomeUnchanged {
		t.Errorf("envoi identique : %s", same.Outcome)
	}
	moved := f.store(t, f.hostRecord(withLocations("/opt/app/lib.jar", "/opt/other/lib.jar"), t0.Add(2*time.Minute)))
	if moved.SetID == first.SetID || !moved.SetCreated {
		t.Errorf("emplacement ajouté : ensemble %v, créé %v", moved.SetID, moved.SetCreated)
	}
}
