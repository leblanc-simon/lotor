//go:build integration

package finding

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"leblanc.io/lotor/internal/sbom"
)

// TestFindingLocations : un constat porte les emplacements de son composant dans le
// dernier instantané qui l'a constaté, et les garde une fois résolu.
func TestFindingLocations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(built1, log4shellRule())
	data := bytes.Replace(testdata(t, "log4shell.cdx16.json"),
		[]byte(`"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"`),
		[]byte(`"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "properties": [
        {"name": "syft:location:0:path", "value": "/app/lib/log4j-core-2.14.1.jar"},
        {"name": "syft:location:1:path", "value": "/opt/legacy/log4j-core-2.14.1.jar"}
      ]`), 1)
	e.push(data)
	e.analyze(e.org, e.main)
	want := []sbom.Location{{Path: "/app/lib/log4j-core-2.14.1.jar"}, {Path: "/opt/legacy/log4j-core-2.14.1.jar"}}
	page, err := NewService(e.pool).Project(ctx, e.org, e.repo, Filter{}, "", 10)
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0].Locations, want) {
		t.Fatalf("constats %+v, %v", page.Items, err)
	}
	r, err := NewService(e.pool).Get(ctx, e.org, e.repo, page.Items[0].ID)
	if err != nil || !reflect.DeepEqual(r.Locations, want) {
		t.Fatalf("fiche du constat %+v, %v", r.Locations, err)
	}
	// Composant corrigé : le constat résolu garde l'emplacement où il était.
	e.push(sbomWith(t, "2.17.1"))
	e.analyze(e.org, e.main)
	resolved, err := NewService(e.pool).Project(ctx, e.org, e.repo, Filter{Status: StatusResolved}, "", 10)
	if err != nil || len(resolved.Items) != 1 || !reflect.DeepEqual(resolved.Items[0].Locations, want) {
		t.Fatalf("constat résolu %+v, %v", resolved.Items, err)
	}
}
