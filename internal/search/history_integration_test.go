//go:build integration

package search

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// pushAt range data sur la référence ref d'un projet, scanné à la date at (hôte : référence
// d'hôte ; dépôt : branche, un commit par envoi).
func (f *fixture) pushAt(org tenant.OrgID, agent, projectID uuid.UUID, ref string, at time.Time, data []byte) {
	f.t.Helper()
	ctx := context.Background()
	f.scans++
	c := ingest.Context{ProjectID: projectID, RefKind: project.RefHost, RefName: ref, AgentVersion: "1.0.0", ScannedAt: at}
	var kind string
	if err := f.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT kind FROM projects WHERE id = $1`, projectID).Scan(&kind)
	}); err != nil {
		f.t.Fatal(err)
	}
	if kind == "repo" {
		c.RefKind, c.Commit = project.RefBranch, fmt.Sprintf("%040x", 1000+f.scans)
		f.exec(org, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name) VALUES ($1, $2, $3, 'repo', 'branch', $4)
			ON CONFLICT DO NOTHING`, org, uuid.Must(uuid.NewV7()), projectID, ref)
	}
	in, err := f.ingest.Receive(ctx, org, agent, c, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.ingest.Decode(ctx, org, in.ID); err != nil {
		f.t.Fatal(err)
	}
}

func day(d int) time.Time { return time.Date(2026, 9, d, 12, 0, 0, 0, time.UTC) }

// Recherche à une date passée (T21) : un composant retiré le 10 n'apparaît plus le 11 (ni le
// 10, fin de journée), mais apparaît le 9 ; l'instantané retenu est daté ; projets archivés
// et références retirées comptent ; l'autre organisation n'apparaît pas ; une date avant
// l'horizon de la rétention signale un résultat partiel.
func TestSearchAtPastDate(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const gone, kept = "pkg:npm/left-pad@1.3.0", "pkg:npm/chalk@5.3.0"
	host := f.agent(f.a, "host", "srv-histoire")
	srv := f.project(f.a, "host", "srv-histoire", `{}`, host)
	f.pushAt(f.a, host, srv, "srv-histoire", day(1), cdx(gone, kept))
	f.pushAt(f.a, host, srv, "srv-histoire", day(10), cdx(kept))
	repo := f.agentOf(f.a, "depots")
	vieux := f.project(f.a, "repo", "vieux", `{}`, repo)
	f.pushAt(f.a, repo, vieux, "main", day(3), cdx(gone))
	f.exec(f.a, `UPDATE projects SET archived_at = now() WHERE id = $1`, vieux)
	repoB := f.agentOf(f.b, "depots")
	autre := f.project(f.b, "repo", "autre-histoire", `{}`, repoB)
	f.pushAt(f.b, repoB, autre, "main", day(2), cdx(gone))

	expectOccurrences(t, f.run(f.a, "q=left-pad"))
	res := f.run(f.a, "q=left-pad&at=2026-09-09")
	expectOccurrences(t, res, "srv-histoire/srv-histoire:"+gone, "vieux/main:"+gone)
	for _, g := range res.Groups {
		h := g.Hits[0]
		if h.Open != 0 || h.Severity != "" || h.Fixed != nil || h.ScannedAt.IsZero() || h.ScannedAt.After(day(9)) {
			t.Errorf("occurrence datée %+v", h)
		}
	}
	if res.Partial {
		t.Error("résultat partiel sans rétention")
	}
	expectOccurrences(t, f.run(f.a, "q=left-pad&at=2026-09-10"), "vieux/main:"+gone)
	expectOccurrences(t, f.run(f.a, "q=left-pad&at=2026-09-11"), "vieux/main:"+gone)
	expectOccurrences(t, f.run(f.a, "q=pkg:npm/left-pad&at=2026-09-02"), "srv-histoire/srv-histoire:"+gone)
	// Avant tout instantané : rien ; à l'instant RFC 3339 du second scan (exclusif) :
	// encore le premier.
	expectOccurrences(t, f.run(f.a, "q=left-pad&at=2026-08-31"))
	expectOccurrences(t, f.run(f.a, "q=left-pad&at=2026-09-10T12:00:00Z"), "srv-histoire/srv-histoire:"+gone, "vieux/main:"+gone)
	expectOccurrences(t, f.run(f.a, "q=chalk&at=2026-09-11"), "srv-histoire/srv-histoire:"+kept)
	// L'autre organisation voit le sien, pas ceux de la première.
	expectOccurrences(t, f.run(f.b, "q=left-pad&at=2026-09-09"), "autre-histoire/main:"+gone)
	// Export aux mêmes paramètres.
	var buf bytes.Buffer
	if err := f.search.Export(context.Background(), f.a, tenant.AllTeams(), f.request("q=left-pad&at=2026-09-09"), FormatCSV, &buf); err != nil ||
		bytes.Count(buf.Bytes(), []byte(gone)) != 2 {
		t.Errorf("export : %v\n%s", err, buf.String())
	}

	// Rétention passée : horizon au 5, une date du 4 est partielle, une du 6 exacte.
	f.exec(f.a, `INSERT INTO snapshot_retention (org_id, horizon, last_run_at, snapshots_deleted, ingestions_deleted, sets_deleted, blobs_deleted)
		VALUES ($1, $2, $2, 0, 0, 0, 0)`, f.a, day(5))
	if res := f.run(f.a, "q=left-pad&at=2026-09-04"); !res.Partial || res.Horizon == nil || !res.Horizon.Equal(day(5)) {
		t.Errorf("date avant l'horizon : partiel %v, horizon %v", res.Partial, res.Horizon)
	}
	if res := f.run(f.a, "q=left-pad&at=2026-09-06"); res.Partial {
		t.Error("date après l'horizon annoncée partielle")
	}
}

func TestSearchAtRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"q=CVE-2021-44228&at=2026-09-09":       KeyAtComponentsOnly,
		"q=lodash&at=2026-09-09&kev=1":         KeyAtComponentsOnly,
		"q=lodash&at=2026-09-09&severity=high": KeyAtComponentsOnly,
		"q=lodash&at=2026-09-09&resolved=1":    KeyAtComponentsOnly,
		"q=lodash&at=2099-01-01":               KeyAtInvalid,
	}
	f := newFixture(t)
	for params, key := range cases {
		_, err := f.search.Search(context.Background(), f.a, tenant.AllTeams(), f.request(params))
		if e, ok := IsError(err); !ok || e.Key != key {
			t.Errorf("%s : %v", params, err)
		}
	}
}
