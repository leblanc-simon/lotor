//go:build integration

package db_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/dbtest"
	"leblanc.io/lotor/internal/tenant"
)

// orgTable est une table d'organisation du harnais d'isolement SQL : sa colonne
// d'organisation et l'insertion d'une ligne pour l'organisation déclarée (userID est un
// compte global créé pour l'occasion). Un lot qui crée une table d'organisation l'ajoute
// ici, dans l'ordre de ses dépendances : TestOrgTablesAreAllCovered échoue sinon.
type orgTable struct {
	name string
	col  string
	seed func(ctx context.Context, tx *db.OrgTx, userID int64) error
}

var orgTables = []orgTable{
	{"organizations", "id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, default_language)
			VALUES ($1::uuid, 'o-' || right($1::uuid::text, 12), 'Organisation', 'fr')`, tx.OrgID())
		return err
	}},
	{"org_memberships", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, 'admin')`,
			tx.OrgID(), userID)
		return err
	}},
	{"audit_events", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (org_id, id, actor_user_id, action)
			VALUES ($1, $2, $3, 'member.added')`, tx.OrgID(), uuid.Must(uuid.NewV7()), userID)
		return err
	}},
	{"teams", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO teams (org_id, id, name, created_by) VALUES ($1, $2, 'Général', $3)`,
			tx.OrgID(), seedID(tx, "team"), userID)
		return err
	}},
	{"team_members", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO team_members (org_id, team_id, user_id, role) VALUES ($1, $2, $3, 'admin')`,
			tx.OrgID(), seedID(tx, "team"), userID)
		return err
	}},
	{"org_invitations", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO org_invitations (org_id, id, email, role, invited_by, expires_at)
			VALUES ($1, $2, 'invite@example.org', 'member', $3, now() + interval '30 days')`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), userID)
		return err
	}},
	{"agents", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO agents (org_id, id, kind, name, team_id) VALUES ($1, $2, 'host', 'srv-01', $3)`,
			tx.OrgID(), seedID(tx, "agent"), seedID(tx, "team"))
		return err
	}},
	{"projects", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (org_id, id, kind, slug, name, agent_id, team_id)
			VALUES ($1, $2, 'host', 'srv-01', 'srv-01', $3, $4)`, tx.OrgID(), seedID(tx, "project"), seedID(tx, "agent"),
			seedID(tx, "team"))
		return err
	}},
	{"tracked_refs", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			VALUES ($1, $2, $3, 'host', 'host', 'srv-01')`, tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"))
		return err
	}},
	{"sbom_blobs", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sbom_blobs (org_id, id, sha256, size, compressed_size, content)
			VALUES ($1, $2, sha256('{}'::bytea), 2, 1, '\x00'::bytea)`, tx.OrgID(), seedID(tx, "blob"))
		return err
	}},
	{"components", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO components (org_id, id, purl, purl_base, type, name, version)
			VALUES ($1, $2, 'pkg:npm/a@1', 'pkg:npm/a', 'npm', 'a', '1')`, tx.OrgID(), seedID(tx, "component"))
		return err
	}},
	{"component_sets", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
			VALUES ($1, $2, sha256('set'::bytea), 1, 1, 0, 0)`, tx.OrgID(), seedID(tx, "set"))
		return err
	}},
	{"component_set_items", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO component_set_items (org_id, set_id, component_id, origin)
			VALUES ($1, $2, $3, 'syft')`, tx.OrgID(), seedID(tx, "set"), seedID(tx, "component"))
		return err
	}},
	{"set_diffs", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
			VALUES ($1, $2, sha256('set2'::bytea), 0, 0, 0, 0)`, tx.OrgID(), seedID(tx, "set2")); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO set_diffs (org_id, from_set_id, to_set_id, added_count, removed_count, upgraded_count,
			downgraded_count, computed_at) VALUES ($1, $2, $3, 0, 1, 0, 0, now())`, tx.OrgID(), seedID(tx, "set"), seedID(tx, "set2"))
		return err
	}},
	{"set_diff_items", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO set_diff_items (org_id, from_set_id, to_set_id, kind, purl_base, old_component_id)
			VALUES ($1, $2, $3, 'removed', 'pkg:npm/x', $4)`, tx.OrgID(), seedID(tx, "set"), seedID(tx, "set2"), seedID(tx, "component"))
		return err
	}},
	{"snapshot_retention", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO snapshot_retention (org_id, horizon, last_run_at, snapshots_deleted, ingestions_deleted,
			sets_deleted, blobs_deleted) VALUES ($1, now() - interval '90 days', now(), 0, 0, 0, 0)`, tx.OrgID())
		return err
	}},
	{"snapshots", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO snapshots (org_id, id, project_id, ref_id, agent_id, scanned_at, last_scanned_at,
			blob_id, set_id, format, spec_version, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, now(), now(), $6, $7, 'cyclonedx', '1.6', now(), now())`,
			tx.OrgID(), seedID(tx, "snapshot"), seedID(tx, "project"), seedID(tx, "ref"), seedID(tx, "agent"),
			seedID(tx, "blob"), seedID(tx, "set"))
		return err
	}},
	{"ref_current", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ref_current (org_id, ref_id, project_id, snapshot_id, set_id, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())`,
			tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"), seedID(tx, "snapshot"), seedID(tx, "set"))
		return err
	}},
	{"ingestions", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ingestions (org_id, id, agent_id, project_id, ref_id, scanned_at, blob_id,
			status, snapshot_id, outcome, received_at, finished_at)
			VALUES ($1, $2, $3, $4, $5, now(), $6, 'done', $7, 'created', now(), now())`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), seedID(tx, "agent"), seedID(tx, "project"), seedID(tx, "ref"),
			seedID(tx, "blob"), seedID(tx, "snapshot"))
		return err
	}},
	{"findings", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		// Le catalogue est global : la fiche est partagée par les deux organisations.
		if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerabilities (id, source_rank, severity, vulndb_built, updated_at)
			VALUES ('CVE-2021-44228', 0, 'critical', now(), now()) ON CONFLICT DO NOTHING`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO findings (org_id, id, project_id, ref_id, component_id, vuln_id, status,
			severity, risk, fix_state, match_type, first_seen_at, last_seen_at, snapshot_id, vulndb_archive, vulndb_built, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'CVE-2021-44228', 'open', 'critical', 99, 'fixed', 'exact-direct', now(), now(), $6, $7, now(), now())`,
			tx.OrgID(), seedID(tx, "finding"), seedID(tx, "project"), seedID(tx, "ref"), seedID(tx, "component"),
			seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"finding_events", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO finding_events (org_id, finding_id, at, kind, snapshot_id, vulndb_archive)
			VALUES ($1, $2, now(), 'opened', $3, $4)`, tx.OrgID(), seedID(tx, "finding"), seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"triage_decisions", "org_id", func(ctx context.Context, tx *db.OrgTx, userID int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO triage_decisions (org_id, id, scope, project_id, vuln_id, purl, purl_base,
			action, status, justification, comment, author_user_id, author_label, created_at)
			VALUES ($1, $2, 'project', $3, 'CVE-2021-44228', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
			        'pkg:maven/org.apache.logging.log4j/log4j-core', 'set', 'not_affected', 'code_not_reachable', 'JNDI désactivé',
			        $4, 'a@example.org', now())`, tx.OrgID(), seedID(tx, "decision"), seedID(tx, "project"), userID)
		return err
	}},
	{"ref_analyses", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ref_analyses (org_id, ref_id, project_id, set_id, snapshot_id, vulndb_archive,
			vulndb_built, analyzed_at, match_count, unmatched_count)
			VALUES ($1, $2, $3, $4, $5, $6, now(), now(), 1, 0)`,
			tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"), seedID(tx, "set"), seedID(tx, "snapshot"), uuid.Must(uuid.NewV7()))
		return err
	}},
	{"notification_channels", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notification_channels (org_id, id, name, kind, settings, created_at, updated_at)
			VALUES ($1, $2, 'ops', 'email', '{"recipients": ["ops@example.org"]}', now(), now())`, tx.OrgID(), seedID(tx, "channel"))
		return err
	}},
	{"policies", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO policies (org_id, id, name, subject, expression, delivery, created_at, updated_at)
			VALUES ($1, $2, 'muets', 'agent', 'agent.silent_days >= 7', 'immediate', now(), now())`, tx.OrgID(), seedID(tx, "policy"))
		return err
	}},
	{"policy_channels", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO policy_channels (org_id, policy_id, channel_id) VALUES ($1, $2, $3)`,
			tx.OrgID(), seedID(tx, "policy"), seedID(tx, "channel"))
		return err
	}},
	{"policy_violations", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO policy_violations (org_id, id, policy_id, subject, agent_id, opened_at, last_seen_at)
			VALUES ($1, $2, $3, 'agent', $4, now(), now())`, tx.OrgID(), seedID(tx, "violation"), seedID(tx, "policy"), seedID(tx, "agent"))
		return err
	}},
	{"notification_deliveries", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries (org_id, channel_id, violation_id, mode, state, created_at)
			VALUES ($1, $2, $3, 'immediate', 'pending', now())`, tx.OrgID(), seedID(tx, "channel"), seedID(tx, "violation"))
		return err
	}},
	{"policy_evaluations", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO policy_evaluations (org_id, ref_id, project_id, analyzed_at, evaluated_at)
			VALUES ($1, $2, $3, now(), now())`, tx.OrgID(), seedID(tx, "ref"), seedID(tx, "project"))
		return err
	}},
	{"license_policies", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO license_policies (org_id, default_status, denied) VALUES ($1, 'allowed', '{AGPL-3.0-only}')`,
			tx.OrgID())
		return err
	}},
	{"license_expressions", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO license_expressions (org_id, expression) VALUES ($1, 'MIT OR AGPL-3.0-only')`, tx.OrgID())
		return err
	}},
	{"license_findings", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO license_findings (org_id, id, project_id, ref_id, component_id, status, verdict,
			licenses, license_ids, snapshot_id, first_seen_at, last_seen_at)
			VALUES ($1, gen_random_uuid(), $2, $3, $4, 'open', 'denied', '{AGPL-3.0-only}', '{AGPL-3.0-only}', $5, now(), now())`,
			tx.OrgID(), seedID(tx, "project"), seedID(tx, "ref"), seedID(tx, "component"), seedID(tx, "snapshot"))
		return err
	}},
	{"agent_tokens", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO agent_tokens (org_id, id, agent_id, public_id, secret_hash, name)
			VALUES ($1, $2, $3, $4, sha256('a'::bytea), 'initial')`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), seedID(tx, "agent"), publicID(tx, "a"))
		return err
	}},
	{"enrollment_tokens", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens (org_id, id, public_id, secret_hash, name, expires_at, max_uses, team_id)
			VALUES ($1, $2, $3, sha256('e'::bytea), 'parc', now() + interval '1 day', 5, $4)`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), publicID(tx, "e"), seedID(tx, "team"))
		return err
	}},
	{"org_daily_stats", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO org_daily_stats (org_id, day, open_critical, open_high, open_medium, open_low,
			open_negligible, open_unknown, open_kev, kev_vulns, projects, silent_agents, fixed_critical, fixed_high, fixed_medium,
			fixed_low, fixed_negligible, fixed_unknown, recorded_at)
			VALUES ($1, current_date, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, now())`, tx.OrgID())
		return err
	}},
	{"project_daily_stats", "org_id", func(ctx context.Context, tx *db.OrgTx, _ int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO project_daily_stats (org_id, project_id, day, open_critical, open_high,
			open_medium, open_low, open_negligible, open_unknown, open_kev, recorded_at)
			VALUES ($1, $2, current_date, 1, 0, 0, 0, 0, 0, 1, now())`, tx.OrgID(), seedID(tx, "project"))
		return err
	}},
}

// seedID dérive un identifiant stable de l'organisation et d'un nom, pour relier les
// lignes du harnais entre elles.
func seedID(tx *db.OrgTx, name string) uuid.UUID {
	return uuid.NewSHA1(tx.OrgID().UUID(), []byte(name))
}

// publicID dérive un identifiant public de jeton unique par organisation (26 caractères
// base32 minuscules).
func publicID(tx *db.OrgTx, name string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	id := seedID(tx, "token-"+name)
	out := make([]byte, 26)
	for i := range out {
		out[i] = alphabet[int(id[i%16]+byte(i))%32]
	}
	return string(out)
}

// errAbort annule volontairement une transaction de test.
var errAbort = errors.New("annulation volontaire")

func seedOrg(t *testing.T, tdb *dbtest.DB, org tenant.OrgID, email string) {
	t.Helper()
	ctx := context.Background()
	var userID int64
	if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
		return tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&userID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := tdb.App.InOrg(ctx, org, func(tx *db.OrgTx) error {
		for _, tbl := range orgTables {
			if err := tbl.seed(ctx, tx, userID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOrgTablesAreAllCovered : toute table d'organisation du schéma figure au harnais.
func TestOrgTablesAreAllCovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	rows, err := tdb.App.DB().QueryContext(ctx, `
		SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		   AND (c.relname = 'organizations' OR EXISTS (
		         SELECT 1 FROM pg_attribute a
		          WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND a.attnotnull AND NOT a.attisdropped))
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	var want []string
	for _, tbl := range orgTables {
		want = append(want, tbl.name)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tables d'organisation du schéma %v, harnais %v : ajouter la table à orgTables", got, want)
	}
}

// appendOnly sont les tables d'organisation en ajout seul pour le rôle d'exécution
// (journal d'audit, migration 015 ; journal des décisions de triage, migration 018) : ni
// UPDATE ni DELETE. La valeur est l'insertion d'une ligne pour l'organisation $1, que la
// RLS doit refuser depuis une autre organisation.
var appendOnly = map[string]string{
	"audit_events": `INSERT INTO audit_events (org_id, id, action) VALUES ($1, gen_random_uuid(), 'member.added')`,
	"triage_decisions": `INSERT INTO triage_decisions (org_id, id, scope, vuln_id, purl_base, action, status, author_label, created_at)
		VALUES ($1, gen_random_uuid(), 'org', 'CVE-1', 'pkg:npm/a', 'set', 'affected', 'system', now())`,
}

// seededRows est le nombre de lignes que le harnais insère par organisation dans une
// table, 1 sauf exception : une différence relie deux ensembles distincts (set_diffs).
var seededRows = map[string]int{"component_sets": 2}

func rowsOf(table string) int {
	if n, ok := seededRows[table]; ok {
		return n
	}
	return 1
}

// assertAppendOnly : la table refuse UPDATE et DELETE au rôle d'exécution, et la RLS
// refuse d'y ajouter une ligne de B depuis A ; les lignes de B restent intactes.
func assertAppendOnly(t *testing.T, tdb *dbtest.DB, a, b tenant.OrgID, tbl orgTable) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{`UPDATE ` + tbl.name + ` SET ` + tbl.col + ` = ` + tbl.col, `DELETE FROM ` + tbl.name} {
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			_, err := tx.ExecContext(ctx, q)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s : err = %v, attendu un refus de droit", q, err)
		}
	}
	err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
		_, err := tx.ExecContext(ctx, appendOnly[tbl.name], b)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("ajout d'une ligne de B depuis A : err = %v", err)
	}
	var n int
	if err := tdb.App.InOrg(ctx, b, func(tx *db.OrgTx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
	}); err != nil || n != 1 {
		t.Errorf("B : %d lignes, %v", n, err)
	}
}

// TestRLSOnEveryOrgTable : dans InOrg(A), des requêtes sans filtre ne lisent ni n'écrivent
// rien de B ; hors InOrg, elles échouent.
func TestRLSOnEveryOrgTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	a, b := newOrg(t), newOrg(t)
	seedOrg(t, tdb, a, "a@example.org")
	seedOrg(t, tdb, b, "b@example.org")

	for _, tbl := range orgTables {
		t.Run(tbl.name, func(t *testing.T) {
			// Lecture : seules les lignes de A, et aucune de B même en la nommant.
			err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				var total, ofB int
				if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE `+tbl.col+` = $1) FROM `+tbl.name, b).
					Scan(&total, &ofB); err != nil {
					return err
				}
				if total != rowsOf(tbl.name) || ofB != 0 {
					t.Errorf("A voit %d lignes dont %d de B", total, ofB)
				}
				return nil
			}, db.ReadOnly())
			if err != nil {
				t.Fatal(err)
			}

			if appendOnly[tbl.name] != "" {
				assertAppendOnly(t, tdb, a, b, tbl)
				return
			}

			// Écriture sans filtre : seules les lignes de A sont touchées (transaction
			// annulée ensuite).
			_ = tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				res, err := tx.ExecContext(ctx, `UPDATE `+tbl.name+` SET `+tbl.col+` = `+tbl.col)
				if err != nil {
					t.Fatalf("mise à jour sans filtre : %v", err)
				}
				if n, _ := res.RowsAffected(); n != int64(rowsOf(tbl.name)) {
					t.Errorf("mise à jour sans filtre : %d lignes, attendu %d", n, rowsOf(tbl.name))
				}
				return errAbort
			})

			// Déplacer une ligne de A vers B est refusé.
			err = tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
				_, err := tx.ExecContext(ctx, `UPDATE `+tbl.name+` SET `+tbl.col+` = $1`, b)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "row-level security") {
				t.Errorf("déplacement vers B : err = %v", err)
			}

			// Hors InOrg : échec franc, jamais zéro ligne.
			var n int
			if err := tdb.App.DB().QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n); err == nil {
				t.Errorf("hors InOrg : %d lignes sans erreur", n)
			}
			if err := tdb.App.InTx(ctx, func(tx *db.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
			}); err == nil {
				t.Errorf("dans InTx : %d lignes sans erreur", n)
			}

			// Les lignes de B sont intactes.
			if err := tdb.App.InOrg(ctx, b, func(tx *db.OrgTx) error {
				return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+tbl.name).Scan(&n)
			}); err != nil || n != rowsOf(tbl.name) {
				t.Errorf("B : %d lignes, %v", n, err)
			}
		})
	}
}

// TestTeamVisibilityFailsClosed : lotor_team_visible ne répond que si la transaction a
// déclaré ses équipes visibles (db.Visible) ; sans déclaration, sur une connexion neuve ou
// réutilisée, la requête échoue au lieu de tout montrer (ADR 0034).
func TestTeamVisibilityFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tdb := dbtest.New(t)
	tdb.App.DB().SetMaxOpenConns(1)
	a := newOrg(t)
	seedOrg(t, tdb, a, "a@example.org")
	team := uuid.NewSHA1(a.UUID(), []byte("team"))
	count := func(opts ...db.TxOption) (int, error) {
		var n int
		err := tdb.App.InOrg(ctx, a, func(tx *db.OrgTx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM projects WHERE lotor_team_visible(team_id)`).Scan(&n)
		}, append(opts, db.ReadOnly())...)
		return n, err
	}
	if n, err := count(); err == nil {
		t.Fatalf("connexion neuve sans équipes déclarées : %d projets sans erreur", n)
	}
	cases := []struct {
		v    tenant.Visibility
		want int
	}{
		{tenant.AllTeams(), 1}, {tenant.OnlyTeams(team), 1}, {tenant.OnlyTeams(uuid.New()), 0}, {tenant.OnlyTeams(), 0},
		{tenant.Visibility{}, 0},
	}
	for _, c := range cases {
		if n, err := count(db.Visible(c.v)); err != nil || n != c.want {
			t.Errorf("visibilité %q : %d projets, %v ; attendu %d", c.v.Setting(), n, err, c.want)
		}
	}
	// Connexion réutilisée : le réglage de la transaction précédente vaut '' et échoue.
	if n, err := count(); err == nil {
		t.Fatalf("connexion réutilisée sans équipes déclarées : %d projets sans erreur", n)
	}
}
