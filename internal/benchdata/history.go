package benchdata

import (
	"context"
	"fmt"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// HistoryWeeks : 12 mois d'historique, un instantané par semaine et par référence.
const HistoryWeeks = 52

// AddHistory complète un jeu produit par Generate (et ses compléments) de weeks semaines
// d'historique pour la recherche à une date passée (T21) : chaque référence reçoit un
// instantané par semaine, daté de 1 à weeks semaines avant son instantané courant. Pour
// ne pas multiplier les liens, l'instantané de la semaine w reprend l'ensemble courant
// d'une autre référence (rang décalé de w) : l'historique change d'une semaine à l'autre,
// avec les ensembles réels du jeu. La rétention est supposée ne pas être passée.
func AddHistory(ctx context.Context, pool *db.Pool, org tenant.OrgID, weeks int) (int, error) {
	var n int64
	err := pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		res, err := tx.ExecContext(ctx, `
			WITH refs AS (
				SELECT rc.org_id, rc.ref_id, rc.project_id, r.kind, s.scanned_at, s.blob_id,
				       row_number() OVER (ORDER BY rc.ref_id) - 1 AS k, count(*) OVER () AS n
				  FROM ref_current rc
				  JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id
				  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id),
			sets AS (SELECT rc.set_id, row_number() OVER (ORDER BY rc.ref_id) - 1 AS k FROM ref_current rc)
			INSERT INTO snapshots (org_id, id, project_id, ref_id, commit_sha, scanned_at, last_scanned_at, blob_id, set_id,
			                       format, spec_version, created_at, updated_at)
			SELECT r.org_id, gen_random_uuid(), r.project_id, r.ref_id,
			       CASE WHEN r.kind IN ('branch', 'tag') THEN encode(sha256((r.ref_id::text || ':' || w)::bytea), 'hex')
			            ELSE NULL END,
			       r.scanned_at - w * interval '1 week', r.scanned_at - w * interval '1 week', r.blob_id, st.set_id,
			       'cyclonedx', '1.6', now(), now()
			  FROM refs r
			  CROSS JOIN generate_series(1, $1) w
			  JOIN sets st ON st.k = (r.k + w) % r.n`, weeks)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("benchdata: historique : %w", err)
	}
	return int(n), nil
}
