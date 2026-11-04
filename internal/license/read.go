package license

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/tenant"
)

// Finding est un constat de licence ouvert, tel que les écrans le présentent.
type Finding struct {
	ID          uuid.UUID
	ProjectSlug string
	Project     string
	RefID       uuid.UUID
	RefKind     string
	RefName     string
	ComponentID uuid.UUID
	PURL        string
	Name        string
	Version     string
	Verdict     Status
	Licenses    []string
	IDs         []string
	Missing     bool
	FirstSeen   time.Time
}

// MaxFindings borne les constats lus pour un écran.
const MaxFindings = 500

const findingColumns = `f.id, p.slug, p.name, r.id, r.kind, r.name, c.id, c.purl, c.name, c.version, f.verdict, f.licenses,
	f.license_ids, f.missing, f.first_seen_at`

const findingFrom = ` FROM license_findings f
	JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id AND p.archived_at IS NULL AND lotor_team_visible(p.team_id)
	JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id AND r.removed_at IS NULL
	JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
	WHERE f.status = 'open'`

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var verdict string
		if err := rows.Scan(&f.ID, &f.ProjectSlug, &f.Project, &f.RefID, &f.RefKind, &f.RefName, &f.ComponentID, &f.PURL, &f.Name,
			&f.Version, &verdict, db.Array(&f.Licenses), db.Array(&f.IDs), &f.Missing, &f.FirstSeen); err != nil {
			return nil, err
		}
		f.Verdict, f.FirstSeen = Status(verdict), f.FirstSeen.UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}

// Findings renvoie les constats de licence ouverts visibles (refusés d'abord, puis à
// revoir), d'un projet si projectID n'est pas nul, sinon de l'organisation ; verdict, s'il
// n'est pas vide, les restreint.
func (s *Service) Findings(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, projectID uuid.UUID, verdict Status) ([]Finding, error) {
	var out []Finding
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+findingColumns+findingFrom+`
			AND ($1::uuid IS NULL OR f.project_id = $1) AND ($2 = '' OR f.verdict = $2)
			ORDER BY f.verdict = 'denied' DESC, lower(p.name), c.name, c.version, r.name, f.id LIMIT $3`,
			nullUUID(projectID), string(verdict), MaxFindings)
		if err != nil {
			return err
		}
		out, err = scanFindings(rows)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("constats de licence", err)
}

// Counts compte les constats de licence ouverts visibles par verdict.
func (s *Service) Counts(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, projectID uuid.UUID) (map[Status]int, error) {
	out := map[Status]int{}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT f.verdict, count(*)`+findingFrom+` AND ($1::uuid IS NULL OR f.project_id = $1)
			GROUP BY f.verdict`, nullUUID(projectID))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			var n int
			if err := rows.Scan(&v, &n); err != nil {
				return err
			}
			out[Status(v)] = n
		}
		return rows.Err()
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("constats de licence", err)
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// Usage est une licence de l'inventaire courant d'un projet : l'expression telle que
// déclarée, les composants qui la portent, et son verdict selon la politique.
type Usage struct {
	Expression string
	Components int
	Status     Status
	Unknown    bool // nom libre ou identifiant inconnu de la liste SPDX
}

// MaxUsages borne les licences lues pour un projet.
const MaxUsages = 500

// ProjectLicenses renvoie les licences de l'inventaire courant des références actives d'un
// projet visible, avec leur verdict (refusées d'abord) ; « sans licence » est la ligne
// d'expression vide.
func (s *Service) ProjectLicenses(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, projectID uuid.UUID) ([]Usage, error) {
	var out []Usage
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := ReadPolicy(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT coalesce(l, ''), count(DISTINCT i.component_id)
			  FROM ref_current rc
			  JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id AND r.removed_at IS NULL
			  JOIN projects pr ON pr.org_id = rc.org_id AND pr.id = rc.project_id AND lotor_team_visible(pr.team_id)
			  JOIN component_set_items i ON i.org_id = rc.org_id AND i.set_id = rc.set_id
			  LEFT JOIN LATERAL unnest(i.licenses) l ON true
			 WHERE rc.project_id = $1
			 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $2`, projectID, MaxUsages)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u Usage
			if err := rows.Scan(&u.Expression, &u.Components); err != nil {
				return err
			}
			var v Verdict
			if u.Expression == "" {
				v = p.Evaluate(nil, s.known)
			} else {
				v = p.Evaluate([]string{u.Expression}, s.known)
			}
			u.Status = v.Status
			u.Unknown = slices.ContainsFunc(v.Licenses, func(l LicenseVerdict) bool { return l.Reason == ReasonUnknown })
			out = append(out, u)
		}
		return rows.Err()
	}, db.ReadOnly(), db.Visible(vis))
	slices.SortStableFunc(out, func(a, b Usage) int { return rank(b.Status) - rank(a.Status) })
	return out, wrap("licences d'un projet", err)
}

// Expressions renvoie les expressions de licence rencontrées dans l'organisation qui
// citent la licence id (recherche « license: », T20), sans tenir compte de la casse ;
// une expression illisible ne se trouve que par son texte exact.
func Expressions(ctx context.Context, tx *db.OrgTx, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT expression FROM license_expressions ORDER BY expression`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(e), id) {
			out = append(out, e)
			continue
		}
		if n, err := Parse(e); err == nil && slices.ContainsFunc(n.IDs(), func(x string) bool { return strings.EqualFold(x, id) }) {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}
