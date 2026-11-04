package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
)

// Violation est une violation telle que l'écran la présente.
type Violation struct {
	ID          uuid.UUID
	PolicyID    uuid.UUID
	Policy      string
	Blocking    bool
	Subject     Subject
	OpenedAt    time.Time
	LastSeenAt  time.Time
	ResolvedAt  *time.Time
	FindingID   uuid.UUID
	ProjectSlug string
	Project     string
	Ref         string
	VulnID      string
	Severity    string
	KEV         bool
	Component   string
	AgentID     uuid.UUID
	Agent       string
}

// Filter restreint la liste des violations.
type Filter struct {
	// Resolved : violations résolues au lieu des ouvertes.
	Resolved bool
	PolicyID uuid.UUID
}

// Pages de la liste.
const (
	ViolationPageDefault = 50
	ViolationPageMax     = 200
)

// violationFrom joint ce qu'une violation présente ; la visibilité d'équipe s'applique au
// projet d'un constat ou à l'équipe d'un agent (un agent d'organisation n'est visible que
// des administrateurs, comme dans la liste des agents).
const violationFrom = `
	FROM policy_violations v
	JOIN policies p ON p.org_id = v.org_id AND p.id = v.policy_id
	LEFT JOIN findings f ON f.org_id = v.org_id AND f.id = v.finding_id
	LEFT JOIN license_findings lf ON lf.org_id = v.org_id AND lf.id = v.license_finding_id
	LEFT JOIN components c ON c.org_id = v.org_id AND c.id = coalesce(f.component_id, lf.component_id)
	LEFT JOIN projects pr ON pr.org_id = v.org_id AND pr.id = v.project_id
	LEFT JOIN tracked_refs r ON r.org_id = v.org_id AND r.id = v.ref_id
	LEFT JOIN agents a ON a.org_id = v.org_id AND a.id = v.agent_id`

const violationColumns = `v.id, v.policy_id, p.name, p.blocking, v.subject, v.opened_at, v.last_seen_at, v.resolved_at,
	coalesce(v.finding_id, '00000000-0000-0000-0000-000000000000'::uuid), coalesce(pr.slug, ''), coalesce(pr.name, ''),
	coalesce(r.name, ''), coalesce(f.vuln_id, array_to_string(lf.license_ids, ' '), ''), coalesce(f.severity, lf.verdict, ''),
	coalesce(f.kev, false), coalesce(c.purl, ''),
	coalesce(v.agent_id, '00000000-0000-0000-0000-000000000000'::uuid), coalesce(a.name, '')`

const visibleViolation = `(CASE WHEN v.subject IN ('finding', 'license') THEN lotor_team_visible(pr.team_id)
	ELSE lotor_team_visible(a.team_id) END)`

// activeProject écarte des listes de violations ouvertes celles d'un projet archivé (un
// conteneur absent depuis 7 jours, T13) : elles sont résolues à l'évaluation suivante.
const activeProject = `(v.subject = 'agent' OR pr.archived_at IS NULL)`

func scanViolation(row interface{ Scan(...any) error }) (Violation, error) {
	var v Violation
	err := row.Scan(&v.ID, &v.PolicyID, &v.Policy, &v.Blocking, &v.Subject, &v.OpenedAt, &v.LastSeenAt, &v.ResolvedAt,
		&v.FindingID, &v.ProjectSlug, &v.Project, &v.Ref, &v.VulnID, &v.Severity, &v.KEV, &v.Component, &v.AgentID, &v.Agent)
	return v, err
}

type violationCursor struct {
	At time.Time `json:"t"`
	ID uuid.UUID `json:"i"`
}

// Violations renvoie une page de violations visibles, des plus récentes aux plus
// anciennes (ouverture, ou résolution pour les violations résolues).
func (s *Service) Violations(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, f Filter, cursor string, limit int) (pagination.Page[Violation], error) {
	if limit <= 0 {
		limit = ViolationPageDefault
	}
	if limit > ViolationPageMax {
		return pagination.Page[Violation]{}, &pagination.LimitError{Max: ViolationPageMax}
	}
	var cur violationCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &cur); err != nil {
			return pagination.Page[Violation]{}, err
		}
	}
	order := "v.opened_at"
	state := "v.resolved_at IS NULL AND " + activeProject
	if f.Resolved {
		order, state = "v.resolved_at", "v.resolved_at IS NOT NULL"
	}
	q := `SELECT ` + violationColumns + `, ` + order + violationFrom + ` WHERE ` + state + ` AND ` + visibleViolation +
		` AND ($1::uuid IS NULL OR v.policy_id = $1)
		  AND ($2::timestamptz IS NULL OR (` + order + `, v.id) < ($2, $3::uuid))
		ORDER BY ` + order + ` DESC, v.id DESC LIMIT $4`
	var policyArg, atArg, idArg any
	if f.PolicyID != uuid.Nil {
		policyArg = f.PolicyID
	}
	if cursor != "" {
		atArg, idArg = cur.At, cur.ID
	}
	var out pagination.Page[Violation]
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, q, policyArg, atArg, idArg, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var keys []time.Time
		for rows.Next() {
			var v Violation
			var key time.Time
			err := rows.Scan(&v.ID, &v.PolicyID, &v.Policy, &v.Blocking, &v.Subject, &v.OpenedAt, &v.LastSeenAt, &v.ResolvedAt,
				&v.FindingID, &v.ProjectSlug, &v.Project, &v.Ref, &v.VulnID, &v.Severity, &v.KEV, &v.Component, &v.AgentID,
				&v.Agent, &key)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, v)
			keys = append(keys, key)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out.Items) > limit {
			last := limit - 1
			out.Items = out.Items[:limit]
			next, err := pagination.Encode(violationCursor{At: keys[last], ID: out.Items[last].ID})
			if err != nil {
				return err
			}
			out.NextCursor = next
		}
		return nil
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("liste des violations", err)
}

// Summary résume les violations ouvertes visibles (tableau de bord).
type Summary struct {
	Open     int
	Blocking int
	Recent   []Violation
}

// SummaryRecent est le nombre de violations récentes du résumé.
const SummaryRecent = 5

// Summarize lit, dans la transaction de l'appelant (filtre d'équipe déclaré), le résumé
// des violations ouvertes.
func Summarize(ctx context.Context, tx *db.OrgTx) (Summary, error) {
	var s Summary
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE p.blocking)`+violationFrom+
		` WHERE v.resolved_at IS NULL AND `+activeProject+` AND `+visibleViolation).Scan(&s.Open, &s.Blocking); err != nil {
		return s, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+violationColumns+violationFrom+` WHERE v.resolved_at IS NULL AND `+
		activeProject+` AND `+visibleViolation+` ORDER BY v.opened_at DESC, v.id DESC LIMIT $1`, SummaryRecent)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanViolation(rows)
		if err != nil {
			return s, err
		}
		s.Recent = append(s.Recent, v)
	}
	return s, rows.Err()
}

// Summary lit le résumé des violations ouvertes visibles d'un compte.
func (s *Service) Summary(ctx context.Context, org tenant.OrgID, vis tenant.Visibility) (Summary, error) {
	var out Summary
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		out, err = Summarize(ctx, tx)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return out, wrap("résumé des violations", err)
}

// Items implémente notify.Loader : les violations d'un envoi, telles qu'un message les
// présente.
func (s *Service) Items(ctx context.Context, tx *db.OrgTx, ids []uuid.UUID) ([]notify.Item, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+violationColumns+violationFrom+` WHERE v.id = ANY($1::uuid[])
		ORDER BY p.blocking DESC, v.opened_at, v.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []notify.Item
	for rows.Next() {
		v, err := scanViolation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, notify.Item{ViolationID: v.ID, Policy: v.Policy, Blocking: v.Blocking, Subject: string(v.Subject),
			OpenedAt: v.OpenedAt, Project: v.Project, ProjectSlug: v.ProjectSlug, Ref: v.Ref, VulnID: v.VulnID,
			Severity: v.Severity, KEV: v.KEV, Component: v.Component, Agent: v.Agent})
	}
	return out, rows.Err()
}

var _ notify.Loader = (*Service)(nil)

// Preview compte, sans rien enregistrer, les sujets qu'une règle viole aujourd'hui dans
// toute l'organisation (aperçu de l'écran d'édition). La règle est validée d'abord ; les
// évaluations en échec sont comptées à part.
func (s *Service) Preview(ctx context.Context, org tenant.OrgID, subject Subject, expr string) (matches, failures int, err error) {
	if !subject.Valid() {
		return 0, 0, invalid("subject", KeySubjectInvalid)
	}
	prg, err := s.o.Compiler.Compile(subject, expr)
	if err != nil {
		return 0, 0, err
	}
	now := s.now()
	err = s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		count := func(ok bool, err error) error {
			switch {
			case err != nil && ctx.Err() != nil:
				return ctx.Err()
			case err != nil:
				failures++
			case ok:
				matches++
			}
			return nil
		}
		if subject == SubjectAgent {
			return agent.ForEach(ctx, tx, now, func(a agent.Agent) error {
				return count(prg.MatchAgent(ctx, AgentContext(a, now), now))
			})
		}
		rows, err := tx.QueryContext(ctx, `SELECT id FROM projects WHERE archived_at IS NULL ORDER BY id`)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, id := range ids {
			p, err := readProject(ctx, tx, id)
			if err != nil {
				return err
			}
			if subject == SubjectLicense {
				ls, err := readLicenses(ctx, tx, p.Project, id, now)
				if err != nil {
					return err
				}
				for _, l := range ls {
					if err := count(prg.MatchLicense(ctx, l.in, now)); err != nil {
						return err
					}
				}
				continue
			}
			fs, err := readFindings(ctx, tx, p.Project, id, now)
			if err != nil {
				return err
			}
			for _, f := range fs {
				if err := count(prg.MatchFinding(ctx, f.in, now)); err != nil {
					return err
				}
			}
		}
		return nil
	}, db.ReadOnly())
	return matches, failures, wrap("aperçu d'une règle", err)
}

// VerdictState est l'état du verdict d'un instantané.
type VerdictState string

// États d'un verdict.
const (
	VerdictPending VerdictState = "pending"
	VerdictPass    VerdictState = "pass"
	VerdictFail    VerdictState = "fail"
)

// Verdict est le verdict des politiques sur un instantané.
type Verdict struct {
	State    VerdictState
	Blocking int
	Warnings int
	// Policies sont les règles bloquantes violées (10 au plus, par nom).
	Policies []string
	// URL mène à la page des constats du projet (vide sans URL publique).
	URL string
	// Language est la langue de l'organisation, celle du résumé.
	Language string
}

// MaxVerdictPolicies borne les règles citées par un verdict.
const MaxVerdictPolicies = 10

// Verdict renvoie le verdict d'un instantané envoyé par l'agent : en attente tant que
// l'ensemble de l'instantané n'est pas celui de la dernière analyse de sa référence, ou
// que cette analyse n'a pas été évaluée ; sinon non conforme s'il reste une violation
// bloquante ouverte sur la référence, conforme autrement.
func (s *Service) Verdict(ctx context.Context, org tenant.OrgID, agentID, snapshotID uuid.UUID) (Verdict, error) {
	var v Verdict
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var refID, projectID, setID uuid.UUID
		var slug, orgSlug string
		err := tx.QueryRowContext(ctx, `SELECT sn.ref_id, sn.project_id, sn.set_id, p.slug, o.slug, o.default_language FROM snapshots sn
			JOIN projects p ON p.org_id = sn.org_id AND p.id = sn.project_id
			JOIN organizations o ON o.id = sn.org_id
			WHERE sn.id = $1 AND sn.agent_id = $2`, snapshotID, agentID).Scan(&refID, &projectID, &setID, &slug, &orgSlug,
			&v.Language)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if s.o.PublicURL != "" {
			v.URL = s.o.PublicURL + "/o/" + url.PathEscape(orgSlug) + "/projects/" + url.PathEscape(slug) + "/findings?ref=" +
				refID.String()
		}
		var analysedSet uuid.NullUUID
		var analysedAt, evaluatedFor sql.NullTime
		err = tx.QueryRowContext(ctx, `SELECT ra.set_id, ra.analyzed_at, pe.analyzed_at FROM tracked_refs r
			LEFT JOIN ref_analyses ra ON ra.org_id = r.org_id AND ra.ref_id = r.id
			LEFT JOIN policy_evaluations pe ON pe.org_id = r.org_id AND pe.ref_id = r.id
			WHERE r.id = $1`, refID).Scan(&analysedSet, &analysedAt, &evaluatedFor)
		if err != nil {
			return err
		}
		if !analysedSet.Valid || analysedSet.UUID != setID || !evaluatedFor.Valid || evaluatedFor.Time.Before(analysedAt.Time) {
			v.State = VerdictPending
			return nil
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE p.blocking), count(*) FILTER (WHERE NOT p.blocking)
			FROM policy_violations v JOIN policies p ON p.org_id = v.org_id AND p.id = v.policy_id
			WHERE v.ref_id = $1 AND v.resolved_at IS NULL`, refID).Scan(&v.Blocking, &v.Warnings); err != nil {
			return err
		}
		v.State = VerdictPass
		if v.Blocking == 0 {
			return nil
		}
		v.State = VerdictFail
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT p.name, lower(p.name) FROM policy_violations v
			JOIN policies p ON p.org_id = v.org_id AND p.id = v.policy_id
			WHERE v.ref_id = $1 AND v.resolved_at IS NULL AND p.blocking ORDER BY lower(p.name) LIMIT $2`, refID, MaxVerdictPolicies)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name, lower string
			if err := rows.Scan(&name, &lower); err != nil {
				return err
			}
			v.Policies = append(v.Policies, name)
		}
		return rows.Err()
	}, db.ReadOnly())
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, fmt.Errorf("policy: verdict : %w", err)
	}
	return v, err
}
