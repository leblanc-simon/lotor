package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/notify"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
)

// Jobs de l'évaluation.
const (
	// ProjectKind évalue les règles de constat sur les constats ouverts d'un projet
	// (charge ProjectPayload) : après chaque analyse, chaque changement de statut de triage,
	// et chaque jour.
	ProjectKind = "policy.evaluate_project"
	// OrgKind évalue les règles d'agent de l'organisation et met en file l'évaluation de
	// chacun de ses projets actifs : chaque jour, et après un changement de règle.
	OrgKind = "policy.evaluate_org"
	// AllKind met en file OrgKind pour chaque organisation active (échéance quotidienne).
	AllKind = "policy.evaluate_all"
	// AllEvery est la période de l'échéance (le décompte des jours d'une règle avance
	// d'un jour à chaque passage).
	AllEvery = 24 * time.Hour
	// AllOffset place l'échéance à 02:00 UTC, après les réanalyses de la nuit.
	AllOffset = 2 * time.Hour
)

// ProjectPayload est la charge de ProjectKind.
type ProjectPayload struct {
	ProjectID uuid.UUID `json:"project_id"`
}

// evalLockClass est la classe des verrous consultatifs de l'évaluation (« pol »).
const evalLockClass = 0x706f6c

// EnqueueProject met en file l'évaluation d'un projet, dans la transaction de l'appelant.
func EnqueueProject(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID, priority int) error {
	_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: ProjectKind, Payload: ProjectPayload{ProjectID: projectID},
		Priority: priority, UniqueKey: "project:" + projectID.String()})
	return err
}

// EnqueueOrg met en file l'évaluation de toute l'organisation de tx.
func EnqueueOrg(ctx context.Context, tx *db.OrgTx) error {
	_, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: OrgKind, Priority: jobs.PriorityNormal,
		UniqueKey: "org:" + tx.OrgID().String()})
	return err
}

// OnAnalyzed est le point d'accroche de finding.Analyzer : la référence analysée met
// son projet en évaluation, en priorité haute (un agent dépôt attend le verdict).
func OnAnalyzed(ctx context.Context, tx *db.OrgTx, _ uuid.UUID, projectID uuid.UUID) error {
	return EnqueueProject(ctx, tx, projectID, jobs.PriorityHigh)
}

// OnLicenseChange est le point d'accroche de license.Options.OnChange : un projet dont des
// constats de licence changent est réévalué (règles de sujet « licence », T20).
func OnLicenseChange(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) error {
	return EnqueueProject(ctx, tx, projectID, jobs.PriorityNormal)
}

// OnTriageChange est le point d'accroche de triage.Options.OnChange : chaque projet dont
// un statut de triage change est réévalué.
func OnTriageChange(ctx context.Context, tx *db.OrgTx, changes []triage.Change) error {
	seen := map[uuid.UUID]bool{}
	for _, c := range changes {
		if seen[c.ProjectID] {
			continue
		}
		seen[c.ProjectID] = true
		if err := EnqueueProject(ctx, tx, c.ProjectID, jobs.PriorityNormal); err != nil {
			return err
		}
	}
	return nil
}

// Schedule est l'échéance quotidienne de l'évaluation.
func Schedule() jobs.Schedule {
	return jobs.Schedule{Name: AllKind, Every: AllEvery, Offset: AllOffset, Job: jobs.Job{Kind: AllKind, Priority: jobs.PriorityLow}}
}

// AllHandler met en file OrgKind pour chaque organisation active.
func (s *Service) AllHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, _ jobs.Execution) error {
		after := ""
		for {
			var page []crossorg.OrgSummary
			err := s.o.Pool.InTx(ctx, func(tx *db.Tx) error {
				var err error
				if page, err = crossorg.ListOrganizations(ctx, tx, after, crossorg.MaxPage); err != nil {
					return err
				}
				for _, o := range page {
					if o.ArchivedAt != nil {
						continue
					}
					if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: OrgKind, OrgID: o.Org, Priority: jobs.PriorityLow,
						UniqueKey: "org:" + o.Org.String()}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("policy: évaluation du parc : %w", err)
			}
			if len(page) < crossorg.MaxPage {
				return nil
			}
			after = page[len(page)-1].Slug
		}
	})
}

// OrgHandler est le handler de OrgKind.
func (s *Service) OrgHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		if e.OrgID.IsZero() {
			return jobs.Permanent(errors.New("policy: évaluation sans organisation"))
		}
		return s.EvaluateOrg(ctx, e.OrgID)
	})
}

// ProjectHandler est le handler de ProjectKind.
func (s *Service) ProjectHandler() jobs.Handler {
	return jobs.HandlerFunc(func(ctx context.Context, e jobs.Execution) error {
		var p ProjectPayload
		if err := e.Decode(&p); err != nil {
			return err
		}
		if e.OrgID.IsZero() || p.ProjectID == uuid.Nil {
			return jobs.Permanent(errors.New("policy: évaluation sans organisation ni projet"))
		}
		return s.EvaluateProject(ctx, e.OrgID, p.ProjectID)
	})
}

// EvaluateOrg évalue les règles d'agent et met en file l'évaluation de chaque projet.
func (s *Service) EvaluateOrg(ctx context.Context, org tenant.OrgID) error {
	if err := s.EvaluateAgents(ctx, org); err != nil {
		return err
	}
	return wrap("évaluation de l'organisation", s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM projects WHERE archived_at IS NULL
			UNION SELECT DISTINCT project_id FROM policy_violations WHERE resolved_at IS NULL AND project_id IS NOT NULL
			ORDER BY 1`)
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
			if err := EnqueueProject(ctx, tx, id, jobs.PriorityLow); err != nil {
				return err
			}
		}
		return nil
	}))
}

// rule est une règle active compilée.
type rule struct {
	Policy
	prg    *Program
	errors int
	first  string
}

// rules lit et compile les règles actives d'un sujet. Une règle qui ne compile plus
// (environnement changé) note son erreur et ne s'évalue pas.
func (s *Service) rules(ctx context.Context, tx *db.OrgTx, subject Subject) ([]*rule, error) {
	ps, err := listPolicies(ctx, tx, `p.enabled AND p.subject = $1`, subject)
	if err != nil {
		return nil, err
	}
	var out []*rule
	for _, p := range ps {
		prg, err := s.o.Compiler.Compile(p.Subject, p.Expression)
		r := &rule{Policy: p, prg: prg}
		if err != nil {
			r.errors, r.first = 1, err.Error()
			r.prg = nil
		}
		out = append(out, r)
	}
	return out, nil
}

// recordErrors note sur chaque règle sa dernière erreur d'évaluation, ou l'efface.
func recordErrors(ctx context.Context, tx *db.OrgTx, rules []*rule, now time.Time) error {
	for _, r := range rules {
		if r.errors == 0 {
			if r.LastError != "" {
				if _, err := tx.ExecContext(ctx, `UPDATE policies SET last_error = NULL, last_error_at = NULL WHERE id = $1`,
					r.ID); err != nil {
					return err
				}
			}
			continue
		}
		msg := r.first
		if len(msg) > 480 {
			msg = msg[:480]
		}
		msg = strings.ToValidUTF8(msg, "")
		if _, err := tx.ExecContext(ctx, `UPDATE policies SET last_error = $2, last_error_at = $3 WHERE id = $1`,
			r.ID, fmt.Sprintf("%s (%d)", msg, r.errors), now); err != nil {
			return err
		}
	}
	return nil
}

func (r *rule) fail(err error) {
	r.errors++
	if r.first == "" {
		r.first = err.Error()
	}
}

// subjectKey identifie une violation par sa règle et son sujet.
type subjectKey struct {
	policy  uuid.UUID
	subject uuid.UUID
}

type findingHit struct {
	ref, project uuid.UUID
}

// days renvoie les jours entiers écoulés de since à now (0 si since est postérieure).
func days(since, now time.Time) int64 {
	if since.IsZero() || now.Before(since) {
		return 0
	}
	return int64(math.Floor(now.Sub(since).Hours() / 24))
}

// actionable dit si un statut de triage demande encore une action.
func actionable(s triage.Status) bool {
	return s == triage.StatusInTriage || s == triage.StatusAffected
}

// projectRow est le projet évalué.
type projectRow struct {
	Project
	archived bool
}

func readProject(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (projectRow, error) {
	var p projectRow
	var labels []byte
	var archived sql.NullTime
	// Un conteneur (T13) hérite des étiquettes de son hôte, les siennes l'emportant : la
	// règle « KEV sur un projet de production » vaut pour les conteneurs d'un hôte de
	// production.
	err := tx.QueryRowContext(ctx, `SELECT p.name, p.slug, p.kind, coalesce(h.labels, '{}') || p.labels, p.archived_at,
		coalesce((SELECT t.name FROM teams t WHERE t.org_id = p.org_id AND t.id = p.team_id), ''), coalesce(h.name, '')
		FROM projects p LEFT JOIN projects h ON h.org_id = p.org_id AND h.id = p.parent_id
		WHERE p.id = $1`, id).Scan(&p.Name, &p.Slug, &p.Kind, &labels, &archived, &p.Team, &p.Host)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.archived = archived.Valid
	p.Labels = map[string]string{}
	if err := json.Unmarshal(labels, &p.Labels); err != nil {
		return p, fmt.Errorf("étiquettes du projet : %w", err)
	}
	return p, nil
}

// findingRow est un constat ouvert lu pour l'évaluation.
type findingRow struct {
	id, ref uuid.UUID
	in      FindingInput
}

const findingQuery = `SELECT f.id, f.ref_id, f.vuln_id, f.severity, coalesce(f.cvss_score, 0)::float8, coalesce(f.epss, 0)::float8,
	coalesce(f.epss_percentile, 0)::float8, f.risk::float8, f.kev, f.fix_state, f.fixed_versions, f.fixed_seen_at,
	f.first_seen_at, f.match_type, f.triage_status, c.purl, c.purl_base, c.type, c.name, c.version, r.kind, r.name
	FROM findings f
	JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
	JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
	WHERE f.project_id = $1 AND f.status = 'open' AND r.removed_at IS NULL
	ORDER BY f.id`

// readFindings lit les constats ouverts des références actives d'un projet.
func readFindings(ctx context.Context, tx *db.OrgTx, p Project, projectID uuid.UUID, now time.Time) ([]findingRow, error) {
	rows, err := tx.QueryContext(ctx, findingQuery, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var f findingRow
		var fixState, status string
		var fixedSeen sql.NullTime
		fd := &f.in.Finding
		if err := rows.Scan(&f.id, &f.ref, &fd.VulnID, &fd.Severity, &fd.CVSS, &fd.EPSS, &fd.EPSSPercentile, &fd.Risk, &fd.KEV,
			&fixState, db.Array(&fd.FixedVersions), &fixedSeen, &fd.FirstSeen, &fd.MatchType, &status,
			&f.in.Component.PURL, &f.in.Component.PURLBase, &f.in.Component.Type, &f.in.Component.Name, &f.in.Component.Version,
			&f.in.Ref.Kind, &f.in.Ref.Name); err != nil {
			return nil, err
		}
		fd.FirstSeen = fd.FirstSeen.UTC()
		fd.AgeDays = days(fd.FirstSeen, now)
		fd.FixAvailable = fixState == "fixed"
		if fixedSeen.Valid {
			fd.FixAgeDays = days(fixedSeen.Time, now)
		}
		fd.Actionable = actionable(triage.Status(status))
		f.in.Triage.Status = status
		f.in.Project = p
		out = append(out, f)
	}
	return out, rows.Err()
}

// EvaluateProject évalue les règles de constat actives sur les constats ouverts des
// références actives d'un projet, ouvre les violations nouvelles (et met leurs envois en
// file), prolonge celles qui tiennent, résout les autres, et note l'évaluation de chaque
// référence. Un projet archivé n'a plus de violation. Idempotent ; un verrou consultatif
// par projet sérialise deux évaluations simultanées.
func (s *Service) EvaluateProject(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) error {
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, evalLockClass,
			projectID.String()); err != nil {
			return err
		}
		now := s.now()
		p, err := readProject(ctx, tx, projectID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		rules, err := s.rules(ctx, tx, SubjectFinding)
		if err != nil {
			return err
		}
		hits := map[subjectKey]findingHit{}
		if !p.archived && len(rules) > 0 {
			fs, err := readFindings(ctx, tx, p.Project, projectID, now)
			if err != nil {
				return err
			}
			for _, f := range fs {
				for _, r := range rules {
					if r.prg == nil {
						continue
					}
					ok, err := r.prg.MatchFinding(ctx, f.in, now)
					if err != nil {
						if ctx.Err() != nil {
							return ctx.Err()
						}
						r.fail(err)
						continue
					}
					if ok {
						hits[subjectKey{r.ID, f.id}] = findingHit{ref: f.ref, project: projectID}
					}
				}
			}
		}
		if err := s.apply(ctx, tx, SubjectFinding, `project_id = $1`, []any{projectID}, rules, hits, now); err != nil {
			return err
		}
		if err := recordErrors(ctx, tx, rules, now); err != nil {
			return err
		}
		if err := s.evaluateLicenses(ctx, tx, p, projectID, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO policy_evaluations (org_id, ref_id, project_id, analyzed_at, evaluated_at)
			SELECT ra.org_id, ra.ref_id, ra.project_id, ra.analyzed_at, $2 FROM ref_analyses ra WHERE ra.project_id = $1
			ON CONFLICT (org_id, ref_id) DO UPDATE SET analyzed_at = EXCLUDED.analyzed_at, evaluated_at = EXCLUDED.evaluated_at`,
			projectID, now)
		return err
	})
	return wrap("évaluation d'un projet", err)
}

// licenseQuery lit les constats de licence ouverts des références actives d'un projet.
const licenseQuery = `SELECT f.id, f.ref_id, f.verdict, f.license_ids, f.licenses, f.missing, f.first_seen_at,
	c.purl, c.purl_base, c.type, c.name, c.version, r.kind, r.name
	FROM license_findings f
	JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id
	JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
	WHERE f.project_id = $1 AND f.status = 'open' AND r.removed_at IS NULL
	ORDER BY f.id`

// licenseRow est un constat de licence ouvert lu pour l'évaluation.
type licenseRow struct {
	id, ref uuid.UUID
	in      LicenseInput
}

// readLicenses lit les constats de licence ouverts des références actives d'un projet.
func readLicenses(ctx context.Context, tx *db.OrgTx, p Project, projectID uuid.UUID, now time.Time) ([]licenseRow, error) {
	rows, err := tx.QueryContext(ctx, licenseQuery, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []licenseRow
	for rows.Next() {
		var l licenseRow
		lc := &l.in.License
		if err := rows.Scan(&l.id, &l.ref, &lc.Verdict, db.Array(&lc.IDs), db.Array(&lc.Licenses), &lc.Missing, &lc.FirstSeen,
			&l.in.Component.PURL, &l.in.Component.PURLBase, &l.in.Component.Type, &l.in.Component.Name,
			&l.in.Component.Version, &l.in.Ref.Kind, &l.in.Ref.Name); err != nil {
			return nil, err
		}
		lc.FirstSeen = lc.FirstSeen.UTC()
		lc.AgeDays = days(lc.FirstSeen, now)
		l.in.Project = p
		out = append(out, l)
	}
	return out, rows.Err()
}

// evaluateLicenses évalue les règles de licence (T20) sur les constats de licence ouverts
// d'un projet, comme EvaluateProject pour les constats de vulnérabilité.
func (s *Service) evaluateLicenses(ctx context.Context, tx *db.OrgTx, p projectRow, projectID uuid.UUID, now time.Time) error {
	rules, err := s.rules(ctx, tx, SubjectLicense)
	if err != nil {
		return err
	}
	hits := map[subjectKey]findingHit{}
	if !p.archived && len(rules) > 0 {
		ls, err := readLicenses(ctx, tx, p.Project, projectID, now)
		if err != nil {
			return err
		}
		for _, l := range ls {
			for _, r := range rules {
				if r.prg == nil {
					continue
				}
				ok, err := r.prg.MatchLicense(ctx, l.in, now)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					r.fail(err)
					continue
				}
				if ok {
					hits[subjectKey{r.ID, l.id}] = findingHit{ref: l.ref, project: projectID}
				}
			}
		}
	}
	if err := s.apply(ctx, tx, SubjectLicense, `project_id = $1`, []any{projectID}, rules, hits, now); err != nil {
		return err
	}
	return recordErrors(ctx, tx, rules, now)
}

// EvaluateAgents évalue les règles d'agent actives sur les agents non désactivés.
func (s *Service) EvaluateAgents(ctx context.Context, org tenant.OrgID) error {
	err := s.o.Pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, evalLockClass,
			"agents:"+org.String()); err != nil {
			return err
		}
		now := s.now()
		rules, err := s.rules(ctx, tx, SubjectAgent)
		if err != nil {
			return err
		}
		hits := map[subjectKey]findingHit{}
		if len(rules) > 0 {
			err = agent.ForEach(ctx, tx, now, func(a agent.Agent) error {
				in := AgentContext(a, now)
				for _, r := range rules {
					if r.prg == nil {
						continue
					}
					ok, err := r.prg.MatchAgent(ctx, in, now)
					if err != nil {
						if ctx.Err() != nil {
							return ctx.Err()
						}
						r.fail(err)
						continue
					}
					if ok {
						hits[subjectKey{r.ID, a.ID}] = findingHit{}
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		if err := s.apply(ctx, tx, SubjectAgent, `subject = 'agent'`, nil, rules, hits, now); err != nil {
			return err
		}
		return recordErrors(ctx, tx, rules, now)
	})
	return wrap("évaluation des agents", err)
}

// AgentContext construit le contexte d'évaluation d'un agent.
func AgentContext(a agent.Agent, now time.Time) Agent {
	out := Agent{Name: a.Name, Kind: string(a.Kind), Version: a.Version, Team: a.TeamName, State: string(a.StateAt(now)),
		SilentDays: days(a.SilentSince(), now)}
	if a.LastSeenAt != nil {
		out.LastSeen = a.LastSeenAt.UTC()
	}
	return out
}

// apply confronte les correspondances aux violations ouvertes de la portée (where) :
// ouvre, prolonge ou résout. Les violations ouvertes d'une règle absente de rules
// (désactivée entre-temps) sont résolues aussi.
func (s *Service) apply(ctx context.Context, tx *db.OrgTx, subject Subject, where string, args []any, rules []*rule,
	hits map[subjectKey]findingHit, now time.Time) error {
	col := map[Subject]string{SubjectFinding: "finding_id", SubjectAgent: "agent_id", SubjectLicense: "license_finding_id"}[subject]
	rows, err := tx.QueryContext(ctx, `SELECT id, policy_id, `+col+` FROM policy_violations
		WHERE resolved_at IS NULL AND subject = '`+string(subject)+`' AND `+where, args...)
	if err != nil {
		return err
	}
	var keep, resolve []uuid.UUID
	open := map[subjectKey]bool{}
	for rows.Next() {
		var id uuid.UUID
		var k subjectKey
		if err := rows.Scan(&id, &k.policy, &k.subject); err != nil {
			rows.Close()
			return err
		}
		open[k] = true
		if _, ok := hits[k]; ok {
			keep = append(keep, id)
		} else {
			resolve = append(resolve, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(keep) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_violations SET last_seen_at = greatest($2, opened_at)
			WHERE id = ANY($1::uuid[])`, keep, now); err != nil {
			return err
		}
	}
	if len(resolve) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_violations SET resolved_at = greatest($2, opened_at)
			WHERE id = ANY($1::uuid[])`, resolve, now); err != nil {
			return err
		}
	}
	byID := map[uuid.UUID]*rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	var opened []notify.Opened
	var ids, pols, subjects, refs, projects []string
	for k, h := range hits {
		if open[k] {
			continue
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		ids, pols, subjects = append(ids, id.String()), append(pols, k.policy.String()), append(subjects, k.subject.String())
		ref, project := "", ""
		if subject != SubjectAgent {
			ref, project = h.ref.String(), h.project.String()
		}
		refs, projects = append(refs, ref), append(projects, project)
		if r := byID[k.policy]; r != nil && r.Delivery != DeliveryNone {
			opened = append(opened, notify.Opened{ViolationID: id, PolicyID: k.policy, Mode: notify.Mode(r.Delivery)})
		}
	}
	if len(ids) == 0 {
		return nil
	}
	findingCol, agentCol, licenseCol := "NULL::uuid", "NULL::uuid", "NULL::uuid"
	switch subject {
	case SubjectAgent:
		agentCol = "u.subject_id"
	case SubjectLicense:
		licenseCol = "u.subject_id"
	default:
		findingCol = "u.subject_id"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO policy_violations (org_id, id, policy_id, subject, finding_id, agent_id, license_finding_id, project_id, ref_id,
		                               opened_at, last_seen_at)
		SELECT $1, u.id, u.policy_id, $2, `+findingCol+`, `+agentCol+`, `+licenseCol+`, NULLIF(u.project, '')::uuid,
		       NULLIF(u.ref, '')::uuid, $3, $3
		  FROM unnest($4::uuid[], $5::uuid[], $6::uuid[], $7::text[], $8::text[]) AS u(id, policy_id, subject_id, ref, project)`,
		tx.OrgID(), subject, now, ids, pols, subjects, refs, projects); err != nil {
		return err
	}
	return notify.Queue(ctx, tx, now, opened)
}
