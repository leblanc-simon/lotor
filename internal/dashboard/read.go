package dashboard

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/vuln"
)

// Service lit les indicateurs et enregistre les statistiques quotidiennes.
type Service struct {
	pool *db.Pool
	now  func() time.Time
}

// Option règle le service.
type Option func(*Service)

// WithClock remplace l'horloge du système (tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService construit le service.
func NewService(pool *db.Pool, opts ...Option) *Service {
	s := &Service{pool: pool, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Now renvoie l'heure de l'horloge du service, en UTC.
func (s *Service) Now() time.Time { return s.now().UTC() }

// day renvoie le jour UTC (minuit) d'un instant.
func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// scope restreint les lectures aux projets visibles de l'organisation (project nul) ou à
// un projet. Dans le premier cas, les équipes visibles sont déclarées à la transaction
// (db.Visible) et filtrées par lotor_team_visible ; all indique qu'elles le sont toutes,
// ce qui permet de lire les statistiques de l'organisation plutôt que d'additionner
// celles des projets.
type scope struct {
	project uuid.UUID
	all     bool
}

func (s scope) org() bool { return s.project == uuid.Nil }

// mutedTriage exclut des indicateurs les constats « non affecté » et « faux positif »
// (triage.Status.Hidden) : ils n'appellent aucune action (T14, ADR 0035).
const mutedTriage = ` AND f.triage_status NOT IN ('not_affected', 'false_positive')`

// openWhere sélectionne les constats ouverts à traiter (sans les non affectés ni les faux
// positifs) des références actives : des projets actifs
// et visibles pour l'organisation, du projet demandé sinon (projets joints en p dans les deux cas). Le paramètre $1 porte la portée dans les
// deux cas (NULL pour l'organisation), pour que les requêtes numérotent leurs paramètres
// de la même façon. joins s'ajoute aux jointures (composants…).
func (s scope) openWhere(joins string) string {
	if s.org() {
		return ` FROM findings f
		  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
		  JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id` + joins + `
		 WHERE f.status = 'open' AND r.removed_at IS NULL AND p.archived_at IS NULL AND $1::uuid IS NULL
		   AND lotor_team_visible(p.team_id)` + mutedTriage
	}
	return ` FROM findings f
	  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
	  JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id` + joins + `
	 WHERE f.status = 'open' AND r.removed_at IS NULL AND f.project_id = $1` + mutedTriage
}

// arg renvoie le paramètre $1 de la portée (NULL pour l'organisation).
func (s scope) arg() any {
	if s.org() {
		return nil
	}
	return s.project
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dashboard: %s : %w", what, err)
}

// openState lit en un seul passage les constats ouverts de la portée, par projet et par
// sévérité : décomptes de la portée, projets exposés (tous, par risque maximal décroissant,
// puis nombre de constats, puis slug) et nombre de projets qui portent une KEV.
func openState(ctx context.Context, tx *db.OrgTx, sc scope) (Counts, []ExposedProject, error) {
	rows, err := tx.QueryContext(ctx, `SELECT f.project_id, max(p.slug), max(p.name), max(p.kind), f.severity, count(*),
		count(*) FILTER (WHERE f.kev), max(f.risk)`+sc.openWhere("")+`
		 GROUP BY f.project_id, f.severity`, sc.arg())
	if err != nil {
		return Counts{}, nil, wrap("constats ouverts", err)
	}
	defer rows.Close()
	total := newCounts()
	byID := map[uuid.UUID]*ExposedProject{}
	var order []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var slug, name, kind, sev string
		var n, kev int
		var risk float64
		if err := rows.Scan(&id, &slug, &name, &kind, &sev, &n, &kev, &risk); err != nil {
			return Counts{}, nil, wrap("constats ouverts", err)
		}
		e, ok := byID[id]
		if !ok {
			e = &ExposedProject{ID: id, Slug: slug, Name: name, Kind: project.Kind(kind), Open: newCounts()}
			byID[id] = e
			order = append(order, id)
		}
		s := vuln.ParseSeverity(sev)
		e.Open.BySeverity[s] += n
		e.Open.KEV += kev
		e.MaxRisk = math.Max(e.MaxRisk, risk)
		total.BySeverity[s] += n
		total.KEV += kev
	}
	if err := rows.Err(); err != nil {
		return Counts{}, nil, wrap("constats ouverts", err)
	}
	projects := make([]ExposedProject, 0, len(order))
	for _, id := range order {
		projects = append(projects, *byID[id])
	}
	slices.SortFunc(projects, func(a, b ExposedProject) int {
		if c := cmp.Compare(b.MaxRisk, a.MaxRisk); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Open.Total(), a.Open.Total()); c != 0 {
			return c
		}
		return strings.Compare(a.Slug, b.Slug)
	})
	return total, projects, nil
}

// kevVulns compte les vulnérabilités KEV distinctes des constats ouverts de la portée.
func kevVulns(ctx context.Context, tx *db.OrgTx, sc scope) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT f.vuln_id)`+sc.openWhere("")+` AND f.kev`, sc.arg()).Scan(&n)
	return n, wrap("KEV ouvertes", err)
}

func kevProjects(projects []ExposedProject) int {
	n := 0
	for _, p := range projects {
		if p.Open.KEV > 0 {
			n++
		}
	}
	return n
}

// fixTimes renvoie le délai médian de correction par sévérité des constats résolus dans
// [from, to) : des projets actifs pour l'organisation, du projet sinon.
func fixTimes(ctx context.Context, tx *db.OrgTx, sc scope, from, to time.Time) (map[vuln.Severity]FixTime, error) {
	query := `SELECT f.severity, count(*),
		percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM f.resolved_at - f.first_seen_at))
		  FROM findings f`
	if sc.org() {
		query += ` JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id
		 WHERE p.archived_at IS NULL AND $1::uuid IS NULL AND lotor_team_visible(p.team_id)`
	} else {
		query += ` WHERE f.project_id = $1`
	}
	query += ` AND f.status = 'resolved' AND f.resolved_at >= $2 AND f.resolved_at < $3 GROUP BY f.severity`
	rows, err := tx.QueryContext(ctx, query, sc.arg(), from, to)
	if err != nil {
		return nil, wrap("délais de correction", err)
	}
	defer rows.Close()
	out := map[vuln.Severity]FixTime{}
	for rows.Next() {
		var sev string
		var n int
		var median float64
		if err := rows.Scan(&sev, &n, &median); err != nil {
			return nil, wrap("délais de correction", err)
		}
		out[vuln.ParseSeverity(sev)] = FixTime{Fixed: n, Median: seconds(median)}
	}
	return out, wrap("délais de correction", rows.Err())
}

func seconds(s float64) time.Duration {
	return time.Duration(math.Round(math.Max(s, 0) * float64(time.Second)))
}

// series lit les statistiques enregistrées de la portée dans [from, to), un jour sur step
// en remontant depuis to. Pour une partie seulement des équipes, la série additionne les
// statistiques des projets visibles (rattachés à leur équipe actuelle).
func series(ctx context.Context, tx *db.OrgTx, sc scope, from, to time.Time, step int) ([]Point, error) {
	query := `SELECT day, open_critical, open_high, open_medium, open_low, open_negligible, open_unknown, open_kev
		  FROM org_daily_stats WHERE $1::uuid IS NULL AND day >= $2 AND day < $3 AND ($3::date - day) % $4 = 0 ORDER BY day`
	switch {
	case !sc.org():
		query = `SELECT day, open_critical, open_high, open_medium, open_low, open_negligible, open_unknown, open_kev
		  FROM project_daily_stats WHERE project_id = $1 AND day >= $2 AND day < $3 AND ($3::date - day) % $4 = 0 ORDER BY day`
	case !sc.all:
		query = `SELECT s.day, sum(s.open_critical), sum(s.open_high), sum(s.open_medium), sum(s.open_low),
		       sum(s.open_negligible), sum(s.open_unknown), sum(s.open_kev)
		  FROM project_daily_stats s JOIN projects p ON p.org_id = s.org_id AND p.id = s.project_id
		 WHERE $1::uuid IS NULL AND lotor_team_visible(p.team_id)
		   AND s.day >= $2 AND s.day < $3 AND ($3::date - s.day) % $4 = 0
		 GROUP BY s.day ORDER BY s.day`
	}
	rows, err := tx.QueryContext(ctx, query, sc.arg(), from, to, step)
	if err != nil {
		return nil, wrap("série", err)
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		p := Point{Open: newCounts()}
		var crit, high, med, low, negl, unk int
		if err := rows.Scan(&p.Day, &crit, &high, &med, &low, &negl, &unk, &p.Open.KEV); err != nil {
			return nil, wrap("série", err)
		}
		p.Day = day(p.Day)
		for s, n := range map[vuln.Severity]int{vuln.SeverityCritical: crit, vuln.SeverityHigh: high, vuln.SeverityMedium: med,
			vuln.SeverityLow: low, vuln.SeverityNegligible: negl, vuln.SeverityUnknown: unk} {
			p.Open.BySeverity[s] = n
		}
		out = append(out, p)
	}
	return out, wrap("série", rows.Err())
}

// lastAnalysis renvoie la dernière analyse d'une référence de la portée.
func lastAnalysis(ctx context.Context, tx *db.OrgTx, sc scope) (*time.Time, error) {
	var t sql.NullTime
	query := `SELECT max(a.analyzed_at) FROM ref_analyses a JOIN projects p ON p.org_id = a.org_id AND p.id = a.project_id
		WHERE $1::uuid IS NULL AND lotor_team_visible(p.team_id)`
	if !sc.org() {
		query = `SELECT max(analyzed_at) FROM ref_analyses WHERE project_id = $1`
	}
	if err := tx.QueryRowContext(ctx, query, sc.arg()).Scan(&t); err != nil {
		return nil, wrap("dernière analyse", err)
	}
	if !t.Valid {
		return nil, nil
	}
	u := t.Time.UTC()
	return &u, nil
}

// summary lit les indicateurs communs de la portée à l'instant now, et renvoie aussi les
// projets aux constats ouverts (openState).
func summary(ctx context.Context, tx *db.OrgTx, sc scope, now time.Time, period Period) (Summary, []ExposedProject, error) {
	today := day(now)
	s := Summary{At: now, Period: period}
	var projects []ExposedProject
	var err error
	if s.Open, projects, err = openState(ctx, tx, sc); err != nil {
		return Summary{}, nil, err
	}
	s.KEVProjects = kevProjects(projects)
	if s.KEVVulns, err = kevVulns(ctx, tx, sc); err != nil {
		return Summary{}, nil, err
	}
	if s.FixTimes, err = fixTimes(ctx, tx, sc, now.AddDate(0, 0, -int(period)), now); err != nil {
		return Summary{}, nil, err
	}
	if s.Trend, err = series(ctx, tx, sc, today.AddDate(0, 0, -int(period)), today, period.Step()); err != nil {
		return Summary{}, nil, err
	}
	week, err := series(ctx, tx, sc, today.AddDate(0, 0, -WeekAgo), today.AddDate(0, 0, -WeekAgo+1), 1)
	if err != nil {
		return Summary{}, nil, err
	}
	if len(week) == 1 {
		s.WeekAgo = &week[0].Open
	}
	s.Trend = append(s.Trend, Point{Day: today, Open: s.Open})
	s.LastAnalysis, err = lastAnalysis(ctx, tx, sc)
	return s, projects, err
}

// read ouvre la transaction des lectures : lecture seule, un seul état pour toute la page.
func (s *Service) read(ctx context.Context, org tenant.OrgID, fn func(*db.OrgTx) error) error {
	return s.pool.InOrg(ctx, org, fn, db.ReadOnly(), db.Isolation(sql.LevelRepeatableRead))
}

// Project renvoie les indicateurs d'un projet (en-tête de sa fiche).
func (s *Service) Project(ctx context.Context, org tenant.OrgID, projectID uuid.UUID, period Period) (Summary, error) {
	var out Summary
	err := s.read(ctx, org, func(tx *db.OrgTx) error {
		var err error
		out, _, err = summary(ctx, tx, scope{project: projectID}, s.Now(), period)
		return err
	})
	return out, err
}

// Org renvoie le tableau de bord d'une organisation, limité aux projets et agents des
// équipes visibles.
func (s *Service) Org(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, period Period) (Org, error) {
	var out Org
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		now := s.Now()
		var err error
		var projects []ExposedProject
		if out.Summary, projects, err = summary(ctx, tx, scope{all: vis.All()}, now, period); err != nil {
			return err
		}
		out.Exposed = projects[:min(len(projects), TopN)]
		if out.Projects, err = projectKinds(ctx, tx); err != nil {
			return err
		}
		if out.Widespread, err = widespread(ctx, tx); err != nil {
			return err
		}
		out.SilentAgents, out.Silent, err = agent.Silent(ctx, tx, now, TopN, true)
		return err
	}, db.ReadOnly(), db.Isolation(sql.LevelRepeatableRead), db.Visible(vis))
	return out, err
}

// OpenByProject renvoie les constats ouverts à traiter de chaque projet demandé (liste des
// projets), selon la règle de l'en-tête de leur fiche : références actives, sans les non
// affectés ni les faux positifs. Les projets sans constat, ou hors des équipes visibles,
// sont absents de la table.
func (s *Service) OpenByProject(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, ids []uuid.UUID) (map[uuid.UUID]Counts, error) {
	out := map[uuid.UUID]Counts{}
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT f.project_id, f.severity, count(*), count(*) FILTER (WHERE f.kev)
			  FROM findings f
			  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
			  JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id
			 WHERE f.status = 'open' AND r.removed_at IS NULL AND f.project_id = ANY($1::uuid[])
			   AND lotor_team_visible(p.team_id)`+mutedTriage+`
			 GROUP BY f.project_id, f.severity`, strs)
		if err != nil {
			return wrap("constats ouverts par projet", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var sev string
			var n, kev int
			if err := rows.Scan(&id, &sev, &n, &kev); err != nil {
				return wrap("constats ouverts par projet", err)
			}
			c, ok := out[id]
			if !ok {
				c = newCounts()
			}
			c.BySeverity[vuln.ParseSeverity(sev)] += n
			c.KEV += kev
			out[id] = c
		}
		return wrap("constats ouverts par projet", rows.Err())
	}, db.ReadOnly(), db.Visible(vis))
	return out, err
}

// projectKinds compte les projets actifs et visibles par nature.
func projectKinds(ctx context.Context, tx *db.OrgTx) (map[project.Kind]int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT kind, count(*) FROM projects WHERE archived_at IS NULL
		AND lotor_team_visible(team_id) GROUP BY kind`)
	if err != nil {
		return nil, wrap("projets", err)
	}
	defer rows.Close()
	out := map[project.Kind]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, wrap("projets", err)
		}
		out[project.Kind(k)] = n
	}
	return out, wrap("projets", rows.Err())
}

// severityRank classe une sévérité en SQL comme vuln.Severity.Rank.
const severityRank = `CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
	WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END`

func rankSeverity(rank int) vuln.Severity {
	all := vuln.Severities()
	i := len(all) - 1 - rank
	if i < 0 || i >= len(all) {
		return vuln.SeverityUnknown
	}
	return all[i]
}

// widespread renvoie les TopN familles de composants (purl_base) aux constats ouverts qui
// touchent le plus de projets actifs. Les constats sont d'abord réduits à un couple
// (composant, projet), puis regroupés par famille ; les versions ne se lisent que pour
// les familles retenues.
func widespread(ctx context.Context, tx *db.OrgTx) ([]Component, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH open AS (
			SELECT f.component_id, f.project_id, max(`+severityRank+`) AS rank, bool_or(f.kev) AS kev`+
		scope{}.openWhere("")+`
			 GROUP BY f.component_id, f.project_id),
		families AS (
			SELECT c.purl_base, min(c.name) AS name, count(DISTINCT o.project_id) AS projects, max(o.rank) AS rank,
			       bool_or(o.kev) AS kev
			  FROM open o JOIN components c ON c.org_id = current_setting('lotor.org_id')::uuid AND c.id = o.component_id
			 GROUP BY c.purl_base
			 ORDER BY count(DISTINCT o.project_id) DESC, max(o.rank) DESC, c.purl_base LIMIT $2),
		versions AS (
			SELECT DISTINCT c.purl_base, c.version, c.id
			  FROM open o JOIN components c ON c.org_id = current_setting('lotor.org_id')::uuid AND c.id = o.component_id
			 WHERE c.purl_base IN (SELECT purl_base FROM families))
		SELECT fa.purl_base, fa.name, fa.projects,
		       (SELECT array_agg(v ORDER BY v) FROM (SELECT DISTINCT version AS v FROM versions WHERE purl_base = fa.purl_base
		                                              ORDER BY v LIMIT `+fmt.Sprint(VersionsShown)+`) top),
		       (SELECT count(DISTINCT version) FROM versions WHERE purl_base = fa.purl_base),
		       fa.rank, fa.kev,
		       (SELECT id FROM versions WHERE purl_base = fa.purl_base ORDER BY version DESC, id LIMIT 1)
		  FROM families fa
		 ORDER BY fa.projects DESC, fa.rank DESC, fa.purl_base`, nil, TopN)
	if err != nil {
		return nil, wrap("composants répandus", err)
	}
	defer rows.Close()
	var out []Component
	for rows.Next() {
		var c Component
		var rank int
		if err := rows.Scan(&c.PURLBase, &c.Name, &c.Projects, db.Array(&c.Versions), &c.VersionCount, &rank, &c.KEV, &c.ID); err != nil {
			return nil, wrap("composants répandus", err)
		}
		c.Worst = rankSeverity(rank)
		out = append(out, c)
	}
	return out, wrap("composants répandus", rows.Err())
}
