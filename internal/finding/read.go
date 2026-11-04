package finding

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/vuln"
)

// Bornes des listes de constats.
const (
	PageDefault = 50
	PageMax     = 200
	// ListMax borne les listes non paginées (fiche vulnérabilité, fiche composant).
	ListMax = 500
)

// Row est un constat tel que l'affichent les écrans.
type Row struct {
	ID               uuid.UUID
	ProjectID        uuid.UUID
	ProjectSlug      string
	ProjectName      string
	ProjectKind      string
	RefID            uuid.UUID
	RefKind          string
	RefName          string
	ComponentID      uuid.UUID
	ComponentName    string
	ComponentVersion string
	ComponentPURL    string
	VulnID           string
	Severity         vuln.Severity
	CVSS             *float64
	EPSS             *float64
	EPSSPercentile   *float64
	KEV              bool
	Risk             float64
	FixedVersions    []string
	FixState         vuln.FixState
	MatchType        vuln.MatchType
	Status           Status
	Resolution       Resolution
	FirstSeen        time.Time
	LastSeen         time.Time
	ResolvedAt       *time.Time
	// Statut de triage effectif et décision qui le donne (uuid.Nil : aucune), § T14.
	TriageStatus      triage.Status
	TriageDecisionID  uuid.UUID
	ComponentPURLBase string
	ComponentType     string
	// Locations : emplacements du composant dans le dernier instantané qui a constaté la
	// vulnérabilité (sbom.Location), vides pour un inventaire antérieur à la migration 025.
	Locations []sbom.Location
}

const rowColumns = `
	f.id, f.project_id, p.slug, p.name, p.kind, f.ref_id, r.kind, r.name, f.component_id, c.name, c.version, c.purl,
	f.vuln_id, f.severity, f.cvss_score, f.epss, f.epss_percentile, f.kev, f.risk, f.fixed_versions, f.fix_state,
	f.match_type, f.status, coalesce(f.resolution, ''), f.first_seen_at, f.last_seen_at, f.resolved_at,
	f.triage_status, f.triage_decision_id, c.purl_base, c.type,
	(SELECT i.locations FROM snapshots ls
	   JOIN component_set_items i ON i.org_id = ls.org_id AND i.set_id = ls.set_id
	  WHERE ls.org_id = f.org_id AND ls.id = f.snapshot_id AND i.component_id = f.component_id)`

const rowFrom = `
	  FROM findings f
	  JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id
	  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id
	  JOIN components c ON c.org_id = f.org_id AND c.id = f.component_id`

type scanner interface{ Scan(dest ...any) error }

func scanRow(s scanner) (Row, error) {
	var r Row
	var sev, state, mtype, status, res string
	var cvss, epss, pct sql.NullFloat64
	var resolved sql.NullTime
	var triageStatus string
	var decision uuid.NullUUID
	var locations []byte
	err := s.Scan(&r.ID, &r.ProjectID, &r.ProjectSlug, &r.ProjectName, &r.ProjectKind, &r.RefID, &r.RefKind, &r.RefName,
		&r.ComponentID, &r.ComponentName, &r.ComponentVersion, &r.ComponentPURL, &r.VulnID, &sev, &cvss, &epss, &pct,
		&r.KEV, &r.Risk, db.Array(&r.FixedVersions), &state, &mtype, &status, &res, &r.FirstSeen, &r.LastSeen, &resolved,
		&triageStatus, &decision, &r.ComponentPURLBase, &r.ComponentType, &locations)
	if err != nil {
		return Row{}, err
	}
	r.TriageStatus, r.TriageDecisionID = triage.Status(triageStatus), decision.UUID
	r.Locations = sbom.ParseLocations(locations)
	r.Severity, r.FixState, r.MatchType, r.Status, r.Resolution = vuln.Severity(sev), vuln.FixState(state),
		vuln.MatchType(mtype), Status(status), Resolution(res)
	r.CVSS, r.EPSS, r.EPSSPercentile = nullFloat(cvss), nullFloat(epss), nullFloat(pct)
	if resolved.Valid {
		t := resolved.Time.UTC()
		r.ResolvedAt = &t
	}
	r.FirstSeen, r.LastSeen = r.FirstSeen.UTC(), r.LastSeen.UTC()
	return r, nil
}

func nullFloat(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

func scanRows(rows *sql.Rows, err error) ([]Row, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Filter restreint les constats d'un projet.
type Filter struct {
	// RefID : une seule référence (nul : toutes).
	RefID uuid.UUID
	// Status : open par défaut.
	Status   Status
	Severity vuln.Severity // vide : toutes
	KEVOnly  bool
	// Triage ne garde qu'un statut de triage effectif (vide : tous).
	Triage triage.Status
	// HideMuted masque les constats « non affecté » et « faux positif »
	// (triage.Status.Hidden), comme les écrans par défaut ; sans effet avec Triage.
	HideMuted bool
}

type rowCursor struct {
	R string    `json:"r"`
	I uuid.UUID `json:"i"`
}

// ProjectFindings renvoie les constats d'un projet, par risque décroissant.
func ProjectFindings(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID, f Filter, cursor string, limit int) (pagination.Page[Row], error) {
	if limit < 1 || limit > PageMax {
		return pagination.Page[Row]{}, &pagination.LimitError{Max: PageMax}
	}
	if f.Status == "" {
		f.Status = StatusOpen
	}
	where := []string{"f.project_id = $1", "f.status = $2"}
	args := []any{projectID, string(f.Status)}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if f.RefID != uuid.Nil {
		add("f.ref_id = ?", f.RefID)
	}
	if f.Severity != "" {
		add("f.severity = ?", string(f.Severity))
	}
	if f.KEVOnly {
		where = append(where, "f.kev")
	}
	if f.Triage != "" {
		add("f.triage_status = ?", string(f.Triage))
	} else if f.HideMuted {
		add("f.triage_status <> ALL(?::text[])", hiddenStatuses())
	}
	if cursor != "" {
		var c rowCursor
		if err := pagination.Decode(cursor, &c); err != nil {
			return pagination.Page[Row]{}, err
		}
		args = append(args, c.R, c.I)
		n := strconv.Itoa(len(args) - 1)
		m := strconv.Itoa(len(args))
		where = append(where, "(f.risk < $"+n+"::numeric OR (f.risk = $"+n+"::numeric AND f.id > $"+m+"))")
	}
	rows, err := scanRows(tx.QueryContext(ctx, `SELECT `+rowColumns+rowFrom+` WHERE `+strings.Join(where, " AND ")+
		` ORDER BY f.risk DESC, f.id LIMIT `+strconv.Itoa(limit+1), args...))
	if err != nil {
		return pagination.Page[Row]{}, wrap("constats du projet", err)
	}
	return pagination.Build(rows, limit, func(r Row) any {
		return rowCursor{R: strconv.FormatFloat(r.Risk, 'f', 2, 64), I: r.ID}
	})
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return &readError{what: what, err: err}
}

type readError struct {
	what string
	err  error
}

func (e *readError) Error() string { return "finding: " + e.what + " : " + e.err.Error() }
func (e *readError) Unwrap() error { return e.err }

func hiddenStatuses() []string {
	var out []string
	for _, s := range triage.HiddenStatuses() {
		out = append(out, string(s))
	}
	return out
}

// Counts résume des constats.
type Counts struct {
	Open     int
	Resolved int
	KEV      int // ouverts
	// Muted compte les constats ouverts « non affecté » ou « faux positif », masqués par
	// défaut des listes (ils restent comptés dans Open et BySeverity).
	Muted      int
	BySeverity map[vuln.Severity]int
	Projects   int // projets distincts aux constats ouverts (fiche vulnérabilité)
}

// Of renvoie le nombre de constats ouverts d'une sévérité (pour les gabarits).
func (c Counts) Of(s vuln.Severity) int { return c.BySeverity[s] }

func scanCounts(rows *sql.Rows, err error, key func(*sql.Rows) (uuid.UUID, string, string, bool, bool, int, error)) (map[uuid.UUID]Counts, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]Counts{}
	for rows.Next() {
		id, status, sev, kev, muted, n, err := key(rows)
		if err != nil {
			return nil, err
		}
		c := out[id]
		if c.BySeverity == nil {
			c.BySeverity = map[vuln.Severity]int{}
		}
		if Status(status) == StatusResolved {
			c.Resolved += n
		} else {
			c.Open += n
			c.BySeverity[vuln.Severity(sev)] += n
			if kev {
				c.KEV += n
			}
			if muted {
				c.Muted += n
			}
		}
		out[id] = c
	}
	return out, rows.Err()
}

// RefCounts résume les constats de chaque référence d'un projet.
func RefCounts(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) (map[uuid.UUID]Counts, error) {
	rows, err := tx.QueryContext(ctx, `SELECT ref_id, status, severity, kev, triage_status = ANY($2::text[]), count(*)
		  FROM findings WHERE project_id = $1
		 GROUP BY 1, 2, 3, 4, 5`, projectID, hiddenStatuses())
	out, err := scanCounts(rows, err, func(r *sql.Rows) (uuid.UUID, string, string, bool, bool, int, error) {
		var id uuid.UUID
		var status, sev string
		var kev, muted bool
		var n int
		err := r.Scan(&id, &status, &sev, &kev, &muted, &n)
		return id, status, sev, kev, muted, n, err
	})
	return out, wrap("décompte par référence", err)
}

// Sum additionne des décomptes.
func Sum(cs map[uuid.UUID]Counts) Counts {
	t := Counts{BySeverity: map[vuln.Severity]int{}}
	for _, c := range cs {
		t.Open, t.Resolved, t.KEV, t.Muted = t.Open+c.Open, t.Resolved+c.Resolved, t.KEV+c.KEV, t.Muted+c.Muted
		for s, n := range c.BySeverity {
			t.BySeverity[s] += n
		}
	}
	return t
}

// VulnerabilityFindings renvoie les constats d'une vulnérabilité dans les projets visibles
// (db.Visible) de l'organisation, de l'état demandé, par risque décroissant (ListMax au
// plus), et le décompte par état.
func VulnerabilityFindings(ctx context.Context, tx *db.OrgTx, vulnID string, status Status) ([]Row, Counts, error) {
	rows, err := scanRows(tx.QueryContext(ctx, `SELECT `+rowColumns+rowFrom+` WHERE f.vuln_id = $1 AND f.status = $2
		  AND lotor_team_visible(p.team_id)
		ORDER BY f.risk DESC, p.name, r.name, c.version, f.id LIMIT `+strconv.Itoa(ListMax), vulnID, string(status)))
	if err != nil {
		return nil, Counts{}, wrap("constats d'une vulnérabilité", err)
	}
	var c Counts
	err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE f.status = 'open'), count(*) FILTER (WHERE f.status = 'resolved'),
		count(DISTINCT f.project_id) FILTER (WHERE f.status = 'open')
		  FROM findings f JOIN projects p ON p.org_id = f.org_id AND p.id = f.project_id
		 WHERE f.vuln_id = $1 AND lotor_team_visible(p.team_id)`, vulnID).
		Scan(&c.Open, &c.Resolved, &c.Projects)
	return rows, c, wrap("décompte d'une vulnérabilité", err)
}

// ComponentFindings renvoie les constats ouverts des composants de base purlBase
// (toutes versions) dans les projets visibles (db.Visible), pour la fiche composant
// (ListMax au plus).
func ComponentFindings(ctx context.Context, tx *db.OrgTx, purlBase string) ([]Row, error) {
	rows, err := scanRows(tx.QueryContext(ctx, `SELECT `+rowColumns+rowFrom+` WHERE c.purl_base = $1 AND f.status = 'open'
		  AND lotor_team_visible(p.team_id)
		ORDER BY f.risk DESC, f.vuln_id, f.id LIMIT `+strconv.Itoa(ListMax), purlBase))
	return rows, wrap("constats d'un composant", err)
}

// ErrNotFound : constat inconnu dans le projet.
var ErrNotFound = errors.New("finding: constat introuvable")

// Get renvoie un constat d'un projet ; ErrNotFound s'il n'en est pas.
func (s *Service) Get(ctx context.Context, org tenant.OrgID, projectID, findingID uuid.UUID) (r Row, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		r, err = scanRow(tx.QueryRowContext(ctx, `SELECT `+rowColumns+rowFrom+` WHERE f.id = $1 AND f.project_id = $2`,
			findingID, projectID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	return r, err
}

// Event est un événement du cycle de vie d'un constat.
type Event struct {
	At         time.Time
	Kind       string // opened, resolved, reopened
	Resolution Resolution
}

// EventsMax borne l'historique d'un constat.
const EventsMax = 200

// Events renvoie l'historique d'un constat, du plus récent au plus ancien (EventsMax au
// plus).
func (s *Service) Events(ctx context.Context, org tenant.OrgID, findingID uuid.UUID) (out []Event, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT at, kind, coalesce(resolution, '') FROM finding_events WHERE finding_id = $1
			ORDER BY seq DESC LIMIT `+strconv.Itoa(EventsMax), findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Event
			var res string
			if err := rows.Scan(&e.At, &e.Kind, &res); err != nil {
				return err
			}
			e.At, e.Resolution = e.At.UTC(), Resolution(res)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, wrap("historique d'un constat", err)
}

// Analysis est la dernière analyse d'une référence.
type Analysis struct {
	AnalyzedAt time.Time
	Built      time.Time
	Matches    int
}

// Analyses renvoie la dernière analyse de chaque référence d'un projet.
func Analyses(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) (map[uuid.UUID]Analysis, error) {
	rows, err := tx.QueryContext(ctx, `SELECT ref_id, analyzed_at, vulndb_built, match_count FROM ref_analyses WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, wrap("analyses", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]Analysis{}
	for rows.Next() {
		var id uuid.UUID
		var a Analysis
		if err := rows.Scan(&id, &a.AnalyzedAt, &a.Built, &a.Matches); err != nil {
			return nil, wrap("analyses", err)
		}
		a.AnalyzedAt, a.Built = a.AnalyzedAt.UTC(), a.Built.UTC()
		out[id] = a
	}
	return out, wrap("analyses", rows.Err())
}

// Service expose les lectures aux écrans, chacune dans sa transaction en lecture seule.
type Service struct {
	pool *db.Pool
}

// NewService construit le service.
func NewService(pool *db.Pool) *Service { return &Service{pool: pool} }

func (s *Service) read(ctx context.Context, org tenant.OrgID, fn func(*db.OrgTx) error) error {
	return s.pool.InOrg(ctx, org, fn, db.ReadOnly())
}

// Project renvoie une page de constats d'un projet.
func (s *Service) Project(ctx context.Context, org tenant.OrgID, projectID uuid.UUID, f Filter, cursor string, limit int) (page pagination.Page[Row], err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		page, err = ProjectFindings(ctx, tx, projectID, f, cursor, limit)
		return err
	})
	return page, err
}

// RefCounts résume les constats de chaque référence d'un projet.
func (s *Service) RefCounts(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) (out map[uuid.UUID]Counts, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		out, err = RefCounts(ctx, tx, projectID)
		return err
	})
	return out, err
}

// Analyses renvoie la dernière analyse de chaque référence d'un projet.
func (s *Service) Analyses(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) (out map[uuid.UUID]Analysis, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		out, err = Analyses(ctx, tx, projectID)
		return err
	})
	return out, err
}

// Vulnerability renvoie la fiche du catalogue (publique) et les constats des projets
// visibles qui la concernent. vuln.ErrNotFound si le catalogue ne la connaît pas.
func (s *Service) Vulnerability(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, id string, status Status) (e vuln.Entry, rows []Row, c Counts, err error) {
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if e, err = vuln.GetVulnerability(ctx, tx, id); err != nil {
			return err
		}
		rows, c, err = VulnerabilityFindings(ctx, tx, e.ID, status)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return e, rows, c, err
}

// Component renvoie les constats ouverts d'une famille de composants, dans les projets
// visibles.
func (s *Service) Component(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, purlBase string) (rows []Row, err error) {
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err = ComponentFindings(ctx, tx, purlBase)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return rows, err
}
