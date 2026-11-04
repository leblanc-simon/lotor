package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/db/crossorg"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version"
	"leblanc.io/lotor/internal/vuln"
)

// Bornes de l'exécution.
const (
	// MaxPackageComponents borne les composants d'un même paquet (purl_base) lus pour une
	// recherche par purl : versions, qualificatifs et sous-chemins confondus.
	MaxPackageComponents = 5000
	// MaxGroupHits borne les occurrences montrées par projet dans une page (l'export les
	// donne toutes).
	MaxGroupHits = 100
	// maxVulnIDs borne les identifiants d'une vulnérabilité (identifiant et alias).
	maxVulnIDs = 32
	// maxUnreadable borne les versions illisibles citées dans un résultat.
	maxUnreadable = 20
)

// Service exécute les recherches d'une organisation, sous la RLS.
type Service struct {
	pool *db.Pool
	cmp  version.Comparer
	now  func() time.Time
}

// NewService construit le service ; cmp compare les versions (grypeversion).
func NewService(pool *db.Pool, cmp version.Comparer) *Service {
	return &Service{pool: pool, cmp: cmp, now: time.Now}
}

// WithClock remplace l'horloge qui borne les dates de recherche (tests).
func (s *Service) WithClock(now func() time.Time) *Service {
	cp := *s
	cp.now = now
	return &cp
}

// partial signale une date antérieure à l'horizon de la rétention (ADR 0039) : avant lui,
// seul le dernier instantané de chaque mois est gardé. Sans passage de la rétention,
// l'historique est complet.
func partial(ctx context.Context, tx *db.OrgTx, f Filters, res *Result) error {
	if f.At == nil {
		return nil
	}
	st, ok, err := inventory.ReadRetention(ctx, tx)
	if err != nil || !ok {
		return err
	}
	if f.At.Before(st.Horizon) {
		h := st.Horizon
		res.Partial, res.Horizon = true, &h
	}
	return nil
}

// Comparer renvoie le comparateur de versions du service.
func (s *Service) Comparer() version.Comparer { return s.cmp }

// ProjectRef est le projet d'un groupe de résultats.
type ProjectRef struct {
	ID     uuid.UUID
	Slug   string
	Name   string
	Kind   project.Kind
	Labels project.Labels
	// Parent est l'hôte d'un conteneur.
	Parent *project.ParentRef
	// Team est l'équipe propriétaire (T16).
	Team TeamRef
}

// TeamRef est l'équipe d'un projet.
type TeamRef struct {
	ID   uuid.UUID
	Name string
}

// Hit est une occurrence : un composant dans l'inventaire courant d'une référence (ou,
// pour une recherche par vulnérabilité, un constat).
type Hit struct {
	RefID      uuid.UUID
	RefKind    string
	RefName    string
	SnapshotID uuid.UUID // nul si la référence n'a plus d'instantané courant
	ScannedAt  time.Time
	Commit     string

	ComponentID uuid.UUID
	PURL        string
	Name        string
	Version     string
	Type        string
	// Origin, Confidence, Weak : l'élément de l'inventaire courant (Origin vide pour un
	// constat résolu dont le composant a quitté l'inventaire).
	Origin     sbom.Origin
	Confidence *float64
	Weak       bool

	// Open : vulnérabilités ouvertes de l'occurrence ; Severity, KEV, Risk : la pire
	// d'entre elles (Severity vide sans vulnérabilité). Recherche par vulnérabilité : ceux
	// du constat.
	Open     int
	Severity vuln.Severity
	KEV      bool
	Risk     float64
	// Fixed : versions corrigées connues, triées selon l'écosystème.
	Fixed []string

	// Recherche par vulnérabilité : identifiant, état et statut de triage effectif du
	// constat (T14).
	VulnID    string
	Status    finding.Status
	Triage    triage.Status
	FindingID uuid.UUID

	scan *hitScan
}

// Group réunit les occurrences d'un projet.
type Group struct {
	Project   ProjectRef
	Hits      []Hit
	HitCount  int
	MaxRisk   float64
	Scanned   *time.Time
	Truncated bool // plus de MaxGroupHits occurrences
}

// VersionCount est une version illisible selon l'écosystème et ses occurrences.
type VersionCount struct {
	Version     string
	Occurrences int
}

// Result est une page de résultats.
type Result struct {
	Query      Query
	Groups     []Group
	Projects   int // projets concernés, toutes pages
	Hits       int // occurrences, toutes pages
	NextCursor string
	// Truncated : la requête désigne plus de composants que la borne (nom, empreinte,
	// paquet) ; le résultat porte sur les premiers.
	Truncated bool
	// Approx : aucun nom ne contient la requête, les composants sont ceux dont le nom lui
	// ressemble.
	Approx bool
	// OutOfRange : occurrences du paquet hors de la plage ou de la version demandées
	// (non montrées).
	OutOfRange int
	// Unreadable : versions du paquet illisibles selon l'écosystème, donc ni dans la plage
	// ni hors d'elle (non montrées, mais signalées).
	Unreadable []VersionCount
	// Partial : la date demandée (Filters.At) précède l'horizon de la rétention (T17) ;
	// il ne reste de cette période que le dernier instantané de chaque mois, le résultat
	// est partiel. Horizon est la date de coupure appliquée.
	Partial bool
	Horizon *time.Time
}

// target est ce que désigne une requête : des composants, ou des constats.
type target struct {
	components []uuid.UUID
	vulnIDs    []string
	// excluded et unreadable : composants du paquet écartés par la version ou la plage
	// (recherche par purl).
	excluded   []uuid.UUID
	unreadable map[string][]uuid.UUID
	truncated  bool
	approx     bool
}

// read ouvre la transaction d'une recherche, limitée aux projets des équipes visibles.
func (s *Service) read(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, fn func(*db.OrgTx) error) error {
	return s.pool.InOrg(ctx, org, fn, db.ReadOnly(), db.Visible(vis))
}

// Search exécute une recherche sur les projets visibles : une page de projets, chacun
// avec ses occurrences.
func (s *Service) Search(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, req Request) (Result, error) {
	q, err := Parse(req.Q, s.cmp)
	if err != nil {
		return Result{}, err
	}
	if err := checkFilters(q, req.Filters); err != nil {
		return Result{}, err
	}
	if err := checkAt(req.Filters, s.now()); err != nil {
		return Result{}, err
	}
	if req.Sort == "" {
		req.Sort = SortRisk
	}
	if _, ok := orders[req.Sort]; !ok {
		return Result{}, refuse(KeyFilterInvalid)
	}
	limit := req.Limit
	if limit == 0 {
		limit = DefaultPage
	}
	if limit < 1 || limit > MaxPage {
		return Result{}, &pagination.LimitError{Max: MaxPage}
	}
	var after pageCursor
	if req.Cursor != "" {
		if err := pagination.Decode(req.Cursor, &after); err != nil || after.S != req.Sort {
			return Result{}, pagination.ErrInvalidCursor
		}
	}
	res := Result{Query: q}
	err = s.read(ctx, org, vis, func(tx *db.OrgTx) error {
		t, err := s.resolve(ctx, tx, q)
		if err != nil {
			return err
		}
		res.Truncated, res.Approx = t.truncated, t.approx
		if err := partial(ctx, tx, req.Filters, &res); err != nil {
			return err
		}
		if err := s.page(ctx, tx, t, req, after, limit, &res); err != nil {
			return err
		}
		return s.outside(ctx, tx, t, req.Filters, &res)
	})
	if err != nil {
		return Result{}, wrap("recherche", err)
	}
	return res, nil
}

// checkFilters refuse les filtres sans objet pour la requête : un statut de triage n'existe
// que sur un constat, donc pour une recherche par vulnérabilité.
func checkFilters(q Query, f Filters) error {
	if len(f.Triage) > 0 && q.Kind != KindVulnerability {
		return refuse(KeyTriageVulnOnly)
	}
	// À une date passée, seuls les composants : ni constat, ni sévérité, ni KEV d'alors.
	if f.At != nil && (q.Kind == KindVulnerability || f.KEV || len(f.Severities) > 0 || f.Resolved) {
		return refuse(KeyAtComponentsOnly)
	}
	return nil
}

// checkAt refuse une date dans le futur (au-delà de l'horloge du serveur et de la journée
// en cours) : l'état demandé n'existe pas encore.
func checkAt(f Filters, now time.Time) error {
	if f.At != nil && f.At.After(now.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)) {
		return refuse(KeyAtInvalid)
	}
	return nil
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := IsError(err); ok || errors.Is(err, pagination.ErrInvalidCursor) {
		return err
	}
	var le *pagination.LimitError
	if errors.As(err, &le) {
		return err
	}
	return fmt.Errorf("search: %s : %w", what, err)
}

// resolve traduit la requête en composants (nom, empreinte, purl et plage) ou en
// identifiants de vulnérabilité.
func (s *Service) resolve(ctx context.Context, tx *db.OrgTx, q Query) (target, error) {
	switch q.Kind {
	case KindName:
		m, err := crossorg.ComponentsByName(ctx, tx, q.Name)
		return target{components: m.IDs, truncated: m.Truncated, approx: m.Approx}, err
	case KindHash:
		m, err := crossorg.ComponentsByHash(ctx, tx, q.Hash)
		return target{components: m.IDs, truncated: m.Truncated}, err
	case KindVulnerability:
		ids, err := vulnIDs(ctx, tx, q.VulnID)
		return target{vulnIDs: ids}, err
	case KindPURL:
		return s.resolvePURL(ctx, tx, q)
	}
	return target{}, fmt.Errorf("nature de requête %q", q.Kind)
}

// vulnIDs renvoie les identifiants du catalogue qui désignent id (lui-même, ou une fiche
// dont il est un alias, comme un GHSA ramené à son CVE) ; le catalogue est global, son
// index GIN sur les alias sert sans RLS.
func vulnIDs(ctx context.Context, tx *db.OrgTx, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM vulnerabilities WHERE id = $1 OR aliases @> ARRAY[$1]
		ORDER BY id LIMIT `+strconv.Itoa(maxVulnIDs), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{id}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v != id {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// resolvePURL lit les composants du paquet (un nombre borné), puis retient en Go ceux
// qu'admettent la version, les qualificatifs, le sous-chemin et la plage : une plage n'est
// jamais comparée comme du texte.
func (s *Service) resolvePURL(ctx context.Context, tx *db.OrgTx, q Query) (target, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, purl FROM components WHERE purl_base = $1 ORDER BY id LIMIT $2`,
		q.PURL.PURL.Base, MaxPackageComponents+1)
	if err != nil {
		return target{}, err
	}
	defer rows.Close()
	t := target{unreadable: map[string][]uuid.UUID{}}
	n := 0
	for rows.Next() {
		var id uuid.UUID
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return target{}, err
		}
		if n++; n > MaxPackageComponents {
			t.truncated = true
			break
		}
		p, err := packageurl.FromString(raw)
		if err != nil || !q.PURL.admits(p) {
			t.excluded = append(t.excluded, id)
			continue
		}
		if q.Range == nil {
			t.components = append(t.components, id)
			continue
		}
		in, err := q.Range.Contains(s.cmp, p.Version)
		switch {
		case errors.Is(err, version.ErrNotComparable):
			t.unreadable[p.Version] = append(t.unreadable[p.Version], id)
		case err != nil:
			return target{}, err
		case in:
			t.components = append(t.components, id)
		default:
			t.excluded = append(t.excluded, id)
		}
	}
	return t, rows.Err()
}

// admits indique si un composant du paquet correspond au purl recherché : même version
// s'il en donne une, mêmes valeurs pour ses qualificatifs, même sous-chemin s'il en donne.
func (q PURLQuery) admits(p packageurl.PackageURL) bool {
	if q.PURL.Version != "" && p.Version != q.PURL.Version {
		return false
	}
	if q.Subpath != "" && p.Subpath != q.Subpath {
		return false
	}
	have := p.Qualifiers.Map()
	for k, v := range q.Qualifiers {
		if have[k] != v {
			return false
		}
	}
	return true
}

// pageCursor est la clé du dernier projet d'une page.
type pageCursor struct {
	S Sort      `json:"s"`
	R float64   `json:"r,omitempty"`
	T time.Time `json:"t,omitzero"`
	N string    `json:"n"`
	I uuid.UUID `json:"i"`
}

// orders donne, pour chaque ordre, la clause ORDER BY et la condition « après le
// curseur » ($c1, $c2, $c3 : clé, nom, identifiant).
var orders = map[Sort]struct{ order, after string }{
	SortRisk: {`risk DESC, sort_name, project_id`,
		`(risk < $c1 OR (risk = $c1 AND (sort_name, project_id) > ($c2, $c3)))`},
	SortName: {`sort_name, project_id`, `(sort_name, project_id) > ($c2, $c3)`},
	SortSnapshot: {`scanned DESC NULLS LAST, sort_name, project_id`,
		`(scanned < $c1 OR scanned IS NULL OR (scanned = $c1 AND (sort_name, project_id) > ($c2, $c3)))`},
}

// page lit une page de projets, puis leurs occurrences.
func (s *Service) page(ctx context.Context, tx *db.OrgTx, t target, req Request, after pageCursor, limit int, res *Result) error {
	if len(t.components) == 0 && len(t.vulnIDs) == 0 {
		return nil
	}
	a := &args{}
	hits := hitsSQL(t, req.Filters, nil, a)
	ord := orders[req.Sort]
	if ord.order == "" {
		ord = orders[SortRisk]
	}
	where := "true"
	if req.Cursor != "" {
		c1 := ""
		switch req.Sort {
		case SortRisk:
			c1 = a.add(after.R) + "::float8"
		case SortSnapshot:
			if !after.T.IsZero() {
				c1 = a.add(after.T) + "::timestamptz"
			}
		}
		c2, c3 := a.add(after.N)+"::text", a.add(after.I)+"::uuid"
		where = strings.NewReplacer("$c1", c1, "$c2", c2, "$c3", c3).Replace(ord.after)
		if req.Sort == SortSnapshot && after.T.IsZero() {
			// Le curseur est déjà parmi les projets sans date : seul l'ordre du nom compte.
			where = `scanned IS NULL AND (sort_name, project_id) > (` + c2 + `, ` + c3 + `)`
		}
	}
	query := `WITH hits AS (` + hits + `),
	grouped AS (
		SELECT h.project_id, count(*) AS n, max(h.risk) AS risk, max(s.scanned_at) AS scanned
		  FROM hits h LEFT JOIN snapshots s ON s.org_id = h.org_id AND s.id = h.snapshot_id
		 GROUP BY h.project_id),
	ranked AS (
		SELECT g.project_id, p.slug, p.name, p.kind, p.labels, g.n, g.risk, g.scanned, lower(p.name) AS sort_name,
		       count(*) OVER () AS projects, sum(g.n) OVER () AS total, pp.id AS parent_id, pp.slug AS parent_slug,
		       pp.name AS parent_name, t.id AS team_id, t.name AS team_name
		  FROM grouped g JOIN projects p ON p.id = g.project_id
		  JOIN teams t ON t.org_id = p.org_id AND t.id = p.team_id
		  LEFT JOIN projects pp ON pp.org_id = p.org_id AND pp.id = p.parent_id)
	SELECT project_id, slug, name, kind, labels, n, risk, scanned, sort_name, projects, total, parent_id,
	       coalesce(parent_slug, ''), coalesce(parent_name, ''), team_id, team_name
	  FROM ranked WHERE ` + where + ` ORDER BY ` + ord.order + ` LIMIT ` + a.add(limit+1)
	rows, err := tx.QueryContext(ctx, query, a.list...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type pageRow struct {
		group    Group
		sortName string
	}
	var out []pageRow
	for rows.Next() {
		var r pageRow
		var labels []byte
		var kind, parentSlug, parentName string
		var scanned sql.NullTime
		var parentID uuid.NullUUID
		if err := rows.Scan(&r.group.Project.ID, &r.group.Project.Slug, &r.group.Project.Name, &kind, &labels,
			&r.group.HitCount, &r.group.MaxRisk, &scanned, &r.sortName, &res.Projects, &res.Hits, &parentID, &parentSlug,
			&parentName, &r.group.Project.Team.ID, &r.group.Project.Team.Name); err != nil {
			return err
		}
		if parentID.Valid {
			r.group.Project.Parent = &project.ParentRef{ID: parentID.UUID, Slug: parentSlug, Name: parentName}
		}
		r.group.Project.Kind = project.Kind(kind)
		if err := json.Unmarshal(labels, &r.group.Project.Labels); err != nil {
			return err
		}
		if scanned.Valid {
			ts := scanned.Time.UTC()
			r.group.Scanned = &ts
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if len(out) == 0 {
		return nil
	}
	p, err := pagination.Build(out, limit, func(r pageRow) any {
		c := pageCursor{S: req.Sort, N: r.sortName, I: r.group.Project.ID}
		switch req.Sort {
		case SortSnapshot:
			if r.group.Scanned != nil {
				c.T = *r.group.Scanned
			}
		case SortName:
		default:
			c.R = r.group.MaxRisk
		}
		return c
	})
	if err != nil {
		return err
	}
	res.NextCursor = p.NextCursor
	ids := make([]uuid.UUID, len(p.Items))
	for i, r := range p.Items {
		ids[i] = r.group.Project.ID
		res.Groups = append(res.Groups, r.group)
	}
	return s.details(ctx, tx, t, req.Filters, ids, res.Groups)
}

// details remplit les occurrences des projets d'une page (MaxGroupHits par projet).
func (s *Service) details(ctx context.Context, tx *db.OrgTx, t target, f Filters, projectIDs []uuid.UUID, groups []Group) error {
	a := &args{}
	hits := hitsSQL(t, f, projectIDs, a)
	query := `WITH hits AS (` + hits + `)
	SELECT * FROM (` + hitColumns + `,
	       row_number() OVER (PARTITION BY h.project_id ORDER BY ` + hitOrder + `) AS rn
	  ` + hitJoins(t, f) + `) x
	 WHERE rn <= ` + a.add(MaxGroupHits) + ` ORDER BY project_id, rn`
	rows, err := tx.QueryContext(ctx, query, a.list...)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := map[uuid.UUID]int{}
	for i, g := range groups {
		index[g.Project.ID] = i
	}
	for rows.Next() {
		var h Hit
		var projectID uuid.UUID
		var rn int
		dest := append([]any{&projectID}, h.scanTargets()...)
		if err := rows.Scan(append(dest, &rn)...); err != nil {
			return err
		}
		h.finish(s.cmp)
		if i, ok := index[projectID]; ok {
			groups[i].Hits = append(groups[i].Hits, h)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range groups {
		groups[i].Truncated = groups[i].HitCount > len(groups[i].Hits)
	}
	return nil
}

// outside compte les occurrences du paquet écartées par la version ou la plage, et celles
// des versions illisibles (recherche par purl), avec les mêmes filtres.
func (s *Service) outside(ctx context.Context, tx *db.OrgTx, t target, f Filters, res *Result) error {
	count := func(ids []uuid.UUID) (int, error) {
		if len(ids) == 0 {
			return 0, nil
		}
		a := &args{}
		var n int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (`+hitsSQL(target{components: ids}, f, nil, a)+`) h`, a.list...).Scan(&n)
		return n, err
	}
	var err error
	if res.OutOfRange, err = count(t.excluded); err != nil {
		return err
	}
	versions := make([]string, 0, len(t.unreadable))
	for v := range t.unreadable {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	for _, v := range versions {
		n, err := count(t.unreadable[v])
		if err != nil {
			return err
		}
		if n > 0 && len(res.Unreadable) < maxUnreadable {
			res.Unreadable = append(res.Unreadable, VersionCount{Version: v, Occurrences: n})
		}
	}
	return nil
}

// Labels renvoie les étiquettes des projets actifs et visibles (« clé=valeur » ou
// « clé »), pour le filtre de l'écran.
func (s *Service) Labels(ctx context.Context, org tenant.OrgID, vis tenant.Visibility) ([]string, error) {
	var out []string
	err := s.read(ctx, org, vis, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT l.key, l.value FROM projects p, jsonb_each_text(p.labels) l
			WHERE p.archived_at IS NULL AND lotor_team_visible(p.team_id) ORDER BY l.key, l.value LIMIT 100`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			out = append(out, project.Labels{k: v}.Pairs()[0])
		}
		return rows.Err()
	})
	return out, wrap("étiquettes", err)
}
