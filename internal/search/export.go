package search

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// Format est le format d'un export.
type Format string

// Formats d'export.
const (
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

// exportColumns nomme les colonnes de l'export, dans l'ordre (en-tête CSV, clés JSON) :
// des identifiants stables, pas des libellés traduits.
var exportColumns = []string{
	"project", "project_name", "project_type", "ref_type", "ref", "commit", "scanned_at",
	"component", "version", "purl", "component_type", "origin", "confidence", "weak_identification",
	"open_vulnerabilities", "max_severity", "kev", "risk", "fixed_versions", "vulnerability", "status",
	// Ajoutées en T18, en fin de ligne pour ne pas décaler les colonnes existantes.
	"team", "triage_status",
	// Ajoutée avec les emplacements (ADR 0057) : chemins principaux séparés par « ; ».
	"locations",
}

// ExportRow est une occurrence exportée, avec son projet.
type ExportRow struct {
	Project ProjectRef
	Hit
}

// Export écrit toutes les occurrences d'une recherche dans w, au format f, par projet
// (nom), référence et composant. Les lignes sont lues et écrites en flux, une à une : la
// mémoire ne dépend pas du volume. La lecture se fait dans une transaction en lecture
// seule, que l'appelant borne par le délai de ctx (ADR 0024).
func (s *Service) Export(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, req Request, f Format, w io.Writer) error {
	q, err := Parse(req.Q, s.cmp)
	if err != nil {
		return err
	}
	if err := checkFilters(q, req.Filters); err != nil {
		return err
	}
	var enc rowEncoder
	switch f {
	case FormatCSV:
		enc = newCSVEncoder(w)
	case FormatJSON:
		enc = newJSONEncoder(w, q)
	default:
		return refuse(KeyFilterInvalid)
	}
	err = s.read(ctx, org, vis, func(tx *db.OrgTx) error {
		t, err := s.resolve(ctx, tx, q)
		if err != nil {
			return err
		}
		if err := enc.begin(t.truncated); err != nil {
			return err
		}
		if len(t.components) == 0 && len(t.vulnIDs) == 0 {
			return nil
		}
		a := &args{}
		hits := hitsSQL(t, req.Filters, nil, a)
		rows, err := tx.QueryContext(ctx, `WITH hits AS (`+hits+`)
			`+hitColumns+`, p.slug, p.name, p.kind, tm.id, tm.name `+hitJoins(t)+`
			  JOIN projects p ON p.org_id = h.org_id AND p.id = h.project_id
			  JOIN teams tm ON tm.org_id = p.org_id AND tm.id = p.team_id
			 ORDER BY lower(p.name), p.id, r.name, h.ref_id, c.name, c.version, c.id, h.vuln_id`, a.list...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ExportRow
			var kind string
			dest := append([]any{&r.Project.ID}, r.scanTargets()...)
			if err := rows.Scan(append(dest, &r.Project.Slug, &r.Project.Name, &kind, &r.Project.Team.ID, &r.Project.Team.Name)...); err != nil {
				return err
			}
			r.Project.Kind = project.Kind(kind)
			r.finish(s.cmp)
			if err := enc.row(r); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return wrap("export", err)
	}
	return enc.end()
}

type rowEncoder interface {
	begin(truncated bool) error
	row(ExportRow) error
	end() error
}

// cells écrit une ligne en texte, dans l'ordre d'exportColumns.
func (r ExportRow) cells() []string {
	scanned, conf := "", ""
	if !r.ScannedAt.IsZero() {
		scanned = r.ScannedAt.Format(time.RFC3339)
	}
	if r.Confidence != nil {
		conf = strconv.FormatFloat(*r.Confidence, 'f', -1, 64)
	}
	return []string{
		r.Project.Slug, r.Project.Name, string(r.Project.Kind), r.RefKind, r.RefName, r.Commit, scanned,
		r.Name, r.Version, r.PURL, r.Type, string(r.Origin), conf, strconv.FormatBool(r.Weak),
		strconv.Itoa(r.Open), string(r.Severity), strconv.FormatBool(r.KEV), strconv.FormatFloat(r.Risk, 'f', -1, 64),
		strings.Join(r.Fixed, " "), r.VulnID, string(r.Status), r.Project.Team.Name, string(r.Triage),
		mainPaths(r.Locations),
	}
}

// mainPaths joint les chemins des emplacements principaux (sbom.MainLocations).
func mainPaths(ls []sbom.Location) string {
	paths := make([]string, 0, len(ls))
	for _, l := range sbom.MainLocations(ls) {
		paths = append(paths, l.Path)
	}
	return strings.Join(paths, "; ")
}

type csvEncoder struct {
	buf *bufio.Writer
	w   *csv.Writer
}

func newCSVEncoder(w io.Writer) *csvEncoder {
	buf := bufio.NewWriter(w)
	return &csvEncoder{buf: buf, w: csv.NewWriter(buf)}
}

func (e *csvEncoder) begin(bool) error { return e.w.Write(exportColumns) }

func (e *csvEncoder) row(r ExportRow) error {
	cells := r.cells()
	for i, c := range cells {
		cells[i] = defuse(c)
	}
	return e.w.Write(cells)
}

func (e *csvEncoder) end() error {
	e.w.Flush()
	if err := e.w.Error(); err != nil {
		return err
	}
	return e.buf.Flush()
}

// defuse neutralise une cellule qu'un tableur prendrait pour une formule (« =… », « +… »,
// « -… », « @… ») : noms et versions viennent de SBOM non fiables.
func defuse(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// jsonRow est une occurrence exportée en JSON.
type jsonRow struct {
	Project             string          `json:"project"`
	ProjectName         string          `json:"project_name"`
	ProjectType         string          `json:"project_type"`
	RefType             string          `json:"ref_type"`
	Ref                 string          `json:"ref"`
	Commit              string          `json:"commit,omitempty"`
	ScannedAt           *string         `json:"scanned_at,omitempty"`
	Component           string          `json:"component"`
	Version             string          `json:"version"`
	PURL                string          `json:"purl"`
	ComponentType       string          `json:"component_type"`
	Origin              string          `json:"origin,omitempty"`
	Confidence          *float64        `json:"confidence,omitempty"`
	WeakIdentification  bool            `json:"weak_identification"`
	OpenVulnerabilities int             `json:"open_vulnerabilities"`
	MaxSeverity         string          `json:"max_severity,omitempty"`
	KEV                 bool            `json:"kev"`
	Risk                float64         `json:"risk"`
	FixedVersions       []string        `json:"fixed_versions"`
	Vulnerability       string          `json:"vulnerability,omitempty"`
	Status              string          `json:"status,omitempty"`
	ComponentID         uuid.UUID       `json:"component_id"`
	Team                string          `json:"team"`
	TeamID              uuid.UUID       `json:"team_id"`
	TriageStatus        string          `json:"triage_status,omitempty"`
	Locations           []sbom.Location `json:"locations,omitempty"`
}

type jsonEncoder struct {
	buf   *bufio.Writer
	q     Query
	first bool
}

func newJSONEncoder(w io.Writer, q Query) *jsonEncoder {
	return &jsonEncoder{buf: bufio.NewWriter(w), q: q, first: true}
}

func (e *jsonEncoder) begin(truncated bool) error {
	head, err := json.Marshal(struct {
		Query     string `json:"query"`
		Kind      Kind   `json:"kind"`
		Truncated bool   `json:"truncated"`
	}{e.q.Raw, e.q.Kind, truncated})
	if err != nil {
		return err
	}
	// En-tête sans son accolade fermante, puis le tableau écrit élément par élément.
	_, err = fmt.Fprintf(e.buf, "%s,\"results\":[", head[:len(head)-1])
	return err
}

func (e *jsonEncoder) row(r ExportRow) error {
	j := jsonRow{Project: r.Project.Slug, ProjectName: r.Project.Name, ProjectType: string(r.Project.Kind),
		RefType: r.RefKind, Ref: r.RefName, Commit: r.Commit, Component: r.Name, Version: r.Version, PURL: r.PURL,
		ComponentType: r.Type, Origin: string(r.Origin), Confidence: r.Confidence, WeakIdentification: r.Weak,
		OpenVulnerabilities: r.Open, MaxSeverity: string(r.Severity), KEV: r.KEV, Risk: r.Risk, FixedVersions: r.Fixed,
		Vulnerability: r.VulnID, Status: string(r.Status), ComponentID: r.ComponentID,
		Team: r.Project.Team.Name, TeamID: r.Project.Team.ID, TriageStatus: string(r.Triage), Locations: r.Locations}
	if j.FixedVersions == nil {
		j.FixedVersions = []string{}
	}
	if !r.ScannedAt.IsZero() {
		ts := r.ScannedAt.Format(time.RFC3339)
		j.ScannedAt = &ts
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if !e.first {
		if err := e.buf.WriteByte(','); err != nil {
			return err
		}
	}
	e.first = false
	_, err = e.buf.Write(b)
	return err
}

func (e *jsonEncoder) end() error {
	if _, err := e.buf.WriteString("]}\n"); err != nil {
		return err
	}
	return e.buf.Flush()
}
