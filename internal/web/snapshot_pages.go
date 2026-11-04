package web

import (
	"errors"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/inventory"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/render"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/sbom/syft"
	"leblanc.io/lotor/internal/tenant"
)

// Tailles des listes des écrans d'instantanés.
const (
	snapshotPageSize  = 10
	ingestionListSize = 10
	itemPageSize      = 100
)

// shortCommit abrège un commit pour l'affichage (7 caractères, comme git).
func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

type refRow struct {
	ID       uuid.UUID
	Kind     string
	Name     string
	Removed  bool
	Count    int
	Last     *stamp
	Href     string
	Selected bool
}

type snapshotRow struct {
	ID          uuid.UUID
	Href        string
	Scanned     *stamp
	LastScanned *stamp // dernière analyse d'un inventaire inchangé (hôte), si plus récente
	Commit      string
	CommitShort string
	AgentName   string
	AgentVer    string
	Counts      sbom.Counts
	Current     bool
	// Enrichment et EnrichmentModel : enrichissement IA déclaré par le SBOM (vide sans).
	Enrichment      string
	EnrichmentModel string
	// Changes résume la différence avec l'instantané précédent ; nil pour le premier ou
	// tant qu'elle n'est pas calculée (ChangesPending). CompareHref ouvre la comparaison.
	Changes        *changeCounts
	ChangesPending bool
	CompareHref    string
}

func (id *identity) snapshotRow(base string, s inventory.Snapshot) snapshotRow {
	row := snapshotRow{ID: s.ID, Href: base + "/snapshots/" + s.ID.String(), Scanned: stampAt(s.ScannedAt),
		Commit: s.Commit, CommitShort: shortCommit(s.Commit), AgentName: s.AgentName, AgentVer: s.AgentVersion,
		Counts: s.Counts, Current: s.Current, Changes: changeCountsOf(s.Changes), ChangesPending: s.ChangesPending,
		Enrichment: string(s.Enrichment), EnrichmentModel: s.EnrichmentModel}
	if s.PreviousID != nil {
		row.CompareHref = base + "/compare?to=" + s.ID.String()
	}
	if s.LastScannedAt.After(s.ScannedAt) {
		row.LastScanned = stampAt(s.LastScannedAt)
	}
	return row
}

type ingestionRow struct {
	Received     *stamp
	RefName      string
	CommitShort  string
	Status       string
	StatusClass  string
	ErrorKey     string
	Outcome      string
	Components   *int
	SnapshotHref string
}

// statusClasses porte l'état d'une ingestion par la forme de sa pastille, pas seulement sa
// couleur.
var statusClasses = map[ingest.Status]string{
	ingest.StatusQueued:     "status",
	ingest.StatusProcessing: "status status--warning",
	ingest.StatusDone:       "status status--active",
	ingest.StatusFailed:     "status status--danger",
}

type snapshotsView struct {
	render.Page
	Base       string
	Project    projectRow
	Tabs       []projectTab
	Refs       []refRow
	Selected   *refRow
	Snapshots  []snapshotRow
	NextHref   template.URL
	Ingestions []ingestionRow
	Compare    *compareForm
	Retention  inventory.RetentionPolicy
}

func (id *identity) snapshots(w http.ResponseWriter, r *http.Request) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return
	}
	acc := access(r)
	ctx := r.Context()
	base := orgBase(acc) + "/projects/" + p.Slug
	states, err := id.Inventory.RefStates(ctx, acc.Org, p.ID)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view := &snapshotsView{
		Page: render.Page{TitleKey: "snapshots.title", TitleArgs: map[string]any{"Name": p.Name}, Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "snapshots"),
		Retention: id.History.Policy(),
	}
	selected := selectedRef(states, r.URL.Query().Get("ref"))
	names := map[uuid.UUID]string{}
	for _, st := range states {
		names[st.RefID] = st.Name
		row := refRow{ID: st.RefID, Kind: st.Kind, Name: st.Name, Removed: st.Removed, Count: st.Snapshots,
			Href: base + "/snapshots?ref=" + st.RefID.String(), Selected: st.RefID == selected}
		if st.Current != nil {
			row.Last = stampAt(st.Current.ScannedAt)
		}
		view.Refs = append(view.Refs, row)
	}
	if i := slices.IndexFunc(view.Refs, func(r refRow) bool { return r.Selected }); i >= 0 {
		view.Selected = &view.Refs[i]
		cursor := r.URL.Query().Get("cursor")
		page, err := id.Inventory.Snapshots(ctx, acc.Org, p.ID, selected, cursor, snapshotPageSize)
		if isPaginationError(err) {
			id.rd.Error(w, r, http.StatusBadRequest)
			return
		}
		if err != nil {
			id.serverError(w, r, err)
			return
		}
		for _, s := range page.Items {
			view.Snapshots = append(view.Snapshots, id.snapshotRow(base, s))
		}
		if page.NextCursor != "" {
			q := url.Values{"ref": {selected.String()}, "cursor": {page.NextCursor}}
			// Requête construite ici par url.Values : sûre comme URL.
			view.NextHref = template.URL("?" + q.Encode())
		}
	}
	choices, err := id.History.Choices(ctx, acc.Org, p.ID, compareChoices)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	view.Compare = compareFormOf(base+"/compare", choices, uuid.Nil, uuid.Nil)
	recent, err := id.Ingest.Recent(ctx, acc.Org, p.ID, ingestionListSize)
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	for _, in := range recent {
		row := ingestionRow{Received: stampAt(in.ReceivedAt), RefName: names[in.RefID], CommitShort: shortCommit(in.Commit),
			Status: string(in.Status), StatusClass: statusClasses[in.Status], ErrorKey: in.ErrorKey, Outcome: in.Outcome,
			Components: in.Components}
		if in.SnapshotID != nil {
			row.SnapshotHref = base + "/snapshots/" + in.SnapshotID.String()
		}
		view.Ingestions = append(view.Ingestions, row)
	}
	id.rd.Render(w, r, http.StatusOK, "projects/snapshots", view)
}

// selectedRef choisit la référence affichée : celle de ?ref= si le projet la suit, sinon
// la première qui a un instantané, sinon la première.
func selectedRef(states []inventory.RefState, raw string) uuid.UUID {
	if want, err := uuid.Parse(raw); err == nil {
		for _, st := range states {
			if st.RefID == want {
				return want
			}
		}
	}
	for _, st := range states {
		if st.Current != nil {
			return st.RefID
		}
	}
	if len(states) > 0 {
		return states[0].RefID
	}
	return uuid.Nil
}

// isPaginationError : curseur illisible ou taille de page refusée (400).
func isPaginationError(err error) bool {
	var le *pagination.LimitError
	return errors.Is(err, pagination.ErrInvalidCursor) || errors.As(err, &le)
}

type itemRow struct {
	Name       string
	Version    string
	Type       string
	PURL       string
	Origin     string
	Confidence *int // en pourcentage
	Licenses   []string
	Weak       bool
	Scope      string
	Locations  locationsView
}

type downloadLink struct {
	LabelKey string
	Href     string
}

type snapshotView struct {
	render.Page
	Base      string
	Project   projectRow
	Tabs      []projectTab
	Snapshot  snapshotRow
	RefKind   string
	RefName   string
	Format    string
	Spec      string
	Downloads []downloadLink
	Items     []itemRow
	NextHref  template.URL
	Query     string
	Origins   []option
	Types     []option
	WeakOnly  bool
	Filtered  bool
}

// loadSnapshot lit l'instantané du chemin, dans le projet du chemin ; 404 sinon.
func (id *identity) loadSnapshot(w http.ResponseWriter, r *http.Request) (project.Project, inventory.Snapshot, bool) {
	p, ok := id.loadProject(w, r)
	if !ok {
		return project.Project{}, inventory.Snapshot{}, false
	}
	sid, err := uuid.Parse(chi.URLParam(r, "snapshotID"))
	if err != nil {
		id.rd.Error(w, r, http.StatusNotFound)
		return project.Project{}, inventory.Snapshot{}, false
	}
	s, err := id.Inventory.Snapshot(r.Context(), access(r).Org, p.ID, sid)
	if errors.Is(err, inventory.ErrNotFound) {
		id.rd.Error(w, r, http.StatusNotFound)
		return project.Project{}, inventory.Snapshot{}, false
	}
	if err != nil {
		id.serverError(w, r, err)
		return project.Project{}, inventory.Snapshot{}, false
	}
	return p, s, true
}

func (id *identity) snapshotPage(w http.ResponseWriter, r *http.Request) {
	p, s, ok := id.loadSnapshot(w, r)
	if !ok {
		return
	}
	acc := access(r)
	q := r.URL.Query()
	base := orgBase(acc) + "/projects/" + p.Slug
	f := inventory.ItemFilter{Query: q.Get("q"), Type: q.Get("type"), WeakOnly: q.Get("weak") == "1"}
	if o := sbom.Origin(q.Get("origin")); slices.Contains(sbom.Origins(), o) {
		f.Origin = o
	}
	page, types, err := id.Inventory.Items(r.Context(), acc.Org, s.SetID, f, q.Get("cursor"), itemPageSize)
	if isPaginationError(err) {
		id.rd.Error(w, r, http.StatusBadRequest)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	row := id.snapshotRow(base, s)
	view := &snapshotView{
		Page: render.Page{TitleKey: "snapshot.title", TitleArgs: map[string]any{"Name": p.Name, "Date": row.Scanned.Display},
			Nav: orgNav(acc, "projects")},
		Base: orgBase(acc), Project: id.projectRow(p, id.Agents.Now()), Tabs: projectTabs(acc, p, "snapshots"),
		Snapshot: row, RefKind: s.RefKind, RefName: s.RefName, Format: string(s.Format), Spec: s.SpecVersion,
		Query: f.Query, WeakOnly: f.WeakOnly, Filtered: f != (inventory.ItemFilter{}),
	}
	dl := row.Href + "/sbom?format="
	view.Downloads = []downloadLink{
		{LabelKey: "snapshot.download_original", Href: dl + "original"},
		{LabelKey: "snapshot.download_cyclonedx", Href: dl + string(syft.TargetCycloneDX16)},
		{LabelKey: "snapshot.download_spdx", Href: dl + string(syft.TargetSPDX23)},
	}
	view.Origins = append(view.Origins, option{Value: "", LabelKey: "common.all", Selected: f.Origin == ""})
	for _, o := range sbom.Origins() {
		view.Origins = append(view.Origins, option{Value: string(o), LabelKey: "origin." + string(o), Selected: f.Origin == o})
	}
	view.Types = append(view.Types, option{Value: "", LabelKey: "common.all", Selected: f.Type == ""})
	for _, t := range types {
		view.Types = append(view.Types, option{Value: t, Label: t, Selected: f.Type == t})
	}
	for _, it := range page.Items {
		ir := itemRow{Name: it.Name, Version: it.Version, Type: it.Type, PURL: it.PURL, Origin: string(it.Origin),
			Licenses: it.Licenses, Weak: it.WeakID, Scope: string(it.Scope), Locations: locationsOf(it.Locations)}
		if it.Confidence != nil {
			pct := int(math.Round(*it.Confidence * 100))
			ir.Confidence = &pct
		}
		view.Items = append(view.Items, ir)
	}
	if page.NextCursor != "" {
		next := url.Values{}
		for _, k := range []string{"q", "origin", "type", "weak"} {
			if v := q.Get(k); v != "" {
				next.Set(k, v)
			}
		}
		next.Set("cursor", page.NextCursor)
		// Requête construite ici par url.Values : sûre comme URL.
		view.NextHref = template.URL("?" + next.Encode())
	}
	id.rd.Render(w, r, http.StatusOK, "projects/snapshot", view)
}

// downloadSBOM sert le SBOM d'un instantané : tel que reçu, ou réencodé en CycloneDX 1.6
// ou SPDX 2.3. Le réencodage tient le document entier en mémoire, plusieurs fois sa
// taille : il prend une place parmi les réencodages simultanés de l'instance, une seule
// par compte (429 sinon, SEC-06).
func (id *identity) downloadSBOM(w http.ResponseWriter, r *http.Request) {
	p, s, ok := id.loadSnapshot(w, r)
	if !ok {
		return
	}
	acc := access(r)
	format := r.URL.Query().Get("format")
	var data []byte
	var err error
	name := p.Slug + "-" + snapshotLabel(s)
	switch target, known := syft.ParseTarget(format); {
	case format == "" || format == "original":
		data, err = id.Ingest.Blob(r.Context(), acc.Org, s.BlobID)
		name += "." + string(s.Format) + ".json"
	case known:
		release, ok := id.Reencodes.Acquire("user:" + strconv.FormatInt(viewerFrom(r).user.ID, 10))
		if !ok {
			w.Header().Set("Retry-After", "30")
			id.rd.Error(w, r, http.StatusTooManyRequests)
			return
		}
		// La place ne couvre que le réencodage : libérée avant l'écriture de la réponse, pour
		// qu'un client qui a reçu le document puisse aussitôt en demander un autre.
		data, err = id.Ingest.Export(r.Context(), acc.Org, s.BlobID, s.Format, target)
		release()
		name += "." + string(target) + ".json"
	default:
		id.rd.Error(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		id.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// snapshotLabel nomme un instantané dans un nom de fichier : son commit abrégé, ou sa date
// de scan pour un hôte. Les deux ne contiennent que [0-9a-zT-].
func snapshotLabel(s inventory.Snapshot) string {
	if s.Commit != "" {
		return shortCommit(s.Commit)
	}
	return strings.ReplaceAll(s.ScannedAt.UTC().Format("20060102T150405"), ":", "")
}

// lastSnapshots donne, pour la liste des projets, la date du dernier instantané de chacun.
func (id *identity) lastSnapshots(r *http.Request, org tenant.OrgID, projects []project.Project) (map[uuid.UUID]time.Time, error) {
	ids := make([]uuid.UUID, len(projects))
	for i, p := range projects {
		ids[i] = p.ID
	}
	return id.Inventory.LastSnapshots(r.Context(), org, ids)
}
