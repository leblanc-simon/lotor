package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// Bornes des pages.
const (
	SnapshotPageDefault = 20
	SnapshotPageMax     = 100
	ItemPageDefault     = 100
	ItemPageMax         = 500
)

// Snapshot est un instantané tel que l'affichent l'interface et l'API.
type Snapshot struct {
	ID            uuid.UUID
	ProjectID     uuid.UUID
	RefID         uuid.UUID
	RefKind       string
	RefName       string
	Commit        string
	AgentID       *uuid.UUID
	AgentName     string
	AgentVersion  string
	ScannedAt     time.Time
	LastScannedAt time.Time
	BlobID        uuid.UUID
	SetID         uuid.UUID
	Format        sbom.Format
	SpecVersion   string
	Counts        sbom.Counts
	// Current : instantané courant de sa référence.
	Current bool
	// Enrichment est le statut de l'enrichissement IA déclaré par le SBOM (vide sans
	// enrichissement) ; EnrichmentModel, le modèle déclaré.
	Enrichment      sbom.Enrichment
	EnrichmentModel string
	// PreviousID est l'instantané précédent de la même référence (date de scan, puis
	// identifiant) ; nil pour le premier.
	PreviousID *uuid.UUID
	// Changes compte les changements depuis l'instantané précédent : zéro pour un même
	// ensemble, nil sans précédent ou tant que la différence n'est pas calculée
	// (ChangesPending).
	Changes        *DiffCounts
	ChangesPending bool
}

const snapshotColumns = `
	s.id, s.project_id, s.ref_id, r.kind, r.name, coalesce(s.commit_sha, ''), s.agent_id, coalesce(a.name, ''),
	s.agent_version, s.scanned_at, s.last_scanned_at, s.blob_id, s.set_id, s.format, s.spec_version,
	cs.component_count, cs.syft_count, cs.ia_count, cs.weak_count, rc.snapshot_id IS NOT NULL,
	coalesce(s.enrichment, ''), s.enrichment_model,
	prev.id, prev.set_id = s.set_id, d.added_count, d.removed_count, d.upgraded_count, d.downgraded_count`

const snapshotFrom = `
	  FROM snapshots s
	  JOIN tracked_refs r ON r.org_id = s.org_id AND r.id = s.ref_id
	  JOIN component_sets cs ON cs.org_id = s.org_id AND cs.id = s.set_id
	  LEFT JOIN agents a ON a.org_id = s.org_id AND a.id = s.agent_id
	  LEFT JOIN ref_current rc ON rc.org_id = s.org_id AND rc.ref_id = s.ref_id AND rc.snapshot_id = s.id
	  LEFT JOIN LATERAL (
	        SELECT p.id, p.set_id FROM snapshots p
	         WHERE p.org_id = s.org_id AND p.ref_id = s.ref_id AND (p.scanned_at, p.id) < (s.scanned_at, s.id)
	         ORDER BY p.scanned_at DESC, p.id DESC LIMIT 1) prev ON true
	  LEFT JOIN set_diffs d ON d.org_id = s.org_id AND d.from_set_id = prev.set_id AND d.to_set_id = s.set_id`

type scanner interface{ Scan(dest ...any) error }

func scanSnapshot(row scanner) (Snapshot, error) {
	var s Snapshot
	var agentID, prevID uuid.NullUUID
	var sameSet sql.NullBool
	var added, removed, upgraded, downgraded sql.NullInt64
	var format, enrichment string
	err := row.Scan(&s.ID, &s.ProjectID, &s.RefID, &s.RefKind, &s.RefName, &s.Commit, &agentID, &s.AgentName,
		&s.AgentVersion, &s.ScannedAt, &s.LastScannedAt, &s.BlobID, &s.SetID, &format, &s.SpecVersion,
		&s.Counts.Total, &s.Counts.Syft, &s.Counts.IA, &s.Counts.Weak, &s.Current, &enrichment, &s.EnrichmentModel,
		&prevID, &sameSet, &added, &removed, &upgraded, &downgraded)
	if agentID.Valid {
		s.AgentID = &agentID.UUID
	}
	if prevID.Valid {
		s.PreviousID = &prevID.UUID
		switch {
		case sameSet.Bool:
			s.Changes = &DiffCounts{}
		case added.Valid:
			s.Changes = &DiffCounts{Added: int(added.Int64), Removed: int(removed.Int64), Upgraded: int(upgraded.Int64),
				Downgraded: int(downgraded.Int64)}
		default:
			s.ChangesPending = true
		}
	}
	s.Format = sbom.Format(format)
	s.Enrichment = sbom.Enrichment(enrichment)
	return s, err
}

type snapshotCursor struct {
	T time.Time `json:"t"`
	I uuid.UUID `json:"i"`
}

// ListSnapshots renvoie les instantanés d'un projet, ou d'une seule de ses références si
// refID n'est pas nul, du plus récent au plus ancien.
func ListSnapshots(ctx context.Context, tx *db.OrgTx, projectID, refID uuid.UUID, cursor string, limit int) (pagination.Page[Snapshot], error) {
	if limit < 1 || limit > SnapshotPageMax {
		return pagination.Page[Snapshot]{}, &pagination.LimitError{Max: SnapshotPageMax}
	}
	var after snapshotCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Snapshot]{}, err
		}
	}
	query := `SELECT ` + snapshotColumns + snapshotFrom + ` WHERE s.project_id = $1 AND ($2::uuid IS NULL OR s.ref_id = $2)`
	args := []any{projectID, nullUUID(refID)}
	if cursor != "" {
		query += ` AND (s.scanned_at, s.id) < ($3, $4)`
		args = append(args, after.T, after.I)
	}
	query += ` ORDER BY s.scanned_at DESC, s.id DESC LIMIT ` + strconv.Itoa(limit+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Page[Snapshot]{}, wrap("instantanés", err)
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return pagination.Page[Snapshot]{}, wrap("instantanés", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[Snapshot]{}, wrap("instantanés", err)
	}
	return pagination.Build(out, limit, func(s Snapshot) any { return snapshotCursor{T: s.ScannedAt, I: s.ID} })
}

// GetSnapshot renvoie l'instantané id du projet projectID.
func GetSnapshot(ctx context.Context, tx *db.OrgTx, projectID, id uuid.UUID) (Snapshot, error) {
	s, err := scanSnapshot(tx.QueryRowContext(ctx, `SELECT `+snapshotColumns+snapshotFrom+` WHERE s.project_id = $1 AND s.id = $2`,
		projectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	return s, wrap("instantané", err)
}

// RefState résume les instantanés d'une référence d'un projet.
type RefState struct {
	RefID   uuid.UUID
	Kind    string
	Name    string
	Removed bool
	// Snapshots compte les instantanés de la référence.
	Snapshots int
	// Current est l'instantané courant ; nil sans instantané.
	Current *Snapshot
}

// RefStates renvoie l'état des références d'un projet : actives, et retirées qui ont des
// instantanés, triées par nature puis par nom.
func RefStates(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) ([]RefState, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.id, r.kind, r.name, r.removed_at IS NOT NULL,
		       (SELECT count(*) FROM snapshots s WHERE s.org_id = r.org_id AND s.ref_id = r.id), rc.snapshot_id
		  FROM tracked_refs r
		  LEFT JOIN ref_current rc ON rc.org_id = r.org_id AND rc.ref_id = r.id
		 WHERE r.project_id = $1 AND (r.removed_at IS NULL OR rc.ref_id IS NOT NULL)
		 ORDER BY r.kind, r.name`, projectID)
	if err != nil {
		return nil, wrap("états des références", err)
	}
	defer rows.Close()
	var out []RefState
	var currents []uuid.UUID
	for rows.Next() {
		var st RefState
		var cur uuid.NullUUID
		if err := rows.Scan(&st.RefID, &st.Kind, &st.Name, &st.Removed, &st.Snapshots, &cur); err != nil {
			return nil, wrap("états des références", err)
		}
		if cur.Valid {
			currents = append(currents, cur.UUID)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, wrap("états des références", err)
	}
	rows.Close()
	if len(currents) == 0 {
		return out, nil
	}
	snaps, err := snapshotsByID(ctx, tx, currents)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if s, ok := snaps[out[i].RefID]; ok {
			out[i].Current = &s
		}
	}
	return out, nil
}

// snapshotsByID lit des instantanés, indexés par référence.
func snapshotsByID(ctx context.Context, tx *db.OrgTx, ids []uuid.UUID) (map[uuid.UUID]Snapshot, error) {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+snapshotColumns+snapshotFrom+` WHERE s.id = ANY($1::uuid[])`, strs)
	if err != nil {
		return nil, wrap("instantanés courants", err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]Snapshot, len(ids))
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, wrap("instantanés courants", err)
		}
		out[s.RefID] = s
	}
	return out, wrap("instantanés courants", rows.Err())
}

// Current est l'instantané courant d'une référence, tel que l'API des agents l'expose.
type Current struct {
	SnapshotID uuid.UUID
	Commit     string
	ScannedAt  time.Time
}

// CurrentByRef renvoie l'instantané courant de chacune des références qui en ont un.
func CurrentByRef(ctx context.Context, tx *db.OrgTx, refIDs []uuid.UUID) (map[uuid.UUID]Current, error) {
	out := map[uuid.UUID]Current{}
	if len(refIDs) == 0 {
		return out, nil
	}
	strs := make([]string, len(refIDs))
	for i, id := range refIDs {
		strs[i] = id.String()
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT rc.ref_id, s.id, coalesce(s.commit_sha, ''), s.scanned_at FROM ref_current rc
		  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
		 WHERE rc.ref_id = ANY($1::uuid[])`, strs)
	if err != nil {
		return nil, wrap("instantanés courants", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ref uuid.UUID
		var c Current
		if err := rows.Scan(&ref, &c.SnapshotID, &c.Commit, &c.ScannedAt); err != nil {
			return nil, wrap("instantanés courants", err)
		}
		out[ref] = c
	}
	return out, wrap("instantanés courants", rows.Err())
}

// LastSnapshotByProject renvoie, pour chaque projet qui en a un, la date de scan du plus
// récent de ses instantanés courants (liste des projets).
func LastSnapshotByProject(ctx context.Context, tx *db.OrgTx, projectIDs []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := map[uuid.UUID]time.Time{}
	if len(projectIDs) == 0 {
		return out, nil
	}
	strs := make([]string, len(projectIDs))
	for i, id := range projectIDs {
		strs[i] = id.String()
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT rc.project_id, max(s.last_scanned_at) FROM ref_current rc
		  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
		 WHERE rc.project_id = ANY($1::uuid[]) GROUP BY rc.project_id`, strs)
	if err != nil {
		return nil, wrap("derniers instantanés", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var t time.Time
		if err := rows.Scan(&id, &t); err != nil {
			return nil, wrap("derniers instantanés", err)
		}
		out[id] = t
	}
	return out, wrap("derniers instantanés", rows.Err())
}

// Item est un composant d'un ensemble d'inventaire.
type Item struct {
	ComponentID uuid.UUID
	PURL        string
	Type        string
	Name        string
	Version     string
	CPEs        []string
	Hashes      []string
	Origin      sbom.Origin
	Confidence  *float64
	Model       string
	Scope       sbom.Scope
	WeakID      bool
	Licenses    []string
	Evidence    json.RawMessage
	Locations   []sbom.Location
}

// ItemFilter restreint les composants listés.
type ItemFilter struct {
	// Query cherche dans le nom et le purl, sans tenir compte de la casse.
	Query  string
	Origin sbom.Origin
	Type   string
	// WeakOnly ne garde que les composants à identification faible.
	WeakOnly bool
}

// maxQuery borne la saisie d'un filtre.
const maxQuery = 200

type itemCursor struct {
	P string `json:"p"`
}

// ListItems renvoie les composants de l'ensemble setID, par purl.
func ListItems(ctx context.Context, tx *db.OrgTx, setID uuid.UUID, f ItemFilter, cursor string, limit int) (pagination.Page[Item], error) {
	if limit < 1 || limit > ItemPageMax {
		return pagination.Page[Item]{}, &pagination.LimitError{Max: ItemPageMax}
	}
	var after itemCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Item]{}, err
		}
	}
	q := strings.TrimSpace(f.Query)
	if len(q) > maxQuery {
		q = q[:maxQuery]
	}
	pattern := ""
	if q != "" {
		pattern = "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.purl, c.type, c.name, c.version, c.cpes, c.hashes, i.origin, i.confidence::float8, i.model,
		       coalesce(i.scope, ''), i.weak_id, i.licenses, i.evidence, i.locations
		  FROM component_set_items i
		  JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id
		 WHERE i.set_id = $1 AND c.purl > $2
		   AND ($3 = '' OR c.name ILIKE $3 OR c.purl ILIKE $3)
		   AND ($4 = '' OR i.origin = $4) AND ($5 = '' OR c.type = $5) AND (NOT $6 OR i.weak_id)
		 ORDER BY c.purl LIMIT $7`,
		setID, after.P, pattern, string(f.Origin), f.Type, f.WeakOnly, limit+1)
	if err != nil {
		return pagination.Page[Item]{}, wrap("composants", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		var origin, scope string
		var conf sql.NullFloat64
		var evidence, locations []byte
		if err := rows.Scan(&it.ComponentID, &it.PURL, &it.Type, &it.Name, &it.Version, db.Array(&it.CPEs), db.Array(&it.Hashes),
			&origin, &conf, &it.Model, &scope, &it.WeakID, db.Array(&it.Licenses), &evidence, &locations); err != nil {
			return pagination.Page[Item]{}, wrap("composants", err)
		}
		it.Locations = sbom.ParseLocations(locations)
		it.Origin, it.Scope = sbom.Origin(origin), sbom.Scope(scope)
		if conf.Valid {
			it.Confidence = &conf.Float64
		}
		if len(evidence) > 0 {
			it.Evidence = evidence
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[Item]{}, wrap("composants", err)
	}
	return pagination.Build(out, limit, func(it Item) any { return itemCursor{P: it.PURL} })
}

// ItemTypes renvoie les types purl présents dans un ensemble (options du filtre).
func ItemTypes(ctx context.Context, tx *db.OrgTx, setID uuid.UUID) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT c.type FROM component_set_items i JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id
		 WHERE i.set_id = $1 ORDER BY 1`, setID)
	if err != nil {
		return nil, wrap("types", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, wrap("types", err)
		}
		out = append(out, t)
	}
	return out, wrap("types", rows.Err())
}

// Service expose les lectures de l'inventaire aux écrans, chacune dans sa transaction
// InOrg en lecture seule.
type Service struct {
	pool *db.Pool
}

// NewService construit le service.
func NewService(pool *db.Pool) *Service { return &Service{pool: pool} }

func (s *Service) read(ctx context.Context, org tenant.OrgID, fn func(*db.OrgTx) error) error {
	return s.pool.InOrg(ctx, org, fn, db.ReadOnly())
}

// Snapshots : voir ListSnapshots.
func (s *Service) Snapshots(ctx context.Context, org tenant.OrgID, projectID, refID uuid.UUID, cursor string, limit int) (page pagination.Page[Snapshot], err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		page, err = ListSnapshots(ctx, tx, projectID, refID, cursor, limit)
		return err
	})
	return page, err
}

// Snapshot : voir GetSnapshot.
func (s *Service) Snapshot(ctx context.Context, org tenant.OrgID, projectID, id uuid.UUID) (snap Snapshot, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		snap, err = GetSnapshot(ctx, tx, projectID, id)
		return err
	})
	return snap, err
}

// RefStates : voir la fonction RefStates.
func (s *Service) RefStates(ctx context.Context, org tenant.OrgID, projectID uuid.UUID) (out []RefState, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		out, err = RefStates(ctx, tx, projectID)
		return err
	})
	return out, err
}

// Items renvoie une page des composants d'un ensemble et les types présents.
func (s *Service) Items(ctx context.Context, org tenant.OrgID, setID uuid.UUID, f ItemFilter, cursor string, limit int) (page pagination.Page[Item], types []string, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		if page, err = ListItems(ctx, tx, setID, f, cursor, limit); err != nil {
			return err
		}
		types, err = ItemTypes(ctx, tx, setID)
		return err
	})
	return page, types, err
}

// LastSnapshots : voir LastSnapshotByProject.
func (s *Service) LastSnapshots(ctx context.Context, org tenant.OrgID, projectIDs []uuid.UUID) (out map[uuid.UUID]time.Time, err error) {
	err = s.read(ctx, org, func(tx *db.OrgTx) error {
		out, err = LastSnapshotByProject(ctx, tx, projectIDs)
		return err
	})
	return out, err
}
