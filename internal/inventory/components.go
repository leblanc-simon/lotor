package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/tenant"
)

// UsageMax borne la liste des usages d'un composant.
const UsageMax = 500

// Component est un composant de l'organisation.
type Component struct {
	ID       uuid.UUID
	PURL     string
	PURLBase string
	Type     string
	Name     string
	Version  string
	CPEs     []string
	Hashes   []string
}

// GetComponent lit le composant id.
func GetComponent(ctx context.Context, tx *db.OrgTx, id uuid.UUID) (Component, error) {
	var c Component
	err := tx.QueryRowContext(ctx, `SELECT id, purl, purl_base, type, name, version, cpes, hashes FROM components WHERE id = $1`, id).
		Scan(&c.ID, &c.PURL, &c.PURLBase, &c.Type, &c.Name, &c.Version, db.Array(&c.CPEs), db.Array(&c.Hashes))
	if errors.Is(err, sql.ErrNoRows) {
		return Component{}, ErrNotFound
	}
	return c, wrap("composant", err)
}

// Usage est la présence d'un composant dans l'inventaire courant d'une référence.
type Usage struct {
	ComponentID uuid.UUID
	Version     string
	PURL        string
	ProjectID   uuid.UUID
	ProjectSlug string
	ProjectName string
	ProjectKind string
	RefID       uuid.UUID
	RefKind     string
	RefName     string
	Origin      sbom.Origin
	Confidence  *float64
	// Model et Evidence : modèle et preuve d'un composant d'origine IA.
	Model    string
	Evidence json.RawMessage
	Licenses []string
	// Locations : emplacements du composant dans l'inventaire courant de la référence.
	Locations    []sbom.Location
	SnapshotID   uuid.UUID
	ScannedAt    time.Time
	Commit       string
	AgentVersion string
}

// ComponentUsage renvoie les références dont l'inventaire courant contient un composant
// de base purlBase (toutes versions), du plus récent instantané au plus ancien
// (UsageMax au plus). Références retirées, projets archivés et projets invisibles
// (db.Visible) exclus.
func ComponentUsage(ctx context.Context, tx *db.OrgTx, purlBase string) ([]Usage, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.id, c.version, c.purl, p.id, p.slug, p.name, p.kind, r.id, r.kind, r.name, i.origin, i.confidence, i.licenses,
		       s.id, s.scanned_at, coalesce(s.commit_sha, ''), i.model, i.evidence, s.agent_version, i.locations
		  FROM components c
		  JOIN component_set_items i ON i.org_id = c.org_id AND i.component_id = c.id
		  JOIN ref_current rc ON rc.org_id = i.org_id AND rc.set_id = i.set_id
		  JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id AND r.removed_at IS NULL
		  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id AND p.archived_at IS NULL
		  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
		 WHERE c.purl_base = $1 AND lotor_team_visible(p.team_id)
		 ORDER BY s.scanned_at DESC, p.name, r.name, c.version
		 LIMIT `+strconv.Itoa(UsageMax), purlBase)
	if err != nil {
		return nil, wrap("usages d'un composant", err)
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		var origin string
		var conf sql.NullFloat64
		var evidence, locations []byte
		if err := rows.Scan(&u.ComponentID, &u.Version, &u.PURL, &u.ProjectID, &u.ProjectSlug, &u.ProjectName, &u.ProjectKind,
			&u.RefID, &u.RefKind, &u.RefName, &origin, &conf, db.Array(&u.Licenses), &u.SnapshotID, &u.ScannedAt, &u.Commit,
			&u.Model, &evidence, &u.AgentVersion, &locations); err != nil {
			return nil, wrap("usages d'un composant", err)
		}
		u.Locations = sbom.ParseLocations(locations)
		if len(evidence) > 0 {
			u.Evidence = evidence
		}
		u.Origin = sbom.Origin(origin)
		if conf.Valid {
			f := conf.Float64
			u.Confidence = &f
		}
		u.ScannedAt = u.ScannedAt.UTC()
		out = append(out, u)
	}
	return out, wrap("usages d'un composant", rows.Err())
}

// Component renvoie le composant id et l'usage courant de sa famille (même purl_base)
// dans les projets visibles. Un composant qui n'a jamais figuré dans un instantané d'un
// projet visible répond ErrNotFound : son nom ne se lit pas depuis une autre équipe.
func (s *Service) Component(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, id uuid.UUID) (c Component, usage []Usage, err error) {
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		if c, err = GetComponent(ctx, tx, id); err != nil {
			return err
		}
		if !vis.All() {
			var seen bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
				SELECT 1 FROM component_set_items i
				  JOIN snapshots s ON s.org_id = i.org_id AND s.set_id = i.set_id
				  JOIN projects p ON p.org_id = s.org_id AND p.id = s.project_id
				 WHERE i.component_id = $1 AND lotor_team_visible(p.team_id))`, id).Scan(&seen); err != nil {
				return wrap("visibilité d'un composant", err)
			}
			if !seen {
				return ErrNotFound
			}
		}
		usage, err = ComponentUsage(ctx, tx, c.PURLBase)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return c, usage, err
}

// AIComponentsMax borne la liste des composants IA d'une référence.
const AIComponentsMax = 1000

// AIComponent est un composant d'origine IA de l'inventaire courant d'une référence, avec
// sa preuve.
type AIComponent struct {
	PURL       string
	Name       string
	Version    string
	Confidence *float64
	Model      string
	Occurrence sbom.Occurrence
}

// AIComponents renvoie les composants d'origine IA de l'instantané courant de la
// référence refID (l'appelant a vérifié l'accès), triés par purl ; ceux dont la preuve
// n'a pas d'occurrence lisible sont omis.
func AIComponents(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) ([]AIComponent, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.purl, c.name, c.version, i.confidence::float8, i.model, i.evidence
		  FROM ref_current rc
		  JOIN component_set_items i ON i.org_id = rc.org_id AND i.set_id = rc.set_id AND i.origin = 'ia'
		  JOIN components c ON c.org_id = i.org_id AND c.id = i.component_id
		 WHERE rc.ref_id = $1
		 ORDER BY c.purl LIMIT `+strconv.Itoa(AIComponentsMax), refID)
	if err != nil {
		return nil, wrap("composants IA", err)
	}
	defer rows.Close()
	out := []AIComponent{}
	for rows.Next() {
		var a AIComponent
		var conf sql.NullFloat64
		var evidence []byte
		if err := rows.Scan(&a.PURL, &a.Name, &a.Version, &conf, &a.Model, &evidence); err != nil {
			return nil, wrap("composants IA", err)
		}
		occ, ok := sbom.FirstOccurrence(evidence)
		if !ok {
			continue
		}
		a.Occurrence = occ
		if conf.Valid {
			f := conf.Float64
			a.Confidence = &f
		}
		out = append(out, a)
	}
	return out, wrap("composants IA", rows.Err())
}
