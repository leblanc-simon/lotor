package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/jobs"
	"leblanc.io/lotor/internal/sbom"
)

// AnalysisKind est le type du job d'analyse d'une référence, mis en file quand son
// ensemble courant change. Son handler (T06) analyse l'ensemble courant au moment où il
// s'exécute ; la clé d'unicité fond les mises en file successives d'une même référence.
const AnalysisKind = "analysis.ref"

// AnalysisPayload est la charge d'un job analysis.ref.
type AnalysisPayload struct {
	RefID uuid.UUID `json:"ref_id"`
}

// AnalysisUniqueKey est la clé d'unicité du job d'analyse d'une référence.
func AnalysisUniqueKey(refID uuid.UUID) string { return "ref:" + refID.String() }

// ErrNotFound : référence, instantané ou ensemble introuvable dans l'organisation.
var ErrNotFound = errors.New("inventory: introuvable")

// Outcome est l'effet d'un envoi sur les instantanés de la référence.
type Outcome string

// Effets d'un envoi.
const (
	// OutcomeCreated : nouvel instantané.
	OutcomeCreated Outcome = "created"
	// OutcomeReplaced : nouvel inventaire pour le commit d'un instantané de dépôt existant.
	OutcomeReplaced Outcome = "replaced"
	// OutcomeUnchanged : inventaire identique ; seule la date de dernière analyse avance.
	OutcomeUnchanged Outcome = "unchanged"
)

// Record est un inventaire à ranger pour une référence.
type Record struct {
	ProjectID uuid.UUID
	RefID     uuid.UUID
	// Commit est le commit d'un dépôt ; vide pour un hôte.
	Commit       string
	AgentID      uuid.UUID
	AgentVersion string
	ScannedAt    time.Time
	BlobID       uuid.UUID
	Format       sbom.Format
	SpecVersion  string
	// Components sont normalisés (sbom.Normalize) : purl uniques.
	Components []sbom.Component
	// Enrichment et EnrichmentModel : statut de l'enrichissement IA déclaré par le SBOM
	// (vide sans enrichissement), repris par l'instantané à chaque envoi.
	Enrichment      sbom.Enrichment
	EnrichmentModel string
}

// Result décrit ce que Store a écrit.
type Result struct {
	SnapshotID uuid.UUID
	SetID      uuid.UUID
	// SetCreated : l'ensemble n'existait pas encore dans l'organisation.
	SetCreated bool
	Outcome    Outcome
	// CurrentChanged : l'ensemble courant de la référence a changé ; analysis.ref est en
	// file.
	CurrentChanged bool
}

// chunk borne le nombre de lignes d'une instruction d'insertion en lot.
const chunk = 2000

// maxAccumulated borne les CPE et empreintes accumulées sur un composant.
const maxAccumulated = 64

// Store range un inventaire dans la transaction de l'appelant : composants (upsert trié),
// ensemble (réutilisé si son empreinte existe), instantané selon la règle du dépôt ou de
// l'hôte, état courant de la référence et, s'il change, job analysis.ref. Store est
// idempotent : rejouer le même Record ne crée rien.
func Store(ctx context.Context, tx *db.OrgTx, r Record, now time.Time) (Result, error) {
	var refKind string
	err := tx.QueryRowContext(ctx, `SELECT kind FROM tracked_refs WHERE id = $1 AND project_id = $2 FOR UPDATE`,
		r.RefID, r.ProjectID).Scan(&refKind)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, wrap("verrou de la référence", err)
	}
	host := machineRef(refKind)
	if host != (r.Commit == "") {
		return Result{}, fmt.Errorf("inventory: commit %q incompatible avec une référence %s", r.Commit, refKind)
	}
	ids, err := upsertComponents(ctx, tx, r.Components)
	if err != nil {
		return Result{}, wrap("composants", err)
	}
	var res Result
	if res.SetID, res.SetCreated, err = ensureSet(ctx, tx, r.Components, ids); err != nil {
		return Result{}, wrap("ensemble d'inventaire", err)
	}
	cur, err := readCurrent(ctx, tx, r.RefID)
	if err != nil {
		return Result{}, wrap("état courant", err)
	}
	if host {
		err = storeHostSnapshot(ctx, tx, r, cur, now, &res)
	} else {
		err = storeRepoSnapshot(ctx, tx, r, now, &res)
	}
	if err != nil {
		return Result{}, wrap("instantané", err)
	}
	if res.CurrentChanged, err = updateCurrent(ctx, tx, r, cur, res, now); err != nil {
		return Result{}, wrap("état courant", err)
	}
	if res.Outcome != OutcomeUnchanged {
		// Un instantané créé ou remplacé change les couples d'instantanés consécutifs.
		if err := enqueueDiff(ctx, tx, r.RefID); err != nil {
			return Result{}, wrap("mise en file des différences", err)
		}
	}
	if res.CurrentChanged {
		if _, err := jobs.Enqueue(ctx, tx, jobs.Job{Kind: AnalysisKind, Payload: AnalysisPayload{RefID: r.RefID},
			Priority: jobs.PriorityHigh, UniqueKey: AnalysisUniqueKey(r.RefID)}); err != nil {
			return Result{}, wrap("mise en file de l'analyse", err)
		}
	}
	return res, nil
}

func wrap(what string, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("inventory: %s : %w", what, err)
}

// join assemble une liste dont aucun élément ne contient le séparateur 0x1f (les champs
// normalisés n'ont aucun caractère de contrôle) ; string_to_array la relit côté SQL.
func join(s []string) string { return strings.Join(s, "\x1f") }

// upsertComponents insère les composants absents, accumule CPE et empreintes des autres,
// puis renvoie l'identifiant de chacun par purl. Les lignes sont écrites dans l'ordre des
// purl : deux ingestions concurrentes de l'organisation verrouillent leurs composants
// communs dans le même ordre et ne s'interbloquent pas.
func upsertComponents(ctx context.Context, tx *db.OrgTx, cs []sbom.Component) (map[string]uuid.UUID, error) {
	ids := make(map[string]uuid.UUID, len(cs))
	for start := 0; start < len(cs); start += chunk {
		part := cs[start:min(start+chunk, len(cs))]
		n := len(part)
		newIDs, purls, bases, types, names, versions, cpes, hashes :=
			make([]string, n), make([]string, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		for i, c := range part {
			id, err := uuid.NewV7()
			if err != nil {
				return nil, err
			}
			newIDs[i], purls[i], bases[i], types[i], names[i], versions[i] = id.String(), c.PURL, c.PURLBase, c.Type, c.Name, c.Version
			cpes[i], hashes[i] = join(c.CPEs), join(c.Hashes)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO components (org_id, id, purl, purl_base, type, name, version, cpes, hashes)
			SELECT $1, u.id, u.purl, u.purl_base, u.type, u.name, u.version,
			       string_to_array(u.cpes, E'\x1f'), string_to_array(u.hashes, E'\x1f')
			  FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[])
			       AS u(id, purl, purl_base, type, name, version, cpes, hashes)
			 ORDER BY u.purl
			ON CONFLICT (org_id, purl) DO UPDATE SET
			    cpes   = (ARRAY(SELECT DISTINCT e FROM unnest(components.cpes || EXCLUDED.cpes) e ORDER BY e))[1:`+strconv.Itoa(maxAccumulated)+`],
			    hashes = (ARRAY(SELECT DISTINCT e FROM unnest(components.hashes || EXCLUDED.hashes) e ORDER BY e))[1:`+strconv.Itoa(maxAccumulated)+`]
			 WHERE NOT (components.cpes @> EXCLUDED.cpes AND components.hashes @> EXCLUDED.hashes)
			   AND (cardinality(components.cpes) < `+strconv.Itoa(maxAccumulated)+` OR cardinality(components.hashes) < `+strconv.Itoa(maxAccumulated)+`)`,
			tx.OrgID(), newIDs, purls, bases, types, names, versions, cpes, hashes); err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, `SELECT purl, id FROM components WHERE purl = ANY($1::text[])`, purls)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p string
			var id uuid.UUID
			if err := rows.Scan(&p, &id); err != nil {
				rows.Close()
				return nil, err
			}
			ids[p] = id
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	if len(ids) != len(cs) {
		return nil, fmt.Errorf("%d composants relus pour %d écrits (purl en double ?)", len(ids), len(cs))
	}
	return ids, nil
}

// ensureSet renvoie l'ensemble d'empreinte celle des composants, créé au besoin avec ses
// éléments. Deux ingestions qui créent le même ensemble en même temps : la seconde attend
// la première (contrainte unique) puis relit son ensemble, complet puisqu'écrit dans la
// même transaction que lui.
//
// Un ensemble existant est verrouillé (FOR KEY SHARE) avant d'être référencé : la
// rétention, qui supprime les ensembles orphelins en sautant ceux qui sont verrouillés,
// ne peut pas le supprimer entre sa lecture et l'insertion de l'instantané. Supprimé
// juste avant la lecture, il est recréé.
func ensureSet(ctx context.Context, tx *db.OrgTx, cs []sbom.Component, ids map[string]uuid.UUID) (uuid.UUID, bool, error) {
	fp := sbom.Fingerprint(cs)
	counts := sbom.CountsOf(cs)
	for range 3 {
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM component_sets WHERE fingerprint = $1 FOR KEY SHARE`, fp[:]).Scan(&id)
		if err == nil {
			return id, false, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, false, err
		}
		if id, err = uuid.NewV7(); err != nil {
			return uuid.Nil, false, err
		}
		var created uuid.UUID
		err = tx.QueryRowContext(ctx, `
			INSERT INTO component_sets (org_id, id, fingerprint, component_count, syft_count, ia_count, weak_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (org_id, fingerprint) DO NOTHING RETURNING id`,
			tx.OrgID(), id, fp[:], counts.Total, counts.Syft, counts.IA, counts.Weak).Scan(&created)
		if errors.Is(err, sql.ErrNoRows) {
			// Créé par une ingestion concurrente : relu au tour suivant.
			continue
		}
		if err != nil {
			return uuid.Nil, false, err
		}
		return created, true, insertItems(ctx, tx, created, cs, ids)
	}
	return uuid.Nil, false, errors.New("ensemble d'inventaire introuvable après trois essais")
}

func insertItems(ctx context.Context, tx *db.OrgTx, setID uuid.UUID, cs []sbom.Component, ids map[string]uuid.UUID) error {
	for start := 0; start < len(cs); start += chunk {
		part := cs[start:min(start+chunk, len(cs))]
		n := len(part)
		comp, origin, conf, model, scope, weak, lic, ev, loc :=
			make([]string, n), make([]string, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		for i, c := range part {
			comp[i], origin[i], model[i], scope[i], lic[i], ev[i] = ids[c.PURL].String(), string(c.Origin), c.Model, string(c.Scope), join(c.Licenses), string(c.Evidence)
			if len(c.Locations) > 0 {
				b, err := json.Marshal(c.Locations)
				if err != nil {
					return err
				}
				loc[i] = string(b)
			}
			if c.Confidence != nil {
				conf[i] = strconv.FormatFloat(*c.Confidence, 'f', 4, 64)
			}
			weak[i] = strconv.FormatBool(c.WeakID)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO component_set_items (org_id, set_id, component_id, origin, confidence, model, scope, weak_id, licenses, evidence, locations)
			SELECT $1, $2, u.component_id, u.origin, NULLIF(u.confidence, '')::numeric, u.model, NULLIF(u.scope, ''),
			       u.weak::boolean, string_to_array(u.licenses, E'\x1f'), NULLIF(u.evidence, '')::jsonb, NULLIF(u.locations, '')::jsonb
			  FROM unnest($3::uuid[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[])
			       AS u(component_id, origin, confidence, model, scope, weak, licenses, evidence, locations)`,
			tx.OrgID(), setID, comp, origin, conf, model, scope, weak, lic, ev, loc); err != nil {
			return err
		}
	}
	return recordLicenseExpressions(ctx, tx, cs)
}

// recordLicenseExpressions note les expressions de licence de l'ensemble parmi celles de
// l'organisation (recherche « license: », T20) ; triées, sans doublon.
func recordLicenseExpressions(ctx context.Context, tx *db.OrgTx, cs []sbom.Component) error {
	seen := map[string]bool{}
	for _, c := range cs {
		for _, l := range c.Licenses {
			seen[l] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	exprs := slices.Sorted(maps.Keys(seen))
	_, err := tx.ExecContext(ctx, `INSERT INTO license_expressions (org_id, expression)
		SELECT $1, e FROM unnest($2::text[]) e ON CONFLICT DO NOTHING`, tx.OrgID(), exprs)
	return err
}

// current est l'état courant d'une référence.
type current struct {
	exists     bool
	snapshotID uuid.UUID
	setID      uuid.UUID
	scannedAt  time.Time
}

func readCurrent(ctx context.Context, tx *db.OrgTx, refID uuid.UUID) (current, error) {
	var c current
	err := tx.QueryRowContext(ctx, `
		SELECT rc.snapshot_id, rc.set_id, s.scanned_at FROM ref_current rc
		  JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
		 WHERE rc.ref_id = $1`, refID).Scan(&c.snapshotID, &c.setID, &c.scannedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return current{}, nil
	}
	c.exists = err == nil
	return c, err
}

func insertSnapshot(ctx context.Context, tx *db.OrgTx, r Record, setID uuid.UUID, now time.Time) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO snapshots (org_id, id, project_id, ref_id, commit_sha, agent_id, agent_version, scanned_at, last_scanned_at,
		                       blob_id, set_id, format, spec_version, created_at, updated_at, enrichment, enrichment_model)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $8, $9, $10, $11, $12, $13, $13, NULLIF($14, ''), $15)`,
		tx.OrgID(), id, r.ProjectID, r.RefID, r.Commit, nullUUID(r.AgentID), r.AgentVersion, r.ScannedAt,
		r.BlobID, setID, string(r.Format), r.SpecVersion, now, string(r.Enrichment), r.EnrichmentModel)
	return id, err
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// touch avance la date de dernière analyse d'un instantané à inventaire inchangé.
func touch(ctx context.Context, tx *db.OrgTx, snapshotID uuid.UUID, scannedAt, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE snapshots SET last_scanned_at = GREATEST(last_scanned_at, $2), updated_at = $3
		WHERE id = $1`, snapshotID, scannedAt, now)
	return err
}

// touchSent fait de même pour un SBOM reçu à inventaire inchangé, et reprend son statut
// d'enrichissement IA.
func touchSent(ctx context.Context, tx *db.OrgTx, snapshotID uuid.UUID, r Record, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE snapshots SET last_scanned_at = GREATEST(last_scanned_at, $2), updated_at = $3,
		enrichment = NULLIF($4, ''), enrichment_model = $5
		WHERE id = $1`, snapshotID, r.ScannedAt, now, string(r.Enrichment), r.EnrichmentModel)
	return err
}

func storeHostSnapshot(ctx context.Context, tx *db.OrgTx, r Record, cur current, now time.Time, res *Result) error {
	if cur.exists && cur.setID == res.SetID {
		res.SnapshotID, res.Outcome = cur.snapshotID, OutcomeUnchanged
		return touchSent(ctx, tx, cur.snapshotID, r, now)
	}
	id, err := insertSnapshot(ctx, tx, r, res.SetID, now)
	res.SnapshotID, res.Outcome = id, OutcomeCreated
	return err
}

func storeRepoSnapshot(ctx context.Context, tx *db.OrgTx, r Record, now time.Time, res *Result) error {
	var id, setID uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id, set_id FROM snapshots WHERE ref_id = $1 AND commit_sha = $2 FOR UPDATE`,
		r.RefID, r.Commit).Scan(&id, &setID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id, err := insertSnapshot(ctx, tx, r, res.SetID, now)
		res.SnapshotID, res.Outcome = id, OutcomeCreated
		return err
	case err != nil:
		return err
	case setID == res.SetID:
		res.SnapshotID, res.Outcome = id, OutcomeUnchanged
		return touchSent(ctx, tx, id, r, now)
	}
	// Même commit, autre inventaire (agent mis à jour, enrichissement) : le dernier envoi
	// fait foi. ref_current suit par ON UPDATE CASCADE s'il désigne cet instantané.
	res.SnapshotID, res.Outcome = id, OutcomeReplaced
	_, err = tx.ExecContext(ctx, `
		UPDATE snapshots SET set_id = $2, blob_id = $3, agent_id = $4, agent_version = $5, format = $6, spec_version = $7,
		       scanned_at = $8, last_scanned_at = $8, updated_at = $9, enrichment = NULLIF($10, ''), enrichment_model = $11
		 WHERE id = $1`,
		id, res.SetID, r.BlobID, nullUUID(r.AgentID), r.AgentVersion, string(r.Format), r.SpecVersion, r.ScannedAt, now,
		string(r.Enrichment), r.EnrichmentModel)
	return err
}

// updateCurrent fait de l'instantané écrit l'instantané courant s'il est le plus récent
// (date de scan, puis identifiant, chronologique) et dit si l'ensemble courant a changé.
// Un instantané inchangé garde sa date de scan : il ne redevient pas courant.
func updateCurrent(ctx context.Context, tx *db.OrgTx, r Record, cur current, res Result, now time.Time) (bool, error) {
	switch {
	case !cur.exists:
		_, err := tx.ExecContext(ctx, `INSERT INTO ref_current (org_id, ref_id, project_id, snapshot_id, set_id, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, tx.OrgID(), r.RefID, r.ProjectID, res.SnapshotID, res.SetID, now)
		return true, err
	case cur.snapshotID == res.SnapshotID:
		if cur.setID == res.SetID {
			return false, nil
		}
		// ON UPDATE CASCADE a déjà reporté le nouvel ensemble.
		_, err := tx.ExecContext(ctx, `UPDATE ref_current SET updated_at = $2 WHERE ref_id = $1`, r.RefID, now)
		return true, err
	case res.Outcome == OutcomeUnchanged, !newer(r.ScannedAt, res.SnapshotID, cur):
		return false, nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE ref_current SET snapshot_id = $2, set_id = $3, updated_at = $4 WHERE ref_id = $1`,
		r.RefID, res.SnapshotID, res.SetID, now)
	return cur.setID != res.SetID, err
}

func newer(scannedAt time.Time, id uuid.UUID, cur current) bool {
	if !scannedAt.Equal(cur.scannedAt) {
		return scannedAt.After(cur.scannedAt)
	}
	return strings.Compare(id.String(), cur.snapshotID.String()) > 0
}

// machineRef dit si une référence suit une machine (un hôte ou un conteneur) ou une
// version reçue par le point compatible Dependency-Track, plutôt qu'un commit de dépôt :
// pas de commit, et un inventaire identique au courant ne fait qu'avancer la date de
// dernière analyse.
func machineRef(kind string) bool { return kind == "host" || kind == "container" || kind == "version" }
