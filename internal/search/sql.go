package search

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/finding"
	"leblanc.io/lotor/internal/sbom"
	"leblanc.io/lotor/internal/triage"
	"leblanc.io/lotor/internal/version"
	"leblanc.io/lotor/internal/vuln"
)

// args numérote les paramètres d'une requête construite morceau par morceau.
type args struct{ list []any }

func (a *args) add(v any) string {
	a.list = append(a.list, v)
	return "$" + strconv.Itoa(len(a.list))
}

// severityRanks ordonne les sévérités : la plus grave a le rang le plus haut.
var severityRanks = map[vuln.Severity]int{
	vuln.SeverityUnknown: 1, vuln.SeverityNegligible: 2, vuln.SeverityLow: 3,
	vuln.SeverityMedium: 4, vuln.SeverityHigh: 5, vuln.SeverityCritical: 6,
}

func severityOfRank(rank sql.NullInt64) vuln.Severity {
	if !rank.Valid {
		return ""
	}
	for s, r := range severityRanks {
		if int64(r) == rank.Int64 {
			return s
		}
	}
	return vuln.SeverityUnknown
}

// rankSQL écrit le rang de la sévérité col en SQL.
func rankSQL(col string) string {
	var b strings.Builder
	b.WriteString("CASE " + col)
	for _, s := range vuln.Severities() {
		b.WriteString(" WHEN '" + string(s) + "' THEN " + strconv.Itoa(severityRanks[s]))
	}
	b.WriteString(" ELSE 1 END")
	return b.String()
}

// Colonnes communes des occurrences : org_id, project_id, ref_id, component_id, origin,
// confidence, weak_id, snapshot_id, finding_id, vuln_id, status, triage, open, sev, kev,
// risk, kind, labels et team_id du projet.

// componentHits : composants désignés, dans l'inventaire courant des références actives
// des projets actifs et visibles (db.Visible), avec la pire de leurs vulnérabilités
// ouvertes. Comme les listes de constats, elles écartent les constats triés « non
// affecté » ou « faux positif » (triage.HiddenStatuses, T14), qui n'appellent pas d'action.
const componentHits = `
	SELECT i.org_id, p.id AS project_id, r.id AS ref_id, i.component_id, i.origin, i.confidence, i.weak_id,
	       rc.snapshot_id, NULL::uuid AS finding_id, ''::text AS vuln_id, ''::text AS status, ''::text AS triage,
	       coalesce(v.open, 0) AS open, v.sev, coalesce(v.kev, false) AS kev, coalesce(v.risk, 0) AS risk,
	       p.kind, p.labels, p.team_id
	  FROM component_set_items i
	  JOIN ref_current rc ON rc.org_id = i.org_id AND rc.set_id = i.set_id
	  JOIN tracked_refs r ON r.org_id = rc.org_id AND r.id = rc.ref_id AND r.removed_at IS NULL
	  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id AND p.archived_at IS NULL
	       AND lotor_team_visible(p.team_id)
	  LEFT JOIN LATERAL (
	       SELECT count(*)::int AS open, max(` + "%RANK%" + `) AS sev, bool_or(f.kev) AS kev, max(f.risk)::float8 AS risk
	         FROM findings f
	        WHERE f.org_id = i.org_id AND f.ref_id = r.id AND f.component_id = i.component_id AND f.status = 'open'
	          AND f.triage_status <> ALL(%HIDDEN%::text[])) v ON true
	 WHERE i.component_id = ANY(%IDS%::uuid[])`

// componentHitsAt : composants désignés dans l'instantané en vigueur à une date de chaque
// référence (le dernier scanné avant elle, par snapshots_ref_idx), des projets visibles.
// Projets archivés et références retirées depuis comptent : la question porte sur l'état
// d'alors. Sans vulnérabilités : les constats d'alors ne sont pas conservés (T21).
const componentHitsAt = `
	SELECT i.org_id, p.id AS project_id, r.id AS ref_id, i.component_id, i.origin, i.confidence, i.weak_id,
	       s.id AS snapshot_id, NULL::uuid AS finding_id, ''::text AS vuln_id, ''::text AS status, ''::text AS triage,
	       0 AS open, NULL::int AS sev, false AS kev, 0::float8 AS risk,
	       p.kind, p.labels, p.team_id
	  FROM tracked_refs r
	  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id AND lotor_team_visible(p.team_id)
	  CROSS JOIN LATERAL (
	       SELECT s.id, s.set_id FROM snapshots s
	        WHERE s.org_id = r.org_id AND s.ref_id = r.id AND s.scanned_at < %AT%::timestamptz
	        ORDER BY s.scanned_at DESC, s.id DESC LIMIT 1) s
	  JOIN component_set_items i ON i.org_id = r.org_id AND i.set_id = s.set_id
	 WHERE i.component_id = ANY(%IDS%::uuid[])`

// vulnHits : constats des vulnérabilités désignées, sur les références actives des projets
// actifs et visibles, avec l'élément de l'inventaire courant s'il contient encore le composant,
// et le statut de triage effectif du constat (tous les statuts : la question « qui est
// touché » appelle aussi la réponse « non affecté »).
const vulnHits = `
	SELECT f.org_id, f.project_id, f.ref_id, f.component_id, i.origin, i.confidence, coalesce(i.weak_id, false) AS weak_id,
	       rc.snapshot_id, f.id AS finding_id, f.vuln_id, f.status, f.triage_status AS triage,
	       CASE WHEN f.status = 'open' THEN 1 ELSE 0 END AS open, ` + "%RANK%" + ` AS sev, f.kev, f.risk::float8 AS risk,
	       p.kind, p.labels, p.team_id
	  FROM findings f
	  JOIN tracked_refs r ON r.org_id = f.org_id AND r.id = f.ref_id AND r.removed_at IS NULL
	  JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id AND p.archived_at IS NULL
	       AND lotor_team_visible(p.team_id)
	  LEFT JOIN ref_current rc ON rc.org_id = f.org_id AND rc.ref_id = f.ref_id
	  LEFT JOIN component_set_items i ON i.org_id = rc.org_id AND i.set_id = rc.set_id AND i.component_id = f.component_id
	 WHERE f.vuln_id = ANY(%IDS%::text[]) AND f.status = ANY(%STATUS%::text[])`

// hitsSQL écrit la requête des occurrences d'une cible, filtres compris ; projectIDs, s'il
// n'est pas nul, la limite à ces projets.
func hitsSQL(t target, f Filters, projectIDs []uuid.UUID, a *args) string {
	var base string
	if t.vulnIDs != nil {
		statuses := []string{string(finding.StatusOpen)}
		if f.Resolved {
			statuses = append(statuses, string(finding.StatusResolved))
		}
		base = strings.NewReplacer("%RANK%", rankSQL("f.severity"), "%IDS%", a.add(t.vulnIDs),
			"%STATUS%", a.add(statuses)).Replace(vulnHits)
	} else if f.At != nil {
		base = strings.NewReplacer("%IDS%", a.add(t.components), "%AT%", a.add(*f.At)).Replace(componentHitsAt)
	} else {
		base = strings.NewReplacer("%RANK%", rankSQL("f.severity"), "%IDS%", a.add(t.components),
			"%HIDDEN%", a.add(hiddenStatuses())).Replace(componentHits)
	}
	var where []string
	if projectIDs != nil {
		where = append(where, "h.project_id = ANY("+a.add(projectIDs)+"::uuid[])")
	}
	// Toujours posé : les conteneurs ne figurent que s'ils sont inclus.
	where = append(where, "h.kind = ANY("+a.add(f.kinds())+"::text[])")
	if len(f.Teams) > 0 {
		where = append(where, "h.team_id = ANY("+a.add(f.Teams)+"::uuid[])")
	}
	if len(f.Triage) > 0 {
		statuses := make([]string, len(f.Triage))
		for i, s := range f.Triage {
			statuses[i] = string(s)
		}
		where = append(where, "h.triage = ANY("+a.add(statuses)+"::text[])")
	}
	if len(f.Labels) > 0 {
		docs := make([]string, 0, len(f.Labels))
		for _, l := range f.Labels {
			labels, err := labelPair(l)
			if err != nil {
				continue // déjà refusé par ParseRequest
			}
			b, _ := json.Marshal(labels)
			docs = append(docs, string(b))
		}
		where = append(where, "h.labels @> ANY("+a.add(docs)+"::text[]::jsonb[])")
	}
	if len(f.Origins) > 0 {
		origins := make([]string, len(f.Origins))
		for i, o := range f.Origins {
			origins[i] = string(o)
		}
		where = append(where, "h.origin = ANY("+a.add(origins)+"::text[])")
	}
	if f.KEV {
		where = append(where, "h.kev")
	}
	if len(f.Severities) > 0 {
		var ranks []int64
		none := false
		for _, s := range f.Severities {
			if s == SeverityNone {
				none = true
				continue
			}
			ranks = append(ranks, int64(severityRanks[vuln.Severity(s)]))
		}
		cond := "h.sev = ANY(" + a.add(ranks) + "::int[])"
		if none {
			cond = "(" + cond + " OR h.open = 0)"
		}
		where = append(where, cond)
	}
	if len(where) == 0 {
		return base
	}
	return "SELECT * FROM (" + base + ") h WHERE " + strings.Join(where, " AND ")
}

// hitOrder ordonne les occurrences d'un projet.
const hitOrder = `h.risk DESC, c.name, c.version, r.name, h.ref_id, c.id, h.vuln_id`

// hitColumns : colonnes d'une occurrence, dans l'ordre de Hit.scanTargets, précédées du
// projet.
const hitColumns = `SELECT h.project_id, h.ref_id, r.kind, r.name, s.id, s.scanned_at, coalesce(s.commit_sha, ''),
	       c.id, c.purl, c.name, c.version, c.type, coalesce(h.origin, ''), h.confidence, h.weak_id,
	       h.open, h.sev, h.kev, h.risk, fx.fixed, h.vuln_id, h.status, h.triage, h.finding_id`

// hitJoins : jointures des colonnes d'une occurrence. Versions corrigées : celles des
// vulnérabilités ouvertes du composant dans la référence, ou celles du constat ; aucune à
// une date passée (f.At), faute de constats d'alors.
func hitJoins(t target, f Filters) string {
	fixed := `SELECT array_agg(DISTINCT fv) AS fixed FROM findings f CROSS JOIN LATERAL unnest(f.fixed_versions) fv
	           WHERE f.org_id = h.org_id AND f.ref_id = h.ref_id AND f.component_id = h.component_id AND f.status = 'open'
	             AND f.triage_status NOT IN ('` + strings.Join(hiddenStatuses(), "', '") + `')`
	switch {
	case t.vulnIDs != nil:
		fixed = `SELECT f.fixed_versions AS fixed FROM findings f WHERE f.org_id = h.org_id AND f.id = h.finding_id`
	case f.At != nil:
		fixed = `SELECT NULL::text[] AS fixed`
	}
	return `FROM hits h
	  JOIN tracked_refs r ON r.org_id = h.org_id AND r.id = h.ref_id
	  JOIN components c ON c.org_id = h.org_id AND c.id = h.component_id
	  LEFT JOIN snapshots s ON s.org_id = h.org_id AND s.id = h.snapshot_id
	  LEFT JOIN LATERAL (` + fixed + `) fx ON true`
}

// hitScan reçoit les colonnes nullables d'une occurrence.
type hitScan struct {
	snapshot   uuid.NullUUID
	scanned    sql.NullTime
	origin     string
	confidence sql.NullFloat64
	sev        sql.NullInt64
	status     string
	triage     string
	finding    uuid.NullUUID
}

// scanTargets renvoie les destinations des colonnes de hitColumns (projet exclu). Les
// valeurs nullables passent par h.scan, que finish recopie.
func (h *Hit) scanTargets() []any {
	h.scan = &hitScan{}
	return []any{&h.RefID, &h.RefKind, &h.RefName, &h.scan.snapshot, &h.scan.scanned, &h.Commit,
		&h.ComponentID, &h.PURL, &h.Name, &h.Version, &h.Type, &h.scan.origin, &h.scan.confidence, &h.Weak,
		&h.Open, &h.scan.sev, &h.KEV, &h.Risk, db.Array(&h.Fixed), &h.VulnID, &h.scan.status, &h.scan.triage, &h.scan.finding}
}

// finish recopie les colonnes nullables et trie les versions corrigées selon
// l'écosystème du composant.
func (h *Hit) finish(c version.Comparer) {
	s := h.scan
	h.scan = nil
	if s.snapshot.Valid {
		h.SnapshotID = s.snapshot.UUID
	}
	if s.scanned.Valid {
		h.ScannedAt = s.scanned.Time.UTC()
	}
	h.Origin = sbom.Origin(s.origin)
	if s.confidence.Valid {
		v := s.confidence.Float64
		h.Confidence = &v
	}
	h.Severity = severityOfRank(s.sev)
	h.Status = finding.Status(s.status)
	h.Triage = triage.Status(s.triage)
	if s.finding.Valid {
		h.FindingID = s.finding.UUID
	}
	if len(h.Fixed) > 1 {
		scheme := version.ForPURLType(purlType(h.PURL))
		sorted, unreadable := version.Sort(c, scheme, h.Fixed)
		h.Fixed = append(sorted, unreadable...)
	}
}

// hiddenStatuses : statuts de triage écartés du décompte des vulnérabilités d'un composant.
func hiddenStatuses() []string {
	out := []string{}
	for _, s := range triage.HiddenStatuses() {
		out = append(out, string(s))
	}
	return out
}

// purlType lit le type d'un purl canonique (pkg:<type>/…).
func purlType(p string) string {
	rest, _ := strings.CutPrefix(p, "pkg:")
	t, _, _ := strings.Cut(rest, "/")
	return t
}
