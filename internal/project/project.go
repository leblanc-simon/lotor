package project

import (
	"cmp"
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
	"github.com/jackc/pgx/v5/pgconn"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/db"
	"leblanc.io/lotor/internal/pagination"
	"leblanc.io/lotor/internal/tenant"
)

// ErrNotFound : projet inconnu dans l'organisation déclarée (ou d'une autre organisation,
// ce qui revient au même sous la RLS).
var ErrNotFound = errors.New("project: introuvable")

// Kind est la nature d'un projet.
type Kind string

// Natures de projets. Un conteneur est un projet enfant d'un hôte, créé et tenu par
// l'agent de l'hôte (T13, ADR 0040) : il ne se crée pas à la main.
const (
	KindRepo      Kind = "repo"
	KindHost      Kind = "host"
	KindContainer Kind = "container"
)

// Kinds renvoie les natures de projets de premier niveau, celles qu'on crée à la main ;
// les conteneurs, enfants d'un hôte, n'y sont pas.
func Kinds() []Kind { return []Kind{KindRepo, KindHost} }

// ParseKind lit une nature de projet de premier niveau.
func ParseKind(s string) (Kind, error) {
	switch k := Kind(s); k {
	case KindRepo, KindHost:
		return k, nil
	}
	return "", invalid("kind", KeyKindInvalid)
}

// AIMode est le réglage d'enrichissement IA d'un dépôt.
type AIMode string

// Réglages d'enrichissement IA.
const (
	// AIDisabled : aucun modèle n'est appelé (défaut).
	AIDisabled AIMode = "disabled"
	// AILocal : modèle local seulement (le code ne quitte pas l'infrastructure de
	// l'exploitant de l'agent).
	AILocal AIMode = "local"
	// AIExternal : fournisseur externe autorisé par un administrateur d'organisation.
	AIExternal AIMode = "external"
)

// AIModes liste les réglages dans l'ordre d'affichage.
func AIModes() []AIMode { return []AIMode{AIDisabled, AILocal, AIExternal} }

// Valid indique un réglage connu.
func (m AIMode) Valid() bool { return slices.Contains(AIModes(), m) }

// Effective borne le réglage par la politique de l'instance : un fournisseur externe
// interdit ramène « external » à « local ».
func (m AIMode) Effective(externalAllowed bool) AIMode {
	if m == AIExternal && !externalAllowed {
		return AILocal
	}
	if !m.Valid() {
		return AIDisabled
	}
	return m
}

// RefKind est la nature d'une référence suivie.
type RefKind string

// Natures de références suivies.
const (
	RefBranch    RefKind = "branch"
	RefTag       RefKind = "tag"
	RefHost      RefKind = "host"
	RefContainer RefKind = "container"
	// RefVersion : version d'un dépôt au sens de Dependency-Track (T19, ADR 0057), sans
	// commit, rangée comme un hôte.
	RefVersion RefKind = "version"
)

// Ref est une référence suivie active d'un projet.
type Ref struct {
	ID   uuid.UUID
	Kind RefKind
	Name string
}

// AgentRef résume l'agent auquel un projet est confié.
type AgentRef struct {
	ID         uuid.UUID
	Kind       Kind
	Name       string
	Version    string
	LastSeenAt *time.Time
	CreatedAt  time.Time
	Disabled   bool
	// LastInventoryAt est la date de dernière analyse la plus récente des projets de
	// l'agent : l'état « muet » d'un agent serveur en dépend.
	LastInventoryAt *time.Time
}

// Project est un projet : un dépôt, un serveur ou un conteneur d'un serveur.
type Project struct {
	ID          uuid.UUID
	Kind        Kind
	Slug        string
	Name        string
	Description string
	Labels      Labels
	ForgeURL    string
	Agent       *AgentRef
	TeamID      uuid.UUID // équipe du projet (toujours présente, ADR 0034)
	AIMode      AIMode    // réglage de l'enrichissement IA (dépôts, ADR 0043)
	TeamName    string
	ArchivedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Refs        []Ref // références actives, par nature puis nom (Get seulement)
	// Parent est l'hôte d'un conteneur ; Container, son identité et son contexte.
	Parent    *ParentRef
	Container *Container

	sortName string // lower(name) calculé par PostgreSQL, clé du curseur de List
}

// ParentRef résume l'hôte d'un conteneur.
type ParentRef struct {
	ID   uuid.UUID
	Slug string
	Name string
}

// HostRef renvoie la référence d'hôte d'un projet de serveur.
func (p Project) HostRef() string {
	for _, r := range p.Refs {
		if r.Kind == RefHost {
			return r.Name
		}
	}
	return ""
}

// RefNames renvoie les noms des références actives de nature kind.
func (p Project) RefNames(kind RefKind) []string {
	var out []string
	for _, r := range p.Refs {
		if r.Kind == kind {
			out = append(out, r.Name)
		}
	}
	return out
}

// RefsOf renvoie les références actives de nature kind.
func (p Project) RefsOf(kind RefKind) []Ref {
	var out []Ref
	for _, r := range p.Refs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// Input est la saisie d'un projet. Kind et Slug ne valent qu'à la création ; un slug vide
// est dérivé du nom. Branches, Tags et Versions ne valent que pour un dépôt, HostRef que pour un
// serveur.
type Input struct {
	Kind        Kind
	TeamID      uuid.UUID // équipe, à la création seulement (SetTeam la change ensuite)
	Slug        string
	Name        string
	Description string
	Labels      Labels
	ForgeURL    string
	Branches    []string
	Tags        []string
	// Versions : versions au sens de Dependency-Track (dépôts seulement, ADR 0057).
	Versions []string
	HostRef  string
}

// Service gère les projets. Toute lecture et toute écriture passent par InOrg ; chaque
// modification est journalisée dans la même transaction.
type Service struct {
	pool *db.Pool
}

// NewService construit le service.
func NewService(pool *db.Pool) *Service { return &Service{pool: pool} }

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := account.IsValidation(err); ok || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("project: %s : %w", what, err)
}

func pgCode(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func pgConstraint(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.ConstraintName
	}
	return ""
}

// clean valide une saisie ; kind est la nature du projet (saisie ou existante).
func clean(kind Kind, in Input) (Input, error) {
	var err error
	out := Input{Kind: kind, Slug: strings.TrimSpace(in.Slug), Labels: in.Labels}
	if out.Name, err = validName(in.Name); err != nil {
		return Input{}, err
	}
	if out.Description, err = validDescription(in.Description); err != nil {
		return Input{}, err
	}
	if out.Labels == nil {
		out.Labels = Labels{}
	}
	if err := out.Labels.Validate(); err != nil {
		return Input{}, err
	}
	switch kind {
	case KindRepo:
		if out.ForgeURL, err = validForgeURL(in.ForgeURL); err != nil {
			return Input{}, err
		}
		for _, names := range [][]string{in.Branches, in.Tags} {
			for _, n := range names {
				if !validRefName(n) {
					return Input{}, invalid("branches", KeyRefInvalid)
				}
			}
		}
		if len(in.Branches)+len(in.Tags) > maxRefs {
			return Input{}, invalid("branches", KeyRefsTooMany)
		}
		for _, n := range in.Versions {
			if !ValidVersionName(n) {
				return Input{}, invalid("versions", KeyRefInvalid)
			}
		}
		if len(in.Versions) > MaxVersions {
			return Input{}, invalid("versions", KeyRefsTooMany)
		}
		if len(in.Branches)+len(in.Tags)+len(in.Versions) == 0 {
			return Input{}, invalid("branches", KeyRefsMissing)
		}
		out.Branches, out.Tags, out.Versions = in.Branches, in.Tags, in.Versions
	case KindHost:
		if out.HostRef, err = NormalizeHostRef(in.HostRef); err != nil {
			return Input{}, err
		}
	case KindContainer:
		// Sa référence est son identité dans l'hôte, tenue par l'agent.
	default:
		return Input{}, invalid("kind", KeyKindInvalid)
	}
	return out, nil
}

func event(action audit.Action, p Project, details map[string]string) audit.Event {
	return audit.Event{Action: action, TargetType: "project", TargetID: p.ID.String(), TargetLabel: p.Slug, Details: details}
}

// Create crée un projet.
func (s *Service) Create(ctx context.Context, actor audit.Actor, org tenant.OrgID, in Input) (Project, error) {
	kind, err := ParseKind(string(in.Kind))
	if err != nil {
		return Project{}, err
	}
	team := in.TeamID
	in, err = clean(kind, in)
	if err != nil {
		return Project{}, err
	}
	in.TeamID = team
	if in.Slug != "" && (!slugPattern.MatchString(in.Slug) || reservedSlugs[in.Slug]) {
		return Project{}, invalid("slug", KeySlugInvalid)
	}
	if in.TeamID == uuid.Nil {
		return Project{}, invalid("team", KeyTeamInvalid)
	}
	var p Project
	err = s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err = insert(ctx, tx, in, nil)
		if err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, event(audit.ProjectCreated, p, map[string]string{"kind": string(p.Kind), "team": p.TeamName}))
	})
	return p, wrap("création d'un projet", err)
}

// CreateHost crée, dans la transaction de l'appelant, le projet de serveur d'un hôte qui
// s'inscrit : nom et référence tirés du nom d'hôte, slug dérivé et rendu unique, agent
// confié, dans l'équipe du jeton d'inscription. Utilisé par l'inscription des agents.
func CreateHost(ctx context.Context, tx *db.OrgTx, hostRef string, labels Labels, agentID, teamID uuid.UUID) (Project, error) {
	in, err := clean(KindHost, Input{Name: hostRef, HostRef: hostRef, Labels: labels})
	in.TeamID = teamID
	if err != nil {
		return Project{}, err
	}
	return insert(ctx, tx, in, &agentID)
}

// insert crée la ligne du projet et ses références. Un slug vide est dérivé du nom et
// rendu unique par un suffixe.
func insert(ctx context.Context, tx *db.OrgTx, in Input, agentID *uuid.UUID) (Project, error) {
	slug := in.Slug
	if slug == "" {
		var err error
		if slug, err = freeSlug(ctx, tx, Slugify(in.Name)); err != nil {
			return Project{}, err
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Project{}, err
	}
	labels, err := json.Marshal(in.Labels)
	if err != nil {
		return Project{}, err
	}
	p := Project{ID: id, Kind: in.Kind, Slug: slug, Name: in.Name, Description: in.Description, Labels: in.Labels,
		ForgeURL: in.ForgeURL, TeamID: in.TeamID, AIMode: AIDisabled}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO projects (org_id, id, kind, slug, name, description, labels, forge_url, agent_id, team_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING created_at, updated_at`,
		tx.OrgID(), id, string(in.Kind), slug, in.Name, in.Description, labels, in.ForgeURL, agentID, in.TeamID,
	).Scan(&p.CreatedAt, &p.UpdatedAt)
	if pgCode(err) == "23505" {
		return Project{}, invalid("slug", KeySlugTaken)
	}
	if pgCode(err) == "23503" && pgConstraint(err) == "projects_team_fk" {
		return Project{}, invalid("team", KeyTeamInvalid)
	}
	if err != nil {
		return Project{}, err
	}
	if agentID != nil {
		p.Agent = &AgentRef{ID: *agentID}
	}
	if err := tx.QueryRowContext(ctx, `SELECT name FROM teams WHERE id = $1`, in.TeamID).Scan(&p.TeamName); err != nil {
		return Project{}, err
	}
	if err := syncRefs(ctx, tx, p, in); err != nil {
		return Project{}, err
	}
	return p, nil
}

// reservedSlugs sont des segments d'URL de l'interface (…/projects/new).
var reservedSlugs = map[string]bool{"new": true}

// freeSlug renvoie base, ou base-2, base-3… s'il est pris ou réservé.
func freeSlug(ctx context.Context, tx *db.OrgTx, base string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT slug FROM projects WHERE slug = $1 OR slug LIKE $2`,
		base, strings.ReplaceAll(base, "-", `\-`)+`-%`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	taken := map[string]bool{}
	for s := range reservedSlugs {
		taken[s] = true
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		taken[s] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for i := 1; ; i++ {
		candidate := base
		if i > 1 {
			suffix := "-" + strconv.Itoa(i)
			candidate = strings.TrimRight(base[:min(len(base), maxSlug-len(suffix))], "-") + suffix
		}
		if !taken[candidate] {
			return candidate, nil
		}
	}
}

// syncRefs aligne les références actives d'un projet sur la saisie : les absentes sont
// retirées (removed_at), les nouvelles créées ou réactivées. La référence d'un hôte est
// renommée sur place, pour garder son historique.
func syncRefs(ctx context.Context, tx *db.OrgTx, p Project, in Input) error {
	if p.Kind == KindContainer {
		return nil
	}
	if p.Kind == KindHost {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
			VALUES ($1, $2, $3, 'host', 'host', $4)
			ON CONFLICT (org_id, project_id) WHERE kind = 'host' DO UPDATE SET name = EXCLUDED.name, removed_at = NULL`,
			tx.OrgID(), uuid.Must(uuid.NewV7()), p.ID, in.HostRef)
		if pgConstraint(err) == "tracked_refs_host_name" {
			return invalid("host_ref", KeyHostRefTaken)
		}
		return err
	}
	type key struct {
		kind RefKind
		name string
	}
	want := map[key]bool{}
	for _, n := range in.Branches {
		want[key{RefBranch, n}] = true
	}
	for _, n := range in.Tags {
		want[key{RefTag, n}] = true
	}
	for _, n := range in.Versions {
		want[key{RefVersion, n}] = true
	}
	keys := slices.SortedFunc(maps.Keys(want), func(a, b key) int {
		return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.name, b.name))
	})
	kinds, names := make([]string, 0, len(keys)), make([]string, 0, len(keys))
	for _, k := range keys {
		kinds, names = append(kinds, string(k.kind)), append(names, k.name)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE tracked_refs r SET removed_at = now()
		 WHERE r.project_id = $1 AND r.removed_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM unnest($2::text[], $3::text[]) AS w(kind, name)
		                    WHERE w.kind = r.kind AND w.name = r.name)`, p.ID, kinds, names); err != nil {
		return err
	}
	// Insertions triées : deux modifications simultanées ne s'interbloquent pas.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO tracked_refs (org_id, id, project_id, project_kind, kind, name)
		SELECT $1, w.id, $2, 'repo', w.kind, w.name
		  FROM unnest($3::text[], $4::text[], $5::uuid[]) AS w(kind, name, id)
		 ORDER BY w.kind, w.name
		ON CONFLICT (org_id, project_id, kind, name) DO UPDATE SET removed_at = NULL`,
		tx.OrgID(), p.ID, kinds, names, newIDs(len(kinds)))
	return err
}

// newIDs tire n identifiants, sous forme de texte pour un paramètre uuid[].
func newIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = uuid.Must(uuid.NewV7()).String()
	}
	return out
}

// columns lit un projet ; l'agent d'un conteneur est celui de son hôte (pp).
const columns = `lower(p.name), p.id, p.kind, p.slug, p.name, p.description, p.labels, p.forge_url, p.archived_at,
	p.created_at, p.updated_at, a.id, coalesce(a.name, ''), coalesce(a.version, ''), a.last_seen_at, a.disabled_at IS NOT NULL,
	coalesce(a.kind, ''), a.created_at, p.team_id, t.name, p.ai_mode,
	(SELECT max(s.last_scanned_at) FROM projects ap
	   JOIN ref_current rc ON rc.org_id = ap.org_id AND rc.project_id = ap.id
	   JOIN snapshots s ON s.org_id = rc.org_id AND s.id = rc.snapshot_id
	  WHERE ap.org_id = a.org_id AND ap.agent_id = a.id),
	pp.id, coalesce(pp.slug, ''), coalesce(pp.name, ''), coalesce(p.container_key, ''), p.container, p.seen_at,
	p.archived_absent`

const from = ` FROM projects p JOIN teams t ON t.org_id = p.org_id AND t.id = p.team_id
	LEFT JOIN projects pp ON pp.org_id = p.org_id AND pp.id = p.parent_id
	LEFT JOIN agents a ON a.org_id = p.org_id AND a.id = coalesce(p.agent_id, pp.agent_id)`

func scan(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	var kind string
	var labels []byte
	var archived, lastSeen, agentCreated, inventoried sql.NullTime
	var agentID, parentID uuid.NullUUID
	var agentName, agentVersion, agentKind, aiMode, parentSlug, parentName, containerKey string
	var disabled sql.NullBool
	var container []byte
	var seen sql.NullTime
	var absent bool
	if err := row.Scan(&p.sortName, &p.ID, &kind, &p.Slug, &p.Name, &p.Description, &labels, &p.ForgeURL, &archived,
		&p.CreatedAt, &p.UpdatedAt, &agentID, &agentName, &agentVersion, &lastSeen, &disabled, &agentKind, &agentCreated,
		&p.TeamID, &p.TeamName, &aiMode, &inventoried, &parentID, &parentSlug, &parentName, &containerKey, &container, &seen,
		&absent); err != nil {
		return Project{}, err
	}
	if parentID.Valid {
		p.Parent = &ParentRef{ID: parentID.UUID, Slug: parentSlug, Name: parentName}
	}
	if containerKey != "" {
		c, err := readContainer(containerKey, container, seen, absent)
		if err != nil {
			return Project{}, err
		}
		p.Container = &c
	}
	p.Kind, p.AIMode = Kind(kind), AIMode(aiMode)
	if err := json.Unmarshal(labels, &p.Labels); err != nil {
		return Project{}, fmt.Errorf("étiquettes : %w", err)
	}
	if archived.Valid {
		t := archived.Time
		p.ArchivedAt = &t
	}
	if agentID.Valid {
		p.Agent = &AgentRef{ID: agentID.UUID, Kind: Kind(agentKind), Name: agentName, Version: agentVersion,
			Disabled: disabled.Bool, CreatedAt: agentCreated.Time}
		if lastSeen.Valid {
			t := lastSeen.Time
			p.Agent.LastSeenAt = &t
		}
		if inventoried.Valid {
			t := inventoried.Time
			p.Agent.LastInventoryAt = &t
		}
	}
	return p, nil
}

// load lit un projet par son slug, avec ses références actives. visible restreint aux
// projets des équipes déclarées par db.Visible (lectures pour un compte).
func load(ctx context.Context, tx *db.OrgTx, slug string, lock, visible bool) (Project, error) {
	query := `SELECT ` + columns + from + ` WHERE p.slug = $1`
	if visible {
		query += ` AND lotor_team_visible(p.team_id)`
	}
	if lock {
		query += ` FOR UPDATE OF p`
	}
	p, err := scan(tx.QueryRowContext(ctx, query, slug))
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	p.Refs, err = activeRefs(ctx, tx, p.ID)
	return p, err
}

func activeRefs(ctx context.Context, tx *db.OrgTx, projectID uuid.UUID) ([]Ref, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, kind, name FROM tracked_refs
		 WHERE project_id = $1 AND removed_at IS NULL ORDER BY kind, name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ref
	for rows.Next() {
		var r Ref
		var kind string
		if err := rows.Scan(&r.ID, &kind, &r.Name); err != nil {
			return nil, err
		}
		r.Kind = RefKind(kind)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get renvoie un projet visible par son slug ; ErrNotFound pour un projet d'une équipe
// invisible, comme pour un projet inconnu.
func (s *Service) Get(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, slug string) (Project, error) {
	var p Project
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		var err error
		p, err = load(ctx, tx, slug, false, true)
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return p, wrap("lecture d'un projet", err)
}

// Update modifie un projet : nom, description, étiquettes, et selon sa nature URL de
// forge et références, ou référence d'hôte. Nature et slug ne changent pas.
//
// L'autorisation d'un fournisseur d'IA externe vaut pour un dépôt (SEC2-03) : changer
// l'URL de forge d'un dépôt réglé sur « externe » ramène le réglage à « désactivé », dans
// la même transaction et journalisé (project.ai_mode_changed, motif forge_url_changed),
// sauf si l'acteur peut lui-même autoriser l'IA externe (externalAI : droit ai.external,
// et instance qui ne l'interdit pas).
func (s *Service) Update(ctx context.Context, actor audit.Actor, org tenant.OrgID, slug string, in Input, externalAI bool) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := load(ctx, tx, slug, true, false)
		if err != nil {
			return err
		}
		if p.ArchivedAt != nil {
			return invalid("project", KeyProjectArchived)
		}
		in, err := clean(p.Kind, in)
		if err != nil {
			return err
		}
		labels, err := json.Marshal(in.Labels)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE projects SET name = $2, description = $3, labels = $4, forge_url = $5, updated_at = now()
			 WHERE id = $1`, p.ID, in.Name, in.Description, labels, in.ForgeURL); err != nil {
			return err
		}
		if err := syncRefs(ctx, tx, p, in); err != nil {
			return err
		}
		if err := audit.RecordOrg(ctx, tx, actor, event(audit.ProjectUpdated, p, changes(p, in))); err != nil {
			return err
		}
		if p.AIMode != AIExternal || p.ForgeURL == in.ForgeURL || externalAI {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET ai_mode = $2 WHERE id = $1`, p.ID, string(AIDisabled)); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, event(audit.ProjectAIModeChanged, p,
			map[string]string{"from": string(AIExternal), "to": string(AIDisabled), "reason": "forge_url_changed"}))
	})
	return wrap("modification d'un projet", err)
}

// changes résume une modification pour le journal (champs modifiés, jamais de contenu
// long).
func changes(p Project, in Input) map[string]string {
	var fields []string
	if p.Name != in.Name {
		fields = append(fields, "name")
	}
	if p.Description != in.Description {
		fields = append(fields, "description")
	}
	if p.Labels.String() != in.Labels.String() {
		fields = append(fields, "labels")
	}
	if p.ForgeURL != in.ForgeURL {
		fields = append(fields, "forge_url")
	}
	switch p.Kind {
	case KindHost:
		if p.HostRef() != in.HostRef {
			fields = append(fields, "host_ref")
		}
	case KindRepo:
		if strings.Join(p.RefNames(RefBranch), ",") != strings.Join(in.Branches, ",") ||
			strings.Join(p.RefNames(RefTag), ",") != strings.Join(in.Tags, ",") ||
			strings.Join(p.RefNames(RefVersion), "\n") != strings.Join(in.Versions, "\n") {
			fields = append(fields, "refs")
		}
	}
	if len(fields) == 0 {
		fields = []string{"-"}
	}
	return map[string]string{"fields": strings.Join(fields, ", ")}
}

// SetArchived archive un projet (il disparaît des listes et de l'API des agents) ou le
// réactive. Un conteneur archivé par un utilisateur ne revient pas quand l'agent le
// revoit ; un conteneur archivé pour absence ne se réactive pas à la main, il revient
// quand il redémarre.
func (s *Service) SetArchived(ctx context.Context, actor audit.Actor, org tenant.OrgID, slug string, archived bool) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := load(ctx, tx, slug, true, false)
		if err != nil {
			return err
		}
		if (p.ArchivedAt != nil) == archived {
			return nil
		}
		if !archived && p.Container != nil && p.Container.ArchivedAbsent {
			// Il se réactive de lui-même quand l'agent le revoit.
			return invalid("project", KeyContainerAbsent)
		}
		query, action := `UPDATE projects SET archived_at = now(), updated_at = now() WHERE id = $1`, audit.ProjectArchived
		if !archived {
			query, action = `UPDATE projects SET archived_at = NULL, archived_absent = false, updated_at = now() WHERE id = $1`,
				audit.ProjectUnarchived
		}
		if _, err := tx.ExecContext(ctx, query, p.ID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, event(action, p, nil))
	})
	return wrap("archivage d'un projet", err)
}

// AssignAgent confie un dépôt à un agent dépôt actif, ou le lui retire (agentID nil). Un
// serveur reçoit son agent à l'inscription, jamais d'ici.
func (s *Service) AssignAgent(ctx context.Context, actor audit.Actor, org tenant.OrgID, slug string, agentID *uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := load(ctx, tx, slug, true, false)
		if err != nil {
			return err
		}
		if p.Kind != KindRepo {
			return invalid("agent", KeyAgentInvalid)
		}
		if p.ArchivedAt != nil {
			return invalid("project", KeyProjectArchived)
		}
		details := map[string]string{"agent": "-"}
		if agentID != nil {
			// Un agent sert les projets de son équipe, ou de toutes s'il est d'organisation.
			var name string
			err := tx.QueryRowContext(ctx,
				`SELECT name FROM agents WHERE id = $1 AND kind = 'repo' AND disabled_at IS NULL
				    AND (team_id IS NULL OR team_id = $2) FOR SHARE`, *agentID, p.TeamID).Scan(&name)
			if errors.Is(err, sql.ErrNoRows) {
				return invalid("agent", KeyAgentInvalid)
			}
			if err != nil {
				return err
			}
			details["agent"] = name
		}
		if p.Agent == nil && agentID == nil || p.Agent != nil && agentID != nil && p.Agent.ID == *agentID {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET agent_id = $2, updated_at = now() WHERE id = $1`, p.ID, agentID); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, event(audit.ProjectAgentChanged, p, details))
	})
	return wrap("affectation d'un agent", err)
}

// SetTeam rattache un projet à une autre équipe. L'appelant vérifie le droit
// tenant.PermProjectMove dans les deux équipes. Un dépôt confié à un agent d'une autre
// équipe le perd (l'agent ne sert que son équipe) ; un serveur garde son agent, qui suit
// le projet dans sa nouvelle équipe, avec ses conteneurs (clé étrangère en cascade). Un
// conteneur suit toujours l'équipe de son hôte : il ne se rattache pas seul.
func (s *Service) SetTeam(ctx context.Context, actor audit.Actor, org tenant.OrgID, slug string, team uuid.UUID) error {
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := load(ctx, tx, slug, true, false)
		if err != nil {
			return err
		}
		if p.Kind == KindContainer {
			return invalid("team", KeyContainerTeam)
		}
		if p.TeamID == team {
			return nil
		}
		var name string
		err = tx.QueryRowContext(ctx, `SELECT name FROM teams WHERE id = $1 FOR SHARE`, team).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return invalid("team", KeyTeamInvalid)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET team_id = $2, updated_at = now() WHERE id = $1`, p.ID, team); err != nil {
			return err
		}
		details := map[string]string{"from": p.TeamName, "to": name}
		if p.Agent != nil {
			switch p.Kind {
			case KindHost:
				if _, err := tx.ExecContext(ctx, `UPDATE agents SET team_id = $2 WHERE id = $1`, p.Agent.ID, team); err != nil {
					return err
				}
			case KindRepo:
				res, err := tx.ExecContext(ctx, `UPDATE projects SET agent_id = NULL WHERE id = $1 AND EXISTS (
					SELECT 1 FROM agents a WHERE a.id = $2 AND a.team_id IS NOT NULL AND a.team_id <> $3)`, p.ID, p.Agent.ID, team)
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n > 0 {
					details["agent"] = "-"
				}
			}
		}
		return audit.RecordOrg(ctx, tx, actor, event(audit.ProjectTeamChanged, p, details))
	})
	return wrap("rattachement d'un projet", err)
}

// SetAIMode change le réglage d'enrichissement IA d'un dépôt. L'appelant vérifie les
// droits : project.manage pour tout réglage, et en plus project.ai_external (administrateur
// d'organisation) pour autoriser un fournisseur externe ; externalAllowed reflète la
// politique de l'instance, qui peut interdire tout fournisseur externe. Chaque changement
// est journalisé (ADR 0043).
func (s *Service) SetAIMode(ctx context.Context, actor audit.Actor, org tenant.OrgID, slug string, mode AIMode, externalAllowed bool) error {
	if !mode.Valid() {
		return invalid("ai_mode", KeyAIModeInvalid)
	}
	if mode == AIExternal && !externalAllowed {
		return invalid("ai_mode", KeyAIExternalOff)
	}
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		p, err := load(ctx, tx, slug, true, false)
		if err != nil {
			return err
		}
		if p.Kind != KindRepo {
			return invalid("ai_mode", KeyAIModeInvalid)
		}
		if p.ArchivedAt != nil {
			return invalid("project", KeyProjectArchived)
		}
		if p.AIMode == mode {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET ai_mode = $2, updated_at = now() WHERE id = $1`, p.ID, string(mode)); err != nil {
			return err
		}
		return audit.RecordOrg(ctx, tx, actor, event(audit.ProjectAIModeChanged, p, map[string]string{"from": string(p.AIMode), "to": string(mode)}))
	})
	return wrap("réglage de l'enrichissement IA", err)
}

// Filter restreint une liste de projets.
type Filter struct {
	Query    string    // partie du nom ou du slug
	Kind     Kind      // vide : toutes natures
	Label    string    // « clé » ou « clé=valeur »
	Archived bool      // projets archivés au lieu des actifs
	Team     uuid.UUID // nul : toutes les équipes visibles
	// Containers ajoute les conteneurs (projets enfants des hôtes), écartés sinon.
	Containers bool
}

// kindCondition renvoie la condition SQL sur p.kind d'un filtre : la nature demandée (ou
// toutes celles de premier niveau), plus les conteneurs s'ils sont inclus.
func kindCondition(kind Kind, containers bool) string {
	switch {
	case kind != "" && containers:
		return `p.kind IN ($?, 'container')`
	case kind != "":
		return `p.kind = $?`
	case containers:
		return ""
	}
	return `p.kind <> 'container'`
}

// DefaultPage et MaxPage bornent une page de projets.
const (
	DefaultPage = 50
	MaxPage     = 200
)

type listCursor struct {
	N string    `json:"n"`
	I uuid.UUID `json:"i"`
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// List renvoie une page des projets visibles, par nom.
func (s *Service) List(ctx context.Context, org tenant.OrgID, vis tenant.Visibility, f Filter, cursor string, limit int) (pagination.Page[Project], error) {
	if limit < 1 || limit > MaxPage {
		return pagination.Page[Project]{}, &pagination.LimitError{Max: MaxPage}
	}
	var after listCursor
	if cursor != "" {
		if err := pagination.Decode(cursor, &after); err != nil {
			return pagination.Page[Project]{}, err
		}
	}
	args := []any{f.Archived, limit + 1}
	where := []string{`(p.archived_at IS NOT NULL) = $1`, `lotor_team_visible(p.team_id)`}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if cursor != "" {
		args = append(args, after.N, after.I)
		where = append(where, fmt.Sprintf(`(lower(p.name), p.id) > ($%d, $%d)`, len(args)-1, len(args)))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		add(`(lower(p.name) LIKE $? OR p.slug LIKE $?)`, "%"+likeEscape(strings.ToLower(q))+"%")
	}
	switch cond := kindCondition(f.Kind, f.Containers); {
	case f.Kind != "":
		add(cond, string(f.Kind))
	case cond != "":
		where = append(where, cond)
	}
	if f.Team != uuid.Nil {
		add(`p.team_id = $?`, f.Team)
	}
	if l := strings.TrimSpace(f.Label); l != "" {
		k, v, hasValue := strings.Cut(l, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if hasValue {
			body, err := json.Marshal(map[string]string{k: strings.TrimSpace(v)})
			if err != nil {
				return pagination.Page[Project]{}, err
			}
			add(`p.labels @> $?::jsonb`, body)
		} else {
			add(`p.labels ? $?`, k)
		}
	}
	var page pagination.Page[Project]
	err := s.pool.InOrg(ctx, org, func(tx *db.OrgTx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+columns+from+` WHERE `+strings.Join(where, " AND ")+
			` ORDER BY lower(p.name), p.id LIMIT $2`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		var out []Project
		for rows.Next() {
			p, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		page, err = pagination.Build(out, limit, func(p Project) any { return listCursor{N: p.sortName, I: p.ID} })
		return err
	}, db.ReadOnly(), db.Visible(vis))
	return page, wrap("liste des projets", err)
}
