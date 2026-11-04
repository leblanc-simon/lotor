package policy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/ext"
)

// Subject est la nature de ce qu'une règle évalue.
type Subject string

// Sujets d'une règle.
const (
	// SubjectFinding : un constat ouvert, avec son projet, son composant, sa référence et
	// son statut de triage.
	SubjectFinding Subject = "finding"
	// SubjectAgent : un agent non désactivé.
	SubjectAgent Subject = "agent"
	// SubjectLicense : un constat de licence ouvert (T20), avec son projet, son composant et
	// sa référence.
	SubjectLicense Subject = "license"
)

// Subjects renvoie les sujets, dans l'ordre des écrans.
func Subjects() []Subject { return []Subject{SubjectFinding, SubjectLicense, SubjectAgent} }

// Valid indique un sujet connu.
func (s Subject) Valid() bool { return s == SubjectFinding || s == SubjectAgent || s == SubjectLicense }

// Contexte d'évaluation, tel que la règle le lit. Les noms CEL sont ceux des étiquettes
// « cel » ; les types sont déclarés à CEL, si bien qu'un champ inconnu est refusé à la
// compilation.

// Project est le projet d'un constat.
type Project struct {
	Name   string            `cel:"name"`
	Slug   string            `cel:"slug"`
	Kind   string            `cel:"kind"`
	Team   string            `cel:"team"`
	Labels map[string]string `cel:"labels"`
	// Host est le nom du projet de l'hôte d'un conteneur (vide pour un dépôt ou un hôte).
	Host string `cel:"host"`
}

// Component est le composant d'un constat.
type Component struct {
	PURL     string `cel:"purl"`
	PURLBase string `cel:"purl_base"`
	Type     string `cel:"type"`
	Name     string `cel:"name"`
	Version  string `cel:"version"`
}

// Finding est un constat ouvert.
type Finding struct {
	VulnID         string   `cel:"vuln_id"`
	Severity       string   `cel:"severity"`
	CVSS           float64  `cel:"cvss"`
	EPSS           float64  `cel:"epss"`
	EPSSPercentile float64  `cel:"epss_percentile"`
	Risk           float64  `cel:"risk"`
	KEV            bool     `cel:"kev"`
	FixAvailable   bool     `cel:"fix_available"`
	FixedVersions  []string `cel:"fixed_versions"`
	// FixAgeDays : jours écoulés depuis qu'un correctif a été vu (0 sans correctif).
	FixAgeDays int64     `cel:"fix_age_days"`
	FirstSeen  time.Time `cel:"first_seen"`
	AgeDays    int64     `cel:"age_days"`
	MatchType  string    `cel:"match_type"`
	// Actionable : statut de triage « à analyser » ou « affecté » (ni non affecté, ni
	// faux positif, ni risque accepté, ni corrigé).
	Actionable bool `cel:"actionable"`
}

// Triage est le statut de triage effectif d'un constat (T14).
type Triage struct {
	Status string `cel:"status"`
}

// Ref est la référence suivie d'un constat.
type Ref struct {
	Kind string `cel:"kind"`
	Name string `cel:"name"`
}

// Agent est un agent.
type Agent struct {
	Name    string `cel:"name"`
	Kind    string `cel:"kind"`
	Version string `cel:"version"`
	Team    string `cel:"team"`
	// State : pending, active ou silent (état des écrans des agents).
	State string `cel:"state"`
	// SilentDays : jours entiers depuis le dernier inventaire (agent serveur) ou le
	// dernier contact (agent dépôt), à partir de la création sans l'un ni l'autre.
	SilentDays int64     `cel:"silent_days"`
	LastSeen   time.Time `cel:"last_seen"`
}

// License est un constat de licence ouvert (T20).
type License struct {
	// Verdict : « denied » (refusée) ou « review » (à revoir) selon la politique de
	// licences de l'organisation.
	Verdict string `cel:"verdict"`
	// IDs : identifiants des licences qui décident du verdict ; Licenses : licences
	// déclarées par le composant, telles que reçues.
	IDs       []string  `cel:"ids"`
	Licenses  []string  `cel:"licenses"`
	Missing   bool      `cel:"missing"`
	FirstSeen time.Time `cel:"first_seen"`
	AgeDays   int64     `cel:"age_days"`
}

// LicenseInput est le contexte d'évaluation d'une règle sur un constat de licence.
type LicenseInput struct {
	Project   Project
	Component Component
	License   License
	Ref       Ref
}

// FindingInput est le contexte d'évaluation d'une règle sur un constat.
type FindingInput struct {
	Project   Project
	Component Component
	Finding   Finding
	Triage    Triage
	Ref       Ref
}

// Bornes des règles.
const (
	MaxExpression = 4000
	// MaxCost borne le coût estimé d'une règle à l'enregistrement et son coût réel à
	// chaque évaluation : aucune règle ne s'exécute sans limite.
	MaxCost = 50_000
	// estimatedSize est la taille supposée d'une chaîne, d'une liste ou d'une table pour
	// l'estimation du coût (étiquettes : 20 au plus ; versions corrigées : quelques-unes).
	estimatedSize = 100
)

// Clés des erreurs d'une règle (validation.*), situées par ligne et colonne.
const (
	KeyExprRequired     = "validation.policy_expression_required"
	KeyExprTooLong      = "validation.policy_expression_too_long"
	KeyExprSyntax       = "validation.policy_syntax"
	KeyExprUnknownField = "validation.policy_unknown_field"
	KeyExprUnknownName  = "validation.policy_unknown_name"
	KeyExprType         = "validation.policy_type"
	KeyExprInvalid      = "validation.policy_invalid"
	KeyExprNotBool      = "validation.policy_not_bool"
	KeyExprTooCostly    = "validation.policy_too_costly"
)

// ExprError est une règle refusée à la compilation : clé traduisible, position (ligne et
// colonne à partir de 1, zéro si sans objet), nom en cause, et message technique de CEL
// (en anglais, montré en complément).
type ExprError struct {
	Key    string
	Line   int
	Column int
	Name   string
	Detail string
}

func (e *ExprError) Error() string {
	return fmt.Sprintf("policy: règle invalide (%s, %d:%d) : %s", e.Key, e.Line, e.Column, e.Detail)
}

// IsExprError renvoie l'erreur de règle de err, si c'en est une.
func IsExprError(err error) (*ExprError, bool) {
	var e *ExprError
	ok := errors.As(err, &e)
	return e, ok
}

// Program est une règle compilée.
type Program struct {
	Subject    Subject
	Expression string
	prg        cel.Program
}

// Compiler compile les règles et garde les programmes compilés (une règle s'évalue sur
// des milliers de constats : la compilation ne se fait qu'une fois).
type Compiler struct {
	envs  map[Subject]*cel.Env
	mu    sync.Mutex
	cache map[string]*Program
}

// maxCache borne le cache des programmes.
const maxCache = 512

// NewCompiler prépare les environnements CEL des deux sujets.
func NewCompiler() (*Compiler, error) {
	common := []cel.EnvOption{
		cel.Variable("now", cel.TimestampType),
		ext.Strings(),
		cel.CrossTypeNumericComparisons(true),
		cel.ParserExpressionSizeLimit(MaxExpression),
	}
	findingEnv, err := cel.NewEnv(append([]cel.EnvOption{
		ext.NativeTypes(reflect.TypeFor[Project](), reflect.TypeFor[Component](), reflect.TypeFor[Finding](),
			reflect.TypeFor[Triage](), reflect.TypeFor[Ref](), ext.ParseStructTags(true)),
		cel.Variable("project", cel.ObjectType("policy.Project")),
		cel.Variable("component", cel.ObjectType("policy.Component")),
		cel.Variable("finding", cel.ObjectType("policy.Finding")),
		cel.Variable("triage", cel.ObjectType("policy.Triage")),
		cel.Variable("ref", cel.ObjectType("policy.Ref")),
	}, common...)...)
	if err != nil {
		return nil, fmt.Errorf("policy: environnement CEL des constats : %w", err)
	}
	licenseEnv, err := cel.NewEnv(append([]cel.EnvOption{
		ext.NativeTypes(reflect.TypeFor[Project](), reflect.TypeFor[Component](), reflect.TypeFor[License](),
			reflect.TypeFor[Ref](), ext.ParseStructTags(true)),
		cel.Variable("project", cel.ObjectType("policy.Project")),
		cel.Variable("component", cel.ObjectType("policy.Component")),
		cel.Variable("license", cel.ObjectType("policy.License")),
		cel.Variable("ref", cel.ObjectType("policy.Ref")),
	}, common...)...)
	if err != nil {
		return nil, fmt.Errorf("policy: environnement CEL des licences : %w", err)
	}
	agentEnv, err := cel.NewEnv(append([]cel.EnvOption{
		ext.NativeTypes(reflect.TypeFor[Agent](), ext.ParseStructTags(true)),
		cel.Variable("agent", cel.ObjectType("policy.Agent")),
	}, common...)...)
	if err != nil {
		return nil, fmt.Errorf("policy: environnement CEL des agents : %w", err)
	}
	return &Compiler{envs: map[Subject]*cel.Env{SubjectFinding: findingEnv, SubjectAgent: agentEnv, SubjectLicense: licenseEnv},
		cache: map[string]*Program{}}, nil
}

// Compile vérifie et compile une règle : syntaxe, champs et types connus, résultat
// booléen, coût estimé borné. Une règle refusée renvoie une *ExprError.
func (c *Compiler) Compile(s Subject, expr string) (*Program, error) {
	env, ok := c.envs[s]
	if !ok {
		return nil, fmt.Errorf("policy: sujet %q inconnu", s)
	}
	if strings.TrimSpace(expr) == "" {
		return nil, &ExprError{Key: KeyExprRequired}
	}
	if utf8.RuneCountInString(expr) > MaxExpression || !utf8.ValidString(expr) {
		return nil, &ExprError{Key: KeyExprTooLong}
	}
	key := string(s) + "\x00" + expr
	c.mu.Lock()
	p, ok := c.cache[key]
	c.mu.Unlock()
	if ok {
		return p, nil
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, exprError(iss.Errors())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, &ExprError{Key: KeyExprNotBool, Detail: ast.OutputType().String()}
	}
	est, err := env.EstimateCost(ast, sizeEstimator{})
	if err != nil || est.Max > MaxCost {
		return nil, &ExprError{Key: KeyExprTooCostly, Detail: fmt.Sprintf("estimated cost %d > %d", est.Max, MaxCost)}
	}
	prg, err := env.Program(ast, cel.CostLimit(MaxCost), cel.InterruptCheckFrequency(100),
		cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, &ExprError{Key: KeyExprInvalid, Detail: err.Error()}
	}
	p = &Program{Subject: s, Expression: expr, prg: prg}
	c.mu.Lock()
	if len(c.cache) >= maxCache {
		clear(c.cache)
	}
	c.cache[key] = p
	c.mu.Unlock()
	return p, nil
}

var quoted = regexp.MustCompile(`'([^']{1,200})'`)

// exprError traduit la première erreur de CEL en clé situable.
func exprError(errs []*common.Error) error {
	if len(errs) == 0 {
		return &ExprError{Key: KeyExprInvalid}
	}
	e := errs[0]
	out := &ExprError{Key: KeyExprInvalid, Detail: e.Message}
	if loc := e.Location; loc != nil && loc.Line() > 0 {
		out.Line, out.Column = loc.Line(), loc.Column()+1
	}
	name := ""
	if m := quoted.FindStringSubmatch(e.Message); m != nil {
		name = m[1]
	}
	switch msg := e.Message; {
	case strings.HasPrefix(msg, "Syntax error"):
		out.Key = KeyExprSyntax
	case strings.HasPrefix(msg, "undefined field"):
		out.Key, out.Name = KeyExprUnknownField, name
	case strings.HasPrefix(msg, "undeclared reference"):
		out.Key, out.Name = KeyExprUnknownName, name
	case strings.Contains(msg, "no matching overload"), strings.Contains(msg, "type"):
		out.Key = KeyExprType
	}
	return out
}

// sizeEstimator donne à CEL une taille plausible des chaînes, listes et tables du
// contexte, sans quoi toute compréhension aurait un coût estimé infini.
type sizeEstimator struct{}

func (sizeEstimator) EstimateSize(checker.AstNode) *checker.SizeEstimate {
	return &checker.SizeEstimate{Min: 0, Max: estimatedSize}
}

func (sizeEstimator) EstimateCallCost(string, string, *checker.AstNode, []checker.AstNode) *checker.CallEstimate {
	return nil
}

// ErrEval est une évaluation en échec (champ absent d'une table, coût dépassé…) : la
// règle est considérée comme non satisfaite pour ce sujet.
var ErrEval = errors.New("policy: évaluation en échec")

func (p *Program) eval(ctx context.Context, vars map[string]any) (bool, error) {
	out, _, err := p.prg.ContextEval(ctx, vars)
	if err != nil {
		return false, fmt.Errorf("%w : %v", ErrEval, err)
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("%w : résultat non booléen", ErrEval)
	}
	return b, nil
}

// MatchFinding évalue une règle de constat.
func (p *Program) MatchFinding(ctx context.Context, in FindingInput, now time.Time) (bool, error) {
	if p.Subject != SubjectFinding {
		return false, fmt.Errorf("policy: règle de %s évaluée sur un constat", p.Subject)
	}
	if in.Project.Labels == nil {
		in.Project.Labels = map[string]string{}
	}
	if in.Finding.FixedVersions == nil {
		in.Finding.FixedVersions = []string{}
	}
	return p.eval(ctx, map[string]any{"project": in.Project, "component": in.Component, "finding": in.Finding,
		"triage": in.Triage, "ref": in.Ref, "now": now})
}

// MatchLicense évalue une règle de licence.
func (p *Program) MatchLicense(ctx context.Context, in LicenseInput, now time.Time) (bool, error) {
	if p.Subject != SubjectLicense {
		return false, fmt.Errorf("policy: règle de %s évaluée sur une licence", p.Subject)
	}
	if in.Project.Labels == nil {
		in.Project.Labels = map[string]string{}
	}
	if in.License.IDs == nil {
		in.License.IDs = []string{}
	}
	if in.License.Licenses == nil {
		in.License.Licenses = []string{}
	}
	return p.eval(ctx, map[string]any{"project": in.Project, "component": in.Component, "license": in.License,
		"ref": in.Ref, "now": now})
}

// MatchAgent évalue une règle d'agent.
func (p *Program) MatchAgent(ctx context.Context, a Agent, now time.Time) (bool, error) {
	if p.Subject != SubjectAgent {
		return false, fmt.Errorf("policy: règle de %s évaluée sur un agent", p.Subject)
	}
	return p.eval(ctx, map[string]any{"agent": a, "now": now})
}

// Variable est une variable du contexte d'une règle et ses champs (aide de l'écran).
type Variable struct {
	Name   string
	Fields []string
}

func celFields(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("cel"), ","); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Variables renvoie les variables du contexte d'un sujet.
func Variables(s Subject) []Variable {
	if s == SubjectAgent {
		return []Variable{{Name: "agent", Fields: celFields(reflect.TypeFor[Agent]())}, {Name: "now"}}
	}
	if s == SubjectLicense {
		return []Variable{
			{Name: "project", Fields: celFields(reflect.TypeFor[Project]())},
			{Name: "component", Fields: celFields(reflect.TypeFor[Component]())},
			{Name: "license", Fields: celFields(reflect.TypeFor[License]())},
			{Name: "ref", Fields: celFields(reflect.TypeFor[Ref]())},
			{Name: "now"},
		}
	}
	return []Variable{
		{Name: "project", Fields: celFields(reflect.TypeFor[Project]())},
		{Name: "component", Fields: celFields(reflect.TypeFor[Component]())},
		{Name: "finding", Fields: celFields(reflect.TypeFor[Finding]())},
		{Name: "triage", Fields: celFields(reflect.TypeFor[Triage]())},
		{Name: "ref", Fields: celFields(reflect.TypeFor[Ref]())},
		{Name: "now"},
	}
}
