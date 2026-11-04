package policy

// Template est un modèle de règle fourni : son nom et sa description sont traduits
// (policy_template.<Key>.name et .text). Un modèle indisponible (Available faux) est
// affiché mais ne peut pas être utilisé : il attend une donnée d'un lot à venir.
type Template struct {
	Key        string
	Subject    Subject
	Expression string
	Blocking   bool
	Delivery   Delivery
	Available  bool
}

// Clés des modèles fournis.
const (
	TemplateKEVProduction = "kev_production"
	TemplateCriticalFix   = "critical_fix_30d"
	TemplateAgentSilent   = "agent_silent_7d"
	TemplateLicenseAGPL   = "license_agpl"
)

var templates = []Template{
	{
		Key: TemplateKEVProduction, Subject: SubjectFinding, Blocking: true, Delivery: DeliveryImmediate, Available: true,
		Expression: `finding.kev && finding.actionable && has(project.labels.env) && project.labels.env == "production"`,
	},
	{
		Key: TemplateCriticalFix, Subject: SubjectFinding, Blocking: true, Delivery: DeliveryDigest, Available: true,
		Expression: `finding.severity == "critical" && finding.actionable && finding.fix_available && finding.fix_age_days > 30`,
	},
	{
		Key: TemplateAgentSilent, Subject: SubjectAgent, Blocking: false, Delivery: DeliveryDigest, Available: true,
		Expression: `agent.silent_days >= 7`,
	},
	// Licence AGPL dans un produit distribué (T20) : un projet qui porte l'étiquette
	// « distribution » (avec ou sans valeur).
	{
		Key: TemplateLicenseAGPL, Subject: SubjectLicense, Blocking: true, Delivery: DeliveryDigest, Available: true,
		Expression: `license.ids.exists(id, id.startsWith("AGPL-")) && has(project.labels.distribution)`,
	},
}

// Templates renvoie les modèles fournis.
func Templates() []Template { return append([]Template(nil), templates...) }

// TemplateByKey renvoie un modèle disponible.
func TemplateByKey(key string) (Template, bool) {
	for _, t := range templates {
		if t.Key == key && t.Available {
			return t, true
		}
	}
	return Template{}, false
}
