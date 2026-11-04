package archtest

import (
	"fmt"
	"slices"
	"strings"
)

// Package décrit un paquet par son chemin relatif à la racine du module
// (« internal/web ») et ses imports directs, tests compris.
type Package struct {
	Path    string
	Imports []string
}

// Violation est un import direct contraire à une règle. Un import interne au module
// est donné par son chemin relatif.
type Violation struct {
	Package string
	Import  string
	Rule    string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s importe %s : %s", v.Package, v.Import, v.Rule)
}

// anchoreImporters liste, pour chaque bibliothèque d'Anchore, les seuls paquets autorisés
// à l'importer directement (sous-paquets compris).
var anchoreImporters = map[string][]string{
	"github.com/anchore/syft": {"internal/sbom/syft", "internal/vuln/grype", "internal/hostagent", "internal/repoagent"},
	// stereoscope (références de fichier de Syft) : seulement le résolveur de l'agent serveur.
	"github.com/anchore/stereoscope": {"internal/hostagent"},
	"github.com/anchore/grype":       {"internal/vuln/grype", "internal/version/grypeversion"},
	"github.com/anchore/grant":       {"internal/license/grant"},
}

// domainPackages sont les paquets métier : ni HTTP, ni gabarits, ni couche de présentation.
var domainPackages = []string{
	"internal/account", "internal/agent", "internal/audit", "internal/benchdata", "internal/dashboard",
	"internal/db", "internal/finding", "internal/ingest", "internal/inventory",
	"internal/jobs", "internal/license", "internal/locale", "internal/notify", "internal/org",
	"internal/pagination", "internal/policy", "internal/project", "internal/sbom", "internal/search",
	"internal/secret", "internal/team", "internal/tenant", "internal/token", "internal/triage",
	"internal/version", "internal/vuln",
}

// presentationPackages ne sont importés que par cmd et entre eux. web (à la racine)
// embarque gabarits et fichiers statiques.
var presentationPackages = []string{"internal/web", "internal/api", "internal/render", "web"}

// agentPackages forment les binaires d'agents, qui restent légers.
var agentPackages = []string{
	"internal/agentclient", "internal/hostagent", "internal/repoagent", "internal/forge", "internal/llm",
}

// serverPackages sont réservés au serveur : un agent ne les importe jamais.
var serverPackages = []string{
	"internal/account", "internal/agent", "internal/api", "internal/audit", "internal/benchdata", "internal/config",
	"internal/dashboard", "internal/db", "internal/delivery", "internal/download", "internal/finding", "internal/ingest",
	"internal/inventory", "internal/jobs", "internal/locale", "internal/notify", "internal/org",
	"internal/pagination", "internal/policy", "internal/project", "internal/render",
	"internal/search", "internal/secret", "internal/team", "internal/tenant", "internal/token",
	"internal/triage", "internal/version", "internal/vuln", "internal/web", "web",
}

// forbiddenInDomain sont les paquets de la bibliothèque standard interdits au métier.
var forbiddenInDomain = []string{"net/http", "html/template"}

// within indique si path est root ou l'un de ses sous-paquets.
func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func withinAny(path string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool { return within(path, r) })
}

// Check applique les règles à des paquets dont les chemins d'import commencent par
// module. Les imports internes au module sont ramenés à leur chemin relatif.
func Check(module string, pkgs []Package) []Violation {
	var out []Violation
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			rel, internal := strings.CutPrefix(imp, module+"/")
			if internal {
				out = append(out, checkInternal(p.Path, rel)...)
				continue
			}
			out = append(out, checkExternal(p.Path, imp)...)
		}
	}
	return out
}

func checkExternal(pkg, imp string) []Violation {
	var out []Violation
	for lib, allowed := range anchoreImporters {
		if within(imp, lib) && !withinAny(pkg, allowed) {
			out = append(out, Violation{pkg, imp, "Anchore n'est importé que par ses adaptateurs (§ 4)"})
		}
	}
	if withinAny(pkg, domainPackages) && slices.Contains(forbiddenInDomain, imp) {
		out = append(out, Violation{pkg, imp, "le métier ne dépend ni de net/http ni de html/template (§ 4)"})
	}
	return out
}

func checkInternal(pkg, imp string) []Violation {
	var out []Violation
	if withinAny(imp, presentationPackages) && !within(pkg, "cmd") && !withinAny(pkg, presentationPackages) {
		out = append(out, Violation{pkg, imp, "web, api et render ne sont importés que par cmd (§ 4)"})
	}
	if withinAny(pkg, agentPackages) && withinAny(imp, serverPackages) {
		out = append(out, Violation{pkg, imp, "un agent n'importe aucun paquet serveur (§ 4)"})
	}
	return out
}
