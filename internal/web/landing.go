package web

import (
	"net/http"
	"regexp"
	"strings"

	"leblanc.io/lotor/internal/render"
)

// root sert « / » : la page de présentation à un visiteur anonyme (ADR 0054), l'accueil du
// compte sinon, derrière requireAuth comme les autres pages (une session de configuration
// va à l'enrôlement du TOTP).
func (id *identity) root(w http.ResponseWriter, r *http.Request) {
	if viewerFrom(r) == nil {
		id.rd.Render(w, r, http.StatusOK, "landing/index", &landingView{
			Page:           render.Page{TitleKey: "landing.title"},
			PackageVersion: packageVersion(id.rd.Version()),
		})
		return
	}
	requireAuth(http.HandlerFunc(id.home)).ServeHTTP(w, r)
}

// landingView est la page de présentation : rien n'y vient de la base, puisque le visiteur
// n'est pas connecté. PackageVersion est la version des paquets de ce binaire, vide pour un
// binaire de développement (la page affiche alors un paramètre à remplacer).
type landingView struct {
	render.Page
	PackageVersion string
}

// releaseVersion est la version d'un binaire publié (scripts/release.sh : vX.Y.Z, suffixe de
// préversion éventuel) ; git describe (v0.2.0-3-g9c96c4f, -dirty) ou un commit n'en sont pas.
var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// packageVersion renvoie la version des paquets deb et rpm d'un binaire publié, calculée
// comme PKG_VERSION du Makefile (v0.2.0 → 0.2.0, v0.3.0-rc.1 → 0.3.0.rc.1), ou "".
func packageVersion(v string) string {
	if !releaseVersion.MatchString(v) || strings.HasSuffix(v, "-dirty") {
		return ""
	}
	return strings.ReplaceAll(strings.TrimPrefix(v, "v"), "-", ".")
}
