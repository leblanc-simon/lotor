package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

// StylesheetName est la feuille concaténée, servie sous ce nom.
const StylesheetName = "css/app.css"

// stylesheetOrder fixe l'ordre de concaténation : tokens, polices, base, composants,
// écrans. Une feuille ailleurs sous css/ est une erreur, plutôt qu'un oubli silencieux.
var stylesheetOrder = []string{"css/tokens.css", "css/fonts.css", "css/base.css", "css/components/*.css", "css/screens/*.css"}

// contentTypes couvre les extensions servies ; un autre fichier est refusé au démarrage.
var contentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".woff2": "font/woff2",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".webp":  "image/webp",
	".txt":   "text/plain; charset=utf-8",
}

type asset struct {
	body  []byte
	ctype string
	etag  string
}

// Assets sert les fichiers statiques sous une URL à empreinte : /static/<empreinte>/<nom>.
// L'empreinte couvre tous les fichiers servis, si bien que les chemins relatifs entre
// eux (url() d'une feuille vers une police, import d'un module) restent valides.
type Assets struct {
	prefix string
	hash   string
	files  map[string]asset
}

// NewAssets lit les fichiers de static (racine : css/, js/, fonts/, img/), concatène les
// feuilles dans StylesheetName et calcule l'empreinte.
func NewAssets(static fs.FS) (*Assets, error) {
	a := &Assets{files: map[string]asset{}}
	css, sources, err := concatStylesheets(static)
	if err != nil {
		return nil, err
	}
	a.add(StylesheetName, css)
	err = fs.WalkDir(static, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasPrefix(name, "css/") {
			if !slices.Contains(sources, name) {
				return fmt.Errorf("render: feuille %s hors de l'ordre de concaténation %v", name, stylesheetOrder)
			}
			return nil
		}
		body, err := fs.ReadFile(static, name)
		if err != nil {
			return err
		}
		if _, ok := contentTypes[path.Ext(name)]; !ok {
			return fmt.Errorf("render: type de fichier statique non pris en charge : %s", name)
		}
		a.add(name, body)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("render: fichiers statiques : %w", err)
	}

	names := make([]string, 0, len(a.files))
	for n := range a.files {
		names = append(names, n)
	}
	slices.Sort(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%s\x00", n, a.files[n].etag)
	}
	a.hash = hex.EncodeToString(h.Sum(nil))[:16]
	a.prefix = "/static/" + a.hash + "/"
	return a, nil
}

func (a *Assets) add(name string, body []byte) {
	sum := sha256.Sum256(body)
	a.files[name] = asset{body: body, ctype: contentTypes[path.Ext(name)], etag: hex.EncodeToString(sum[:])}
}

func concatStylesheets(static fs.FS) ([]byte, []string, error) {
	var buf bytes.Buffer
	var sources []string
	for _, pattern := range stylesheetOrder {
		matches, err := fs.Glob(static, pattern)
		if err != nil {
			return nil, nil, err
		}
		if len(matches) == 0 && !strings.Contains(pattern, "*") {
			return nil, nil, fmt.Errorf("render: feuille %s absente", pattern)
		}
		slices.Sort(matches)
		for _, m := range matches {
			body, err := fs.ReadFile(static, m)
			if err != nil {
				return nil, nil, err
			}
			fmt.Fprintf(&buf, "/* %s */\n", m)
			buf.Write(bytes.TrimSpace(body))
			buf.WriteString("\n\n")
			sources = append(sources, m)
		}
	}
	return buf.Bytes(), sources, nil
}

// Hash renvoie l'empreinte courante.
func (a *Assets) Hash() string { return a.hash }

// URL renvoie l'URL à empreinte d'un fichier servi (« css/app.css », « js/theme.js »).
func (a *Assets) URL(name string) (string, error) {
	if _, ok := a.files[name]; !ok {
		return "", fmt.Errorf("render: fichier statique inconnu %q", name)
	}
	return a.prefix + name, nil
}

// Handler sert /static/<empreinte>/<nom>. Avec l'empreinte courante, la réponse est
// immuable et mise en cache un an ; avec une autre (page rendue par une instance d'une
// autre version pendant un déploiement), le fichier courant est servi sans cache.
func (a *Assets) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/static/")
		hash, name, ok2 := strings.Cut(rest, "/")
		f, found := a.files[name]
		if !ok || !ok2 || !found {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", f.ctype)
		h.Set("ETag", `"`+f.etag+`"`)
		if hash == a.hash {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
	})
}
