package web

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"leblanc.io/lotor/internal/triage/vex"
)

// Téléversement d'une archive de la base de vulnérabilités (import manuel, T11).
//
// Le corps d'un formulaire de l'interface est borné à 64 Kio (limitBody) et csrfx lit le
// jeton par PostFormValue, qui, sur un corps multipart, écrirait le fichier entier sur le
// disque avant toute vérification. Pour la seule route de téléversement, uploadGate :
//
//   - n'élargit la borne du corps qu'à un administrateur d'instance authentifié (les autres
//     gardent 64 Kio et reçoivent la réponse habituelle de la garde : 404) ;
//   - lit la première partie du formulaire, qui doit être le jeton CSRF (le gabarit le
//     place avant le fichier, et le navigateur envoie les champs dans l'ordre du
//     document), et le présente à csrfx dans l'en-tête qu'il accepte : la vérification
//     reste celle de csrfx (comparaison au cookie), sans rien lire du fichier ;
//   - laisse au handler le lecteur multipart, qui lit le fichier en flux jusqu'à
//     PostgreSQL ;
//   - repousse les délais de lecture et d'écriture de la connexion : un fichier de
//     plusieurs centaines de Mio dépasse http.read_timeout.

const (
	pathVulnDBImport = "/admin/vulndb/import"
	// csrfFieldName et csrfHeaderName sont les noms par défaut de csrfx.
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	// maxCSRFToken borne la partie du jeton (64 caractères hexadécimaux chez csrfx).
	maxCSRFToken = 256
	// uploadOverhead couvre, au-delà de l'archive, les en-têtes multipart et le jeton.
	uploadOverhead = 64 << 10
)

// isUpload désigne les requêtes dont uploadGate borne le corps : téléversement d'une
// archive de la base, import d'un VEX.
func isUpload(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == pathVulnDBImport || isVEXImport(r) || isArchiveImport(r))
}

// isVEXImport désigne l'import d'un VEX (T14) : /o/{slug}/projects/{project}/vex/import
// ou /o/{slug}/triage/import.
func isVEXImport(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 6 && parts[0] == "o" && parts[2] == "projects" && parts[4] == "vex" && parts[5] == "import":
		return parts[1] != "" && parts[3] != ""
	case len(parts) == 4 && parts[0] == "o" && parts[2] == "triage" && parts[3] == "import":
		return parts[1] != ""
	}
	return false
}

// vexUploadBytes borne le corps d'un import de VEX : le document et le formulaire.
// En deçà de la mémoire de ParseMultipartForm (32 Mio), csrfx lit tout le formulaire en
// mémoire, sans fichier temporaire : l'import passe par le chemin habituel de csrfx.
const vexUploadBytes = vex.MaxDocument + uploadOverhead

type uploadKey struct{}

// uploadReader renvoie le lecteur multipart posé par uploadGate, positionné après le
// jeton CSRF ; nil si la requête n'en a pas.
func uploadReader(r *http.Request) *multipart.Reader {
	mr, _ := r.Context().Value(uploadKey{}).(*multipart.Reader)
	return mr
}

// uploadGate prépare la requête de téléversement (voir plus haut) ; les autres requêtes
// passent telles quelles.
func (id *identity) uploadGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpload(r) {
			next.ServeHTTP(w, r)
			return
		}
		if isVEXImport(r) {
			// Un compte authentifié seulement ; la garde de la route vérifie ensuite le droit.
			limit := int64(maxFormBytes)
			if v := viewerFrom(r); v.authenticated() {
				limit = vexUploadBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
			return
		}
		limit := id.VulnDB.MaxArchive + uploadOverhead
		allowed := viewerFrom(r).authenticated() && viewerFrom(r).admin()
		if isArchiveImport(r) {
			// Archive hors ligne (T23) : un compte authentifié ; la garde de la route vérifie
			// ensuite le droit de gérer les agents.
			limit, allowed = id.Ingest.MaxArchive()+uploadOverhead, viewerFrom(r).authenticated()
		}
		if !allowed {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		rc := http.NewResponseController(w)
		deadline := time.Now().Add(id.VulnDB.UploadTimeout)
		if err := rc.SetReadDeadline(deadline); err != nil {
			id.logger.Debug("délai de lecture du téléversement", "err", err)
		}
		if err := rc.SetWriteDeadline(deadline); err != nil {
			id.logger.Debug("délai d'écriture du téléversement", "err", err)
		}
		// MultipartReader marque la requête comme lue en flux : sur un autre corps, csrfx ne
		// pourrait plus lire le jeton du formulaire ; on ne l'appelle que pour du multipart.
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			next.ServeHTTP(w, r)
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		part, err := mr.NextPart()
		if err != nil || part.FormName() != csrfFieldName {
			// Sans jeton en tête, csrfx refuse la requête (le formulaire est déjà lu en
			// flux : il ne peut plus l'analyser).
			next.ServeHTTP(w, r)
			return
		}
		token, err := io.ReadAll(io.LimitReader(part, maxCSRFToken+1))
		if err == nil && len(token) <= maxCSRFToken {
			r.Header.Set(csrfHeaderName, string(token))
			r = r.WithContext(context.WithValue(r.Context(), uploadKey{}, mr))
		}
		next.ServeHTTP(w, r)
	})
}
