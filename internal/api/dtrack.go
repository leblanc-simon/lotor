package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/web/middleware"
)

// Point compatible Dependency-Track (T19, ADR 0058). Un client configuré pour
// Dependency-Track avec l'adresse de base https://<serveur>/dt envoie ses SBOM à
// /dt/api/v1/bom et suit leur traitement par /dt/api/v1/event/token/{uuid}, avec sa clé
// d'API dans X-Api-Key : un jeton d'agent dépôt. Rien n'est contourné : l'envoi devient
// une ingestion ordinaire (mêmes bornes, mêmes quotas, même file, référence confiée à
// l'agent), sur une référence de nature « version ».

// dtPrefix est le préfixe des routes du point compatible.
const dtPrefix = "/dt"

// dtFieldMax borne un champ texte du formulaire multipart (nom, version, identifiant…).
const dtFieldMax = 16 << 10

// apiKey lit la clé d'API d'un client Dependency-Track.
func apiKey(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Api-Key")) }

// MountDT monte le point compatible Dependency-Track sur r, routeur de /dt : mêmes
// limiteurs, même authentification (X-Api-Key au lieu de Authorization) et même mTLS
// que l'API des agents.
func MountDT(r chi.Router, o AgentOptions) error {
	h, err := newAgentAPI(o)
	if err != nil {
		return err
	}
	// Corps JSON : SBOM en base64 (4/3 de sa taille) et champs ; corps multipart : SBOM
	// brut et champs.
	maxJSON := o.Ingest.Limits().MaxUpload/3*4 + 4 + multipartOverhead
	maxMultipart := o.Ingest.Limits().MaxUpload + multipartOverhead
	r.Group(func(r chi.Router) {
		if o.RequireClientCert {
			r.Use(h.requireClientCert)
		}
		r.Use(h.authenticate(apiKey), h.perToken, h.dtAgentOnly)
		r.With(bodyLimit(maxJSON)).Put("/api/v1/bom", h.dtPutBOM)
		r.With(bodyLimit(maxMultipart)).Post("/api/v1/bom", h.dtPostBOM)
		r.With(bodyLimit(maxAgentJSON)).Get("/api/v1/event/token/{token}", h.dtToken)
		// Chemin de Dependency-Track 4, déprécié depuis sa 4.11 mais encore employé.
		r.With(bodyLimit(maxAgentJSON)).Get("/api/v1/bom/token/{token}", h.dtToken)
	})
	return nil
}

func bodyLimit(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// dtAgentOnly refuse un jeton d'inscription : seul un jeton d'agent ouvre le point
// compatible (la nature de l'agent est vérifiée par ResolveUpload).
func (h *agentAPI) dtAgentOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := principalFrom(r.Context()); !ok || p.Kind != agent.KindAgent {
			h.responseError(w, r, &agent.AuthError{Key: agent.KeyTokenInvalid})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// dtSubmit est le corps de PUT /api/v1/bom (BomSubmitRequest de Dependency-Track) ; les
// champs non retenus (étiquettes, parent, isLatest) sont ignorés.
type dtSubmit struct {
	Project        string `json:"project"`
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	BOM            string `json:"bom"`
}

// dtUploadResponse est la réponse d'un envoi (BomUploadResponse) : le jeton de suivi est
// l'identifiant de l'ingestion, projectUuid celui de la référence « version ».
type dtUploadResponse struct {
	Token       uuid.UUID `json:"token"`
	ProjectUUID uuid.UUID `json:"projectUuid"`
}

// dtTokenResponse est l'état d'un traitement (IsTokenBeingProcessedResponse) ; status,
// ajouté par Dependency-Track 5, est nul pour un jeton inconnu.
type dtTokenResponse struct {
	Processing bool    `json:"processing"`
	Status     *string `json:"status"`
}

// dtStatus traduit l'état d'une ingestion dans le vocabulaire de Dependency-Track 5.
func dtStatus(s ingest.Status) *string {
	v := map[ingest.Status]string{ingest.StatusQueued: "PENDING", ingest.StatusProcessing: "RUNNING",
		ingest.StatusDone: "COMPLETED", ingest.StatusFailed: "FAILED"}[s]
	return &v
}

func (h *agentAPI) dtPutBOM(w http.ResponseWriter, r *http.Request) {
	if !mediaType(r, "application/json") {
		h.badRequest(w, r, nil)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.responseError(w, r, badMultipart(err))
		return
	}
	var req dtSubmit
	if err := json.Unmarshal(data, &req); err != nil {
		h.badRequest(w, r, err)
		return
	}
	data = nil
	bom, err := base64.StdEncoding.DecodeString(req.BOM)
	if err != nil {
		h.responseError(w, r, &account.ValidationError{Field: "bom", Key: KeyDTBase64})
		return
	}
	req.BOM = ""
	target, err := dtTarget(req.Project, req.ProjectName, req.ProjectVersion, req.AutoCreate)
	if err != nil {
		h.responseError(w, r, err)
		return
	}
	h.dtReceive(w, r, target, bom)
}

func (h *agentAPI) dtPostBOM(w http.ResponseWriter, r *http.Request) {
	if !mediaType(r, "multipart/form-data") {
		h.badRequest(w, r, nil)
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		h.badRequest(w, r, err)
		return
	}
	fields := map[string]string{}
	var bom []byte
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.responseError(w, r, badMultipart(err))
			return
		}
		name := part.FormName()
		switch name {
		case "bom":
			if bom != nil {
				h.badRequest(w, r, nil)
				return
			}
			// Lu en entier : les champs peuvent suivre le SBOM. La borne du corps limite la
			// mémoire, et rien n'est rangé avant la vérification de la cible.
			if bom, err = io.ReadAll(tooLargeReader{part}); err != nil {
				h.responseError(w, r, badMultipart(err))
				return
			}
			if bom == nil {
				bom = []byte{}
			}
		case "project", "projectName", "projectVersion", "autoCreate":
			v, err := readField(part)
			if err != nil {
				h.responseError(w, r, err)
				return
			}
			fields[name] = v
		default:
			// Champs de Dependency-Track non retenus (étiquettes, parent, isLatest) : lus
			// et ignorés, sous la même borne.
			if _, err := readField(part); err != nil {
				h.responseError(w, r, err)
				return
			}
		}
	}
	if bom == nil {
		h.responseError(w, r, errMissingPart)
		return
	}
	target, err := dtTarget(fields["project"], fields["projectName"], fields["projectVersion"],
		strings.EqualFold(strings.TrimSpace(fields["autoCreate"]), "true"))
	if err != nil {
		h.responseError(w, r, err)
		return
	}
	h.dtReceive(w, r, target, bom)
}

func readField(part *multipart.Part) (string, error) {
	data, err := io.ReadAll(io.LimitReader(part, dtFieldMax+1))
	if err != nil {
		return "", badMultipart(err)
	}
	if len(data) > dtFieldMax {
		return "", &requestError{err: errors.New("champ trop long")}
	}
	return string(data), nil
}

func mediaType(r *http.Request, want string) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == want
}

// dtTarget lit la cible d'un envoi : l'identifiant « project » (une référence
// « version ») l'emporte, comme chez Dependency-Track, sur le nom et la version.
func dtTarget(projectID, name, version string, autoCreate bool) (agent.UploadTarget, error) {
	t := agent.UploadTarget{ProjectName: strings.TrimSpace(name), Version: strings.TrimSpace(version), AutoCreate: autoCreate}
	if id := strings.TrimSpace(projectID); id != "" {
		ref, err := uuid.Parse(id)
		if err != nil || ref == uuid.Nil {
			return agent.UploadTarget{}, &account.ValidationError{Field: "project", Key: agent.KeyDTTargetMissing}
		}
		t.RefID = ref
	}
	return t, nil
}

// dtReceive résout la cible, vérifie la référence comme l'ingestion native, puis reçoit
// le SBOM. Un SBOM refusé au décodage donne, comme en natif, une ingestion « failed » :
// le client le voit par le suivi du jeton (traitement terminé) et à l'écran.
func (h *agentAPI) dtReceive(w http.ResponseWriter, r *http.Request, t agent.UploadTarget, bom []byte) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	ip, _ := ctx.Value(clientIPKey{}).(string)
	target, err := h.Agents.ResolveUpload(ctx, p, t, ip, middleware.RequestIDFrom(ctx))
	if err != nil {
		h.responseError(w, r, err)
		return
	}
	c := ingest.Context{ProjectID: target.ProjectID, RefKind: project.RefVersion, RefName: target.Version,
		AgentVersion: "", ScannedAt: h.Agents.Now()}
	if err := h.Ingest.Authorize(ctx, p.Org, p.AgentID, c); err != nil {
		h.responseError(w, r, err)
		return
	}
	in, err := h.Ingest.Receive(ctx, p.Org, p.AgentID, c, bytes.NewReader(bom))
	if err != nil {
		h.responseError(w, r, err)
		return
	}
	writeJSON(w, dtUploadResponse{Token: in.ID, ProjectUUID: target.RefID})
}

// dtToken répond si un envoi est encore en traitement. Comme Dependency-Track, un jeton
// inconnu (ou d'un autre agent) répond « false » : la réponse ne dit rien de plus.
func (h *agentAPI) dtToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "token"))
	if err != nil {
		writeJSON(w, dtTokenResponse{})
		return
	}
	in, err := h.Ingest.Get(ctx, p.Org, p.AgentID, id)
	if errors.Is(err, ingest.ErrNotFound) {
		writeJSON(w, dtTokenResponse{})
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	writeJSON(w, dtTokenResponse{Processing: in.Status == ingest.StatusQueued || in.Status == ingest.StatusProcessing,
		Status: dtStatus(in.Status)})
}

// KeyDTBase64 : le champ bom d'un envoi JSON n'est pas du base64.
const KeyDTBase64 = "validation.dt.base64"

// dtProblem traduit les refus propres au point compatible ; false s'il n'en est pas un.
func (h *agentAPI) dtProblem(w http.ResponseWriter, r *http.Request, err error) bool {
	var fe *agent.ForbiddenError
	switch {
	case errors.As(err, &fe):
		problem.Write(w, r, h.Catalog, http.StatusForbidden, fe.Key, nil)
	case errors.Is(err, agent.ErrDTUnknown):
		problem.Write(w, r, h.Catalog, http.StatusNotFound, agent.KeyDTProjectUnknown, nil)
	default:
		return false
	}
	return true
}
