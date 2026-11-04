package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/api/gen/userapi"
	"leblanc.io/lotor/internal/api/problem"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/tenant"
	"leblanc.io/lotor/internal/web/middleware"
)

// keyForbidden : droit manquant (403), comme l'interface.
const keyForbidden = "error.forbidden"

// ImportArchive importe une archive hors ligne (T23, ADR 0060) : corps brut borné à la
// taille admise d'une archive, propriétaire du jeton autorisé à gérer des agents, puis
// import au nom de l'agent que l'archive authentifie.
func (h *userAPI) ImportArchive(w http.ResponseWriter, r *http.Request, _ userapi.Org) {
	acc, _ := tenant.AccessFrom(r.Context())
	if !acc.CanAny(tenant.PermAgentManage) {
		problem.Write(w, r, h.Catalog, http.StatusForbidden, keyForbidden, nil)
		return
	}
	p, _ := r.Context().Value(userKey{}).(account.TokenPrincipal)
	actor := audit.Actor{UserID: p.UserID, Email: p.Email, RequestID: middleware.RequestIDFrom(r.Context())}
	body := http.MaxBytesReader(w, r.Body, h.Ingest.MaxArchive())
	im := &ingest.Importer{Ingest: h.Ingest, Agents: h.Agents, Logger: h.Logger}
	res, err := im.Import(r.Context(), acc.Org, actor, tooLargeReader{body})
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) || errors.Is(err, ingest.ErrUploadTooLarge) {
			problem.Write(w, r, h.Catalog, http.StatusRequestEntityTooLarge, "error.ingest.too_large", nil)
			return
		}
		if key, ok := ingest.IsArchiveRefusal(err); ok {
			status := http.StatusUnprocessableEntity
			if key == ingest.KeyQuota {
				status = http.StatusTooManyRequests
			}
			problem.Write(w, r, h.Catalog, status, key, nil)
			return
		}
		if v, ok := account.IsValidation(err); ok {
			problem.WriteValidation(w, r, h.Catalog, v.Key)
			return
		}
		h.internal(w, r, err)
		return
	}
	status := http.StatusCreated
	if res.Ingestion.Duplicate {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(userapi.ArchiveImport{IngestionId: res.Ingestion.ID, Status: string(res.Ingestion.Status),
		ProjectId: res.Ingestion.ProjectID, Agent: res.Sender.Principal.AgentName, Duplicate: res.Ingestion.Duplicate,
		Enrolled: res.Sender.Enrolled})
}
