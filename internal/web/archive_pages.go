package web

import (
	"errors"
	"net/http"
	"strings"

	"leblanc.io/lotor/internal/ingest"
	"leblanc.io/lotor/internal/render"
)

// Import des archives hors ligne (T23, ADR 0059) : Agents › Importer des archives. Le
// fichier est lu en flux (uploadGate : jeton CSRF en première partie), borné à la taille
// admise d'une archive, puis importé au nom de l'agent émetteur, que l'archive
// authentifie elle-même.

type archiveImportView struct {
	render.Page
	Base  string
	Error formError
	// Result : l'archive importée, sa réception et son projet.
	Result *archiveResult
}

type archiveResult struct {
	Duplicate  bool
	Enrolled   bool
	AgentName  string
	StatusKey  string
	ProjectRef string
	Snapshots  string
}

// isArchiveImport désigne l'envoi du formulaire d'import : /o/{slug}/agents/import.
func isArchiveImport(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "o" && parts[1] != "" && parts[2] == "agents" &&
		parts[3] == "import"
}

func (id *identity) importer() *ingest.Importer {
	return &ingest.Importer{Ingest: id.Ingest, Agents: id.Agents, Logger: id.logger}
}

func (id *identity) archiveImportPage(w http.ResponseWriter, r *http.Request) {
	id.renderArchiveImport(w, r, http.StatusOK, nil, formError{})
}

func (id *identity) renderArchiveImport(w http.ResponseWriter, r *http.Request, status int, res *archiveResult, fe formError) {
	acc := access(r)
	view := &archiveImportView{Page: render.Page{TitleKey: "archive_import.title", Nav: orgNav(acc, "agents")},
		Base: orgBase(acc), Error: fe, Result: res}
	id.rd.Render(w, r, status, "agents/import", view)
}

// importArchive importe l'archive envoyée.
func (id *identity) importArchive(w http.ResponseWriter, r *http.Request) {
	mr := uploadReader(r)
	if mr == nil {
		id.renderArchiveImport(w, r, http.StatusBadRequest, nil, formError{Key: "archive_import.missing", Field: "archive"})
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "archive" || part.FileName() == "" {
		id.renderArchiveImport(w, r, http.StatusBadRequest, nil, formError{Key: "archive_import.missing", Field: "archive"})
		return
	}
	acc := access(r)
	res, err := id.importer().Import(r.Context(), acc.Org, id.actor(r), tooLargePart{part})
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) || errors.Is(err, ingest.ErrUploadTooLarge) {
			id.renderArchiveImport(w, r, http.StatusRequestEntityTooLarge, nil, formError{Key: "error.ingest.too_large.text", Field: "archive"})
			return
		}
		if key, ok := ingest.IsArchiveRefusal(err); ok {
			id.renderArchiveImport(w, r, http.StatusUnprocessableEntity, nil, formError{Key: key + ".text", Field: "archive"})
			return
		}
		if fe, ok := validationOf(err); ok {
			id.renderArchiveImport(w, r, http.StatusUnprocessableEntity, nil, fe)
			return
		}
		id.serverError(w, r, err)
		return
	}
	out := &archiveResult{Duplicate: res.Ingestion.Duplicate, Enrolled: res.Sender.Enrolled, AgentName: res.Sender.Principal.AgentName,
		StatusKey: "ingestion_status." + string(res.Ingestion.Status)}
	// Le projet n'est montré qu'à qui le voit (équipes du compte).
	if p, err := id.Projects.GetByID(r.Context(), acc.Org, acc.Visibility(), res.Ingestion.ProjectID); err == nil {
		out.ProjectRef, out.Snapshots = p.Name, orgBase(acc)+"/projects/"+p.Slug+"/snapshots"
	}
	id.renderArchiveImport(w, r, http.StatusOK, out, formError{})
}

// tooLargePart signale par ingest.ErrUploadTooLarge un corps qui dépasse la borne de
// uploadGate pendant la lecture de l'archive.
type tooLargePart struct {
	r interface{ Read([]byte) (int, error) }
}

func (t tooLargePart) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return n, ingest.ErrUploadTooLarge
	}
	return n, err
}
