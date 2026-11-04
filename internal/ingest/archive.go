package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"

	"leblanc.io/lotor/internal/agent"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/offline"
	"leblanc.io/lotor/internal/project"
	"leblanc.io/lotor/internal/tenant"
)

// Importer importe les archives hors ligne (T23, ADR 0059) : lecture bornée, émetteur
// authentifié par agent.Service.ArchiveSender (code de l'archive, organisation du jeton,
// inscription hors ligne), puis réception ordinaire (Receive) au nom de l'agent émetteur,
// avec la date de scan de l'archive : mêmes contrôles qu'un envoi réseau. Une archive
// importée deux fois renvoie la même ingestion.
type Importer struct {
	Ingest *Service
	Agents *agent.Service
	Logger *slog.Logger
}

// ImportResult est le résultat d'un import.
type ImportResult struct {
	Ingestion Ingestion
	Sender    agent.ArchiveSender
}

// archiveOverhead s'ajoute à la taille admise d'un SBOM pour borner une archive entière.
const archiveOverhead = 1 << 20

// MaxArchive renvoie la taille admise d'une archive.
func (s *Service) MaxArchive() int64 { return s.limits.MaxUpload + archiveOverhead }

// Import lit et importe une archive dans l'organisation org ; actor est l'auteur de
// l'import (journal d'une inscription hors ligne).
func (im *Importer) Import(ctx context.Context, org tenant.OrgID, actor audit.Actor, r io.Reader) (ImportResult, error) {
	a, err := im.read(r)
	if err != nil {
		return ImportResult{}, err
	}
	return im.importArchive(ctx, org, actor, a)
}

// ImportAny importe une archive dans l'organisation qu'elle désigne (répertoire
// surveillé) : celle de son jeton d'agent, ou du jeton d'inscription de son inscription.
func (im *Importer) ImportAny(ctx context.Context, actor audit.Actor, r io.Reader) (ImportResult, tenant.OrgID, error) {
	a, err := im.read(r)
	if err != nil {
		return ImportResult{}, tenant.OrgID{}, err
	}
	org, err := im.Agents.ArchiveOrg(ctx, a)
	if err != nil {
		return ImportResult{}, tenant.OrgID{}, err
	}
	res, err := im.importArchive(ctx, org, actor, a)
	return res, org, err
}

func (im *Importer) read(r io.Reader) (offline.Archive, error) {
	a, err := offline.Read(io.LimitReader(r, im.Ingest.MaxArchive()+1), im.Ingest.limits.MaxUpload)
	if err != nil {
		if errors.Is(err, ErrUploadTooLarge) {
			return offline.Archive{}, ErrUploadTooLarge
		}
		return offline.Archive{}, &agent.ArchiveError{Key: agent.KeyArchiveInvalid}
	}
	return a, nil
}

func (im *Importer) importArchive(ctx context.Context, org tenant.OrgID, actor audit.Actor, a offline.Archive) (ImportResult, error) {
	sender, err := im.Agents.ArchiveSender(ctx, org, a, actor)
	if err != nil {
		return ImportResult{}, err
	}
	m := a.Manifest.Context
	digest := a.Digest()
	c := Context{ProjectID: sender.ProjectID, RefKind: project.RefKind(m.Ref.Kind), RefName: m.Ref.Name, Commit: m.Commit,
		AgentVersion: m.AgentVersion, ScannedAt: m.ScannedAt, Archive: &digest}
	if sender.Enrolled && c.RefName == "" {
		// L'agent inscrit hors ligne ne connaît pas encore sa référence d'hôte : celle de
		// son projet, que l'inscription vient de créer ou de rattacher.
		host, err := project.NormalizeHostRef(a.Manifest.Enrollment.Hostname)
		if err != nil {
			return ImportResult{}, err
		}
		c.RefKind, c.RefName = project.RefHost, host
	}
	if err := im.Ingest.Authorize(ctx, org, sender.Principal.AgentID, c); err != nil {
		return ImportResult{}, err
	}
	in, err := im.Ingest.Receive(ctx, org, sender.Principal.AgentID, c, bytes.NewReader(a.SBOM))
	if err != nil {
		return ImportResult{}, err
	}
	if h := m.Host; h != nil && sender.Principal.AgentKind == agent.KindHost && !in.Duplicate {
		hc := agent.HostContext{Hostname: h.Hostname, OSID: h.OSID, OSVersion: h.OSVersion, OSName: h.OSName, Kernel: h.Kernel,
			Arch: h.Arch, ScanDuration: h.ScanDurationMs}
		if err := hc.Validate(); err == nil {
			if err := im.Agents.RecordHost(ctx, sender.Principal, hc); err != nil {
				im.Logger.WarnContext(ctx, "contexte d'hôte d'une archive ignoré", "err", err)
			}
		}
	}
	return ImportResult{Ingestion: in, Sender: sender}, nil
}

// IsArchiveRefusal dit si err est un refus d'archive à montrer (clé traduisible) plutôt
// qu'une erreur interne.
func IsArchiveRefusal(err error) (string, bool) {
	var ae *agent.ArchiveError
	var au *agent.AuthError
	var ce *agent.ConflictError
	switch {
	case errors.As(err, &ae):
		return ae.Key, true
	case errors.As(err, &au):
		return au.Key, true
	case errors.As(err, &ce):
		return ce.Key, true
	case errors.Is(err, ErrRefUnknown):
		return KeyRefUnknown, true
	case errors.Is(err, ErrUploadTooLarge):
		return "error.ingest.too_large", true
	case errors.Is(err, ErrQuota):
		return KeyQuota, true
	}
	return "", false
}
