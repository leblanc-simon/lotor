package repoagent

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"leblanc.io/lotor/internal/offline"
)

// ArchiveWriter écrit, en plus de l'envoi au serveur, une archive hors ligne par SBOM
// envoyé (T23, ADR 0060) : copie transportable vers un autre serveur ou conservée pour un
// import ultérieur. L'agent dépôt n'a pas de mode « hors ligne seul » : la liste des
// dépôts et leur dernier commit viennent du serveur.
type ArchiveWriter struct {
	Dir      string
	publicID string
	key      [32]byte
	now      func() time.Time
}

// NewArchiveWriter prépare l'écriture des archives dans dir (absolu), signées avec le
// jeton d'agent token.
func NewArchiveWriter(dir, token string) (*ArchiveWriter, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("repoagent: offline.dir : chemin absolu attendu")
	}
	pub, key, err := offline.ParseToken("agt", token)
	if err != nil {
		return nil, fmt.Errorf("repoagent: jeton d'agent illisible : %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("repoagent: offline.dir : %w", err)
	}
	return &ArchiveWriter{Dir: dir, publicID: pub, key: key, now: time.Now}, nil
}

// Write écrit l'archive d'un envoi ; écriture atomique (fichier caché, puis renommage).
func (w *ArchiveWriter) Write(u Upload, slug string) (string, error) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(u.SBOM); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	pid, err := uuid.Parse(u.ProjectID)
	if err != nil {
		return "", fmt.Errorf("repoagent: projet %q : %w", u.ProjectID, err)
	}
	now := w.now().UTC()
	m := offline.Manifest{AgentToken: w.publicID, CreatedAt: now, Context: offline.Context{ProjectID: pid,
		Ref: offline.Ref{Kind: string(u.Ref.Kind), Name: u.Ref.Name}, Commit: u.Commit, AgentVersion: u.AgentVersion,
		ScannedAt: u.ScannedAt}}
	var buf bytes.Buffer
	if err := offline.Write(&buf, m, offline.Keys{Agent: w.key}, gz.Bytes()); err != nil {
		return "", err
	}
	path := filepath.Join(w.Dir, offline.FileName(slug, now, u.Commit))
	tmp, err := os.CreateTemp(w.Dir, ".archive-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return "", err
	}
	return path, os.Rename(tmp.Name(), path)
}

// archive écrit l'archive d'un envoi réussi ; un échec est journalisé sans faire échouer
// l'analyse.
func (a *Agent) archive(ctx context.Context, t tracked, u Upload) {
	if a.opts.Archive == nil {
		return
	}
	path, err := a.opts.Archive.Write(u, t.project.Slug)
	if err != nil {
		a.log.ErrorContext(ctx, "archive hors ligne en échec", "project", t.project.Slug, "err", err.Error())
		return
	}
	a.log.InfoContext(ctx, "archive hors ligne écrite", "file", path)
}
