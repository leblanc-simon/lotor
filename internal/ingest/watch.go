package ingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"leblanc.io/lotor/internal/account"
	"leblanc.io/lotor/internal/audit"
	"leblanc.io/lotor/internal/offline"
)

// Watcher importe les archives déposées dans un répertoire (offline.watch_dir, T23) : à
// chaque passage, chaque fichier *.lotor est d'abord renommé (.import-…, ce qui le réserve :
// deux instances qui surveillent le même répertoire ne l'importent pas deux fois), importé
// dans l'organisation qu'il désigne, puis rangé dans done/ ou failed/ ; un refus laisse
// à côté de l'archive un fichier .error qui en donne la clé (jamais de secret). Les fichiers
// cachés (écritures en cours) sont ignorés.
type Watcher struct {
	Importer *Importer
	Dir      string
	Interval time.Duration
}

// Sous-répertoires du répertoire surveillé.
const (
	watchDone   = "done"
	watchFailed = "failed"
	watchClaim  = ".import-"
)

// Run surveille le répertoire jusqu'à l'annulation de ctx.
func (w *Watcher) Run(ctx context.Context) error {
	for _, d := range []string{watchDone, watchFailed} {
		if err := os.MkdirAll(filepath.Join(w.Dir, d), 0o700); err != nil {
			return fmt.Errorf("ingest: répertoire surveillé : %w", err)
		}
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		if _, err := w.Scan(ctx); err != nil && ctx.Err() == nil {
			w.Importer.Logger.ErrorContext(ctx, "répertoire surveillé illisible", "dir", w.Dir, "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// WatchReport résume un passage.
type WatchReport struct {
	Imported, Duplicates, Failed int
}

// Scan fait un passage sur le répertoire.
func (w *Watcher) Scan(ctx context.Context) (WatchReport, error) {
	var rep WatchReport
	entries, err := os.ReadDir(w.Dir)
	if err != nil {
		return rep, err
	}
	for _, e := range entries {
		name := e.Name()
		if ctx.Err() != nil {
			return rep, nil
		}
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, offline.Extension) {
			continue
		}
		claimed := filepath.Join(w.Dir, watchClaim+name)
		if err := os.Rename(filepath.Join(w.Dir, name), claimed); err != nil {
			continue // pris par une autre instance, ou disparu
		}
		res, key, err := w.importFile(ctx, claimed)
		dest := watchDone
		switch {
		case err != nil && key == "":
			// Erreur interne : l'archive reprend sa place, pour un passage suivant.
			w.Importer.Logger.ErrorContext(ctx, "import d'une archive en échec", "file", name, "err", err.Error())
			_ = os.Rename(claimed, filepath.Join(w.Dir, name))
			continue
		case err != nil:
			dest = watchFailed
			rep.Failed++
			w.Importer.Logger.WarnContext(ctx, "archive refusée", "file", name, "key", key)
			_ = os.WriteFile(filepath.Join(w.Dir, watchFailed, name+".error"), []byte(key+"\n"), 0o600)
		case res.Ingestion.Duplicate:
			rep.Duplicates++
		default:
			rep.Imported++
			w.Importer.Logger.InfoContext(ctx, "archive importée", "file", name, "ingestion", res.Ingestion.ID.String(),
				"agent", res.Sender.Principal.AgentName, "enrolled", res.Sender.Enrolled)
		}
		if err := os.Rename(claimed, filepath.Join(w.Dir, dest, name)); err != nil {
			w.Importer.Logger.ErrorContext(ctx, "archive non rangée", "file", name, "err", err.Error())
		}
	}
	return rep, nil
}

func (w *Watcher) importFile(ctx context.Context, path string) (ImportResult, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return ImportResult{}, "", err
	}
	defer f.Close()
	res, _, err := w.Importer.ImportAny(ctx, audit.Actor{Email: "offline.watch_dir"}, f)
	if err != nil {
		if key, ok := IsArchiveRefusal(err); ok {
			return res, key, err
		}
		if v, ok := account.IsValidation(err); ok {
			return res, v.Key, err
		}
	}
	return res, "", err
}
