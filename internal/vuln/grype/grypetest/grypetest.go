// Package grypetest construit pour les tests une vraie archive de base Grype v6, valide
// (schéma et date de construction), vide ou remplie par le test, sans la base complète ni
// réseau. Il vit sous vuln/grype : seul l'adaptateur importe Grype.
package grypetest

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
)

// TinyArchive écrit dans dir une archive tar.gz d'une base Grype v6 vide et renvoie son
// chemin.
func TinyArchive(dir string) (string, error) {
	return Archive(dir, nil)
}

// Archive écrit dans dir une archive tar.gz d'une base Grype v6 remplie par fill (nil :
// base vide) et renvoie son chemin.
func Archive(dir string, fill func(v6.ReadWriter) error) (string, error) {
	work, err := os.MkdirTemp(dir, "grypetest-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	w, err := v6.NewWriter(v6.Config{DBDirPath: work})
	if err != nil {
		return "", fmt.Errorf("grypetest: %w", err)
	}
	if fill != nil {
		if err := fill(w); err != nil {
			_ = w.Close()
			return "", fmt.Errorf("grypetest: %w", err)
		}
	}
	if err := w.SetDBMetadata(); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("grypetest: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("grypetest: %w", err)
	}
	db, err := os.ReadFile(filepath.Join(work, v6.VulnerabilityDBFileName))
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "vulnerability-db-*.tar.gz")
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = tw.WriteHeader(&tar.Header{Name: v6.VulnerabilityDBFileName, Mode: 0o644, Size: int64(len(db)), ModTime: time.Now()})
	if err == nil {
		_, err = tw.Write(db)
	}
	for _, c := range []interface{ Close() error }{tw, gz, f} {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("grypetest: %w", err)
	}
	return f.Name(), nil
}
