package hostagent

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"

	// Syft lit les bases RPM récentes (SQLite) par database/sql : le pilote pur Go doit
	// être enregistré dans tout binaire qui catalogue.
	_ "modernc.org/sqlite"

	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// Inventory est le résultat d'un scan : le SBOM (Syft JSON) et son empreinte
// d'inventaire, calculée comme le serveur la calcule à la réception.
type Inventory struct {
	SBOM        []byte
	Fingerprint [32]byte
	Components  int
	Started     time.Time
	Duration    time.Duration
}

// Scanner inventorie l'hôte.
type Scanner interface {
	Scan(ctx context.Context) (Inventory, error)
}

// SyftScanner inventorie un système installé avec Syft : catalogueurs des systèmes
// installés (ceux d'une image : bases dpkg, rpm, apk, paquets Python, Ruby, Node.js,
// archives Java, binaires Go et Rust installés), sans catalogage de fichiers (ni
// empreintes, ni contenus : le coût d'un scan reste celui des bases de paquets).
type SyftScanner struct {
	Root     string
	Hostname string
	// Exclude complète DefaultExclusions (chemins absolus relatifs à Root).
	Exclude []string
	// Parallelism borne les catalogueurs exécutés en même temps.
	Parallelism int
	// Version est la version de l'agent, inscrite comme outil dans le SBOM.
	Version string
	// Mounts remplace les montages du système (tests) ; nil : /proc/self/mountinfo.
	Mounts func() []mount
}

// Scan inventorie Root et calcule l'empreinte d'inventaire du SBOM produit.
func (s SyftScanner) Scan(ctx context.Context) (Inventory, error) {
	start := time.Now()
	mounts := s.Mounts
	if mounts == nil {
		mounts = systemMounts
	}
	// Index compact au lieu de la source « répertoire » de Syft, qui lit l'en-tête de
	// chaque fichier de l'hôte (ADR 0055).
	idx, err := buildIndex(ctx, s.Root, s.exclusions(mounts()))
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: index de %s : %w", s.Root, err)
	}
	inv, err := s.catalog(ctx, newIndexSource(idx, s.Hostname))
	if err != nil {
		return Inventory{}, err
	}
	inv.Started, inv.Duration = start.UTC(), time.Since(start)
	return inv, nil
}

// exclusions renvoie les motifs écartés du scan : exclusions par défaut et configurées,
// montages à ne pas parcourir.
func (s SyftScanner) exclusions(mounts []mount) []string {
	return exclusionPatterns(append(append([]string{}, DefaultExclusions...), s.Exclude...), skippedMounts(mounts, s.Root))
}

// catalog fait inventorier src par les catalogueurs d'un système installé, sans
// catalogage de fichiers, et calcule l'empreinte du SBOM produit.
func (s SyftScanner) catalog(ctx context.Context, src source.Source) (Inventory, error) {
	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("lotor-host-agent", s.Version).
		WithParallelism(max(s.Parallelism, 1)).
		WithoutFiles().
		WithPackagesConfig(offlineCatalogers()).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(pkgcataloging.ImageTag))
	doc, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: scan : %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Inventory{}, fmt.Errorf("hostagent: scan interrompu : %w", err)
	}
	var buf bytes.Buffer
	if err := syftjson.NewFormatEncoder().Encode(&buf, *doc); err != nil {
		return Inventory{}, fmt.Errorf("hostagent: encodage du SBOM : %w", err)
	}
	return fingerprint(buf.Bytes())
}

// fingerprint décode le SBOM comme le serveur (même adaptateur, même normalisation) et en
// calcule l'empreinte d'inventaire : deux scans sans changement de paquets donnent la
// même empreinte, quels que soient horodatages et identifiants du document.
func fingerprint(data []byte) (Inventory, error) {
	doc, err := sbomsyft.Decode(sbom.FormatSyft, data)
	if err != nil {
		return Inventory{}, fmt.Errorf("hostagent: relecture du SBOM : %w", err)
	}
	return Inventory{SBOM: data, Fingerprint: sbom.Fingerprint(doc.Components), Components: len(doc.Components)}, nil
}
