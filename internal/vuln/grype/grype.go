package grype

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/clio"
	grypelib "github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"

	"leblanc.io/lotor/internal/vuln"
)

// Engine installe et ouvre les bases Grype (schéma v6).
type Engine struct {
	id clio.Identification
}

// NewEngine renvoie un Engine.
func NewEngine() *Engine {
	return &Engine{id: clio.Identification{Name: "lotor-server"}}
}

var _ vuln.Engine = (*Engine)(nil)

// curator gère la base de dir. L'âge n'est pas un motif de refus (le serveur alerte
// au-delà de vulndb.max_age) ; la somme de la base décompressée est vérifiée à chaque
// ouverture. Le client de distribution n'est jamais appelé : Import reçoit un fichier.
func (e *Engine) curator(dir string) (v6.Curator, error) {
	client, err := v6dist.NewClient(v6dist.DefaultConfig())
	if err != nil {
		return nil, err
	}
	c := v6inst.DefaultConfig(e.id)
	c.DBRootDir = dir
	c.ValidateAge = false
	c.ValidateChecksum = true
	c.UpdateCheckMaxFrequency = 0
	return v6inst.NewCurator(c, client)
}

// Install décompresse l'archive (tar.zst ou autre format accepté par Grype) dans dir,
// l'hydrate, puis l'ouvre une fois pour la valider. Grype ne prend pas de contexte : une
// installation commencée va à son terme.
func (e *Engine) Install(ctx context.Context, archivePath, dir string) (vuln.Description, error) {
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		return vuln.Description{}, fmt.Errorf("grype: répertoire d'installation %s déjà présent", dir)
	}
	abs, err := filepath.Abs(archivePath)
	if err != nil {
		return vuln.Description{}, err
	}
	if err := ctx.Err(); err != nil {
		return vuln.Description{}, err
	}
	c, err := e.curator(dir)
	if err != nil {
		return vuln.Description{}, fmt.Errorf("grype: installation : %w", err)
	}
	if err := c.Import(abs); err != nil {
		_ = os.RemoveAll(dir)
		return vuln.Description{}, fmt.Errorf("grype: archive refusée : %w", err)
	}
	d, err := e.Open(ctx, dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return vuln.Description{}, err
	}
	desc := d.Description()
	return desc, d.Close()
}

// Open ouvre la base installée dans dir.
func (e *Engine) Open(_ context.Context, dir string) (vuln.Database, error) {
	c, err := e.curator(dir)
	if err != nil {
		return nil, fmt.Errorf("grype: ouverture : %w", err)
	}
	status := c.Status()
	if status.Error != nil {
		return nil, fmt.Errorf("grype: base invalide dans %s : %w", dir, status.Error)
	}
	if status.Built.IsZero() || status.SchemaVersion == "" {
		return nil, fmt.Errorf("grype: base sans date ni schéma dans %s", dir)
	}
	rdr, err := c.Reader()
	if err != nil {
		return nil, fmt.Errorf("grype: ouverture de %s : %w", dir, err)
	}
	return &database{
		provider: v6.NewVulnerabilityProvider(rdr),
		desc:     vuln.Description{Built: status.Built.UTC(), Schema: status.SchemaVersion},
	}, nil
}

type database struct {
	provider vulnerability.Provider
	desc     vuln.Description
}

func (d *database) Description() vuln.Description { return d.desc }

func (d *database) Close() error { return d.provider.Close() }

// matcherConfig reprend les réglages par défaut de la commande grype : CPE seulement pour
// les paquets sans correspondance d'écosystème (stock), époques manquantes à zéro pour
// dpkg et déduites pour rpm, aucune recherche externe (Maven Central).
func matcherConfig() matcher.Config {
	return matcher.Config{
		Stock: stock.MatcherConfig{UseCPEs: true},
		Dpkg:  dpkg.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyZero},
		Rpm:   rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
	}
}

// Match décode le SBOM d'origine par les décodeurs de Syft (distribution, CPE, paquets
// sources intacts) et le confronte à la base. Les identifiants sont ramenés au CVE quand
// la source n'en cite qu'un (comme grype --by-cve).
func (d *database) Match(ctx context.Context, blob []byte) ([]vuln.Match, map[string]vuln.Vulnerability, error) {
	pkgs, pctx, _, err := pkg.ProvideFromReader(bytes.NewReader(blob), pkg.ProviderConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("grype: décodage du SBOM : %w", err)
	}
	signedKernelUpstreams(pkgs)
	// VulnerabilityMatcher garde un état par appel : un par correspondance.
	m := grypelib.VulnerabilityMatcher{
		VulnerabilityProvider: d.provider,
		Matchers:              matcher.NewDefaultMatchers(matcherConfig()),
		NormalizeByCVE:        true,
	}
	found, _, err := m.FindMatchesContext(ctx, pkgs, pctx)
	if err != nil {
		return nil, nil, fmt.Errorf("grype: correspondance : %w", err)
	}
	return convert(dropOwnedCPEDuplicates(found.Sorted()), d.cveMetadata)
}

// cveMetadata renvoie la fiche NVD d'un CVE, ou nil si la base n'en a pas.
func (d *database) cveMetadata(id string) *vulnerability.Metadata {
	//lint:ignore SA1019 seule lecture exacte d'une fiche par identifiant et source ; Grype s'en sert lui-même pour NormalizeByCVE.
	md, err := d.provider.VulnerabilityMetadata(vulnerability.Reference{ID: id, Namespace: nvdNamespace})
	if err != nil || md == nil || (len(md.Cvss) == 0 && md.Description == "") {
		return nil
	}
	return md
}
