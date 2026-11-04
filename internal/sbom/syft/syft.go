package syft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"

	"leblanc.io/lotor/internal/sbom"
)

// Propriétés CycloneDX propres au projet (§ 11 de l'architecture).
const (
	PropOrigin     = "lotor:origin"
	PropConfidence = "lotor:confidence"
	PropModel      = "lotor:model"
	// Propriétés des métadonnées du document : statut et modèle de l'enrichissement IA.
	PropEnrichment      = "lotor:enrichment"
	PropEnrichmentModel = "lotor:enrichment-model"
)

// Decode décode un SBOM dont sbom.Precheck a reconnu le format, puis le normalise
// (sbom.Normalize). Les paquets viennent du décodeur de Syft, celui-là même que Grype
// emploie : leurs purl sont ceux que l'analyse retrouvera. CycloneDX est relu pour ce que
// Syft ne garde pas : empreintes, portée, propriétés lotor: et champ evidence ; SPDX pour
// les sommes de contrôle des paquets. Le composant décrit par le document lui-même
// (metadata.component, racine SPDX) n'est pas un composant de l'inventaire.
func Decode(format sbom.Format, data []byte) (sbom.Document, error) {
	s, version, err := decode(format, data)
	if err != nil {
		return sbom.Document{}, err
	}
	extra, err := readExtras(format, data)
	if err != nil {
		return sbom.Document{}, sbom.Reject(sbom.KeyDecodeFailed, "", err)
	}
	raw := sbom.RawDocument{Format: format, SpecVersion: version, Enrichment: extra.enrichment, EnrichmentModel: extra.enrichmentModel}
	if d := s.Artifacts.LinuxDistribution; d != nil && d.ID != "" {
		raw.Distro = &sbom.Distro{ID: d.ID, VersionID: d.VersionID, Name: d.PrettyName}
	}
	for _, p := range s.Artifacts.Packages.Sorted() {
		id := string(p.ID())
		if extra.described[id] {
			continue
		}
		rc := sbom.RawComponent{PURL: p.PURL, Name: p.Name, Version: p.Version, Licenses: licenses(p),
			Locations: locations(p)}
		for _, c := range p.CPEs {
			rc.CPEs = append(rc.CPEs, c.Attributes.String())
		}
		if x, ok := extra.byID[id]; ok {
			x.apply(&rc)
		}
		raw.Components = append(raw.Components, rc)
	}
	return sbom.Normalize(raw), nil
}

// decode passe le document au décodeur Syft de son format ; une panique du décodeur
// devient un refus, pas l'arrêt du worker.
func decode(format sbom.Format, data []byte) (s *syftsbom.SBOM, version string, err error) {
	var dec syftsbom.FormatDecoder
	switch format {
	case sbom.FormatCycloneDX:
		dec = cyclonedxjson.NewFormatDecoder()
	case sbom.FormatSPDX:
		dec = spdxjson.NewFormatDecoder()
	case sbom.FormatSyft:
		dec = syftjson.NewFormatDecoder()
	default:
		return nil, "", sbom.Reject(sbom.KeyUnsupportedFormat, string(format), nil)
	}
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, sbom.Reject(sbom.KeyDecodeFailed, "", fmt.Errorf("panique du décodeur : %v", r))
		}
	}()
	s, _, version, err = dec.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", sbom.Reject(sbom.KeyDecodeFailed, "", err)
	}
	if s == nil {
		return nil, "", sbom.Reject(sbom.KeyDecodeFailed, "", nil)
	}
	return s, version, nil
}

// locations lit les emplacements du paquet : chemin réel, chemin d'accès, couche et
// annotation de preuve (Syft JSON les donne tous ; CycloneDX le chemin et la couche ; SPDX
// aucun).
func locations(p pkg.Package) []sbom.RawLocation {
	var out []sbom.RawLocation
	for _, l := range p.Locations.ToUnorderedSlice() {
		out = append(out, sbom.RawLocation{Path: l.RealPath, AccessPath: l.AccessPath, Layer: l.FileSystemID,
			Evidence: l.Annotations[pkg.EvidenceAnnotationKey]})
	}
	return out
}

func licenses(p pkg.Package) []string {
	var out []string
	for _, l := range p.Licenses.ToSlice() {
		v := l.SPDXExpression
		if v == "" {
			v = l.Value
		}
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// extras est ce que Syft ne garde pas, indexé par identifiant de paquet Syft (bom-ref
// CycloneDX, SPDXID sans son préfixe).
type extras struct {
	byID      map[string]extra
	described map[string]bool
	// enrichment et enrichmentModel : propriétés lotor: des métadonnées (CycloneDX).
	enrichment, enrichmentModel string
}

type extra struct {
	hashes     []sbom.RawHash
	origin     string
	confidence string
	model      string
	evidence   json.RawMessage
	scope      string
}

func (x extra) apply(rc *sbom.RawComponent) {
	rc.Hashes, rc.Origin, rc.Confidence, rc.Model, rc.Evidence, rc.Scope =
		x.hashes, x.origin, x.confidence, x.model, x.evidence, x.scope
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	BOMRef     string          `json:"bom-ref"`
	Scope      string          `json:"scope"`
	Hashes     []cdxHash       `json:"hashes"`
	Properties []cdxProperty   `json:"properties"`
	Evidence   json.RawMessage `json:"evidence"`
	Components []cdxComponent  `json:"components"`
}

type cdxDocument struct {
	Metadata *struct {
		Component  *cdxComponent `json:"component"`
		Properties []cdxProperty `json:"properties"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

type spdxDocument struct {
	DocumentDescribes []string `json:"documentDescribes"`
	Packages          []struct {
		SPDXID    string `json:"SPDXID"`
		Checksums []struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"checksumValue"`
		} `json:"checksums"`
	} `json:"packages"`
}

func readExtras(format sbom.Format, data []byte) (extras, error) {
	x := extras{byID: map[string]extra{}, described: map[string]bool{}}
	switch format {
	case sbom.FormatCycloneDX:
		var d cdxDocument
		if err := json.Unmarshal(data, &d); err != nil {
			return x, err
		}
		if d.Metadata != nil && d.Metadata.Component != nil && d.Metadata.Component.BOMRef != "" {
			x.described[d.Metadata.Component.BOMRef] = true
		}
		if d.Metadata != nil {
			for _, p := range d.Metadata.Properties {
				switch p.Name {
				case PropEnrichment:
					x.enrichment = p.Value
				case PropEnrichmentModel:
					x.enrichmentModel = p.Value
				}
			}
		}
		x.addCycloneDX(d.Components)
	case sbom.FormatSPDX:
		var d spdxDocument
		if err := json.Unmarshal(data, &d); err != nil {
			return x, err
		}
		for _, p := range d.Packages {
			var e extra
			for _, c := range p.Checksums {
				e.hashes = append(e.hashes, sbom.RawHash{Algorithm: c.Algorithm, Value: c.Value})
			}
			if len(e.hashes) > 0 {
				x.byID[strings.TrimPrefix(p.SPDXID, "SPDXRef-")] = e
			}
		}
	}
	return x, nil
}

func (x extras) addCycloneDX(cs []cdxComponent) {
	for _, c := range cs {
		if c.BOMRef != "" {
			e := extra{scope: c.Scope, evidence: c.Evidence}
			for _, h := range c.Hashes {
				e.hashes = append(e.hashes, sbom.RawHash{Algorithm: h.Alg, Value: h.Content})
			}
			for _, p := range c.Properties {
				switch p.Name {
				case PropOrigin:
					e.origin = p.Value
				case PropConfidence:
					e.confidence = p.Value
				case PropModel:
					e.model = p.Value
				}
			}
			x.byID[c.BOMRef] = e
		}
		x.addCycloneDX(c.Components)
	}
}

// Target est un format de réencodage proposé au téléchargement.
type Target string

// Formats de réencodage.
const (
	TargetCycloneDX16 Target = "cyclonedx-1.6"
	TargetSPDX23      Target = "spdx-2.3"
)

// Targets liste les formats de réencodage.
func Targets() []Target { return []Target{TargetCycloneDX16, TargetSPDX23} }

// ParseTarget lit un format de réencodage.
func ParseTarget(s string) (Target, bool) {
	t := Target(s)
	return t, slices.Contains(Targets(), t)
}

// Encode réencode le SBOM d'origine data (format format) en CycloneDX 1.6 ou SPDX 2.3, à
// partir de son décodage par Syft et par ses modèles d'encodage : distribution, CPE,
// licences et relations sont repris. Les propriétés lotor: et le champ evidence, que
// Syft ne lit pas, ne sont pas reportés ; le SBOM d'origine reste téléchargeable tel quel.
//
// cdxLicenses (schema.Validator.CycloneDXLicenseIDs("1.6")) liste les identifiants SPDX
// qu'admet le schéma de CycloneDX 1.6 : un identifiant plus récent est écrit en nom de
// licence, sans quoi le document ne serait pas valide pour son format. nil : aucune
// réécriture.
func Encode(w io.Writer, format sbom.Format, data []byte, target Target, cdxLicenses map[string]bool) error {
	if _, ok := ParseTarget(string(target)); !ok {
		return fmt.Errorf("syft: format de réencodage inconnu %q", target)
	}
	s, _, err := decode(format, data)
	if err != nil {
		return err
	}
	if target == TargetSPDX23 {
		enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: "2.3"})
		if err != nil {
			return fmt.Errorf("syft: encodeur %s : %w", target, err)
		}
		if err := enc.Encode(w, *s); err != nil {
			return fmt.Errorf("syft: encodage %s : %w", target, err)
		}
		return nil
	}
	bom := cyclonedxhelpers.ToFormatModel(*s)
	if cdxLicenses != nil && bom.Components != nil {
		licensesAsNames(*bom.Components, cdxLicenses)
	}
	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("syft: encodage %s : %w", target, err)
	}
	return nil
}

// licensesAsNames écrit en nom toute licence dont l'identifiant n'est pas admis.
func licensesAsNames(cs []cyclonedx.Component, allowed map[string]bool) {
	for i := range cs {
		if ls := cs[i].Licenses; ls != nil {
			for j := range *ls {
				if l := (*ls)[j].License; l != nil && l.ID != "" && !allowed[l.ID] {
					l.Name, l.ID = l.ID, ""
				}
			}
		}
		if cs[i].Components != nil {
			licensesAsNames(*cs[i].Components, allowed)
		}
	}
}
