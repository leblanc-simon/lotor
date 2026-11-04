package sbom

import (
	"encoding/json"
	"testing"
)

func fingerprintOf(raw ...RawComponent) [32]byte {
	return Fingerprint(Normalize(RawDocument{Components: raw}).Components)
}

func TestFingerprintIgnoresOrderAndDocumentMetadata(t *testing.T) {
	a := RawComponent{PURL: "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12", Name: "libc6"}
	b := RawComponent{PURL: "pkg:deb/debian/openssl@3.0.14?distro=debian-12&arch=amd64", Name: "openssl"}
	if fingerprintOf(a, b) != fingerprintOf(b, a) {
		t.Error("l'empreinte dépend de l'ordre des composants")
	}
	// Les CPE et empreintes de fichier sont portés par le composant, pas par l'ensemble.
	b2 := b
	b2.CPEs = []string{"cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"}
	if fingerprintOf(a, b) != fingerprintOf(a, b2) {
		t.Error("l'empreinte dépend des CPE")
	}
}

func TestFingerprintChangesWithInventory(t *testing.T) {
	base := RawComponent{PURL: "pkg:npm/jquery@3.4.1", Name: "jquery"}
	ref := fingerprintOf(base)
	variants := map[string]func(*RawComponent){
		"version":     func(c *RawComponent) { c.PURL = "pkg:npm/jquery@3.5.0" },
		"qualifier":   func(c *RawComponent) { c.PURL = "pkg:npm/jquery@3.4.1?arch=x" },
		"origine":     func(c *RawComponent) { c.Origin = "ia" },
		"confiance":   func(c *RawComponent) { c.Confidence = "0.5" },
		"modèle":      func(c *RawComponent) { c.Model = "m" },
		"portée":      func(c *RawComponent) { c.Scope = "required" },
		"licence":     func(c *RawComponent) { c.Licenses = []string{"MIT"} },
		"preuve":      func(c *RawComponent) { c.Evidence = json.RawMessage(`{"a":1}`) },
		"faible":      func(c *RawComponent) { c.PURL = "" },
		"emplacement": func(c *RawComponent) { c.Locations = []RawLocation{{Path: "/app/package-lock.json"}} },
		"accès": func(c *RawComponent) {
			c.Locations = []RawLocation{{Path: "/app/package-lock.json", AccessPath: "/srv/package-lock.json"}}
		},
		"couche": func(c *RawComponent) {
			c.Locations = []RawLocation{{Path: "/app/package-lock.json", Layer: "sha256:ab"}}
		},
		"secondaire": func(c *RawComponent) {
			c.Locations = []RawLocation{{Path: "/app/package-lock.json", Evidence: "supporting"}}
		},
	}
	for name, change := range variants {
		c := base
		change(&c)
		if fingerprintOf(c) == ref {
			t.Errorf("%s : empreinte inchangée", name)
		}
	}
	if fingerprintOf() == ref || fingerprintOf() != Fingerprint(nil) {
		t.Error("inventaire vide")
	}
}

func TestFingerprintUnsortedInput(t *testing.T) {
	cs := Normalize(RawDocument{Components: []RawComponent{{PURL: "pkg:npm/a@1"}, {PURL: "pkg:npm/b@1"}}}).Components
	rev := []Component{cs[1], cs[0]}
	if Fingerprint(cs) != Fingerprint(rev) {
		t.Error("Fingerprint doit trier lui-même")
	}
	if rev[0].PURL != "pkg:npm/b@1" {
		t.Error("Fingerprint a modifié la tranche de l'appelant")
	}
}

func TestFingerprintEvidenceKeyOrder(t *testing.T) {
	a := RawComponent{PURL: "pkg:npm/a@1", Evidence: json.RawMessage(`{"x":1,"y":[1,2]}`)}
	b := RawComponent{PURL: "pkg:npm/a@1", Evidence: json.RawMessage(`{ "y":[1,2], "x":1 }`)}
	if fingerprintOf(a) != fingerprintOf(b) {
		t.Error("l'ordre des clés de la preuve change l'empreinte")
	}
}
