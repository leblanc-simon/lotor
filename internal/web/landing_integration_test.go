//go:build integration

package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var imgSources = regexp.MustCompile(`(?:src|srcset)="(/static/[^"]+\.webp)"`)

// TestLandingForAnonymousVisitors (ADR 0054) : « / » présente lotor au visiteur anonyme,
// dans sa langue, avec un lien vers la connexion et des captures servies par l'instance ;
// rien n'y vient de la base. Un compte connecté garde son accueil (redirection vers son
// organisation, couverte par les tests de l'administration).
func TestLandingForAnonymousVisitors(t *testing.T) {
	t.Parallel()
	a := newApp(t)
	a.user("admin@example.org", true)
	b := a.browser()

	cases := map[string]struct{ path, heading, login string }{
		"français": {"/", "Une CVE tombe.", "Se connecter"},
		"anglais":  {"/?lang=en", "A CVE drops.", "Sign in"},
	}
	for name, c := range cases {
		p := b.get(c.path)
		if p.status != http.StatusOK {
			t.Fatalf("%s : %d %q", name, p.status, p.location)
		}
		body := unescape(p.body)
		if !strings.Contains(body, c.heading) || !strings.Contains(p.body, `href="/login"`) || !strings.Contains(body, c.login) {
			t.Errorf("%s : titre ou lien de connexion absent", name)
		}
		if strings.Contains(p.body, "admin@example.org") || strings.Contains(p.body, `action="/logout"`) {
			t.Errorf("%s : la page anonyme montre un compte", name)
		}
		assertScreen(t, "présentation "+name, p)
	}

	// Les captures existent et sont servies avec leur type.
	srcs := imgSources.FindAllStringSubmatch(b.get("/").body, -1)
	if len(srcs) < 6 {
		t.Fatalf("captures : %d", len(srcs))
	}
	for _, m := range srcs {
		if img := b.get(m[1]); img.status != http.StatusOK || img.header.Get("Content-Type") != "image/webp" {
			t.Errorf("%s : %d %q", m[1], img.status, img.header.Get("Content-Type"))
		}
	}

	// Le lien mène bien à la connexion, publique.
	if p := b.get("/login"); p.status != http.StatusOK {
		t.Errorf("connexion : %d", p.status)
	}
}
