package hostagent

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/bmatcuk/doublestar/v4"

	"leblanc.io/lotor/internal/sbom"
	sbomsyft "leblanc.io/lotor/internal/sbom/syft"
)

// components renvoie les composants d'un SBOM Syft JSON, triés, tels que le serveur les lit.
func components(t *testing.T, inv Inventory) []string {
	t.Helper()
	doc, err := sbomsyft.Decode(sbom.FormatSyft, inv.SBOM)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, c := range doc.Components {
		out = append(out, c.PURL+" "+c.Name+" "+c.Version)
	}
	slices.Sort(out)
	return out
}

// syftDirectoryInventory inventorie avec la source « répertoire » de Syft, utilisée avant
// l'ADR 0055 : la référence des tests de parité.
func syftDirectoryInventory(t *testing.T, s SyftScanner, mounts []mount) Inventory {
	t.Helper()
	cfg := syft.DefaultGetSourceConfig().WithSources("dir").WithBasePath(s.Root).
		WithExcludeConfig(source.ExcludeConfig{Paths: s.exclusions(mounts)}).WithAlias(source.Alias{Name: s.Hostname})
	src, err := syft.GetSource(context.Background(), s.Root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	inv, err := s.catalog(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// TestIndexSourceMatchesSyftDirectory : l'index donne le même inventaire, à l'empreinte
// près, que la source « répertoire » de Syft. LOTOR_PARITY_ROOT compare aussi une vraie
// racine (/ d'un hôte), hors CI : go test -run TestIndexSourceMatchesSyftDirectory.
func TestIndexSourceMatchesSyftDirectory(t *testing.T) {
	roots := []SyftScanner{testScanner(t)}
	if root := os.Getenv("LOTOR_PARITY_ROOT"); root != "" {
		roots = append(roots, SyftScanner{Root: root, Hostname: "parite", Parallelism: 4, Version: "test"})
	}
	for _, s := range roots {
		t.Run(s.Root, func(t *testing.T) {
			mounts := systemMounts()
			if s.Mounts != nil {
				mounts = s.Mounts()
			}
			s.Mounts = func() []mount { return mounts }
			want := syftDirectoryInventory(t, s, mounts)
			got, err := s.Scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if w, g := components(t, want), components(t, got); !slices.Equal(w, g) {
				for _, c := range w {
					if !slices.Contains(g, c) {
						t.Errorf("absent de l'index : %s", c)
					}
				}
				for _, c := range g {
					if !slices.Contains(w, c) {
						t.Errorf("en trop dans l'index : %s", c)
					}
				}
			}
			if got.Fingerprint != want.Fingerprint {
				t.Errorf("empreintes différentes (%d et %d composants)", got.Components, want.Components)
			}
			t.Logf("%d composants", got.Components)
		})
	}
}

// fixture construit une arborescence de test :
//
//	/etc/os-release
//	/usr/lib/libz.so.1.3        bibliothèque (non exécutable), en-tête ELF
//	/usr/lib/libz.so.1 -> libz.so.1.3
//	/usr/bin/tool               exécutable, en-tête ELF
//	/usr/share/data.bin         en-tête ELF, ni exécutable ni nom de bibliothèque
//	/lib -> usr/lib             lien de répertoire
//	/opt/app/current -> /opt/app/v2  lien absolu, depuis la racine
//	/opt/app/v2/app.jar
//	/loop -> loop
//	/var/log/big.log            écarté par « ./var/log »
//	/run/fifo                   tube, jamais indexé
func fixture(t *testing.T) (string, *fsIndex) {
	t.Helper()
	root := t.TempDir()
	elf := "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00" + strings.Repeat("\x00", 64)
	write := func(p, content string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", "ID=debian\n", 0o644)
	write("usr/lib/libz.so.1.3", elf, 0o644)
	link("libz.so.1.3", "usr/lib/libz.so.1")
	write("usr/bin/tool", elf, 0o755)
	write("usr/share/data.bin", elf, 0o644)
	link("usr/lib", "lib")
	write("opt/app/v2/app.jar", "PK", 0o644)
	link("/opt/app/v2", "opt/app/current")
	link("loop", "loop")
	write("var/log/big.log", "x", 0o644)
	write("opt/go/pkg/mod/ex.com/m@v1.0.0/LICENSE", "MIT", 0o644)
	write("opt/go/pkg/mod/ex.com/m@v1.0.0/sub/x.go", "package sub", 0o644)
	link("LICENSE", "opt/go/pkg/mod/ex.com/m@v1.0.0/COPYING")
	if err := os.MkdirAll(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "run/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := buildIndex(context.Background(), root, []string{"./var/log"})
	if err != nil {
		t.Fatal(err)
	}
	return root, idx
}

func realPaths(locs []file.Location) []string {
	var out []string
	for _, l := range locs {
		out = append(out, l.RealPath+"<"+l.AccessPath)
	}
	slices.Sort(out)
	return out
}

func TestIndexWalk(t *testing.T) {
	_, idx := fixture(t)
	for _, p := range []string{"/", "/etc/os-release", "/lib", "/opt/app/current", "/var"} {
		if _, ok := idx.lookup(p); !ok {
			t.Errorf("%s absent de l'index", p)
		}
	}
	for _, p := range []string{"/var/log", "/var/log/big.log", "/run/fifo"} {
		if _, ok := idx.lookup(p); ok {
			t.Errorf("%s indexé", p)
		}
	}
}

func TestResolverPaths(t *testing.T) {
	_, idx := fixture(t)
	r := newIndexResolver(idx)
	cases := map[string]string{
		"/etc/os-release":          "/etc/os-release<" + "/etc/os-release",
		"etc/../etc/os-release":    "/etc/os-release<" + "/etc/os-release",
		"/lib/libz.so.1":           "/usr/lib/libz.so.1.3<" + "/lib/libz.so.1",
		"/opt/app/current/app.jar": "/opt/app/v2/app.jar<" + "/opt/app/current/app.jar",
		"/../../etc/os-release":    "/etc/os-release<" + "/etc/os-release",
	}
	for in, want := range cases {
		locs, _ := r.FilesByPath(in)
		if got := realPaths(locs); len(got) != 1 || got[0] != want {
			t.Errorf("FilesByPath(%q) = %v, attendu %s", in, got, want)
		}
	}
	for _, in := range []string{"/usr/lib", "/loop", "/absent", "/var/log/big.log"} {
		if locs, _ := r.FilesByPath(in); len(locs) != 0 {
			t.Errorf("FilesByPath(%q) = %v, attendu rien", in, realPaths(locs))
		}
	}
	if !r.HasPath("/usr/lib") || !r.HasPath("/lib/libz.so.1") || r.HasPath("/loop") || r.HasPath("/var/log") {
		t.Error("HasPath")
	}
	if l := r.RelativeFileByPath(file.Location{}, "/lib/libz.so.1"); l == nil || l.RealPath != "/usr/lib/libz.so.1.3" {
		t.Errorf("RelativeFileByPath = %v", l)
	}
}

func TestResolverGlobs(t *testing.T) {
	_, idx := fixture(t)
	r := newIndexResolver(idx)
	cases := map[string][]string{
		// Le lien et sa cible correspondent : un seul fichier, atteint par le premier vu.
		"**/libz.so*": {"/usr/lib/libz.so.1.3<" + "/usr/lib/libz.so.1"},
		"**/*.jar":    {"/opt/app/v2/app.jar<" + "/opt/app/v2/app.jar"},
		"/etc/os-*":   {"/etc/os-release<" + "/etc/os-release"},
		"**/usr/lib":  nil, // répertoire
		"**/*.log":    nil, // écarté
		// Répertoire parent fixé : seuls ses enfants directs, lien suivi et dédoublonné.
		"**/go/pkg/mod/ex.com/m@v1.0.0/*": {"/opt/go/pkg/mod/ex.com/m@v1.0.0/LICENSE<" + "/opt/go/pkg/mod/ex.com/m@v1.0.0/COPYING"},
		"**/mod/ex.com/absent@v1/*":       nil,
		"**/{tool,data.bin}":              {"/usr/bin/tool<" + "/usr/bin/tool", "/usr/share/data.bin<" + "/usr/share/data.bin"},
	}
	for pattern, want := range cases {
		locs, err := r.FilesByGlob(pattern)
		if err != nil || !slices.Equal(realPaths(locs), want) {
			t.Errorf("FilesByGlob(%q) = %v, %v ; attendu %v", pattern, realPaths(locs), err, want)
		}
	}
	// Plusieurs motifs : chaque fichier une fois.
	if locs, _ := r.FilesByGlob("**/*.jar", "/opt/app/**"); len(locs) != 1 {
		t.Errorf("motifs combinés : %v", realPaths(locs))
	}
}

func TestResolverMIMETypes(t *testing.T) {
	_, idx := fixture(t)
	r := newIndexResolver(idx)
	locs, err := r.FilesByMIMEType("application/x-executable", "application/x-sharedlib", "application/x-elf")
	if err != nil {
		t.Fatal(err)
	}
	// data.bin a un en-tête ELF, mais ni bit d'exécution ni nom de bibliothèque : non lu.
	want := []string{"/usr/bin/tool<" + "/usr/bin/tool", "/usr/lib/libz.so.1.3<" + "/usr/lib/libz.so.1.3"}
	if got := realPaths(locs); !slices.Equal(got, want) {
		t.Errorf("FilesByMIMEType = %v, attendu %v", got, want)
	}
	if locs, _ := r.FilesByMIMEType("text/html"); len(locs) != 0 {
		t.Errorf("type absent : %v", realPaths(locs))
	}
}

func TestResolverContentsAndMetadata(t *testing.T) {
	_, idx := fixture(t)
	r := newIndexResolver(idx)
	locs, _ := r.FilesByPath("/etc/os-release")
	rc, err := r.FileContentsByLocation(locs[0])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "ID=debian\n" {
		t.Errorf("contenu %q", body)
	}
	m, err := r.FileMetadataByLocation(locs[0])
	if err != nil || m.Path != "/etc/os-release" || m.Size() != 10 || m.MIMEType != "text/plain" || m.UserID < 0 {
		t.Errorf("métadonnées %+v, %v", m, err)
	}
	link, _ := r.FilesByGlob("**/current")
	if len(link) != 0 {
		t.Errorf("lien de répertoire renvoyé comme fichier : %v", realPaths(link))
	}
	if _, err := r.FileContentsByLocation(file.NewLocation("/var/log/big.log")); err == nil {
		t.Error("contenu d'un fichier écarté")
	}
	if _, err := r.FileContentsByLocation(file.NewLocation("/usr/lib")); err == nil {
		t.Error("contenu d'un répertoire")
	}
}

func TestResolverAllLocations(t *testing.T) {
	_, idx := fixture(t)
	r := newIndexResolver(idx)
	var got []string
	for l := range r.AllLocations(context.Background()) {
		got = append(got, l.RealPath)
	}
	if len(got) != idx.len() || !slices.Contains(got, "/usr/lib") || !slices.Contains(got, "/lib") || slices.Contains(got, "/var/log") {
		t.Errorf("AllLocations = %v", got)
	}
	// Annulation : le canal se ferme.
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.AllLocations(ctx)
	<-ch
	cancel()
	for range ch {
	}
}

func TestIndexHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Le parcours vérifie le contexte dès la première entrée, puis toutes les 4096.
	if _, err := buildIndex(ctx, testRoot(t), nil); err == nil {
		t.Error("parcours d'un contexte annulé")
	}
}

// TestGlobMatcher : le filtre rapide du nom de base ne change pas le résultat de
// doublestar, quelle que soit la forme du dernier composant.
func TestGlobMatcher(t *testing.T) {
	paths := []string{"/var/lib/dpkg/status", "/var/lib/dpkg/status.d/base", "/opt/a.jar", "/opt/a.jar.bak",
		"/usr/bin/python3", "/usr/bin/firefox", "/usr/lib/libstd-0123456789abcdef.so", "/var/lib/rpm/Packages",
		"/usr/lib/x/libQt5Core.so.5", "/root/go/pkg/mod/golang.org/x/net@v0.17.0/LICENSE",
		"/root/go/pkg/mod/golang.org/x/net@v0.17.0/http2/x.go", "/xgo/pkg/mod/golang.org/x/net@v0.17.0/LICENSE", "/"}
	patterns := []string{"**/lib/dpkg/status", "**/lib/dpkg/status.d/*", "**/*.jar", "**/python*",
		"**/{firefox,firefox.exe}", "**/libstd-????????????????.so", "**/{var/lib,usr/share}/rpm/{Packages,Packages.db}",
		"**/libQt*Core.so*", "/etc/debian_version", "**", "**/[", "**/{a,b", "**/go/pkg/mod/golang.org/x/net@v0.17.0/*",
		"**/dpkg/status"}
	for _, pattern := range patterns {
		g := newGlobMatcher(pattern)
		for _, p := range paths {
			want, err := doublestar.Match(pattern, p)
			if err != nil {
				want = false
			}
			if got := g.match(p); got != want {
				t.Errorf("%q sur %q : %v, attendu %v", pattern, p, got, want)
			}
		}
	}
}

// TestConfiguredExclusionPatterns : les motifs de scan.exclude s'appliquent au parcours
// depuis la racine : « * » couvre un seul niveau, « ** » toutes les profondeurs, « {a,b} »
// une alternative ; un répertoire exclu n'est pas parcouru. Exemples de docs/operations.md.
func TestConfiguredExclusionPatterns(t *testing.T) {
	root := t.TempDir()
	files := []string{
		"home/alice/www/node_modules/a/package.json", "home/bob/www/x.jar", "home/bob/public_html/p.jar",
		"home/alice/www2/z.jar", "home/alice/sites/www/s.jar", "home/bob/app/y.jar", "srv/www/w.jar",
		"srv/data/a/cache/c.jar", "srv/data/a/b/cache/d.jar", "srv/data/a/keep.jar",
	}
	for _, p := range files {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		exclude []string
		gone    []string // dossiers absents de l'index
		kept    []string // fichiers présents
	}{
		{[]string{"/home/*/www"},
			[]string{"/home/alice/www", "/home/bob/www"},
			[]string{"/home/alice/www2/z.jar", "/home/alice/sites/www/s.jar", "/home/bob/public_html/p.jar", "/srv/www/w.jar"}},
		{[]string{"/home/**/www"},
			[]string{"/home/alice/www", "/home/bob/www", "/home/alice/sites/www"},
			[]string{"/home/alice/www2/z.jar", "/srv/www/w.jar"}},
		{[]string{"/home/*/{www,public_html}"},
			[]string{"/home/alice/www", "/home/bob/www", "/home/bob/public_html"},
			[]string{"/home/bob/app/y.jar", "/home/alice/sites/www/s.jar"}},
		{[]string{"/srv/data/**/cache/"},
			[]string{"/srv/data/a/cache", "/srv/data/a/b/cache"},
			[]string{"/srv/data/a/keep.jar", "/srv/www/w.jar"}},
	}
	for _, c := range cases {
		idx, err := buildIndex(context.Background(), root, exclusionPatterns(c.exclude, nil))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range c.gone {
			if _, ok := idx.lookup(p); ok {
				t.Errorf("%v : %s indexé", c.exclude, p)
			}
		}
		for _, p := range c.kept {
			if _, ok := idx.lookup(p); !ok {
				t.Errorf("%v : %s absent", c.exclude, p)
			}
		}
	}
}
