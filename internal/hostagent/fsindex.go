package hostagent

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"github.com/bmatcuk/doublestar/v4"
)

// Index compact de l'arborescence inventoriée (ADR 0055). La source « répertoire » de
// Syft indexe chaque fichier dans un arbre en mémoire (environ 2 Kio par fichier) et en lit
// l'en-tête pour deviner son type MIME : sur un serveur réel, des millions d'ouvertures et
// plusieurs Gio de mémoire. Cet index ne fait qu'un parcours (lstat, readlink), sans ouvrir
// aucun fichier, et ne garde par entrée que son chemin, son type et son bit d'exécution
// (environ 80 octets) ; les métadonnées et le type MIME sont lus à la demande.

// Types d'entrée de l'index, dans les bits bas de kinds ; kindExec marque un fichier
// ordinaire exécutable.
const (
	kindDir     uint8 = 1
	kindRegular uint8 = 2
	kindSymlink uint8 = 3
	kindMask    uint8 = 0x0f
	kindExec    uint8 = 0x10
)

// maxLinkHops borne la résolution des liens symboliques (comme ELOOP du noyau).
const maxLinkHops = 40

// fsIndex est l'index d'une racine. Les chemins sont ceux vus depuis la racine (« chroot »),
// absolus (/var/lib/dpkg/status), mis bout à bout dans arena ; offsets[i]:offsets[i+1]
// délimite le chemin de l'entrée i. Immuable une fois construit : lisible en parallèle.
type fsIndex struct {
	root    string // racine sur le disque, absolue
	arena   []byte
	offsets []int64
	kinds   []uint8
	links   map[int32]string // cible brute (readlink) de chaque lien symbolique
	sorted  []int32          // entrées triées par chemin, pour la recherche
	dirs    []int32          // répertoires, dans l'ordre du parcours
}

// buildIndex parcourt root sans suivre les liens, en écartant les chemins qui
// correspondent à excludes (motifs doublestar relatifs à la racine, « ./proc ») : un
// répertoire écarté n'est pas parcouru. Seuls les répertoires, fichiers ordinaires et
// liens symboliques sont indexés (ni périphériques, ni tubes, ni sockets), comme Syft.
// Un chemin illisible est ignoré.
func buildIndex(ctx context.Context, root string, excludes []string) (*fsIndex, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(excludes))
	for _, e := range excludes {
		patterns = append(patterns, "/"+strings.TrimSuffix(strings.TrimPrefix(e, "./"), "/"))
	}
	idx := &fsIndex{root: root, offsets: []int64{0}, links: map[int32]string{}}
	add := func(p string, kind uint8) int32 {
		idx.arena = append(idx.arena, p...)
		idx.offsets = append(idx.offsets, int64(len(idx.arena)))
		idx.kinds = append(idx.kinds, kind)
		return int32(len(idx.kinds) - 1)
	}
	walked := 0
	err = filepath.WalkDir(root, func(full string, d fs.DirEntry, err error) error {
		if walked++; walked%4096 == 1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err != nil {
			// Répertoire illisible : ignoré, comme un fichier inaccessible chez Syft.
			if d != nil && d.IsDir() && full != root {
				return fs.SkipDir
			}
			return nil
		}
		p := chrootPath(root, full)
		if p != "/" && excluded(patterns, p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch t := d.Type(); {
		case t.IsDir():
			idx.dirs = append(idx.dirs, add(p, kindDir))
		case t.IsRegular():
			kind := kindRegular
			if info, err := d.Info(); err == nil && info.Mode().Perm()&0o111 != 0 {
				kind |= kindExec
			}
			add(p, kind)
		case t&fs.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return nil
			}
			idx.links[add(p, kindSymlink)] = target
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	idx.sorted = make([]int32, len(idx.kinds))
	for i := range idx.sorted {
		idx.sorted[i] = int32(i)
	}
	slices.SortFunc(idx.sorted, func(a, b int32) int { return strings.Compare(idx.path(a), idx.path(b)) })
	return idx, nil
}

// chrootPath renvoie le chemin d'un fichier vu depuis la racine du scan.
func chrootPath(root, full string) string {
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

func excluded(patterns []string, p string) bool {
	for _, pat := range patterns {
		if ok, _ := doublestar.Match(pat, p); ok {
			return true
		}
	}
	return false
}

func (x *fsIndex) len() int { return len(x.kinds) }

// path renvoie le chemin de l'entrée i sans copie : la chaîne pointe dans l'arène, qui
// n'est plus modifiée après la construction et reste en vie tant qu'une chaîne y pointe.
func (x *fsIndex) path(i int32) string {
	start, end := x.offsets[i], x.offsets[i+1]
	if start == end {
		return ""
	}
	return unsafe.String(&x.arena[start], int(end-start))
}

func (x *fsIndex) kind(i int32) uint8 { return x.kinds[i] & kindMask }

// lookup renvoie l'entrée du chemin p (déjà nettoyé), sans résoudre de lien.
func (x *fsIndex) lookup(p string) (int32, bool) {
	n, found := slices.BinarySearchFunc(x.sorted, p, func(i int32, p string) int { return strings.Compare(x.path(i), p) })
	if !found {
		return 0, false
	}
	return x.sorted[n], true
}

// children renvoie les entrées situées directement dans le répertoire dir : dans l'ordre
// trié, son sous-arbre est contigu (préfixe « dir/ »).
func (x *fsIndex) children(dir string, out []int32) []int32 {
	prefix := dir + "/"
	if dir == "/" {
		prefix = "/"
	}
	n, _ := slices.BinarySearchFunc(x.sorted, prefix, func(i int32, p string) int { return strings.Compare(x.path(i), p) })
	for ; n < len(x.sorted); n++ {
		p := x.path(x.sorted[n])
		if !strings.HasPrefix(p, prefix) {
			break
		}
		if p != prefix && !strings.Contains(p[len(prefix):], "/") {
			out = append(out, x.sorted[n])
		}
	}
	return out
}

// resolve suit les liens symboliques de chaque composant de p à l'intérieur de la racine
// (une cible absolue part de la racine, « .. » s'arrête à la racine), comme le résolveur
// de Syft avec FollowBasenameLinks ; followLast suit aussi un lien en dernier composant.
// Un composant absent de l'index (inexistant ou écarté) fait échouer la résolution.
func (x *fsIndex) resolve(p string, followLast bool) (int32, bool) {
	p = path.Clean("/" + p)
	hops := 0
	for {
		if p == "/" {
			return x.lookup("/")
		}
		parts := strings.Split(p[1:], "/")
		cur := ""
		restarted := false
		for n, part := range parts {
			cur += "/" + part
			i, ok := x.lookup(cur)
			if !ok {
				return 0, false
			}
			last := n == len(parts)-1
			if x.kind(i) != kindSymlink || (last && !followLast) {
				if last {
					return i, true
				}
				continue
			}
			if hops++; hops > maxLinkHops {
				return 0, false
			}
			target := x.links[i]
			base := path.Dir(cur)
			if path.IsAbs(target) {
				base = "/"
			}
			p = path.Clean("/" + path.Join(base, target, strings.Join(parts[n+1:], "/")))
			restarted = true
			break
		}
		if !restarted {
			return 0, false
		}
	}
}

// globMatcher est un motif doublestar précompilé. Son dernier composant (le nom de base)
// est d'abord testé par une simple comparaison de chaînes quand sa forme le permet (nom
// exact, « *.ext », « préfixe* », « {a,b} ») : c'est le cas de presque tous les motifs des
// catalogueurs, et ce filtre écarte l'essentiel des entrées sans appeler doublestar.
//
// Un motif « **/chemin/littéral/x » filtre aussi sur le répertoire parent : le catalogueur
// Go cherche ainsi les licences de chaque module de chaque binaire
// (« **/go/pkg/mod/module@version/* »), un parcours de l'index par module.
type globMatcher struct {
	pattern string
	valid   bool
	filter  func(name string) bool // nil : pas de filtre
	parent  string                 // « /chemin/littéral » : suffixe exigé du répertoire parent
}

func newGlobMatcher(pattern string) globMatcher {
	const meta = `*?[{\`
	g := globMatcher{pattern: pattern, valid: doublestar.ValidatePattern(pattern)}
	slash := strings.LastIndexByte(pattern, '/')
	last := pattern[slash+1:]
	if mid, ok := strings.CutPrefix(pattern[:max(slash, 0)], "**/"); ok && mid != "" && !strings.ContainsAny(mid, meta) {
		g.parent = "/" + mid
	}
	switch {
	case last == "" || last == "*" || last == "**" || strings.Count(last, "{") != strings.Count(last, "}"):
		// Pas de filtre : composant qui couvre tout, ou accolades à cheval sur un « / ».
	case !strings.ContainsAny(last, meta):
		g.filter = func(name string) bool { return name == last }
	case last[0] == '*' && !strings.ContainsAny(last[1:], meta):
		suffix := last[1:]
		g.filter = func(name string) bool { return strings.HasSuffix(name, suffix) }
	case last[len(last)-1] == '*' && !strings.ContainsAny(last[:len(last)-1], meta):
		prefix := last[:len(last)-1]
		g.filter = func(name string) bool { return strings.HasPrefix(name, prefix) }
	case last[0] == '{' && last[len(last)-1] == '}' && !strings.ContainsAny(last[1:len(last)-1], meta):
		names := strings.Split(last[1:len(last)-1], ",")
		g.filter = func(name string) bool { return slices.Contains(names, name) }
	default:
		if doublestar.ValidatePattern(last) {
			g.filter = func(name string) bool { return doublestar.MatchUnvalidated(last, name) }
		}
	}
	return g
}

func (g globMatcher) match(p string) bool { return g.matchAt(p, strings.LastIndexByte(p, '/')) }

// matchAt teste p, dont le dernier « / » est en slash (calculé une fois par entrée).
func (g globMatcher) matchAt(p string, slash int) bool {
	if !g.valid {
		return false
	}
	if g.parent != "" && !strings.HasSuffix(p[:max(slash, 0)], g.parent) {
		return false
	}
	if g.filter != nil && !g.filter(p[slash+1:]) {
		return false
	}
	return doublestar.MatchUnvalidated(g.pattern, p)
}
