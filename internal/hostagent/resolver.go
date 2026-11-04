package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

// indexSource est la source Syft de l'inventaire d'un hôte, adossée à fsIndex au lieu de
// la source « répertoire » de Syft (ADR 0055). Les catalogueurs n'y voient pas de
// différence : mêmes chemins vus depuis la racine, mêmes liens suivis, mêmes exclusions.
type indexSource struct {
	id       artifact.ID
	name     string
	resolver *indexResolver
}

var _ source.Source = (*indexSource)(nil)

func newIndexSource(idx *fsIndex, name string) *indexSource {
	// Identifiant dérivé du seul alias, comme la source répertoire de Syft avec un alias.
	sum := sha256.Sum256([]byte(name + "@"))
	return &indexSource{id: artifact.ID(hex.EncodeToString(sum[:8])), name: name, resolver: newIndexResolver(idx)}
}

func (s *indexSource) ID() artifact.ID { return s.id }

func (s *indexSource) FileResolver(source.Scope) (file.Resolver, error) { return s.resolver, nil }

func (s *indexSource) Describe() source.Description {
	return source.Description{
		ID:       string(s.id),
		Name:     s.name,
		Metadata: source.DirectoryMetadata{Path: s.resolver.idx.root, Base: s.resolver.idx.root},
	}
}

func (s *indexSource) Close() error { return nil }

// indexResolver répond aux catalogueurs depuis l'index. Les références de fichier
// (identité d'un fichier pour Syft) sont créées à la première demande et gardées ; les
// types MIME ne sont lus que pour les candidats binaires, une fois.
type indexResolver struct {
	idx *fsIndex

	mu   sync.Mutex
	refs map[int32]*stereofile.Reference

	mimeOnce sync.Once
	mimes    []fileMIME
}

type fileMIME struct {
	entry int32
	mime  string
}

var _ file.Resolver = (*indexResolver)(nil)

func newIndexResolver(idx *fsIndex) *indexResolver {
	return &indexResolver{idx: idx, refs: map[int32]*stereofile.Reference{}}
}

func (r *indexResolver) ref(i int32) stereofile.Reference {
	r.mu.Lock()
	defer r.mu.Unlock()
	ref, ok := r.refs[i]
	if !ok {
		ref = stereofile.NewFileReference(stereofile.Path(strings.Clone(r.idx.path(i))))
		r.refs[i] = ref
	}
	return *ref
}

// location construit l'emplacement de l'entrée réelle i, atteinte par access.
func (r *indexResolver) location(i int32, access string) file.Location {
	ref := r.ref(i)
	return file.NewVirtualLocationFromDirectory(string(ref.RealPath), strings.Clone(access), ref)
}

// HasPath dit si le chemin existe dans l'index (répertoire compris).
func (r *indexResolver) HasPath(p string) bool {
	_, ok := r.idx.resolve(p, true)
	return ok
}

// FilesByPath résout chaque chemin (liens suivis) ; les répertoires sont écartés.
func (r *indexResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	out := make([]file.Location, 0, len(paths))
	for _, p := range paths {
		i, ok := r.idx.resolve(p, true)
		if !ok || r.idx.kind(i) == kindDir {
			continue
		}
		out = append(out, r.location(i, path.Clean("/"+p)))
	}
	return out, nil
}

// FilesByGlob renvoie les fichiers dont le chemin correspond à un motif, une seule fois
// chacun ; un lien qui correspond est suivi jusqu'à son fichier réel.
func (r *indexResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	matchers := make([]globMatcher, 0, len(patterns))
	for _, p := range patterns {
		matchers = append(matchers, newGlobMatcher(p))
	}
	seen := map[int32]bool{}
	out := make([]file.Location, 0)
	for i := range r.globCandidates(matchers) {
		kind := r.idx.kind(i)
		if kind == kindDir {
			continue
		}
		p := r.idx.path(i)
		slash := strings.LastIndexByte(p, '/')
		if !slices.ContainsFunc(matchers, func(g globMatcher) bool { return g.matchAt(p, slash) }) {
			continue
		}
		real := i
		if kind == kindSymlink {
			var ok bool
			if real, ok = r.idx.resolve(p, true); !ok || r.idx.kind(real) == kindDir {
				continue
			}
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		out = append(out, r.location(real, p))
	}
	return out, nil
}

// globCandidates renvoie les entrées à tester, dans l'ordre du parcours : toutes, sauf si
// chaque motif fixe son répertoire parent (« **/go/pkg/mod/module@version/* ») ; seuls
// les enfants des répertoires qui finissent par ce chemin sont alors candidats.
func (r *indexResolver) globCandidates(matchers []globMatcher) iter.Seq[int32] {
	var parents []string
	for _, g := range matchers {
		if g.parent == "" {
			return func(yield func(int32) bool) {
				for i := int32(0); i < int32(r.idx.len()); i++ {
					if !yield(i) {
						return
					}
				}
			}
		}
		parents = append(parents, g.parent)
	}
	var out []int32
	for _, d := range r.idx.dirs {
		p := r.idx.path(d)
		if slices.ContainsFunc(parents, func(parent string) bool { return strings.HasSuffix(p, parent) }) {
			out = r.idx.children(p, out)
		}
	}
	slices.Sort(out)
	return slices.Values(slices.Compact(out))
}

// FilesByMIMEType renvoie les fichiers d'un des types demandés. Seuls les candidats
// binaires sont lus (bit d'exécution, ou nom de bibliothèque ou de binaire Windows) : les
// catalogueurs n'interrogent que les types des exécutables (ADR 0055).
func (r *indexResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	r.mimeOnce.Do(r.sniffBinaries)
	out := make([]file.Location, 0)
	for _, m := range r.mimes {
		if slices.Contains(types, m.mime) {
			p := r.idx.path(m.entry)
			out = append(out, r.location(m.entry, p))
		}
	}
	return out, nil
}

func (r *indexResolver) sniffBinaries() {
	for i := int32(0); i < int32(r.idx.len()); i++ {
		if r.idx.kind(i) != kindRegular || !binaryCandidate(r.idx.kinds[i], r.idx.path(i)) {
			continue
		}
		if mime := r.mimeOf(r.idx.path(i)); mime != "" {
			r.mimes = append(r.mimes, fileMIME{entry: i, mime: mime})
		}
	}
}

// binaryCandidate retient les fichiers qui peuvent être un exécutable ou une bibliothèque :
// exécutables, bibliothèques partagées (libx.so, libx.so.1.2, .dylib) et binaires Windows.
func binaryCandidate(kind uint8, p string) bool {
	if kind&kindExec != 0 {
		return true
	}
	name := strings.ToLower(p[strings.LastIndexByte(p, '/')+1:])
	return strings.HasSuffix(name, ".so") || strings.Contains(name, ".so.") ||
		strings.HasSuffix(name, ".dylib") || strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".exe")
}

func (r *indexResolver) mimeOf(p string) string {
	f, err := os.Open(r.onDisk(p))
	if err != nil {
		return ""
	}
	defer f.Close()
	return stereofile.MIMEType(f)
}

func (r *indexResolver) onDisk(p string) string {
	return filepath.Join(r.idx.root, filepath.FromSlash(p))
}

// RelativeFileByPath : un hôte n'a qu'une couche, le chemin se résout depuis la racine.
func (r *indexResolver) RelativeFileByPath(_ file.Location, p string) *file.Location {
	locs, _ := r.FilesByPath(p)
	if len(locs) == 0 {
		return nil
	}
	return &locs[0]
}

// FileContentsByLocation ouvre le fichier à la lecture (ouverture différée).
func (r *indexResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	if loc.RealPath == "" {
		return nil, errors.New("hostagent: chemin vide")
	}
	i, ok := r.idx.lookup(loc.RealPath)
	if !ok {
		return nil, fmt.Errorf("hostagent: %q absent de l'index : %w", loc.RealPath, os.ErrNotExist)
	}
	if r.idx.kind(i) == kindDir {
		return nil, fmt.Errorf("hostagent: %q est un répertoire", loc.RealPath)
	}
	return stereofile.NewLazyReadCloser(r.onDisk(loc.RealPath)), nil
}

// FileMetadataByLocation lit les métadonnées sur le disque, à la demande.
func (r *indexResolver) FileMetadataByLocation(loc file.Location) (file.Metadata, error) {
	i, ok := r.idx.lookup(loc.RealPath)
	if !ok {
		return file.Metadata{}, fmt.Errorf("hostagent: %q : %w", loc.RealPath, os.ErrNotExist)
	}
	info, err := os.Lstat(r.onDisk(loc.RealPath))
	if err != nil {
		return file.Metadata{}, err
	}
	m := file.Metadata{FileInfo: info, Path: loc.RealPath, Type: stereofile.TypeFromMode(info.Mode()), UserID: -1, GroupID: -1}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		m.UserID, m.GroupID = int(st.Uid), int(st.Gid)
	}
	switch r.idx.kind(i) {
	case kindSymlink:
		m.LinkDestination = r.idx.links[i]
	case kindRegular:
		m.MIMEType = r.mimeOf(loc.RealPath)
	}
	return m, nil
}

// AllLocations parcourt toutes les entrées, répertoires compris (le catalogueur Nix le
// fait à chaque scan). Les références n'y sont pas gardées : une par entrée de l'index
// annulerait le gain de mémoire. Le chemin pointe dans l'arène, immuable.
func (r *indexResolver) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for i := int32(0); i < int32(r.idx.len()); i++ {
			ref := *stereofile.NewFileReference(stereofile.Path(r.idx.path(i)))
			select {
			case <-ctx.Done():
				return
			case out <- file.NewLocationFromDirectory(string(ref.RealPath), "", ref):
			}
		}
	}()
	return out
}
