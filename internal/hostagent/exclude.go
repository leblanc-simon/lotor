package hostagent

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// DefaultExclusions sont toujours exclues du scan, relativement à sa racine : systèmes de
// fichiers virtuels, stockages des moteurs de conteneurs, dont les images relèvent de T13
// et jamais du SBOM de l'hôte, et répertoires de données (ADR 0055) : journaux, caches,
// fichiers temporaires, files d'attente, sauvegardes et données des bases, où aucun
// logiciel n'est installé mais qui comptent souvent l'essentiel des fichiers d'un serveur.
var DefaultExclusions = []string{
	"/proc", "/sys", "/dev", "/run", "/var/run",
	"/var/lib/docker", "/var/lib/containers", "/var/lib/containerd",
	"/var/lib/kubelet/pods", "/var/lib/lxc", "/var/lib/lxd", "/var/lib/rancher",
	"/home/**/.local/share/containers", "/root/.local/share/containers",
	"/tmp", "/var/tmp", "/var/log", "/var/cache", "/var/spool", "/var/mail", "/var/backups", "/var/crash",
	"/lost+found", "/var/lib/apt/lists",
	"/home/*/.cache", "/root/.cache",
	"/var/lib/postgresql", "/var/lib/pgsql", "/var/lib/mysql", "/var/lib/mongodb", "/var/lib/redis",
	"/var/lib/elasticsearch", "/var/lib/opensearch", "/var/lib/clickhouse", "/var/lib/influxdb",
	"/var/lib/cassandra", "/var/lib/rabbitmq", "/var/lib/prometheus",
}

// skippedFSTypes sont les types de montage exclus du scan : partages réseau (lents, et
// qui ne sont pas l'hôte), systèmes de fichiers de conteneurs, et autofs, dont le
// parcours déclencherait le montage de partages distants.
var skippedFSTypes = []string{
	"nfs", "nfs4", "cifs", "smb3", "smbfs", "ncpfs", "afs", "ceph", "glusterfs", "lustre", "gpfs", "beegfs", "9p",
	"fuse.sshfs", "fuse.glusterfs", "fuse.cephfs", "fuse.davfs2", "fuse.s3fs", "fuse.rclone", "fuse.gcsfuse",
	"overlay", "aufs", "shiftfs", "fuse.fuse-overlayfs",
	"autofs",
	// Systèmes de fichiers virtuels du noyau, où qu'ils soient montés (Syft les écarte aussi).
	"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs",
	"pstore", "bpf", "configfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc", "efivarfs",
}

// mount est un point de montage lu dans mountinfo.
type mount struct {
	Point  string
	FSType string
}

// readMounts lit les montages au format de /proc/self/mountinfo.
func readMounts(r io.Reader) []mount {
	var out []mount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw
		before, after, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		f, a := strings.Fields(before), strings.Fields(after)
		if len(f) < 5 || len(a) < 1 {
			continue
		}
		out = append(out, mount{Point: unescapeMount(f[4]), FSType: a[0]})
	}
	return out
}

// unescapeMount décode les échappements octaux du noyau (\040 pour l'espace…).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// skippedMounts renvoie les points de montage exclus situés sous root (sauf root
// lui-même : une racine en overlay reste inventoriée).
func skippedMounts(mounts []mount, root string) []string {
	root = filepath.Clean(root)
	var out []string
	for _, m := range mounts {
		if !slices.Contains(skippedFSTypes, m.FSType) {
			continue
		}
		p := filepath.Clean(m.Point)
		if p == root {
			continue
		}
		if rel, err := filepath.Rel(root, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			out = append(out, "/"+filepath.ToSlash(rel))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// systemMounts lit les montages du système ; sans /proc, aucun.
func systemMounts() []mount {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	return readMounts(f)
}

// globEscaper protège les métacaractères de doublestar dans un chemin réel (point de
// montage).
var globEscaper = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`)

// exclusionPatterns traduit des chemins absolus relatifs à la racine du scan (« /proc »)
// en motifs d'exclusion de Syft (« ./proc »). Les chemins configurés sont des motifs ;
// les points de montage, des chemins réels, échappés.
func exclusionPatterns(configured, mountPoints []string) []string {
	var out []string
	add := func(p string) {
		p = "./" + strings.TrimLeft(filepath.ToSlash(p), "/")
		p = strings.TrimSuffix(p, "/")
		if p != "." && p != "./" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, p := range configured {
		add(p)
	}
	for _, p := range mountPoints {
		add(globEscaper.Replace(p))
	}
	return out
}
