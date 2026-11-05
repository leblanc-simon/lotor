#!/bin/sh
# Construit les fichiers d'une version dans un répertoire : archives des trois binaires
# (linux amd64 et arm64, CGO_ENABLED=0, version injectée), paquets deb et rpm de l'agent
# serveur, paquets deb du serveur et de l'agent dépôt, sommes SHA-256. Appelé par `make release` et par .github/workflows/release.yml.
#
# Usage : scripts/release.sh <version> <répertoire de sortie>   (version : v0.1.0)
set -eu

VERSION=${1:?version attendue (v0.1.0)}
OUT=${2:?répertoire de sortie attendu}
GO=${GO:-go}
ARCHES="amd64 arm64"
ROLES="lotor-server lotor-host-agent lotor-repo-agent"

case "$VERSION" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "version invalide : $VERSION (vX.Y.Z attendu)" >&2; exit 2 ;;
esac
NUM=${VERSION#v}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
if [ -n "$(ls -A "$OUT")" ]; then
  echo "répertoire de sortie non vide : $OUT" >&2
  exit 2
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Fichiers d'accompagnement de chaque rôle, en plus de LICENSE, README.md et CHANGELOG.md.
extras() {
  case "$1" in
  lotor-server) echo "config.example.yaml deploy/systemd/lotor-server.service" ;;
  lotor-host-agent) echo "deploy/host-agent/config.example.yaml deploy/systemd/lotor-host-agent.service deploy/systemd/lotor-host-agent-oneshot.service deploy/systemd/lotor-host-agent-oneshot.timer" ;;
  lotor-repo-agent) echo "deploy/lotor-repo-agent/config.example.yaml deploy/lotor-repo-agent/lotor-repo-agent.service" ;;
  esac
}

for arch in $ARCHES; do
  for role in $ROLES; do
    name="${role}_${NUM}_linux_${arch}"
    dir="$WORK/$name"
    mkdir -p "$dir"
    echo "build $role (linux/$arch, $VERSION)"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch $GO build -trimpath \
      -ldflags "-s -w -X 'main.version=$VERSION'" -o "$dir/$role" "./cmd/$role"
    cp LICENSE README.md CHANGELOG.md "$dir/"
    for f in $(extras "$role"); do cp "$f" "$dir/"; done
    # Archive reproductible : ordre, dates et propriétaires fixés.
    tar -C "$WORK" --sort=name --mtime='1970-01-01 00:00:00Z' --owner=0 --group=0 --numeric-owner \
      -cf - "$name" | gzip -n -9 > "$OUT/$name.tar.gz"
  done
done

# Paquets de l'agent serveur, du serveur et de l'agent dépôt (nfpm), version des paquets tirée de l'étiquette.
make --no-print-directory packages VERSION="$VERSION" >/dev/null
cp dist/lotor-host-agent_"$NUM"_amd64.deb dist/lotor-host-agent_"$NUM"_arm64.deb \
  dist/lotor-host-agent-"$NUM"-1.x86_64.rpm dist/lotor-host-agent-"$NUM"-1.aarch64.rpm \
  dist/lotor-server_"$NUM"_amd64.deb dist/lotor-server_"$NUM"_arm64.deb \
  dist/lotor-repo-agent_"$NUM"_amd64.deb dist/lotor-repo-agent_"$NUM"_arm64.deb "$OUT/"

(cd "$OUT" && sha256sum -- *.tar.gz *.deb *.rpm > SHA256SUMS)
echo "fichiers de $VERSION dans $OUT :"
ls -l "$OUT"
