# SBOM d'exemple

Jeux d'essai de l'ingestion (T05) et, plus tard, de l'analyse (T06) et des agents. Les
fichiers attendus (`golden/*.golden.json`) sont le `sbom.Document` que produit
`internal/sbom/syft.Decode` ; après un changement voulu de la normalisation :
`go test ./internal/sbom/syft -run TestGolden -update`, puis relire le diff.

| Fichier | Format | Contenu |
| --- | --- | --- |
| `debian-12.cdx15.json` | CycloneDX 1.5 | Hôte Debian 12 (bookworm), 12 paquets deb (epoch, `upstream`) |
| `rhel-8.cdx16.json` | CycloneDX 1.6 | Hôte RHEL 8.6, 19 paquets rpm (qualificatifs `epoch`, `arch=s390x`, `upstream`) |
| `rhel-8.spdx23.json` | SPDX 2.3 | Même inventaire RHEL |
| `alpine-3.20.syft.json` | Syft JSON (schéma 16.1) | Hôte Alpine 3.20.3, 9 paquets apk |
| `alpine-3.20.spdx23.json` | SPDX 2.3 | Même inventaire Alpine |
| `ubuntu-24.04.cdx17.json` | CycloneDX 1.7 | Hôte Ubuntu 24.04, 24 paquets deb avec licences (fichiers copyright) |
| `ubuntu-24.04.spdx23.json` | SPDX 2.3 | Même inventaire Ubuntu |
| `ubuntu-24.04.syft.json` | Syft JSON | Même inventaire Ubuntu |
| `portail-client.cdx16.json` | CycloneDX 1.6 | Dépôt : npm (dont `@babel/runtime`), PyPI, modules Go |
| `portail-client-ia.cdx16.json` | CycloneDX 1.6 | Le même dépôt enrichi par l'IA (voir plus bas) |
| `log4shell.cdx16.json` | CycloneDX 1.6 | Application Java : `log4j-core` et `log4j-api` 2.14.1, `guava` (analyse, T06) |
| `ubuntu-26.04-kernel.syft.json` | Syft JSON | Hôte Ubuntu 26.04 : image signée et modules du noyau 7.0.0-43, binaire `/boot/vmlinuz-*` (ADR 0064) |
| `debian-12-kernel.syft.json` | Syft JSON | Hôte Debian 12 : image signée du noyau 6.1.174-1, binaire `/boot/vmlinuz-*` (ADR 0064) |
| `ubuntu-26.04-snap.syft.json` | Syft JSON | Hôte Ubuntu 26.04 avec les snaps core22, snapd et canonical-livepatch : paquets des snaps, binaires de core22 (ADR 0065) |

## Provenance

`log4shell.cdx16.json` est écrit à la main (T06) : trois composants Maven de purl
canonique, pour le critère « log4j-core 2.14.1 produit CVE-2021-44228 marquée KEV ».

Tous les fichiers sauf `portail-client-ia.cdx16.json` sont produits par **Syft v1.55.0**
(bibliothèque, catalogueurs par défaut, source « répertoire »), le 31 octobre 2026, par un
programme jetable hors dépôt qui catalogue un système de fichiers factice, garde au besoin
un sous-ensemble de paquets, rend la source anonyme (nom du jeu, chemin `/`) et encode dans
les formats voulus. Les chemins absolus du répertoire temporaire ont ensuite été retirés
(les emplacements deviennent `/var/lib/dpkg/status`…). Systèmes de fichiers :

- **Ubuntu 24.04** : `/etc/os-release` et un sous-ensemble réel de 24 paquets de
  `/var/lib/dpkg/status` de la machine de développement (Ubuntu 24.04.5), avec leurs
  fichiers `/usr/share/doc/<paquet>/copyright` (licences).
- **Debian 12** : `/etc/os-release` de bookworm et une base dpkg de 12 paquets écrite à la
  main sur le modèle de la base Ubuntu, versions de bookworm (point 12.7).
- **RHEL 8.6** : base RPM réelle d'une image UBI 8 (`ubi8-s390x/Packages`, jeu d'essai de
  `github.com/anchore/go-rpmdb` v0.2.2, BerkeleyDB), `/etc/os-release` de RHEL 8.6 (version
  de `redhat-release` de cette base) ; 19 paquets gardés sur 183.
- **Alpine 3.20** : `/etc/os-release` d'Alpine 3.20.3 et une base apk
  (`/lib/apk/db/installed`) de 9 paquets écrite à la main, versions d'Alpine 3.20.
- **portail-client** : `package-lock.json` (v3), `requirements.txt` et `go.mod`/`go.sum`
  écrits à la main.

`portail-client-ia.cdx16.json` est dérivé à la main de `portail-client.cdx16.json` : autre
horodatage et numéro de série, portée et empreinte SHA-512 sur deux composants, et trois
composants d'origine IA (propriétés `lotor:origin`, `lotor:confidence`,
`lotor:model`, champ `evidence`) : `jquery` (purl `pkg:NPM/…` à canonicaliser,
empreinte SHA-256 en majuscules), `libfoo-interne` (sans purl : identification faible) et
`Django_Extensions` (purl PyPI à canonicaliser, qualificatif vide).

`ubuntu-26.04-kernel.syft.json` et `debian-12-kernel.syft.json` (19 novembre 2026, ADR 0064)
sont produits par l'agent serveur lui-même (`hostagent.SyftScanner`, Syft v1.57.1) sur une
racine factice, par un test jetable hors dépôt ; descripteur réduit au nom de l'outil et
chemin de la source ramené à `/`. Chaque racine contient `/etc/os-release`, une base dpkg
écrite à la main (paquets du noyau, `Source:` réels des distributions : `linux-signed` et
`linux` sur Ubuntu, `linux-signed-amd64 (6.1.174+1)` sur Debian), leurs fichiers
`/var/lib/dpkg/info/*.md5sums` (d'où la relation `ownership-by-file-overlap`) et une image
`/boot/vmlinuz-*` minimale : un en-tête bzImage de 4 Kio portant la chaîne de version, que le
catalogueur du noyau reconnaît.

`ubuntu-26.04-snap.syft.json` (19 novembre 2026, ADR 0065) est produit de la même façon. La
racine reproduit les snaps de l'hôte `srv1` d'après son SBOM d'origine : un sous-ensemble
de `/snap/core22/3129/usr/share/snappy/dpkg.yaml` (versions réelles de core22), les
`snap/manifest.yaml` de snapd (sans base, paquets en 22.04) et de canonical-livepatch
(`base: core22`), et quatre faux binaires de core22 (`openssl`, `bash`, `gzip`, `getopt`)
réduits aux motifs que le classificateur binaire de Syft reconnaît.
