# 0065 — Snaps : version d'Ubuntu du snap et binaires rattachés à leurs paquets

- Statut : Accepté
- Date : 2026-11-19
- Lot : hors lot

## Contexte

Sur `srv1` (Ubuntu 26.04), le SBOM de l'agent serveur contient 448 composants trouvés sous
`/snap` : 292 paquets deb lus par le catalogueur des snaps de Syft (`dpkg.yaml` de core22,
`snap/manifest.yaml` de snapd et de canonical-livepatch), cinq binaires de core22 reconnus
par leur contenu (`openssl`, `bash`, `gzip`, `python3.10`, `getopt`), des modules Go et
Python. Deux défauts s'ajoutaient :

- **Mauvaise version d'Ubuntu** : les paquets des snaps n'ont pas de distribution (purl
  `pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.30?arch=amd64`, sans `distro`). Grype leur donne
  celle de l'hôte : `openssl` de core22 (Ubuntu 22.04) était comparé aux correctifs de
  26.04 (en 3.5.x), d'où 86 correspondances, toutes fausses : Ubuntu 22.04 déclare corrigées
  ses 83 CVE d'openssl, la dernière en `3.0.2-0ubuntu1.30`.
- **Binaires orphelins** : `dpkg.yaml` et `manifest.yaml` ne nomment aucun fichier. Les
  binaires du snap n'étaient liés à aucun paquet et restaient comparés par CPE aux versions
  amont de la NVD : 75 correspondances sur `/snap/core22/3129/usr/bin/openssl` (`3.0.2`),
  dont CVE-2022-2068, corrigée par Ubuntu 22.04 en `3.0.2-0ubuntu1.5`.

Le mécanisme de l'ADR 0064 (Grype retire la correspondance CPE d'un fichier possédé quand la
distribution déclare la CVE corrigée, lotor celle qu'elle déclare ouverte) s'applique dès que
le binaire est lié à un paquet rapproché des bonnes données.

## Décision

Un traitement dans l'adaptateur `vuln/grype` (`snap.go`, `snapPackages`), avant la
correspondance, pour les paquets trouvés sous `/snap/<nom>/<révision>/` :

1. **Version d'Ubuntu des paquets deb d'un snap**, par ordre :
   - nom du snap de base : `core` → 16.04, `coreNN` → NN.04 ;
   - base déclarée par le snap applicatif (`base: core22`, métadonnée `SnapEntry.Base` du
     SBOM de Syft) ;
   - sinon, l'**unique** version d'Ubuntu inscrite dans les versions des paquets du snap
     (`1ubuntu0.22.04.3`, `~22.04.1`) : c'est le cas de snapd, sans base déclarée, que Syft
     ne relie pas à la version de construction notée dans son `manifest.yaml` ;
   - sinon (aucune ou plusieurs versions), le paquet garde la distribution de l'hôte, comme
     avant.
2. **Binaires d'un snap** liés (relation `ownership-by-file-overlap`, comme un fichier
   possédé) au paquet deb **du même snap** de même nom, ou de même nom suivi d'une version
   (`python` → `python3.10`), dont la version amont (sans époque ni révision Debian) est la
   version du binaire ou la préfixe à un point près (`bash` 5.1.16, paquet `5.1-6ubuntu1.1`).
   Un nom ou une version qui ne correspond pas laisse le binaire comparé par CPE.

La règle de l'ADR 0064 vaut ici : aucune CVE n'est retirée sans que la distribution (la bonne
version d'Ubuntu) se soit prononcée sur elle.

## Conséquences

- Mesures sur la vraie base (jeu `testdata/sbom/ubuntu-26.04-snap.syft.json`, reproduction
  de core22, snapd et canonical-livepatch de `srv1`) : `openssl` de core22 passe de 86
  correspondances (données de 26.04) et 75 par CPE à 0 ; `gzip` de 2 + 3 à 0 ;
  `python3.10` gagne 33 correspondances selon Ubuntu 22.04, qui ne l'étaient pas avec les
  données de 26.04 ; `util-linux` 12 + 9 → 4 + 1.
- **Limite connue** : les listes des snaps ne donnent pas le paquet source. Un paquet
  binaire dont le nom diffère de son source (`libssl3` pour `openssl`, `libc6` pour `glibc`)
  n'est rapproché de rien, avant comme après. Les binaires du snap rattachés à un paquet de
  même nom que son source (`openssl`, `bash`, `gzip`, `util-linux`, `python3.10`) sont
  couverts.
- La déduction par les versions est une heuristique bornée : elle n'agit qu'en l'absence de
  base, exige une seule version d'Ubuntu dans tout le snap et ne retient que les formes
  `ubuntuN.XX.YY` et `~XX.YY` en fin de version.
- Le purl des composants ne change pas (il vient de Syft) : seul le rapprochement change ;
  aucune migration, aucune nouvelle empreinte d'inventaire.
- Prise en compte à la réanalyse qui suit le prochain changement de base cible
  (`analysis.rescan_all`), sans nouveau scan.
- Hors périmètre : le catalogueur des snaps de Syft lit aussi
  `/usr/share/doc/linux-modules-*/changelog.Debian.gz` de l'hôte et crée un paquet
  `linux-image-*` sans source, rapproché de rien ; un doublon d'inventaire sans effet sur
  les constats.
