# 0064 — Noyau Linux : données de la distribution plutôt que plages amont de la NVD

- Statut : Accepté
- Date : 2026-11-19
- Lot : hors lot

## Contexte

Sur un hôte Ubuntu 26.04 (`srv1`), lotor signalait 1 556 CVE sur le noyau `7.0.0-43-generic`,
dont CVE-2026-53266, corrigée par Ubuntu depuis `7.0.0-31.31`. Le noyau apparaît deux fois dans
le SBOM de l'agent serveur :

- **les paquets de la distribution** `linux-image-7.0.0-43-generic` et
  `linux-modules-7.0.0-43-generic`, comparés par Grype aux données d'Ubuntu ;
- **un paquet `linux-kernel`** que Syft déduit de `/boot/vmlinuz-7.0.0-43-generic`, sans
  distribution, comparé seulement par CPE (`linux:linux_kernel`) aux plages amont de la NVD
  (corrigé en 6.12.94, 7.0.13…). Les correctifs reportés par la distribution ne changent pas
  la version `7.0.0-43` : chaque CVE reste ouverte pour la NVD.

Grype sait déjà corriger ce cas, CVE par CVE : quand un paquet de la distribution est rapproché
de ses données et que celles-ci déclarent une CVE corrigée ou non applicable, Grype retire la
correspondance CPE des fichiers que ce paquet possède (relation `ownership-by-file-overlap`,
présente dans le Syft JSON de l'agent serveur). Il ne le fait pas ici parce que
`linux-image-*` vient d'un paquet source signé (`linux-signed` sur Ubuntu,
`linux-signed-amd64` sur Debian) qui n'existe pas dans les suivis de sécurité des
distributions : ceux-ci, donc la base Grype, ne connaissent que le source `linux*`. L'image
n'est rapprochée de rien, et le binaire qu'elle possède reste comparé à la NVD.

Couverture du noyau dans la base Grype (5 novembre 2026), par distribution :

| Distribution | Source dans la base | Image du noyau installée rapprochée ? |
| --- | --- | --- |
| Ubuntu | `linux` (68 637 entrées) | Non : `linux-image-*` vient de `linux-signed`. `linux-modules-*` vient de `linux` mais ne possède pas `/boot/vmlinuz-*` |
| Debian | `linux` (90 194) | Non : `linux-image-*-amd64` vient de `linux-signed-amd64`, et contient les modules : **aucune** CVE du noyau n'était rapprochée par la distribution |
| RHEL et dérivés, Oracle, Amazon, SLES, Azure Linux | `kernel`, `kernel-default` | Oui (source rpm `kernel`) ; d'après son code, Grype écarte déjà avant la correspondance le binaire possédé de version voisine (non mesuré ici, faute de jeu d'essai rpm avec noyau) |
| Fedora, Alpine | `kernel` (1 596), `linux-lts` (81) | Données maigres : le CPE reste le seul signal fiable |

Une première idée (écarter le CPE du binaire dès qu'un paquet de la distribution le possède) a
été rejetée : sur Debian, elle aurait supprimé toutes les CVE du noyau. Les règles d'exclusion
par défaut de la commande `grype` (`linux-headers-*`, `linux-libc-dev`, `linux-kbuild-*`) ont
aussi été écartées : elles ne corrigent pas ce cas (les en-têtes sont rapprochés avec la bonne
version) et retireraient le seul signal restant là où l'image n'est pas couverte.

## Décision

Deux traitements dans l'adaptateur `vuln/grype` (`kernel.go`), autour de la correspondance :

1. **Renvoi des images signées vers leur source non signé** (`signedKernelUpstreams`), avant
   la correspondance, pour les paquets deb d'Ubuntu et de Debian. Ubuntu : `linux-signed[-X]`
   → `linux[-X]` (`linux-signed-hwe-6.8` → `linux-hwe-6.8`). Debian : `linux-signed[-X]-ARCH`
   → `linux[-X]` pour `amd64`, `arm64` et `i386`. La version du renvoi est celle du **paquet
   binaire**, qui est celle du source `linux*` (`7.0.0-43.43`, `6.1.128-1`), quand le source
   signé de Debian suit sa propre numérotation (`6.1.128+1`). Le source d'origine est gardé.
   Grype rapproche alors l'image des données de la distribution et retire lui-même, CVE par
   CVE, la correspondance CPE du binaire possédé quand la distribution la déclare corrigée ou
   non applicable.
2. **Retrait du doublon** (`dropOwnedCPEDuplicates`), après la correspondance : une
   correspondance **par CPE seul** d'un paquet dont un fichier appartient à un paquet de la
   distribution est retirée quand ce paquet est rapproché de la **même** vulnérabilité par la
   distribution. Sans ce retrait, une CVE encore ouverte selon la distribution apparaissait
   deux fois, et le binaire montrait les versions corrigées amont au lieu de celle de la
   distribution.

Règle de sécurité : **aucune CVE n'est retirée sans que la distribution se soit prononcée sur
elle**. Une CVE que la distribution ne suit pas reste signalée par CPE sur le binaire ; une
CVE ouverte reste signalée sur le paquet de la distribution. Aucune liste de distributions
n'est maintenue : le renvoi ne touche que les noms `linux-signed*` d'Ubuntu et de Debian, et
le retrait du doublon ne dépend que de ce que la base contient.

## Conséquences

- Mesures sur la vraie base (jeux `testdata/sbom/ubuntu-26.04-kernel.syft.json` et
  `debian-12-kernel.syft.json`, `make test-grypedb`) : Ubuntu 26.04, correspondances CPE du
  binaire 1 556 → 24 (anciennes CVE de 2016 à 2018 dont la NVD ne borne pas les versions et
  qu'Ubuntu 26.04 ne cite pas) ; Debian 12, `linux-image` 0 → 4 856 correspondances par la
  distribution (dont les CVE ouvertes ou différées par Debian), binaire 6 042 → 6.
- Sur Debian, le décompte du noyau suit désormais le suivi de sécurité de Debian, plus
  complet et plus strict que les plages de la NVD : CVE différées ou ignorées par Debian
  comprises, avec leur état (`wont-fix`, `not-fixed`).
- Une CVE ouverte selon Ubuntu reste signalée deux fois, sur `linux-image-*` et
  `linux-modules-*` (deux paquets du même source), comme tout paquet binaire d'un même
  source : comportement habituel de Grype, inchangé.
- Les constats existants sont résolus à la réanalyse suivante, déclenchée par le prochain
  changement de base cible (`analysis.rescan_all`), sans nouveau scan des agents.
- Un SBOM sans relation de propriété ni liste de fichiers des paquets (CycloneDX ou SPDX
  produit ailleurs) ne bénéficie que du renvoi : le binaire y reste comparé par CPE.
- Une montée de version de Grype doit vérifier que le cas est toujours nécessaire (Grype
  pourrait apprendre lui-même le renvoi des sources signés) : `TestKernelFollowsDistroData`
  et `TestRealKernel` le montrent.
- Les binaires embarqués dans un snap (`/snap/core22/…/openssl`) relèvent du même défaut
  (version amont lue dans le binaire, correctifs de la distribution invisibles) et ne sont pas
  traités ici.
