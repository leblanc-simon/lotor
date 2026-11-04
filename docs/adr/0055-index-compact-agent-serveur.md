# 0055 — Agent serveur : index compact de l'arborescence, répertoires de données exclus

- Statut : Accepté
- Date : 2026-11-04
- Lot : hors lot (retour de l'utilisateur sur un serveur réel)

## Contexte

Sur un vrai serveur, la génération du SBOM par `lotor-host-agent` échoue : l'agent semble
parcourir tous les fichiers. La cause est dans la source « répertoire » de Syft 1.55
(`syft/internal/fileresolver`), utilisée depuis T07 :

- avant tout catalogage, elle construit un arbre en mémoire de **tous** les fichiers sous
  la racine, environ 2 Kio par fichier ;
- pour **chaque** fichier ordinaire, elle l'ouvre et lit son en-tête pour en deviner le
  type MIME (`NewMetadataFromPath`), y compris les bases de données, journaux, sauvegardes
  et données applicatives.

Mesuré sur un conteneur de développement de 311 000 fichiers : 700 Mio à 1,6 Gio de
mémoire selon le parallélisme, plus de dix minutes de scan. Un serveur de quelques
millions de fichiers dépasse `MemoryMax=1536M` de l'unité systemd (arrêt par manque de
mémoire) ou `scan.max_duration`. Or les catalogueurs ne lisent qu'une poignée de fichiers :
bases de paquets, manifestes, archives, binaires. Une sonde sur un scan réel montre qu'ils
n'utilisent que des motifs `**/…` ou absolus, une seule famille de types MIME (celle des
exécutables), des chemins précis et, pour Nix seulement, le parcours de toutes les entrées.

## Décision

- **Index compact** (`hostagent.fsIndex`) : un seul parcours de la racine (`lstat`,
  `readlink`), sans ouvrir aucun fichier ni suivre de lien de répertoire. Chaque entrée
  garde son chemin vu depuis la racine (dans une arène commune), son type et son bit
  d'exécution, environ 80 octets ; entrées triées pour la recherche par chemin. Mêmes
  règles d'indexation que Syft : répertoires, fichiers ordinaires et liens seulement,
  chemins illisibles ignorés, exclusions appliquées pendant le parcours.
- **Source et résolveur propres** (`indexSource`, `indexResolver`), donnés à
  `syft.CreateSBOM` par les interfaces publiques `source.Source` et `file.Resolver` : les
  catalogueurs et leur configuration ne changent pas. Liens suivis à l'intérieur de la
  racine (cible absolue depuis la racine, « .. » arrêté à la racine, 40 sauts au plus),
  un fichier atteint par un lien renvoyé une seule fois avec son chemin réel, répertoires
  jamais renvoyés comme fichiers. Métadonnées lues sur le disque à la demande.
- **Types MIME à la demande, pour les seuls candidats binaires** : fichiers exécutables,
  bibliothèques (`*.so`, `*.so.*`, `*.dylib`) et binaires Windows (`*.dll`, `*.exe`). Un
  binaire ELF sans bit d'exécution ni nom de bibliothèque n'est plus reconnu : un tel
  fichier n'est pas exécutable en l'état, donc pas un logiciel installé.
- **Motifs filtrés par simple comparaison** avant `doublestar` : nom exact, `*.ext`,
  `préfixe*`, `{a,b}` ; un motif `**/chemin/littéral/*` (licences des modules Go,
  cherchées une fois par module de chaque binaire Go) ne parcourt que les enfants des
  répertoires qui finissent par ce chemin.
- **Répertoires de données exclus par défaut** (`DefaultExclusions`) : `/tmp`, `/var/tmp`,
  `/var/log`, `/var/cache`, `/var/spool`, `/var/mail`, `/var/backups`, `/var/crash`,
  `/lost+found`, `/var/lib/apt/lists`, `~/.cache`, et les données des bases et courtiers
  usuels sous `/var/lib` (PostgreSQL, MySQL/MariaDB, MongoDB, Redis, Elasticsearch,
  OpenSearch, ClickHouse, InfluxDB, Cassandra, RabbitMQ, Prometheus). Les noyaux
  (`/boot`, `/lib/modules`) restent inventoriés. Les systèmes de fichiers virtuels du
  noyau sont écartés par leur type de montage, où qu'ils soient montés.
- `github.com/anchore/stereoscope` (références de fichier de Syft) et
  `github.com/bmatcuk/doublestar/v4`, déjà dans le graphe de Syft, deviennent des imports
  directs de `hostagent` ; `internal/archtest` réserve stereoscope à ce paquet.

## Conséquences

- La mémoire suit le nombre de fichiers à environ 80 octets chacun, au lieu de 2 Kio, et
  aucun fichier n'est lu sans qu'un catalogueur le demande. Mesures (protocole de T07) dans
  `docs/benchmarks.md`.
- **Parité vérifiée** par `TestIndexSourceMatchesSyftDirectory` : même inventaire et même
  empreinte que la source « répertoire » de Syft sur `testdata/rootfs`, et, hors CI avec
  `LOTOR_PARITY_ROOT=/`, sur la racine d'un hôte réel (Ubuntu 24.04 de développement :
  4 615 composants identiques avant les nouvelles exclusions, 4 261 avec).
- Le résolveur dépend du contrat de `file.Resolver`, pas de l'implémentation interne de
  Syft : une montée de version de Syft qui ajouterait un catalogueur interrogeant
  d'autres types MIME que ceux des exécutables le contournerait. Le test de parité sur une
  vraie racine fait partie de la recette d'une montée de version de Syft.
- Les nouvelles exclusions changent l'inventaire de certains hôtes : chaque agent enverra
  un SBOM complet à son premier scan après la mise à jour (empreinte différente), puis
  reprend l'envoi conditionnel.
