# Mesures de performance

Protocole des cibles chiffrées du cahier des charges et de l'architecture (§ 13 et § 21),
écrit en T06 (ADR 0019) et réutilisé par T09, T10, T11, T18 et T21. Une cible non tenue garde
le lot ouvert, sauf nouvelle cible validée par l'utilisateur.

## Machine de référence

Poste de développement de l'utilisateur (décision du 31 octobre 2026) : 16 cœurs, 30 Go
de RAM, disque NVMe, Linux, PostgreSQL 16 local avec la configuration par défaut de la
distribution. Chaque mesure consignée ci-dessous indique la machine qui l'a produite ;
une mesure faite sur une machine moins puissante que la référence et qui tient la cible
vaut pour la référence.

## Protocole

- **Base** : base jetable de `dbtest` (migrations appliquées), requêtes par le **rôle
  d'exécution**, donc **RLS active** ; `ANALYZE` passé par le rôle propriétaire après la
  génération du jeu.
- **Répétitions** : au moins 20 passages par mesure (50 pour les lectures), **95e
  centile** retenu ; médiane et maximum consignés.
- **Cache froid et chaud** : froid = premier passage après l'ouverture de la base Grype
  (ou après la génération du jeu) ; chaud = passages suivants. Le cache du système de
  fichiers n'est pas vidé (pas de droits d'administration requis) : le froid mesure les
  caches applicatifs (Grype, PostgreSQL), pas le disque.
- **Sans `-race`**, binaires de test compilés normalement.

## Jeu de données synthétique

`internal/benchdata.Generate(ctx, pool, org, slug, benchdata.Reference())` : une
organisation de **1 000 projets** (dépôts, une branche `main` chacun), **1 million de
liens** composant × ensemble (1 000 composants par projet, distincts, pris par un pas
multiplicatif parmi **60 013 composants** répartis sur npm, maven, pypi, golang et deb),
un instantané courant par référence, **5 000 vulnérabilités** au catalogue (2 % critiques,
15 % élevées, 50 % moyennes, 30 % faibles, 3 % inconnues, 1 % KEV, EPSS uniforme) et
environ **75 000 constats** (un composant sur 20 vulnérable, un sur 40 deux fois ; un
constat sur dix résolu). Génération en SQL `generate_series`, déterministe, sous la RLS :
environ une minute. `benchdata.SyntheticCycloneDX(n, variante)` produit un SBOM
CycloneDX 1.6 de n composants (dix paquets réellement vulnérables, le reste synthétique),
chaque variante étant un inventaire distinct.

Pour la recherche (T09), `benchdata.AddSearchFixtures` complète le jeu : `pkg:npm/lodash`
en 31 versions (4.17.0 à 4.17.29 et « latest », illisible selon npm), une par projet (le
cas le plus lourd d'une plage `vers` : une occurrence par projet), et une empreinte
SHA-256 sur 1 000 composants. Le jeu de `Generate` n'a qu'une version par paquet et
aucune empreinte.

Pour le lot 2 (T18), `benchdata.AddTeamsAndContainers(ctx, pool, org, params,
benchdata.ReferenceTeams())` complète le jeu : **10 équipes** entre lesquelles les
1 000 dépôts sont répartis (`p-<n>` dans l'équipe `n mod 10`), **50 hôtes** répartis de
même, portant chacun **10 conteneurs** enfants dans l'équipe de leur hôte (550 projets de
plus, 200 composants chacun : 1 110 000 liens au total, 83 270 constats), et une
**décision de triage** de projet pour un constat ouvert sur dix (environ 7 400 :
non affecté, faux positif, affecté, risque accepté à parts égales), qui donne leur statut
aux constats. Environ 40 s de plus. `make bench` et `make bench-search` l'appliquent ; les
mesures « membre d'une équipe » se font avec la visibilité d'une seule équipe (105 projets
sur 1 050), comme un compte qui n'administre pas l'organisation.

## Commandes

```bash
make bench                         # jeu de référence et lectures des écrans (LOTOR_BENCH=1)
LOTOR_TEST_GRYPEDB_DIR=/chemin/db make bench-ingest   # 5 000 composants, vraie base Grype (T11)
make bench-search                  # recherche transverse sur le jeu de référence (T09)
LOTOR_TEST_GRYPEDB_DIR=/chemin/db make test-grypedb   # vraie base Grype : acceptation et 5 000 composants
```

`LOTOR_TEST_GRYPEDB_DIR` désigne le répertoire racine d'une base Grype v6 installée (il
contient `6/vulnerability.db`), par exemple celui de la commande `grype db update`.

## Résultats

### T06 — Ingestion et analyse d'un SBOM de 5 000 composants (cible : 30 s au 95e centile)

`TestIngestAndAnalyze5000` : réception, décodage et rangement, analyse Grype (base v6.1.10
du 30 octobre 2026) et écriture des constats, de bout en bout ; chaque passage est un
nouvel inventaire (variante), donc une analyse complète.

| Machine | Froid | Chaud p50 | Chaud p95 | Maximum | dont ingestion p95 |
| --- | --- | --- | --- | --- | --- |
| Environnement de réalisation (4 cœurs Xeon 2,8 GHz, 15 Gio) | 6,26 s | 6,06 s | **6,45 s** | 6,45 s | 0,70 s |

Ouverture de la base Grype (somme xxh64 comprise) : 2 à 4 s, au démarrage et à chaque
bascule, hors mesure. Cible tenue.

### T06 — Lectures des écrans sur le jeu de référence (sans cible chiffrée)

| Lecture | p50 | p95 | Maximum |
| --- | --- | --- | --- |
| Onglet « Constats » (page de 50, tri par risque) | 3,9 ms | 5,4 ms | 6,4 ms |
| Décomptes par référence d'un projet | 0,9 ms | 1,3 ms | 2,0 ms |
| Fiche vulnérabilité (constats de l'organisation) | 9,7 ms | 13,6 ms | 20,9 ms |
| Fiche composant (famille d'un purl) | 1,5 ms | 3,4 ms | 3,9 ms |

Environnement de réalisation (4 cœurs, 15 Gio) ; génération du jeu : 51 s.

### T09 — Recherche transverse (cible : 2 s au 95e centile, RLS active)

`TestSearchBenchmark` (`make bench-search`) : jeu de référence et compléments, `ANALYZE`
par le propriétaire, puis `search.Service.Search` par le **rôle d'exécution** (RLS
active), un passage froid et 50 chauds par requête ; une page de 20 projets et leurs
occurrences, totaux compris. Environnement de réalisation (4 cœurs Xeon 2,8 GHz,
15 Gio) ; génération du jeu et des compléments : 61 s.

| Requête | Occurrences (projets) | Froid | p50 | p95 | Maximum |
| --- | --- | --- | --- | --- | --- |
| Nom large `lib-1` (1 000 composants, borne atteinte) | 16 675 (1 000) | 317 ms | 238 ms | **348 ms** | 355 ms |
| Nom précis `lib-<i>` | 187 (185) | 19 ms | 19 ms | 24 ms | 34 ms |
| `pkg:npm/lodash vers:npm/<4.17.20` | 648 (648) | 36 ms | 27 ms | 39 ms | 43 ms |
| purl d'un paquet | 15 (15) | 12 ms | 11 ms | 17 ms | 17 ms |
| Vulnérabilité `CVE-2099-…` | 193 (193) | 24 ms | 22 ms | 36 ms | 57 ms |
| Empreinte SHA-256 | 20 (20) | 113 ms | 92 ms | 128 ms | 175 ms |
| Nom large, sévérité moyenne, dépôts, tri par instantané | 524 (500) | 428 ms | 176 ms | 283 ms | 423 ms |
| Nom large, page suivante (curseur) | 16 675 (1 000) | 222 ms | 201 ms | 259 ms | 284 ms |
| Export CSV de `lib-1` (16 675 lignes, 20 passages) | — | — | 795 ms | 939 ms | 939 ms |

Cible tenue, avec une marge d'un facteur cinq sur le pire cas.

Plans (`EXPLAIN ANALYZE` des occurrences, rôle d'exécution) : la plage sur lodash passe par
`component_set_items_component_idx` (4,2 ms), le nom large aussi (15,6 ms pour 16 675
occurrences), la vulnérabilité par `findings_vuln_idx` (8,0 ms) ; `ref_current`,
`tracked_refs` et `projects` (1 000 lignes) sont lus en entier et joints par hachage, ce
que le planificateur préfère à ce volume. La résolution des noms et des empreintes passe
par les fonctions de recherche (ADR 0024) et leurs index GIN `components_name_trgm_idx` et
`components_hashes_idx` ; l'essentiel du temps du nom large est l'agrégat par projet des
16 675 occurrences et de leurs constats. `TestSearchPlansUseTheirIndexes` vérifie ces
index à chaque `make ci` (jeu de 100 projets, parcours séquentiels interdits).

### T10 — Tableau de bord et fiche projet (cible : 1 s au 95e centile)

`TestReferenceDatasetDashboard` (`internal/web`, lancé par `make bench`) : pages HTML
complètes par HTTP (session, garde d'organisation, lectures sous la RLS, rendu), sur le jeu
de référence complété d'un an de statistiques quotidiennes (organisation, et 1 000 projets
× 365 jours) et de 1 000 agents ; 50 passages par page, le premier compté comme froid.

| Page | Froid | p50 | p95 | Maximum |
| --- | --- | --- | --- | --- |
| Tableau de bord, 90 jours | 546 ms | 511 ms | **594 ms** | 651 ms |
| Tableau de bord, 12 mois | 552 ms | 509 ms | **603 ms** | 635 ms |
| Fiche projet, 90 jours | 32 ms | 19 ms | **32 ms** | 37 ms |

Enregistrement des statistiques du jour de l'organisation (job `dashboard.stats_org`) :
0,34 s. Environnement de réalisation (4 cœurs, 15 Gio, partagé avec d'autres tests) ;
cible tenue. Une première version (trois agrégats sur les constats ouverts, familles de
composants regroupées sans réduction préalable) donnait un p95 de 1,8 s.

### T11 — Mesures consolidées du lot 1

Toutes les mesures rejouées le 31 octobre 2026 sur le même commit, l'une après l'autre,
sur l'environnement de réalisation (4 cœurs Intel Xeon 2,8 GHz, 15 Gio, PostgreSQL 16.15),
**moins puissant que la machine de référence** : chaque cible tenue ici vaut pour la
référence. Les cibles elles-mêmes restent « proposées » au cahier des charges, à confirmer
par l'utilisateur.

| Mesure | Commande | Cible | Froid | p50 | p95 | Maximum | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ingestion et analyse, 5 000 composants (base v6.1.10 du 30 octobre 2026) | `make bench-ingest` | 30 s | 5,90 s | 6,07 s | **6,61 s** | 6,61 s | tenue |
| dont ingestion (réception, décodage, rangement) | idem | — | — | — | 0,73 s | — | — |
| Recherche, nom large `lib-1` (16 675 occurrences, 1 000 projets) | `make bench-search` | 2 s | 316 ms | 185 ms | **288 ms** | 359 ms | tenue |
| Recherche, page suivante du nom large (pire cas) | idem | 2 s | 269 ms | 179 ms | **344 ms** | 358 ms | tenue |
| Recherche, nom large filtré | idem | 2 s | 349 ms | 156 ms | 280 ms | 319 ms | tenue |
| Recherche, vulnérabilité (194 projets) | idem | 2 s | 27 ms | 22 ms | 35 ms | 41 ms | tenue |
| Recherche, plage `vers` sur lodash | idem | 2 s | 26 ms | 27 ms | 35 ms | 35 ms | tenue |
| Recherche, empreinte SHA-256 | idem | 2 s | 91 ms | 79 ms | 123 ms | 128 ms | tenue |
| Export CSV de `lib-1` (16 675 lignes) | idem | — | — | 804 ms | 985 ms | 985 ms | — |
| Tableau de bord, 90 jours | `make bench` | 1 s | 550 ms | 548 ms | **626 ms** | 633 ms | tenue |
| Tableau de bord, 12 mois | idem | 1 s | 520 ms | 536 ms | **663 ms** | 797 ms | tenue |
| Fiche projet, 90 jours | idem | 1 s | 38 ms | 24 ms | 34 ms | 38 ms | tenue |

Lectures des écrans (`make bench`, sans cible) : onglet « Constats » p95 8,2 ms, décomptes
par référence 1,4 ms, fiche vulnérabilité 16,2 ms, fiche composant 7,3 ms ; statistiques du
jour 0,33 s.

**Agent serveur** (protocole de T07, `-tags measure -count=3`, binaire réel sous `nobody`
avec `CAP_DAC_READ_SEARCH`, `max_procs` 1, racine `/` sans `/root`, `/home`, `/tmp`, SBOM
gzip 3,5 Mio ; cible : 5 min de CPU et 1 Gio par scan) :

| Passage | Cycle | Durée | CPU | Mémoire maximale |
| --- | --- | --- | --- | --- |
| 1 | envoi | 3 min 52 s | 3 min 8 s | 787 Mio |
| 1 | signal de vie | 2 min 46 s | 2 min 43 s | 881 Mio |
| 2 | envoi | 2 min 37 s | 2 min 33 s | 921 Mio |
| 2 | signal de vie | 2 min 8 s | 2 min 9 s | 897 Mio |
| 3 | envoi | 2 min 25 s | 2 min 22 s | 921 Mio |
| 3 | signal de vie | 2 min 19 s | 2 min 19 s | 859 Mio |

Plafond tenu sur les six cycles : CPU au plus 3 min 8 s (marge 37 %), mémoire au plus
921 Mio (marge 10 %, la plus serrée des cibles ; elle croît avec le nombre de fichiers
parcourus, voir T07). Moindre privilège vérifié à chaque passage (sans la capacité, les
paquets ne sont pas lus). Sur les conteneurs du parc pilote (300 à 400 composants), un
cycle complet prend 3 à 5 s.

### T18 — Mesures consolidées du lot 2, avec les équipes et les conteneurs

Rejouées le 1er novembre 2026 sur le même commit (`44a1715`), l'une après l'autre, sans
autre charge, sur l'environnement de réalisation (**4 cœurs partagés** Intel Xeon
2,8 GHz, 15 Gio, PostgreSQL 16.15), **moins puissant que la machine de référence** :
chaque cible tenue ici vaut pour la référence. Jeu de référence complété des équipes, des
conteneurs et des décisions de triage (ci-dessus) ; base Grype réelle v6.1.10 du
1er novembre 2026 (00:24 UTC), installée par `grype db update`.

| Mesure | Commande | Cible | Froid | p50 | p95 | Maximum | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ingestion et analyse, 5 000 composants, vraie base | `make bench-ingest` | 30 s | 5,54 s | 5,24 s | **5,62 s** | 5,62 s | tenue |
| dont ingestion (réception, décodage, rangement) | idem | — | — | — | 0,60 s | — | — |
| Recherche, nom large `lib-1` (16 837 occurrences, 1 050 projets) | `make bench-search` | 2 s | 328 ms | 311 ms | **437 ms** | 489 ms | tenue |
| Recherche, page suivante du nom large (pire cas) | idem | 2 s | 345 ms | 326 ms | **446 ms** | 522 ms | tenue |
| Recherche, nom large filtré (sévérité, dépôts, tri) | idem | 2 s | 526 ms | 286 ms | 399 ms | 426 ms | tenue |
| Recherche, nom large, **conteneurs compris** (18 507, 1 550 projets) | idem | 2 s | 296 ms | 290 ms | 386 ms | 406 ms | tenue |
| Recherche, nom large, **membre d'une équipe** (1 688, 105 projets) | idem | 2 s | 212 ms | 232 ms | 339 ms | 442 ms | tenue |
| Recherche, nom large, **filtre équipe** | idem | 2 s | 149 ms | 181 ms | 232 ms | 256 ms | tenue |
| Recherche, vulnérabilité (201 projets) | idem | 2 s | 25 ms | 19 ms | 29 ms | 32 ms | tenue |
| Recherche, vulnérabilité, **membre d'une équipe** | idem | 2 s | 20 ms | 15 ms | 22 ms | 30 ms | tenue |
| Recherche, vulnérabilité, **filtre triage** et conteneurs | idem | 2 s | 19 ms | 18 ms | 29 ms | 30 ms | tenue |
| Recherche, plage `vers` sur lodash (677 projets) | idem | 2 s | 31 ms | 44 ms | 51 ms | 53 ms | tenue |
| Recherche, empreinte SHA-256 | idem | 2 s | 81 ms | 74 ms | 104 ms | 110 ms | tenue |
| Export CSV de `lib-1` (16 837 lignes, 20 passages) | idem | — | — | 654 ms | 810 ms | 810 ms | — |
| Export CSV de `lib-1`, conteneurs compris (18 507 lignes) | idem | — | — | 739 ms | 945 ms | 945 ms | — |
| Tableau de bord, 90 jours (administrateur) | `make bench` | 1 s | 532 ms | 656 ms | **814 ms** | 821 ms | tenue |
| Tableau de bord, 12 mois (administrateur) | idem | 1 s | 628 ms | 679 ms | **841 ms** | 884 ms | tenue |
| Tableau de bord, 90 jours, **membre d'une équipe** | idem | 1 s | 752 ms | 405 ms | 752 ms | 857 ms | tenue |
| Tableau de bord, 12 mois, **membre d'une équipe** | idem | 1 s | 490 ms | 459 ms | 567 ms | 598 ms | tenue |
| Fiche projet, 90 jours | idem | 1 s | 36 ms | 30 ms | 36 ms | 38 ms | tenue |
| Fiche d'un **hôte et de ses 10 conteneurs** (périmètre) | idem | 1 s | 37 ms | 31 ms | 39 ms | 47 ms | tenue |
| Fiche d'un **conteneur** | idem | 1 s | 21 ms | 23 ms | 29 ms | 49 ms | tenue |
| Fiche projet, membre d'une équipe | idem | 1 s | 23 ms | 23 ms | 28 ms | 33 ms | tenue |

Lectures des écrans (`make bench`, sans cible) : onglet « Constats » p95 14,9 ms,
décomptes par référence 3,3 ms, fiche vulnérabilité 25,2 ms (membre d'une équipe
12,2 ms), fiche composant 6,9 ms (membre 1,5 ms) ; statistiques du jour de l'organisation
0,43 s ; génération du jeu 44 s et du complément 40 s.

Comparaison avec le lot 1 (T11, même machine) : la recherche large passe de 288 à 437 ms
au 95e centile et le tableau de bord de 626-663 à 814-841 ms, sur un jeu plus gros
(1 550 projets au lieu de 1 000, 1,11 million de liens), avec le filtre des équipes (T16)
et le statut de triage (T14) dans les requêtes ; la part de chacun n'a pas été isolée. La
cible la plus serrée reste le tableau de bord (marge de 16 %). Plan du nom large (`EXPLAIN ANALYZE`, rôle d'exécution, visibilité de toutes les équipes) : le
planificateur part désormais des 1 050 projets visibles (`projects_org_id_id_kind_key`)
et lit leurs liens par `component_set_items_pkey` (1 050 boucles, 301 ms pour le
décompte), au lieu de `component_set_items_component_idx` au lot 1 (15,6 ms) ; la plage
sur lodash (7,6 ms) et la vulnérabilité (`findings_vuln_idx`, 4,6 ms) gardent leurs
index. Les cibles du cahier des
charges restent « proposées », à confirmer par l'utilisateur.

**Agent serveur** (protocole de T07, `-tags measure -count=2`, binaire réel sous `nobody`
avec `CAP_DAC_READ_SEARCH`, `max_procs` 1, racine `/` sans `/root`, `/home`, `/tmp`, SBOM
gzip 3,5 Mio ; cible : 5 min de CPU et 1 Gio par scan). Le scan de l'hôte est hors ligne
depuis T13 (plus de `go list` sous `/`) :

| Passage | Cycle | Durée | CPU | Mémoire maximale |
| --- | --- | --- | --- | --- |
| 1 | envoi | 3 min 22 s | 2 min 13 s | 791 Mio |
| 1 | signal de vie | 2 min 4 s | 2 min 1 s | 782 Mio |
| 2 | envoi | 1 min 57 s | 1 min 51 s | 794 Mio |
| 2 | signal de vie | 1 min 43 s | 1 min 43 s | 819 Mio |

Plafond tenu sur les quatre cycles : CPU au plus 2 min 13 s (marge 56 %, contre 3 min 8 s
au lot 1), mémoire au plus 819 Mio (marge 20 %, contre 921 Mio) ; moindre privilège
vérifié à chaque passage. Conteneurs (recette du lot 2, Docker 29.9 et Podman 4.9) : une
image Alpine ou Redis s'inventorie en 1,5 à 3 s, nginx (64 composants) en 2,4 s ; une
image partagée par deux projets n'est scannée qu'une fois.

### T21 — Recherche à une date passée (cible : 5 s au 95e centile, RLS active)

Mesurée le 4 novembre 2026 (`make bench-search`, `TestSearchAtBenchmark`), sans autre
charge, sur l'environnement de réalisation (**4 cœurs partagés** Intel Xeon 2,1 GHz,
15 Gio, PostgreSQL 16), moins puissant que la machine de référence. Jeu de référence
complété des équipes et des conteneurs (T18), puis de **12 mois d'historique** :
52 instantanés hebdomadaires par référence (80 600 instantanés de plus), chacun reprenant
l'ensemble courant d'une autre référence (`benchdata.AddHistory`), si bien que
l'inventaire d'une date diffère de l'inventaire courant sans multiplier les liens.

| Mesure | Cible | Froid | p50 | p95 | Maximum | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| Nom large `lib-1` il y a 6 mois (12 360 occurrences, 1 050 projets) | 5 s | 805 ms | 1,36 s | **1,55 s** | 1,60 s | tenue |
| Nom large `lib-1`, date variable sur 12 mois | 5 s | 1,32 s | 1,33 s | **1,47 s** | 1,51 s | tenue |
| Nom précis `lib-<i>` il y a 11 mois (142 projets) | 5 s | 42 ms | 38 ms | 53 ms | 63 ms | tenue |
| Plage `vers` sur lodash il y a 3 mois (681 projets) | 5 s | 119 ms | 109 ms | 160 ms | 165 ms | tenue |
| Empreinte il y a 9 mois | 5 s | 64 ms | 50 ms | 75 ms | 80 ms | tenue |
| Nom large, membre d'une équipe, conteneurs compris, il y a 6 mois | 5 s | 320 ms | 265 ms | 319 ms | 430 ms | tenue |
| Export CSV du nom large il y a 6 mois | — | — | 1,54 s | 1,69 s | — | — |

Plan (`EXPLAIN ANALYZE`, RLS active) des occurrences de `lib-1` il y a 6 mois : 115 ms ;
pour chacune des 1 550 références, l'instantané en vigueur est lu par
`snapshots_ref_idx` (jointure latérale, une ligne), puis les éléments de l'ensemble par
la clé de `component_set_items` : aucune lecture de l'historique complet. Le reste du
temps est celui des pages et des détails, comme pour la recherche courante. Les mesures de
la recherche courante, rejouées dans la même session, restent inchangées (p95 ≤ 318 ms).

### Agent serveur — index compact de l'arborescence (ADR 0055)

Protocole de T07 (`-tags measure`, binaire réel sous `nobody` avec `CAP_DAC_READ_SEARCH`,
`max_procs` 1, deux cycles : envoi puis signal de vie), le 4 novembre 2026, dans le
conteneur de développement de l'assistant (4 cœurs, Ubuntu 24.04, 311 000 fichiers sous
`/`, système de fichiers en overlay, plus lent que le poste de référence). Version
précédente (source « répertoire » de Syft) contre version de l'ADR 0055 (index compact et
répertoires de données exclus), compilées avec `CGO_ENABLED=0` :

| Racine | Version | Cycle | Durée | CPU | Mémoire maximale | SBOM gzip |
| --- | --- | --- | --- | --- | --- | --- |
| `/` sans `/root`, `/home`, `/tmp` | précédente | envoi | 2 min 4 s | 1 min 59 s | 946 Mio | 3 536 Kio |
| | précédente | signal de vie | 1 min 56 s | 1 min 56 s | 883 Mio | 3 536 Kio |
| | index | envoi | 59 s | 55 s | 512 Mio | 3 534 Kio |
| | index | signal de vie | 59 s | 58 s | 517 Mio | 3 534 Kio |
| `/` entière | précédente | envoi | 8 min 42 s | 8 min 33 s | **1 782 Mio** | 5 832 Kio |
| | précédente | signal de vie | 7 min 42 s | 7 min 39 s | **2 034 Mio** | 5 832 Kio |
| | index | envoi | 1 min 32 s | 1 min 27 s | 564 Mio | 4 357 Kio |
| | index | signal de vie | 1 min 21 s | 1 min 21 s | 563 Mio | 4 357 Kio |

Sur la racine entière, la version précédente dépasse `MemoryMax=1536M` de l'unité
systemd : c'est l'échec constaté sur un serveur réel. Avec l'index, la durée est divisée par
deux à six et la mémoire ne dépend plus du volume de fichiers de données ; elle reste dominée
par les catalogueurs de Syft (listes de fichiers des paquets dpkg, classification des
binaires), autour de `memory_limit_mib` (512 Mio, limite douce du ramasse-miettes). Sur `/`
entière, l'écart de taille du SBOM vient des nouvelles exclusions (`/tmp`, `~/.cache`) ;
à exclusions égales, `TestIndexSourceMatchesSyftDirectory` (`LOTOR_PARITY_ROOT=/`) donne les
mêmes composants et la même empreinte que la source de Syft (4 615 avant les nouvelles
exclusions, 4 261 avec). Profil CPU du scan avec
l'index : la recherche dans l'index compte pour 17 % ; le reste est le travail propre des
catalogueurs, identique avec les deux sources.
