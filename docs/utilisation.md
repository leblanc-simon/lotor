# Guide d'utilisation

Ce guide décrit l'usage de lotor par les membres d'une organisation. L'installation
et l'exploitation du serveur sont dans [`operations.md`](operations.md) ; les premiers pas
(connexion, organisation, inscription des serveurs et des dépôts) dans le
[guide de démarrage](demarrage.md). Les sections s'ajoutent au fil des lots.

## Recherche

L'écran **Recherche** d'une organisation (`/o/<organisation>/search`) répond à « qui
utilise ce composant, cette version, cette plage de versions ? » et « qui est touché par
cette vulnérabilité ? », dans l'inventaire courant des projets de l'organisation que vous
voyez (ceux de vos équipes, ou tous si vous administrez l'organisation ; projets archivés
et références retirées exclus). Il ne sort jamais de l'organisation.

### Ce qu'on peut chercher

Une seule barre ; le type de requête est déduit de sa forme et rappelé sous la barre
(« Interprété comme »).

| Saisie | Type | Résultat |
| --- | --- | --- |
| `log4j-core` | nom de composant | les composants dont le nom contient le texte (sans casse), toutes versions et tous écosystèmes ; s'il n'y en a aucun, ceux dont le nom lui ressemble (faute de frappe), signalés comme approchés. Moins de trois caractères : nom exact. |
| `pkg:npm/lodash` | purl | toutes les versions du paquet |
| `pkg:npm/lodash@4.17.20` | purl avec version | cette version, quels que soient ses qualificatifs ; ajouter des qualificatifs (`?arch=amd64`) restreint encore |
| `pkg:npm/lodash vers:npm/<4.17.21` | purl et plage | les versions du paquet dans la plage, comparées selon les règles de l'écosystème |
| `CVE-2021-44228`, `GHSA-jfh8-c2jp-5v3q` | vulnérabilité | les projets touchés, avec le statut du constat et la version corrigée ; un GHSA est ramené à son CVE |
| `sha256:0925e8ad…` ou les 64 caractères seuls | empreinte | les composants qui portent ce fichier, et leurs projets |
| `license:AGPL-3.0-only`, `license:LicenseRef-acme` | licence | les composants qui déclarent cette licence, seule ou dans une expression (`MIT OR AGPL-3.0-only`), sans casse, et leurs projets ; un seul identifiant, pas d'expression |

### Plages de versions

Une plage suit le format [vers](https://github.com/package-url/purl-spec/blob/main/VERSION-RANGE-SPEC.rst) :
`vers:<schéma>/<contraintes>`, contraintes séparées par `|`, comparateurs `=` (par défaut),
`!=`, `<`, `<=`, `>`, `>=`, ou `*` pour toutes les versions. Exemples :

- `vers:npm/<4.17.21` : avant 4.17.21 ;
- `vers:maven/>=2.0-beta9|<2.15.0` : de 2.0-beta9 inclus à 2.15.0 exclu ;
- `vers:pypi/>=1.0|!=1.5|<2.0` : de 1.0 à 2.0 sauf 1.5 ;
- `vers:deb/<1:1.0` : avec l'époque Debian.

Le schéma doit être celui du paquet (`vers:npm` pour `pkg:npm`, `vers:deb` pour `pkg:deb`,
`vers:alpine` pour `pkg:apk`…). Les versions sont comparées selon l'écosystème (npm,
Maven, PEP 440, RubyGems, modules Go, Debian, RPM, Alpine, semver pour les autres), jamais
comme du texte : `4.9.0` est bien avant `4.17.21`. Une plage ne s'applique qu'à un purl
sans version : une recherche par nom n'en accepte pas.

Sous les résultats, l'écran indique combien d'occurrences du paquet sont hors de la plage
(avec un lien pour retirer la plage), et liste les versions **non comparables** (par
exemple `latest`) : on ne peut pas dire si elles sont dans la plage, elles ne sont donc pas
affichées, mais elles ne sont pas oubliées.

### Filtres, ordre et partage

Les filtres se combinent : type de projet (« Inclure les conteneurs » ajoute les
conteneurs des serveurs, écartés sinon ; paramètre `containers=1`), **équipe**
propriétaire (`team=<identifiant>`, parmi les équipes que vous voyez), étiquette, origine
de la détection (Syft ou IA), vulnérabilité activement exploitée (KEV), sévérité maximale
(ou « sans vulnérabilité »), et, pour une recherche par vulnérabilité, les constats déjà
résolus et le **statut de triage** (`triage=`, à analyser, affecté, non affecté…).

Une recherche par vulnérabilité montre le statut de triage de chaque constat, avec un lien
vers sa fiche ; elle montre aussi les constats triés « non affecté » ou « faux positif »
(qui répondent à la question « sommes-nous touchés ? »). Une recherche par composant, elle,
ne compte pas ces constats dans les vulnérabilités ouvertes et la sévérité, comme les
listes de constats. Chaque projet des résultats indique son équipe.
Dans un même filtre, les valeurs cochées s'additionnent. Les résultats sont groupés par
projet, triés par risque, par nom ou par instantané le plus récent, vingt projets par page.

Requête, filtres et ordre sont dans l'adresse de la page : la copier suffit pour partager
exactement le même résultat avec un autre membre de l'organisation.

### À une date passée

Le champ **À la date du** (paramètre `at=AAAA-MM-JJ`) répond à « quels projets utilisaient
ce composant à telle date ? », par exemple pour mesurer une exposition passée pendant une
réponse à incident. Pour chaque référence, la recherche porte sur l'instantané **en
vigueur ce jour-là** : le dernier scanné au plus tard à la fin de la journée (UTC). Chaque
occurrence indique la date de l'instantané retenu. Une date et heure précise s'écrit aussi
en RFC 3339 (`at=2026-09-10T12:00:00Z`, instant exclu).

- Les projets archivés et les références retirées depuis comptent : la question porte sur
  l'état d'alors.
- Les vulnérabilités ne sont pas montrées : la base de vulnérabilités et les constats de
  l'époque ne sont pas conservés. Une recherche par vulnérabilité, ou les filtres de
  sévérité, d'exploitation (KEV) et de résolution, sont refusés à une date passée ;
  cherchez le composant, puis ouvrez la recherche sans date pour l'état actuel.
- Les anciens instantanés sont éclaircis par la rétention (90 jours complets, puis le
  dernier instantané de chaque mois) : une date antérieure à la dernière coupure affiche
  l'avertissement **Résultat partiel**, car l'état retenu peut alors être celui de la fin
  du mois précédent ou plus ancien.

### Export

« Exporter en CSV » et « Exporter en JSON » donnent toutes les occurrences de la
recherche (pas seulement la page affichée), avec projet, référence, commit, composant,
version, purl, origine, vulnérabilités ouvertes, sévérité, KEV, risque, versions
corrigées, et, en fin de ligne, équipe, statut de triage et emplacements (colonnes
`team`, `triage_status` et `locations` : chemins principaux séparés par « ; » ; l'export
JSON donne la liste entière). Dans le CSV, une cellule qui commencerait par `=`, `+`, `-` ou `@` est préfixée
d'une apostrophe, pour qu'un tableur ne l'interprète pas comme une formule.

### Par l'API

La même recherche existe dans l'API, avec les mêmes paramètres et les mêmes résultats :

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://lotor.example/api/v1/orgs/<organisation>/search?q=CVE-2021-44228&kev=1"
curl -H "Authorization: Bearer $LOTOR_TOKEN" -o lodash.csv \
  "https://lotor.example/api/v1/orgs/<organisation>/search/export?format=csv&q=pkg:npm/lodash+vers:npm/%3C4.17.21"
```

Le jeton est un **jeton d'accès personnel**, créé depuis « Mon compte » → « Jetons
d'accès » : il expire (7 jours à 1 an), il est affiché une seule fois, il se révoque à
tout moment, et il ne donne que la lecture de ce que votre compte voit, dans les
organisations dont vous êtes membre au moment de chaque requête. Le contrat de l'API est
dans `api/openapi.yaml` (opérations `searchOrganization` et `exportSearch`).

## Emplacements des composants

Chaque composant trouvé par Syft garde les fichiers qui l'ont fait trouver : base de
paquets (`/var/lib/dpkg/status`, `/lib/apk/db/installed`…), manifeste (`go.mod`,
`package-lock.json`…), archive (`.jar`) ou binaire. Les listes de constats, la recherche,
les composants d'un instantané et la fiche d'un composant montrent les emplacements
principaux (trois au plus, puis le nombre des autres) ; la fiche d'un constat les montre
tous, avec le chemin par lequel l'analyse a atteint le fichier s'il diffère (lien
symbolique), la couche de l'image et la mention « secondaire » pour les fichiers d'appoint
d'un paquet (copyright, listes de fichiers). Un constat résolu garde les emplacements où il
était.

Les emplacements viennent du SBOM : complets en Syft JSON (agent serveur), sans chemin
d'accès en CycloneDX (agent dépôt), absents en SPDX (« Non renseigné »). Les inventaires
reçus avant la version qui les garde n'en ont pas : ils apparaissent au scan suivant.

## Historique et comparaison des instantanés

L'onglet **Instantanés** d'un projet présente la **frise** des instantanés de chaque
référence (branche, tag ou hôte), du plus récent au plus ancien. Chaque instantané
indique ce qui a changé depuis le précédent de la même référence : composants
**ajoutés**, **retirés**, **montés** ou **descendus de version** (deux versions d'un même
paquet forment une montée ou une descente, comparées selon les règles de leur
écosystème : npm, Maven, PEP 440, Debian…), ou « inventaire identique ».

« Comparer avec le précédent », ou le formulaire **Comparer deux instantanés** (deux
instantanés quelconques du projet, de références différentes au besoin), ouvre la
comparaison :

- les décomptes de chaque nature de changement, puis la liste des composants changés,
  filtrable par nature ; « Inverser » échange départ et arrivée ;
- l'**effet sur la sécurité** : les **constats résolus** (vulnérabilités des composants
  retirés ou remplacés, absentes de leur nouvelle version — une montée de version qui
  corrige une CVE apparaît ici) et les **constats introduits** (vulnérabilités des
  composants ajoutés ou de leur nouvelle version). Une vulnérabilité présente avant et
  après n'apparaît dans aucune des deux listes. Tant que le dernier instantané n'est pas
  analysé, l'écran prévient que des constats introduits peuvent manquer.

Les instantanés anciens sont réduits par la **rétention** : par défaut, tous ceux des
90 derniers jours sont gardés, puis le dernier de chaque mois, sans limite de durée ; le
dernier instantané d'une référence n'est jamais supprimé. La frise rappelle la politique
de l'instance.

La même frise et la même comparaison existent dans l'API (opérations
`listProjectSnapshots` et `compareSnapshots`) :

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://lotor.example/api/v1/orgs/<organisation>/projects/<projet>/snapshots"
curl -H "Authorization: Bearer $LOTOR_TOKEN" \
  "https://lotor.example/api/v1/orgs/<organisation>/projects/<projet>/compare?to=<instantané>&kind=upgraded"
```

Sans `from`, la comparaison part de l'instantané précédent de `to`.

## Équipes, rôles et invitations

Chaque projet appartient à une **équipe**. Vous voyez les projets de vos équipes — dans
les listes, la recherche, le tableau de bord, les fiches des vulnérabilités et des
composants, les exports et l'API —, et vous y agissez selon votre **rôle d'équipe** :

| Rôle d'équipe | Ce qu'il permet sur les projets de l'équipe |
| --- | --- |
| Lecteur | Consulter les projets, leurs constats, instantanés et SBOM, et les agents de l'équipe |
| Analyste | En plus : demander un scan à un agent serveur, trier les constats, importer un VEX pour un projet |
| Administrateur d'équipe | En plus : créer, modifier, archiver un projet de l'équipe, le confier à un agent, le rattacher à une autre équipe qu'il administre aussi ; gérer les agents et jetons d'inscription de l'équipe ; ajouter et retirer les membres de l'équipe |

Un **administrateur de l'organisation** voit et gère tout : il crée, renomme et supprime
les équipes, invite et retire les membres, règle l'organisation et lit son journal. Un
membre qui n'est dans aucune équipe ne voit aucun projet. La matrice complète est dans
[`security/permissions.md`](security/permissions.md).

**Équipes.** La page **Équipes** liste vos équipes (toutes pour un administrateur de
l'organisation). La page d'une équipe montre ses membres et mène à ses projets ; son
administrateur y ajoute un membre de l'organisation par son adresse, change son rôle ou le
retire. Une équipe ne se supprime qu'une fois tous ses projets rattachés à une autre.

**Agents.** Un agent d'équipe ne sert que les projets de son équipe et se gère par ses
administrateurs ; un agent d'organisation (sans équipe) sert toutes les équipes et ne se
gère que par les administrateurs de l'organisation. Un jeton d'inscription appartient à
une équipe : les serveurs qu'il inscrit, et leurs agents, entrent dans cette équipe.

**Invitations.** Pour rejoindre une organisation, un compte doit être **invité** par un de
ses administrateurs, puis **accepter** l'invitation depuis « Mon compte » → « Invitations »
(elle vaut 30 jours ; la décliner la supprime). L'administrateur ne sait pas, en invitant,
si l'adresse a déjà un compte. Chaque invitation porte un **lien** : envoyé par courriel,
dans la langue de l'administrateur qui invite, si l'instance envoie des courriels, ou
affiché une seule fois sur la page des membres, à transmettre. Ce lien crée le compte de
l'adresse invitée (mot de passe choisi, second facteur aussitôt configuré), ou mène à la
connexion pour accepter ; une nouvelle invitation de la même adresse le remplace. Un compte
créé plus tard par l'administration de l'instance peut aussi accepter l'invitation tant
qu'elle court.

## Triage des constats et VEX

Chaque constat porte un **statut de triage** :

| Statut | Sens |
| --- | --- |
| À analyser | Aucune conclusion pour l'instant (statut par défaut, sans décision) |
| Affecté | Le code vulnérable est atteignable : la correction doit être planifiée |
| Non affecté | Présent mais sans impact, avec une justification VEX |
| Faux positif | Le composant ou sa version ont été mal identifiés |
| Risque accepté | Accepté jusqu'à une date ; le lendemain, le constat revient « à analyser » |
| Corrigé | Correctif déployé ; le prochain instantané le confirmera |

**Trier un constat.** Depuis l'onglet « Constats » d'un projet (ou la fiche d'une
vulnérabilité), le statut d'une ligne mène à la **fiche du constat** : son résumé, le
panneau de triage (rôle analyste ou administrateur dans l'équipe du projet) et son
historique. Une décision demande un commentaire, repris dans l'historique et dans les
exports VEX ; « non affecté » demande une justification VEX, « risque accepté » une date.

**Portée.** Une décision vaut pour **ce projet** — ce composant, dans toutes les références
du projet — ou, pour un administrateur de l'organisation, pour **toute l'organisation** —
tous les composants de la même famille (même purl sans version), éventuellement
restreints à une plage `vers` (`vers:maven/<2.17.0`). Le statut d'un constat est celui de
la décision du projet, sinon de la plus récente décision de l'organisation qui le couvre,
sinon « à analyser ». Une décision vaut aussi pour les constats à venir : un nouveau
projet qui embarque le même composant en hérite dès son analyse. Une décision se retire
depuis l'historique (le constat reprend alors la décision de l'organisation, ou « à
analyser ») ; les décisions de l'organisation se gèrent dans la rubrique **Triage**.

**Constats masqués.** L'onglet « Constats » masque par défaut les constats « non
affecté » et « faux positif » (le nombre masqué s'affiche, « Tout afficher » les montre) ;
le filtre « Statut de triage » choisit un statut. Le tableau de bord ne les compte pas
parmi les constats ouverts.

**Exporter.** L'onglet « VEX » d'un projet télécharge ses décisions en **OpenVEX 0.2.0**
ou en **CycloneDX 1.6** : une déclaration par composant et vulnérabilité des constats
ouverts qui ont une décision. Par l'API :

```bash
curl -H "Authorization: Bearer $LOTOR_TOKEN" -o portail.openvex.json \
  "https://lotor.example/api/v1/orgs/<organisation>/projects/<projet>/vex?format=openvex"
```

**Importer le VEX d'un éditeur** (OpenVEX ou CycloneDX, JSON, 1 Mio au plus) : depuis
l'onglet « VEX » d'un projet, chaque déclaration devient une décision du projet sur les
composants de ses constats de même paquet et de même version ; depuis la rubrique
« Triage » de l'organisation, une décision de l'organisation sur la famille du composant,
restreinte à la version déclarée. Les décisions importées ont pour auteur
`vex:<source>`. Un export réimporté dans le même format redonne les mêmes décisions.

**Correspondance entre les formats.** Les deux formats n'ont pas les mêmes statuts ni les
mêmes justifications. lotor garde la justification telle qu'elle a été donnée et, à
l'export vers l'autre format, écrit la plus proche en notant l'originale :

| CycloneDX | OpenVEX |
| --- | --- |
| `code_not_present` | `vulnerable_code_not_present` |
| `code_not_reachable` | `vulnerable_code_not_in_execute_path` |
| `requires_configuration`, `requires_environment` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `requires_dependency` | `component_not_present` |
| `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` | `inline_mitigations_already_exist` |

En sens inverse, `component_not_present` et `vulnerable_code_not_present` deviennent
`code_not_present`, `vulnerable_code_not_in_execute_path` `code_not_reachable`,
`vulnerable_code_cannot_be_controlled_by_adversary` `requires_environment`,
`inline_mitigations_already_exist` `protected_by_mitigating_control`. « Faux positif » et
« risque accepté », absents d'OpenVEX, y sont écrits `not_affected` et `affected` avec une
note `[lotor:…]` dans `status_notes` ; CycloneDX a `false_positive`, et « risque accepté »
y devient `exploitable` avec la réponse `will_not_fix` et des propriétés `lotor:`. Le
détail est dans l'ADR 0036.

## Composants trouvés par l'IA

Pour un dépôt, l'agent dépôt peut compléter l'inventaire de Syft par les composants
qu'aucun manifeste ne déclare : bibliothèque JavaScript ou C recopiée, image de base d'un
Dockerfile, script chargé depuis un CDN, outil installé par un script. Ces composants ont
l'origine **IA** (badge à bordure tiretée, avec la confiance du modèle) ; ceux de Syft,
l'origine **Syft**.

**Réglage.** Dans **Paramètres** du dépôt, section **Enrichissement IA** : *IA désactivée*
(par défaut : aucun modèle n'est appelé), *Modèle local uniquement* (le code ne va qu'au
modèle que l'exploitant de l'agent fait tourner chez lui), ou *Fournisseur externe
autorisé* (le code lu par l'analyse peut partir chez le fournisseur configuré sur l'agent,
hors fichiers sensibles). Seul un administrateur de l'organisation peut autoriser un
fournisseur externe, et l'instance peut l'interdire à tous ; chaque changement est inscrit
au journal d'audit. L'autorisation vaut pour un dépôt : si quelqu'un d'autre qu'un
administrateur de l'organisation change l'URL du dépôt, le réglage revient à *IA
désactivée*. Ce qui part exactement vers le modèle est décrit dans
[`operations.md`](operations.md#enrichissement-ia).

**Preuve.** Un composant IA n'entre dans l'inventaire que si l'agent a relu sa preuve dans
le fichier, au commit analysé. La fiche du composant montre, pour chaque projet qui
l'utilise, le fichier, la ligne, l'extrait, la confiance et le modèle ; la colonne
**Emplacement** y mène. La preuve garantit que le nom et la version figurent dans le
fichier, pas que la détection est juste : la confiance est l'estimation du modèle.

**Où les voir.** La fiche projet compte les composants de chaque référence par origine ;
la liste des composants d'un instantané et la recherche se filtrent par origine. Un
instantané marqué **Enrichissement IA incomplet** ne contient que les composants de Syft
(analyse interrompue : budget dépassé ou erreur du fournisseur) ; **Composants IA
reportés** signale un commit intermédiaire dont les composants IA du commit précédent ont
été revérifiés sans nouvelle analyse.

## Conteneurs des serveurs

Quand l'agent d'un serveur inventorie aussi ses conteneurs (option de l'agent, désactivée
par défaut : voir `docs/operations.md`, « Conteneurs »), chaque conteneur qui tourne
devient un **projet enfant** du projet du serveur, avec son propre SBOM, ses constats et
son historique.

- **Identité** : un service Compose forme un seul projet, nommé `serveur/projet/service`,
  quel que soit le nombre de ses répliques et même s'il est recréé à chaque déploiement ;
  un conteneur lancé sans Compose est suivi par son nom. Deux services sur la même image
  font deux projets, mais l'image n'est analysée qu'une fois.
- **Équipe** : un conteneur appartient toujours à l'équipe de son serveur ; rattacher le
  serveur à une autre équipe y emmène ses conteneurs, et voir le serveur, c'est voir ses
  conteneurs.
- **Fiche du serveur** : le tableau « Conteneurs et constats par périmètre » montre, pour
  le serveur et chacun de ses conteneurs, l'image, l'état (en cours, absent, archivé) et
  les vulnérabilités ouvertes par sévérité. Chaque projet compte ses vulnérabilités
  distinctes : une CVE présente sur le serveur et dans deux conteneurs compte trois fois
  au total, une CVE présente dans deux composants d'un même conteneur une fois.
- **Fiche d'un conteneur** : moteur (Docker, Podman), image et son empreinte, projet et
  service Compose, noms des répliques, démarrage, dernier signalement par l'agent ; son
  fil d'Ariane remonte au serveur.
- **Disparition** : un conteneur que l'agent ne signale plus depuis 7 jours (réglage du
  serveur) est archivé ; il revient de lui-même, avec son historique, s'il redémarre.
  Archiver soi-même le projet d'un conteneur (Paramètres) arrête son inventaire, même
  s'il tourne encore. Un conteneur archivé pour absence depuis 180 jours (réglage du
  serveur) est supprimé avec son historique, sauf s'il porte une décision de triage ; le
  journal d'audit de l'organisation le dit.
- **Listes et recherche** : les conteneurs n'y figurent que si « Inclure les conteneurs »
  est coché ; le tableau de bord de l'organisation, lui, les compte avec les autres
  projets.
## Politiques et alertes

Une **politique** est une règle évaluée sur chaque constat ouvert, ou sur chaque agent :
quand elle est vraie, une **violation** s'ouvre, datée ; elle se résout d'elle-même quand la
règle cesse d'être vraie (version corrigée, constat déclaré non affecté, agent revenu…).
Les administrateurs de l'organisation gèrent les politiques dans **Politiques** et les
canaux dans **Canaux** ; tout membre voit les violations des projets de ses équipes dans
**Violations**, et les plus récentes dans la section « Alertes » du tableau de bord.

### Modèles fournis

| Modèle | Règle | Par défaut |
| --- | --- | --- |
| KEV sur un projet de production | `finding.kev && finding.actionable && has(project.labels.env) && project.labels.env == "production"` | bloquante, envoi immédiat |
| Critique avec correctif depuis plus de 30 jours | `finding.severity == "critical" && finding.actionable && finding.fix_available && finding.fix_age_days > 30` | bloquante, résumé quotidien |
| Agent muet depuis 7 jours | `agent.silent_days >= 7` | résumé quotidien |
| Licence AGPL dans un produit distribué | `license.ids.exists(id, id.startsWith("AGPL-")) && has(project.labels.distribution)` | bloquante, envoi immédiat (règle de constat de licence) |

« Production » se dit par l'étiquette `env=production` du projet. La date d'un correctif
est celle où lotor l'a vu pour la première fois sur le constat.

### Écrire une règle

Les règles s'écrivent en [CEL](https://cel.dev). Variables d'une règle de constat :

- `project` : `name`, `slug`, `kind` (`repo`, `host`, `container`), `team`, `labels`
  (table : `has(project.labels.env)` teste une étiquette, `project.labels.env` la lit),
  `host` (nom du projet de l'hôte d'un conteneur, vide sinon) ; un conteneur **hérite des
  étiquettes de son hôte**, les siennes l'emportant ;
- `component` : `purl`, `purl_base`, `type`, `name`, `version` ;
- `finding` : `vuln_id`, `severity` (`critical`, `high`, `medium`, `low`, `negligible`,
  `unknown`), `cvss`, `epss`, `epss_percentile`, `risk` (0 à 100), `kev`,
  `fix_available`, `fixed_versions`, `fix_age_days`, `first_seen`, `age_days`,
  `match_type`, `actionable` (statut « à analyser » ou « affecté ») ;
- `triage` : `status` (`in_triage`, `affected`, `not_affected`, `false_positive`,
  `risk_accepted`, `fixed`) ;
- `ref` : `kind` (`branch`, `tag`, `host`, `container`), `name` ;
- `now` : l'instant de l'évaluation.

Les violations d'un conteneur archivé après 7 jours d'absence quittent aussitôt les
listes et sont résolues à l'évaluation suivante ; un conteneur n'a pas d'agent propre :
« agent muet » porte sur l'agent de son hôte.

Une règle d'agent lit `agent` : `name`, `kind` (`host`, `repo`), `version`, `team`,
`state` (`pending`, `active`, `silent`), `silent_days`, `last_seen`.

Une règle de constat de licence lit `project`, `component` et `ref` comme une règle de
constat, `now`, et `license` : `verdict` (`denied`, `review`), `ids` (licences qui décident
du verdict), `licenses` (licences déclarées, telles que reçues), `missing` (composant sans
licence), `first_seen`, `age_days`. Exemple : `license.verdict == "denied" && ref.kind == "tag"`.

Exemples : `finding.epss_percentile > 0.95 && finding.actionable` ;
`component.purl_base == "pkg:npm/lodash" && finding.severity in ["critical", "high"]` ;
`ref.kind == "tag" && finding.kev`.

Avant l'enregistrement, la règle est vérifiée : une erreur de syntaxe, un champ inconnu,
des types incompatibles, un résultat qui n'est pas vrai ou faux, ou une règle trop coûteuse
(boucles imbriquées) sont refusés avec la ligne et la colonne. Le bouton **Aperçu** compte
les violations que la règle ouvrirait aujourd'hui, sans rien enregistrer. Une règle valide
peut encore échouer sur une donnée (lire `project.labels["env"]` sur un projet sans cette
étiquette) : le sujet compte alors comme non violé et l'erreur s'affiche sur la politique.

### Évaluation, envoi et verdict

- Les politiques sont évaluées après chaque analyse, à chaque décision de triage, à chaque
  changement de règle et chaque jour (le décompte des jours avance).
- Une politique choisit ses **canaux** et son **mode d'envoi** : immédiat, résumé
  quotidien, ou aucun. Une violation n'est notifiée qu'une fois par canal tant qu'elle
  reste ouverte. Canaux et format des messages : [`notifications.md`](notifications.md).
- Une politique **bloquante** rend **non conforme** le verdict d'un instantané dont la
  référence garde une violation ouverte de cette politique ; l'agent dépôt peut publier ce
  verdict comme statut du commit sur GitHub ou GitLab. Les politiques d'agent ne bloquent
  jamais un commit.

## Licences

Chaque composant porte les licences de son SBOM (expressions SPDX comme
`MIT OR Apache-2.0`, ou noms libres). La page **Licences** de l'organisation montre sa
**politique de licences** et les composants qu'elle refuse ou demande de revoir ; l'onglet
**Licences** d'un projet montre les licences de son inventaire courant, avec leur verdict
et le nombre de composants, puis ses constats.

### Politique

- Sans réglage, **toute licence SPDX connue est acceptée** : rien n'est signalé, sauf les
  licences en texte libre et les identifiants inconnus de la liste SPDX, toujours **à
  revoir** (jamais acceptés d'office).
- Les administrateurs de l'organisation (permission de gérer les politiques) listent les
  licences **refusées**, **à revoir** et **acceptées**, un identifiant SPDX par ligne
  (`GPL-3.0-only`, `LicenseRef-acme` ; un composant sous `GPL-2.0+` prend le statut de
  `GPL-2.0+` s'il est cité, sinon celui de `GPL-2.0`), choisissent la
  règle des licences SPDX non citées, et peuvent rendre « à revoir » un composant sans
  licence. Une licence citée dans deux listes prend la plus stricte. Chaque changement est
  journalisé et réévalue aussitôt tous les projets.
- Dans une expression, `OR` retient le choix le plus favorable : `MIT OR GPL-3.0-only` est
  conforme si MIT est acceptée ; `AND` retient le moins favorable. Un composant qui déclare
  plusieurs licences prend la moins favorable.

### Constats de licence

Un constat de licence s'ouvre pour chaque composant refusé ou à revoir d'une référence
suivie, à l'analyse de chaque nouvel instantané ; il se résout quand le composant quitte
l'inventaire ou devient conforme (politique ou licence changée), et se rouvre s'il revient.
Les constats alimentent les politiques de sujet « constats de licence » (modèle « Licence
AGPL dans un produit distribué ») : violations, notifications et verdict des commits comme
pour les vulnérabilités.

## Second facteur et codes de secours

Le second facteur (code TOTP d'une application d'authentification) est obligatoire. À
l'enrôlement, lotor affiche **dix codes de secours**, une seule fois : chacun permet de se
connecter **une fois** à la place d'un code de l'application (« Utiliser un code de
secours » à l'étape du code). Seules leurs empreintes sont gardées : lotor ne peut pas
les réafficher.

**Mon compte › Second facteur** :

- indique combien de codes il vous reste, et vous alerte quand il en reste trois ou moins ;
- **génère un nouveau jeu** de codes contre un code de l'application : les anciens codes,
  utilisés ou non, cessent alors de valoir ;
- **change d'application d'authentification** (nouveau téléphone, application perdue) :
  saisissez un code de l'application ou, à défaut, un code de secours, et choisissez un
  nouveau mot de passe ; votre second facteur actuel est retiré et toutes vos sessions sont
  fermées. À la connexion suivante, ce nouveau mot de passe vous mène à la configuration de
  la nouvelle application, puis à un nouveau jeu de codes. Le nouveau mot de passe est
  obligatoire : tant que la nouvelle application n'est pas configurée, le mot de passe seul
  ouvre l'enrôlement, et l'ancien a pu être dérobé. Vos jetons d'accès personnels sont
  gardés.

Après une connexion par code de secours, lotor ouvre directement cette page. Les codes
faux comptent dans le verrouillage du compte comme les codes de l'application. Chaque jeu
généré, chaque code utilisé ou refusé et chaque changement d'application sont inscrits au
journal d'audit de l'instance. Sans application ni code de secours, un administrateur de
l'instance réinitialise votre second facteur.
