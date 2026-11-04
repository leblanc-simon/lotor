# T20 — Licences avec Grant

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé |

## Objectif

Connaître les licences de chaque composant, les confronter à une politique d'organisation
et les rendre cherchables.

## Périmètre

**Inclus**

- `internal/license/grant` : adaptateur Grant (classification et évaluation des licences),
  seul paquet qui l'importe.
- Politique de licences par organisation : licences autorisées, interdites, à revoir ;
  expressions SPDX (`MIT OR Apache-2.0`) évaluées correctement.
- Constats de licence par référence, avec le même cycle de vie que les constats de
  vulnérabilité.
- Activation du modèle de règle « licence AGPL dans un produit distribué » (T15).
- Écrans : licences d'un projet, politique, constats ; filtre et recherche par licence
  enrichis.

**Exclu** : détection de licence dans le code source (au-delà de ce que fournissent Syft et
Grant).

## Conception

- Étude préalable : API de Grant utilisable en bibliothèque à la version épinglée ; à défaut,
  évaluation des expressions SPDX dans le projet et Grant limité à la classification.
- Une licence inconnue n'est jamais considérée comme autorisée.

## Critères d'acceptation

- [x] `MIT OR GPL-3.0-only` est conforme si l'une des deux est autorisée
  (`TestEvaluate`, `TestLicensePolicyLifecycle`).
- [x] Une licence interdite produit un constat et peut déclencher une règle
  (`TestLicensePolicyLifecycle` : constat refusé, violation bloquante du modèle AGPL, verdict
  non conforme, résolution au retrait du composant).
- [x] La recherche `license:AGPL-3.0-only` renvoie les projets concernés
  (`TestLicenseScreens`, `TestParseLicense`).

## Tests attendus

Tables d'expressions SPDX ; intégration sur des SBOM d'exemple ; isolement.

## Points à trancher

- ~~Politique par défaut d'une nouvelle organisation.~~ Tranché par l'utilisateur le
  4 novembre 2026 : toutes les licences sont acceptées.

## Journal

### 2026-11-04 — réalisation (enchaînée avec T19, T21 et T23)

Décisions, toutes **[à relire]** sauf la première (ADR 0060) :

- **Politique par défaut** (décision de l'utilisateur) : sans réglage, toute licence SPDX
  connue est acceptée. Ce qui reste signalé l'est par la fiche : « une licence inconnue
  n'est jamais considérée comme autorisée » — un identifiant hors de la liste SPDX, un
  `LicenseRef-` non cité ou un nom libre est **à revoir**.
- **Grant non importé** (étude de la conception) : Grant v0.6.8 aplatit l'expression et
  refuse un paquet dès qu'une de ses licences n'est pas autorisée (`MIT OR GPL-3.0-only`
  refusé si GPL l'est), contraire au premier critère ; sa classification se réduit à la
  liste SPDX, déjà embarquée par le schéma CycloneDX 1.6. Parseur et évaluateur SPDX 2.3
  dans `internal/license`, sans dépendance ; `internal/license/grant` n'existe pas (écart à
  `architecture.md`, mis à jour ; la règle d'archtest reste en garde).
- **Sémantique** : `OR` = la plus favorable, `AND` = la moins favorable ; plusieurs entrées
  de licence d'un composant = `AND` ; `GPL-2.0+` cherché sous sa forme écrite puis sans
  `+` ; un identifiant dans deux listes prend la plus stricte ; les identifiants décisifs
  (`ids`) sont ceux de la branche retenue.
- **Sans licence** : pas de constat, sauf `RequireLicense` (« à revoir »).
- **Saisie** : identifiants seuls (ni opérateur ni exception), 500 par liste, permission
  `policy.manage` (comme les règles), journalisée ; tout changement réévalue toute
  l'organisation par le job `license.evaluate_org`.
- **Constats** `license_findings` par (référence, composant), même cycle que les constats
  de vulnérabilité ; évalués dans la transaction de l'analyse (`OnAnalyzed`, avant les
  politiques) : sans base de vulnérabilités installée, un nouvel instantané n'est pas
  encore évalué. Un changement de constat met en file l'évaluation des politiques.
- **Règles** : nouveau sujet `license` (contexte `project`, `component`, `license`, `ref`,
  `now`) ; le modèle `license_agpl` devient disponible :
  `license.ids.exists(id, id.startsWith("AGPL-")) && has(project.labels.distribution)`,
  bloquant, envoi immédiat. Violations, notifications et verdict des commits comme pour
  les vulnérabilités (licences décisives à la place de l'identifiant, verdict à la place
  de la sévérité).
- **Recherche** : `license:<un identifiant>` (sans expression, insensible à la casse) ; la
  table `license_expressions` (expressions distinctes par organisation, remplie par la
  migration 027 et à chaque nouvel ensemble) est filtrée en Go, puis SQL cherche les
  éléments qui en portent une ; filtres, export et date passée comme une recherche par
  composant.
- **Écrans** : page **Licences** de l'organisation (politique, constats filtrés par verdict,
  500 au plus) et onglet **Licences** du projet (licences de l'inventaire courant et leur
  verdict, constats) ; lecture pour tout membre, filtrée par équipe.

Livré : migration `027_licenses.sql` (`license_policies`, `license_findings`,
`license_expressions`, sujet `license` de `policies` et `policy_violations`),
`internal/license` (`expression.go`, `policy.go`, `service.go`, `read.go`), sujet licence
dans `internal/policy`, notifications, recherche, écrans `org/licenses` et
`projects/licenses`, traductions, `docs/utilisation.md` (section Licences).

Tests : `TestParse`, `TestEvaluate`, `TestNormalize` (tables d'expressions) ;
`TestLicenseTemplate` (CEL) ; `TestLicenseDefaultPolicyAcceptsKnownLicenses`,
`TestLicensePolicyLifecycle`, `TestLicenseIsolation` (chaîne ingestion → analyse →
licences → politiques) ; `TestLicenseScreens` (deux langues, accessibilité, saisie
refusée, droits, recherche) ; surfaces Licences dans `TestTeamFilterOnEverySurface` ;
harnais RLS des trois tables ; `TestParseLicense` (requête).

Défaut corrigé en route : la recherche `license:` ajoutait le paramètre des composants
inutilisé (« could not determine data type of parameter $1 ») ; les arguments ne sont plus
ajoutés que pour la condition retenue.
