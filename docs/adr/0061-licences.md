# 0061 — Licences : évaluation SPDX dans le projet, politique qui accepte tout par défaut

- Statut : Accepté (**[à relire]** : écart à l'architecture, Grant non importé)
- Date : 2026-11-04
- Lot : T20

## Contexte

Les SBOM reçus portent déjà les licences de chaque composant (`component_set_items.licenses`,
expressions telles que déclarées, depuis T05). T20 demande de les confronter à une
politique d'organisation (autorisées, interdites, à revoir), d'en tirer des constats au même
cycle de vie que les constats de vulnérabilité, d'activer le modèle de règle « licence AGPL
dans un produit distribué » (T15) et de rendre les licences cherchables. L'architecture
prévoyait un adaptateur `internal/license/grant` sur Grant v0.6.8 (ADR 0007), sous réserve
d'une étude préalable : « API de Grant utilisable en bibliothèque à la version épinglée ; à
défaut, évaluation des expressions SPDX dans le projet ».

Étude de Grant v0.6.8 :

- son évaluation aplatit l'expression SPDX : un paquet est refusé dès qu'**une** de ses
  licences n'est pas autorisée. `MIT OR GPL-3.0-only` est donc refusé si GPL l'est, ce que
  le premier critère de la fiche interdit (« conforme si l'une des deux est autorisée ») ;
- sa classification se résume à la liste SPDX et à des motifs de noms ; la liste SPDX est
  déjà embarquée dans le projet (schéma CycloneDX 1.6, `schema.Validator.CycloneDXLicenseIDs`) ;
- l'importer ajouterait une dépendance et son graphe pour n'en garder que la liste SPDX.

L'utilisateur a tranché le point ouvert de la fiche : **la politique par défaut d'une
organisation accepte toutes les licences**.

## Décision

### Évaluation dans le projet, sans Grant

`internal/license` (métier, sans dépendance nouvelle) :

- `Parse` lit une expression SPDX 2.3 (`AND`, `OR`, `WITH`, parenthèses, `+`,
  `LicenseRef-…`, `DocumentRef-…:LicenseRef-…`), opérateurs insensibles à la casse, `AND`
  prioritaire sur `OR` ; une entrée illisible (nom libre comme « Acme Proprietary ») est
  une licence non SPDX, jamais une erreur.
- `Policy.Evaluate` : chaque licence citée a le statut de sa liste (refusée, à revoir,
  acceptée ; une licence suivie de `+` est cherchée sous sa forme écrite, `GPL-2.0+`, puis
  sans le `+`), chaque licence SPDX connue non citée le statut par défaut. **Une licence
  inconnue de la liste SPDX, un `LicenseRef-` non listé ou un nom libre est à revoir**,
  jamais acceptée (fiche). `OR` retient le statut le plus favorable, `AND` le moins
  favorable ; plusieurs entrées de licence d'un composant se
  combinent comme `AND` (CycloneDX : toutes s'appliquent). `RequireLicense` rend « à revoir »
  un composant sans licence (sinon il ne donne pas de constat). Le verdict garde les
  identifiants qui décident (ceux de la branche retenue), affichés et passés aux règles.
- La liste SPDX vient du schéma CycloneDX 1.6 embarqué (`license.KnownFrom`), sans copie.

`internal/archtest` garde la règle « Grant seulement dans `internal/license/grant` » si
Grant devait être adopté plus tard ; `architecture.md` retire le sous-paquet et l'indique.

### Politique

Une ligne `license_policies` par organisation ; sans ligne, `DefaultPolicy()` : statut par
défaut « acceptée », listes vides, `RequireLicense` faux (décision de l'utilisateur). La
saisie (écran Licences, permission `policy.manage`) n'admet que des identifiants (pas
d'opérateur ni d'exception), 500 au plus par liste ; elle est journalisée
(`license_policy.updated`) et met en file `license.evaluate_org`, qui réévalue toutes les
références de l'organisation, une transaction par projet.

### Constats

`license_findings`, un par (référence, composant) dont le verdict n'est pas « acceptée » :
ouvert, mis à jour si le verdict ou les licences changent, résolu quand le composant quitte
l'inventaire courant ou devient conforme, rouvert s'il revient (même cycle que `findings`).
L'évaluation d'une référence (`Service.EvaluateRef`) s'accroche à
`finding.Options.OnAnalyzed` dans `lotor-server`, avant l'évaluation des politiques, dans la
transaction de l'analyse : chaque nouvel instantané est analysé, donc évalué. Un changement
de constat met en file l'évaluation des politiques du projet (`policy.OnLicenseChange`).

### Règles de politique de sujet « licence »

Nouveau sujet `license` (T15) : contexte `project`, `component`, `license` (`verdict`,
`ids`, `licenses`, `missing`, `first_seen`, `age_days`), `ref`, `now`. Une violation
référence le constat (`policy_violations.license_finding_id`, clé étrangère en cascade), compte
dans le verdict de l'instantané et part dans les notifications (licences décisives et
verdict à la place de la vulnérabilité et de la sévérité). Le modèle `license_agpl` devient
disponible : `license.ids.exists(id, id.startsWith("AGPL-")) && has(project.labels.distribution)`,
bloquant.

### Recherche

`license:<identifiant>` (un identifiant SPDX ou `LicenseRef-`, sans expression) : la table
`license_expressions` (expressions distinctes par organisation, alimentée à l'écriture des
ensembles et remplie par la migration 028) est lue, Go retient celles qui citent la licence
(insensible à la casse, dans une expression ou seule), puis SQL cherche les éléments qui en
portent une (`i.licenses && $n`), avec les mêmes filtres, la même pagination et les mêmes
exports que la recherche par composant, à une date passée comprise (T21).

### Écrans

`/o/{slug}/licenses` (permission `org.view`) : politique (formulaire avec `policy.manage`,
lecture seule sinon), constats ouverts des projets visibles filtrés par verdict.
`/o/{slug}/projects/{projet}/licenses` : licences de l'inventaire courant avec leur verdict
et nombre de composants, puis constats du projet. Lectures sous `db.Visible`, filtrées par
`lotor_team_visible`.

## Conséquences

- Aucune dépendance nouvelle ; `MIT OR GPL-3.0-only` est conforme si MIT est acceptée.
- La classification par catégories de Grant (permissive, copyleft…) n'est pas reprise : une
  politique cite des identifiants. Une famille s'écrit par une règle CEL
  (`id.startsWith("GPL-")`).
- L'évaluation suit l'analyse de vulnérabilités : sans base de vulnérabilités installée, un
  nouvel instantané n'est pas encore évalué ; un changement de politique, lui, réévalue tout
  sans attendre.
- `license_expressions` grossit avec le nombre d'expressions distinctes (quelques centaines
  par parc), jamais avec le nombre de composants ; elle n'est pas purgée par la rétention.
