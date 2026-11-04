# Journal des modifications

Toutes les évolutions notables de lotor. Format :
[Keep a Changelog 1.1.0](https://keepachangelog.com/fr/1.1.0/) ; versions selon
[SemVer](https://semver.org/lang/fr/). Avant la v1.0, toute version est une préversion et
peut changer la configuration ou l'API ; les migrations de base restent toujours
appliquées automatiquement, sans retour arrière.

## [Non publié]

### Ajouté

- Page de présentation statique (`site/`, publiable telle quelle, par exemple sur GitHub
  Pages), captures d'écran d'une instance de démonstration (`site/screenshots/`) et
  README réécrit autour des fonctions et des captures.

## [0.2.0] - 2026-11-04

Préversion du **lot 2 · IA et triage** : équipes et droits, conteneurs des serveurs,
triage et VEX, politiques et alertes, différences d'instantanés et rétention,
enrichissement IA prouvé de l'agent dépôt, codes de secours du second facteur. Mêmes
fichiers qu'en 0.1.0 (trois rôles, linux amd64 et arm64, paquets deb et rpm de l'agent
serveur, sommes SHA-256), plus le paquet deb du serveur.

**Mise à jour depuis 0.1.0** : les migrations 016 à 023 s'appliquent au démarrage (équipe
« Général » créée dans chaque organisation, avec tous ses projets et tous ses membres à
leur ancien rôle) ; la rétention nocturne réduit dès la première nuit l'historique
antérieur à 90 jours (un instantané par mois) et supprime les conteneurs archivés pour
absence depuis 180 jours : régler `retention.*` et `containers.purge_after` avant la mise
à jour si une autre politique est voulue ; les comptes existants n'ont pas de codes de
secours (à générer depuis **Mon compte › Second facteur**) ; les ports par défaut changent
(1758, 1761 et 1762, voir « Modifié ») pour une installation qui ne les fixe pas. Détail :
[`docs/operations.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/operations.md#mise-à-jour).

### Ajouté

- Paquet deb `lotor-server` (amd64, arm64 ; T27, ADR 0053) : sur Debian 13 ou Ubuntu 24.04,
  `apt install` crée les rôles et la base PostgreSQL en local, les secrets, le premier
  administrateur avec un mot de passe temporaire affiché une fois, et le site nginx ou Apache,
  avec un certificat existant ou autosigné. Base distante par chaînes de connexion,
  installation sans terminal par réponses prérenseignées. Une mise à jour ne redémarre pas le
  serveur ; une purge garde la base et la clé de chiffrement. Voir
  [`docs/operations.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/operations.md#installation-par-le-paquet-deb).
- Codes de secours du second facteur (T18, ADR 0048 ; open-go-base v1.4.0) : dix codes à
  usage unique, hachés, montrés une seule fois à l'enrôlement ; connexion par « Utiliser
  un code de secours » ; page **Mon compte › Second facteur** : codes restants,
  régénération (code TOTP exigé), changement d'application d'authentification par un code
  TOTP ou un code de secours (nouvel enrôlement imposé). Réglage `mfa.recovery_codes`
  ([#27](https://github.com/leblanc-simon/lotor/pull/27)).
- Recherche (T18, ADR 0050) : filtre « équipe » (`team`) et équipe de chaque projet ;
  statut de triage de chaque constat d'une recherche par vulnérabilité, filtre `triage` ;
  colonnes `team` et `triage_status` ajoutées en fin d'export ([#27](https://github.com/leblanc-simon/lotor/pull/27)).
- Purge des conteneurs archivés pour absence depuis 180 jours, avec leur historique, par la
  rétention nocturne (T18, ADR 0049) ; réglage `containers.purge_after` (`0` : jamais)
  ([#27](https://github.com/leblanc-simon/lotor/pull/27)).

- Politiques, alertes et statuts de commit (T15, ADR 0045 à 0047) : règles en CEL sur les
  constats ou les agents, vérifiées avant l'enregistrement (position de l'erreur, coût
  borné) avec un aperçu du nombre de violations ; modèles fournis (KEV sur un projet de
  production, critique avec correctif depuis plus de 30 jours, agent muet depuis 7 jours) ;
  violations datées, écran des violations et section « Alertes » du tableau de bord ;
  canaux par organisation (e-mail par SMTP, webhook générique signé en HMAC avec
  horodatage, Matrix, Mattermost, Slack), secrets chiffrés, envoi immédiat ou résumé
  quotidien, sans doublon et réessayé, bouton « Envoyer un test » ; verdict d'un
  instantané `GET /api/v1/agent/snapshots/{id}/verdict` ; l'agent dépôt peut publier le
  verdict comme statut de commit sur GitHub et GitLab (`status.enabled`). Réglages
  `notify.*` et `smtp.*` ; format du webhook :
  [`docs/notifications.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/notifications.md) ([#26](https://github.com/leblanc-simon/lotor/pull/26)).

- Équipes et droits (T16, ADR 0034) : chaque projet appartient à une équipe ; un membre ne
  voit que les projets de ses équipes, sur toutes les surfaces (listes, fiches, recherche
  et exports, API utilisateur, tableau de bord, vulnérabilités, composants, agents), et y
  agit selon son rôle d'équipe (lecteur, analyste, administrateur d'équipe) ; écrans des
  équipes et de leurs membres, rattachement d'un projet à une autre équipe, agents et
  jetons d'inscription rattachés à une équipe ; matrice des droits
  [`docs/security/permissions.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/security/permissions.md),
  générée depuis le code ([#21](https://github.com/leblanc-simon/lotor/pull/21)).
- Invitations : un administrateur d'organisation invite une adresse, le compte accepte ou
  décline depuis « Mon compte » → « Invitations » ([#21](https://github.com/leblanc-simon/lotor/pull/21)).
- Enrichissement IA de l'agent dépôt (T12, ADR 0042 à 0044) : un modèle (Ollama en local,
  ou Anthropic, `claude-sonnet-5-5` par défaut) trouve les composants qu'aucun manifeste ne
  déclare (bibliothèques recopiées, images de base, scripts de CDN, outils installés par
  script) ; aucun composant n'est retenu sans preuve relue dans le fichier par un
  vérificateur déterministe ; fichiers sensibles jamais envoyés ; budget par analyse,
  repli sur le SBOM Syft seul marqué « enrichissement incomplet » ; analyse incrémentale.
  Réglage par dépôt (IA désactivée par défaut ; fournisseur externe autorisé par un
  administrateur d'organisation, audité ; `ai.forbid_external` sur l'instance). Bloc
  « preuve » sur la fiche composant, inventaire par origine sur la fiche projet, statut
  d'enrichissement des instantanés. Corpus d'évaluation annoté (`testdata/ai-corpus`) et
  cible `make eval-ai`. Nouvelle dépendance : SDK Go officiel d'Anthropic (v2.4.0)
  ([#25](https://github.com/leblanc-simon/lotor/pull/25)).
- Différences d'instantanés (T17, ADR 0038) : la frise des instantanés d'une référence
  indique les composants ajoutés, retirés, montés ou descendus de version depuis le
  précédent ; écran de comparaison de deux instantanés quelconques d'un projet, avec
  l'effet sur la sécurité (constats introduits et résolus) ; routes d'API
  `GET /api/v1/orgs/{org}/projects/{project}/snapshots` et `…/compare` ([#22](https://github.com/leblanc-simon/lotor/pull/22)).
- Rétention des instantanés (T17, ADR 0039) : tout est gardé 90 jours, puis le dernier
  instantané de chaque mois, sans limite de durée ; le dernier instantané d'une référence
  n'est jamais supprimé ; les réceptions hors fenêtre, puis les ensembles d'inventaire et
  SBOM devenus orphelins sont supprimés chaque nuit. Réglages `retention.*` ([#22](https://github.com/leblanc-simon/lotor/pull/22)).
- Triage et VEX (T14, ADR 0035 à 0037) : chaque constat a un statut de triage (à
  analyser, affecté, non affecté avec justification VEX, faux positif, risque accepté
  jusqu'à une date, corrigé), décidé pour un projet ou pour toute l'organisation (une
  décision de projet surcharge celle de l'organisation) et hérité par les constats à
  venir ; fiche d'un constat avec son panneau de triage et son historique, filtre par
  statut, constats non affectés et faux positifs masqués par défaut ; échéance
  automatique des risques acceptés ; export OpenVEX et CycloneDX VEX d'un projet
  (interface et `GET /api/v1/orgs/{org}/projects/{project}/vex`), import des VEX
  d'éditeurs pour un projet ou pour l'organisation ; chaque décision est journalisée
  ([#23](https://github.com/leblanc-simon/lotor/pull/23)).
- Conteneurs en projets enfants (T13, ADR 0040 et 0041) : l'agent serveur inventorie les
  conteneurs Docker et Podman en cours d'exécution (option `containers.enabled`,
  **désactivée par défaut** : l'accès à la socket d'un moteur équivaut à root) ; chaque
  service Compose, ou chaque conteneur hors Compose, devient un projet enfant du serveur,
  dans son équipe, avec son SBOM ; une image partagée n'est analysée qu'une fois. Fiche du
  serveur avec ses conteneurs et leurs constats par périmètre ; filtre « Inclure les
  conteneurs » des listes de projets et de la recherche (écran et API, `containers=1`) ;
  un conteneur absent depuis `containers.archive_after` (7 jours) est archivé et revient
  s'il redémarre. Nouvelle opération de l'API des agents `reportContainers` ([#24](https://github.com/leblanc-simon/lotor/pull/24)).

- Évaluation de l'enrichissement IA (T18) : échantillon pilote annoté des quatre dépôts
  publics du parc pilote (`testdata/ai-pilot`, `scripts/ai-pilot-fetch.sh`), deux cas de
  plus au corpus, `make eval-ai` par jeu (corpus, pilote) avec revérification de chaque
  preuve et contrôle à blanc sans clé (`LOTOR_EVAL_AI_PROVIDER=credulous`) ; jeu de mesure
  complété des équipes, conteneurs et décisions de triage (`benchdata.AddTeamsAndContainers`).

### Corrigé

- Un composant trouvé par l'IA qui est une image de conteneur (image de base d'un
  Dockerfile, image de l'intégration continue) disparaissait à l'ingestion : l'agent
  l'émettait avec le type CycloneDX « container », que le décodeur du serveur ignore. Les
  composants IA sont désormais tous de type « library », le purl `pkg:docker/…` disant la
  nature (T18).
- Deux envois de notification simultanés du même canal pouvaient envoyer deux fois le
  même lot de violations (même `X-Lotor-Delivery`) : chaque envoi réserve désormais son
  lot avant l'appel réseau (T18, ADR 0052, migration 023).
- `make bench-search` échouait dans son dernier pas (plans `EXPLAIN ANALYZE` sans la
  visibilité des équipes) depuis l'arrivée des équipes (T18).
- `--help` annonce les défauts réels de lotor (port, nom du cookie de session, langue,
  niveau de journal…) au lieu de ceux des fragments d'open-go-base (open-go-base v1.4.2).

### Modifié

- Nouveaux ports par défaut : **1758** pour l'interface et l'API de `lotor-server` (au lieu
  de 8080), **1761** pour son écoute de gestion (au lieu de 8081), **1762** pour le
  récepteur de webhooks de `lotor-repo-agent` (au lieu de 8080). Une installation qui ne
  fixe pas `web.port` (`LOTOR_PORT`), `management.port` (`LOTOR_MANAGEMENT_PORT`) ou
  `webhook.listen` (`LOTOR_REPO_WEBHOOK_LISTEN`) change donc de port à la mise à jour : les
  fixer pour garder les anciens, ou adapter le mandataire inverse, les sondes, la collecte
  des métriques et l'adresse des webhooks déclarée dans les forges.
- La recherche par composant ne compte plus les constats « non affecté » ni « faux
  positif » parmi les vulnérabilités ouvertes d'une occurrence (T18) ; le filtre `triage`
  sur une recherche qui n'est pas par vulnérabilité répond 400 ([#27](https://github.com/leblanc-simon/lotor/pull/27)).
- L'enrôlement du TOTP montre désormais les codes de secours avant de continuer (réponse
  200 au lieu d'une redirection). La migration 022 accorde les droits sur
  `mfa_recovery_codes` ([#27](https://github.com/leblanc-simon/lotor/pull/27)).
- Le tableau de bord ne compte plus les constats « non affecté » ni « faux positif »
  parmi les constats ouverts (T14, [#23](https://github.com/leblanc-simon/lotor/pull/23)).
- Le rôle d'organisation vaut désormais « membre » ou « administrateur » (les rôles
  `viewer` et `analyst` disparaissent). La migration 016 crée une équipe « Général » par
  organisation, y rattache projets, jetons d'inscription et agents serveur, et y fait
  entrer chaque membre avec son ancien rôle : aucun accès n'est perdu ([#21](https://github.com/leblanc-simon/lotor/pull/21)).
- La migration 017 rend facultatif l'instantané d'un constat et de son historique : un
  constat dont la rétention supprime le dernier instantané reste, sans lien vers lui
  ([#22](https://github.com/leblanc-simon/lotor/pull/22)).
- Le scan de l'hôte par l'agent serveur se fait hors ligne, comme celui des images : Syft
  n'exécute plus `go list` sur les modules Go trouvés sous `/` et ne cherche plus de
  licences sur le réseau. L'inventaire d'un hôte qui porte des modules Go peut changer une
  fois (renvoi de son SBOM) ([#24](https://github.com/leblanc-simon/lotor/pull/24)).

### Sécurité

- SEC-09 corrigé : l'ajout d'un membre passe par une invitation à accepter, avec une
  réponse identique que le compte existe ou non ([#21](https://github.com/leblanc-simon/lotor/pull/21)).
- Revue de sécurité du lot 2 (T18, ADR 0051 ; open-go-base v1.4.1) : l'enrôlement du TOTP
  ne « réactive » plus un second facteur actif et compte ses codes faux dans le
  verrouillage par compte (SEC2-01) ; « Changer d'application d'authentification » exige
  un nouveau mot de passe (SEC2-06) ; un jeton d'inscription ne rattache par le nom d'hôte
  que les projets de son équipe (SEC2-02) ; changer le dépôt d'un projet sans le droit
  `ai.external` ramène son IA à « désactivée » (SEC2-03) ; le secret d'un canal Matrix ou
  webhook est à ressaisir quand sa destination change (SEC2-04) ; projets de conteneurs
  bornés par hôte, réglage `containers.max_per_host` (1 000, SEC2-05) ; les fichiers
  exclus ne sont plus nommés au fournisseur de modèle (SEC2-07) ; garde SSRF étendue aux
  adresses NAT64, 6to4 et aux plages réservées (SEC2-08) ; outil de recherche de l'IA
  sous délai et budget, 20 appels d'outils par réponse (SEC2-09) ([#28](https://github.com/leblanc-simon/lotor/pull/28)).

### Accessibilité

- Audit RGAA des écrans du lot 2 : 100 % des critères applicables conformes après
  corrections ([grille](https://github.com/leblanc-simon/lotor/blob/main/docs/accessibilite/grille-rgaa-lot2.md),
  T18). Panneau de triage : champs complémentaires hors de l'étiquette du statut ; fiche
  composant lisible à 320 px avec une version longue ; titre des fiches de constat avec
  le projet et la référence ; statut traduit sur la confirmation du retrait d'une
  décision ; décomptes accordés (équipe, alertes du tableau de bord) ([#29](https://github.com/leblanc-simon/lotor/pull/29)).

## [0.1.0] - 2026-11-01

Préversion du **lot 1 · MVP inventaire** : un parc de serveurs et de dépôts inventorié,
analysé chaque jour avec Grype et interrogé. Binaires des trois rôles (linux amd64 et
arm64), paquets deb et rpm de l'agent serveur, sommes SHA-256. Installation :
[`docs/operations.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/operations.md) ; premiers pas :
[`docs/demarrage.md`](https://github.com/leblanc-simon/lotor/blob/main/docs/demarrage.md) ([English](https://github.com/leblanc-simon/lotor/blob/main/docs/getting-started.md)).

### Ajouté

#### Fondations (T00, T01, T02)

- Dépôt, outillage qualité et CI identique à `make ci` : formatage, code généré, `go vet`
  et staticcheck sur toutes les étiquettes de test, tests unitaires avec `-race`, tests
  d'intégration PostgreSQL, govulncheck, construction amd64 et arm64, autoanalyse des
  binaires par Syft et Grype ([#1](https://github.com/leblanc-simon/lotor/pull/1),
  [#2](https://github.com/leblanc-simon/lotor/pull/2)).
- Serveur `lotor-server` sur open-go-base : configuration YAML et `LOTOR_*`, migrations
  sous verrou et immuables (somme SHA-256), deux rôles PostgreSQL (propriétaire et
  exécution, refus d'un rôle qui contournerait la RLS), TLS natif ou mandataire inverse,
  en-têtes de sécurité et CSP stricte, sondes `/healthz` et `/readyz`, métriques
  Prometheus, interface traduite en français et en anglais, thèmes clair et sombre
  ([#3](https://github.com/leblanc-simon/lotor/pull/3)).
- File de traitements PostgreSQL : baux renouvelés, réessais exponentiels, priorités,
  plafond par organisation, échéances uniques sur un parc d'instances, arrêt propre
  ([#4](https://github.com/leblanc-simon/lotor/pull/4)).

#### Comptes, organisations et agents (T03, T04)

- Comptes locaux avec TOTP obligatoire, premier administrateur par variables de démarrage,
  procédure de secours tracée, administration des comptes ; organisations isolées par la
  sécurité au niveau des lignes de PostgreSQL (RLS forcée), rôles lecteur, analyste,
  administrateur ; journal d'audit ([#5](https://github.com/leblanc-simon/lotor/pull/5)).
- Projets (dépôts et serveurs), agents, jetons d'agent et jetons d'inscription, API des
  agents générée depuis `api/openapi.yaml`, limitation de débit par jeton
  ([#6](https://github.com/leblanc-simon/lotor/pull/6)).

#### Inventaire et analyse (T05, T06)

- Ingestion des SBOM CycloneDX JSON 1.5 à 1.7, SPDX JSON 2.3 et Syft JSON : bornes de
  taille, de profondeur et de composants, décodage dans un worker, inventaire normalisé
  (purl canoniques), instantanés par référence, téléchargement du SBOM reçu ou réencodé
  en CycloneDX 1.6 ou SPDX 2.3 ([#7](https://github.com/leblanc-simon/lotor/pull/7)).
- Analyse de vulnérabilités par Grype : base v6 commune à toutes les instances, rangée par
  blocs dans PostgreSQL, vérifiée et synchronisée sans interruption ; réanalyse de tout
  le parc à chaque nouvelle base ; constats avec sévérité, CVSS, EPSS, KEV et versions
  corrigées ; onglet « Constats », fiches vulnérabilité et composant
  ([#9](https://github.com/leblanc-simon/lotor/pull/9)).

#### Agents (T07, T08)

- Agent serveur `lotor-host-agent` (Linux amd64 et arm64) : inscription par jeton,
  inventaire Syft de l'hôte (paquets du système et des langages), envoi seulement quand
  l'inventaire change, scan à la demande, mTLS, démon ou timer systemd sans root
  (`CAP_DAC_READ_SEARCH`), paquets deb et rpm
  ([#10](https://github.com/leblanc-simon/lotor/pull/10)).
- Agent dépôt `lotor-repo-agent` : GitHub App et compte de service GitLab, webhooks
  signés, rattrapage des commits manqués, clonage du seul commit visé dans un
  environnement git maîtrisé, analyse Syft sans exécuter de code du dépôt, SBOM
  déterministe ([#8](https://github.com/leblanc-simon/lotor/pull/8)).

#### Exploitation des données (T09, T10)

- Tableau de bord d'organisation et en-tête de projet : constats ouverts par sévérité,
  KEV, tendance sur 30, 90 ou 365 jours, délai médian de correction, agents muets,
  projets et composants les plus exposés
  ([#11](https://github.com/leblanc-simon/lotor/pull/11)).
- Recherche transverse par nom, purl, plage de versions `vers`, vulnérabilité (CVE ou
  GHSA) et empreinte, filtres, export CSV et JSON ; API utilisateur en lecture avec jetons
  d'accès personnels ([#12](https://github.com/leblanc-simon/lotor/pull/12)).

#### Recette du lot 1 (T11)

- Administration de l'instance : traitements en échec (relancer, abandonner), état de la
  base de vulnérabilités par instance, import manuel d'une archive pour les sites isolés,
  purge des archives ([#13](https://github.com/leblanc-simon/lotor/pull/13)).
- Page de confirmation des actions irréversibles, plan du site, titres de page distincts
  ([#14](https://github.com/leblanc-simon/lotor/pull/14)).
- Unité systemd du serveur, workflow de publication et cible `make release`, guide
  d'exploitation complété (installation, sauvegarde et restauration, mise à jour,
  supervision), guides de démarrage en français et en anglais
  ([#16](https://github.com/leblanc-simon/lotor/pull/16)).

### Sécurité

- Revue de sécurité du lot 1 (OWASP Risk Rating, aucune faiblesse haute ni critique) et
  corrections : verrouillage par compte des codes TOTP, révocation des jetons personnels
  à toute réinitialisation, mot de passe temporaire imposé après réinitialisation du TOTP,
  durée absolue de session, jeton CSRF lié à la session et protection inter-origines,
  cookies `__Host-`, journaux d'audit en ajout seul, quotas d'ingestion, périmètre
  obligatoire de l'agent dépôt ([#15](https://github.com/leblanc-simon/lotor/pull/15)).

### Accessibilité

- Audit RGAA de tous les écrans du lot 1 : 100 % des critères applicables conformes après
  corrections ([grille](https://github.com/leblanc-simon/lotor/blob/main/docs/accessibilite/grille-rgaa-lot1.md),
  [#14](https://github.com/leblanc-simon/lotor/pull/14)).

[Non publié]: https://github.com/leblanc-simon/lotor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/leblanc-simon/lotor/releases/tag/v0.2.0
[0.1.0]: https://github.com/leblanc-simon/lotor/releases/tag/v0.1.0
