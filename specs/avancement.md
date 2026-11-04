# Avancement

Journal de bord de la réalisation autonome des lots. Chaque entrée renvoie au Journal de la
fiche, qui fait foi pour le détail des décisions. Les décisions prises sans validation
explicite de l'utilisateur sont marquées **[à relire]**.

## Lot 3

Réalisation enchaînée de T19, T20, T21 et T23, demandée le 4 novembre 2026 (« enchaîne »),
sur la branche de la session, sans plan validé au préalable : chaque décision est
consignée dans le Journal de la fiche et marquée **[à relire]**. Décision de
l'utilisateur : la politique de licences par défaut d'une nouvelle organisation accepte
toutes les licences (T20).

| Lot | Statut | Décisions à relire |
| --- | --- | --- |
| T19 | Terminé (exécution de l'action GitHub réelle : action de l'utilisateur) | Clé = jeton d'agent dépôt, agent serveur refusé ; nom exact du dépôt confié ; version = nouvelle nature de référence `version` sans commit, rangée comme un hôte ; `project` = identifiant de la version ; création automatique par agent d'équipe, réglage sur la fiche de l'agent, 200 versions par dépôt ; champs Dependency-Track ignorés ; sortie des agents (serveur : CycloneDX 1.6, `only` ; dépôt : commit de tête seulement) ; mandataire pour l'action GitHub, qui ignore le chemin — tous **[à relire]** ([T19](lots/T19-dependency-track.md#journal), [ADR 0057](../docs/adr/0057-point-compatible-dependency-track.md)) |

| T21 | Terminé | Fin de journée UTC, borne exclusive ; projets archivés et références retirées compris ; composants seulement (recherche par vulnérabilité, sévérité, KEV, résolution refusées) ; avertissement avant l'horizon de la rétention ; mesure sur 12 mois d'historique hebdomadaire synthétique — tous **[à relire]** ([T21](lots/T21-recherche-historique.md#journal), [ADR 0058](../docs/adr/0058-recherche-a-une-date-passee.md)) |
| T23 | Terminé | Archive tar (manifeste, codes, SBOM) ; HMAC de clé l'empreinte du jeton ; inscription par archive avec un jeton tiré par l'agent ; import par l'écran, l'API (seule écriture de l'API utilisateur) et un répertoire surveillé ; agent dépôt en plus seulement ; pas de conteneurs hors ligne — tous **[à relire]** ([T23](lots/T23-hors-ligne.md#journal), [ADR 0059](../docs/adr/0059-mode-hors-ligne.md)) |

### Actions pour l'utilisateur (lot 3)

1. **T19** : enregistrer une exécution réelle de l'action `DependencyTrack/gh-upload-sbom`
   contre lotor (critère 2) : dans un dépôt de test, l'étape de
   [`docs/dependency-track.md`](../docs/dependency-track.md#exemples) vers un nom d'hôte
   servi par le mandataire qui préfixe `/dt` ; vérifier l'instantané créé, puis cocher le
   critère de la fiche. La requête reconstituée a déjà été acceptée par un
   Dependency-Track 5.2.1 et par lotor.

## Lot 2

Réalisation autonome du lot 2 (T16, puis T12, T13, T14, T17, T15 et la recette T18),
demandée le 1er novembre 2026 : enchaîner jusqu'à la recette sans attendre les réponses de
l'utilisateur, en consignant chaque décision pour une relecture a posteriori.

### Synthèse

Le lot 2 est **réalisé** ; la mesure de l'IA par un vrai modèle et la publication de
`v0.2.0` reviennent à l'utilisateur. Livré : équipes et droits (T16), enrichissement IA
prouvé de l'agent dépôt (T12), conteneurs en projets enfants (T13), triage et VEX (T14),
politiques, alertes et statuts de commit (T15), différences d'instantanés et rétention
(T17), puis la recette T18 : codes de secours du second facteur (open-go-base v1.4.0 et
v1.4.1), revue de sécurité (aucune faiblesse haute ni critique ; 2 Medium et 5 Low
corrigés), audit RGAA (100 % des critères applicables) et recette proprement dite. Le
critère du lot, **aucun composant ajouté par l'IA sans preuve vérifiée**, est tenu par
construction et contrôlé de l'extérieur sur le corpus (11 cas) et sur l'échantillon pilote
annoté (4 dépôts réels) ; **le taux de faux positifs et le rappel d'un vrai modèle ne sont
pas mesurés** (aucune clé dans la session : procédure prête). Toutes les cibles chiffrées
tiennent avec les équipes et les conteneurs, sur une machine moins puissante que la
référence (recherche 446 ms pour 2 s, tableau de bord 841 ms pour 1 s, ingestion 5,6 s
pour 30 s, agent 2 min 13 s et 819 Mio). La recette sur une instance 0.1.0 réelle mise à
jour en 0.2.0 (Docker, Compose, Podman) a tout vérifié sauf ce qui demande l'écoulement du
temps ou des services réels, et trouvé deux défauts, corrigés (composants IA d'image
perdus à l'ingestion ; doublons de notification). `v0.2.0` est prête (`CHANGELOG.md`,
`make release` vérifié). Restent à l'utilisateur : la mesure de l'IA avec une clé, la
publication de `v0.2.0`, les essais sur des services réels et la relecture des décisions
(voir « Actions pour l'utilisateur »).

| Lot | PR | Statut | Décisions à relire |
| --- | --- | --- | --- |
| T16 | #21 | Terminé | Filtre d'équipe déclaré à la transaction, fermé par défaut ; matrice des droits (administrateur d'équipe sans gestion des équipes ni des membres de l'organisation, rattachement avec droit dans les deux équipes) ; 404 pour une équipe invisible ; agents sans équipe = agents d'organisation, agents dépôt existants d'organisation ; équipe « Général » aussi pour une nouvelle organisation, « General » en anglais ; invitations de 30 jours, sans équipe, bornées, nouvelle fonction `crossorg` ; tendance d'un membre additionnée par projet ; point d'essai `routeStub` — tous **[à relire]** |
| T17 | #22 | Terminé | Différences enregistrées pour les seuls couples consécutifs, par job ; appariement par `purl_base` et version, même version = retrait + ajout, versions incomparables « approchées » ; effet sur la sécurité calculé à la lecture, sans `not_matched` ; « un par mois » = le dernier du mois, instantané en vigueur à la coupure toujours gardé ; fenêtre sur scan et réception ; `count` en plus de `days` ; réceptions hors fenêtre supprimées, orphelins même rétention désactivée, composants jamais purgés ; constat sans instantané (`SET NULL`) ; verrous ingestion / rétention ; horizon pour T21 ; frise = liste enrichie — tous **[à relire]** |
| T14 | #23 | Terminé | Statut effectif rangé sur chaque constat, verrou consultatif ; journal en ajout seul avec retrait, échéance qui ramène « à analyser » à sa portée ; décision de projet sur le purl exact ; permission `triage.org` ; échéance par job ; audit d'un import groupé ; tableau de bord sans non affectés ni faux positifs ; VEX (structures OpenVEX propres, marques `[lotor:…]`, justification d'origine toujours notée, export des seuls constats ouverts décidés, import de projet par famille et version) ; fiche du constat en page au lieu du tiroir — tous **[à relire]** |
| T13 | #24 | Terminé | Client HTTP sur socket Unix plutôt que le client moby (écart au § 5) ; scan de l'image exportée (`docker save`) ; catalogueurs hors ligne aussi pour l'hôte ; équipe imposée par clé étrangère en cascade ; signalement dédié qui vaut signal de vie ; archivage à la main qui tient ; conteneurs écartés des listes et de la recherche, comptés au tableau de bord ; agrégat par vulnérabilités distinctes — tous **[à relire]** |
| T12 | #25 | Terminé (mesure avec un vrai modèle : action de l'utilisateur, reprise par T18) | SDK officiel d'Anthropic construit sans environnement (ADR 0042) ; réglage par dépôt, permission `ai.external`, `ai.forbid_external` ramène à « local » (ADR 0043) ; règles du vérificateur au-delà de la fiche (documentation, manifestes, marqueurs d'injection, purl dans l'extrait) ; statut `carried` et commits intermédiaires sans modèle ; confinement sans processus fils (ADR 0044) ; exclusions intégrées ; budgets par défaut ; prompt système en anglais — tous **[à relire]** |
| T15 | #26 | Terminé | `cel.dev/cel-go` v0.32.0 (nouveau chemin de `github.com/google/cel-go`) ; contexte typé à deux sujets, `finding.actionable`, coût borné ; « correctif depuis » = première vue par lotor ; violations par couple règle × sujet ; verdict sur l'état courant de la référence ; modèle AGPL indisponible jusqu'à T20 ; objectifs de délai exprimés par des règles ; règles et canaux aux administrateurs ; envois uniques par canal × violation, 30 tentatives puis relance quotidienne ; clé HMAC fournie, garde SSRF sans mandataire ; statut de commit synchrone, désactivé par défaut, jeton GitHub séparé ; rotation des secrets des canaux — tous **[à relire]** |
| T18 (1/n, compléments) | #27 | Fait ; open-go-base PR #5 fusionnée (`a0f777f`), étiquette `v1.4.0` à pousser | Codes de secours : 16 caractères de Crockford (80 bits), SHA-256 lié au compte, 10 par défaut, régénération après un code TOTP, reconfiguration de l'application par le titulaire (au-delà de la fiche), pas de bannière pour les comptes sans codes ; recherche : statut de triage de tous les constats, filtre `triage` refusé hors vulnérabilité, recherche par composant sans constats masqués ; purge des conteneurs archivés pour absence depuis 180 jours, jamais archivés à la main ni triés ; boutons de revue des détections IA de T12 non livrés — tous **[à relire]** |
| T18 (2/n, sécurité) | #28 | Fait ; open-go-base PR #6 fusionnée (`0900e0c`), étiquette `v1.4.1` à pousser | Revue du lot 2 : 0 High, 2 Medium et 5 Low corrigés, 2 Note corrigées, 1 acceptée ; reconfiguration du second facteur avec nouveau mot de passe (modifie ADR 0048) ; défense en profondeur de l'enrôlement gardée dans lotor ; inscription par le nom bornée à l'équipe, homonyme répondu « hôte déjà suivi » ; IA externe ramenée à « désactivé » au changement de dépôt ; secret de canal à ressaisir au changement de destination ; `containers.max_per_host` = 1 000, signalement refusé en entier ; détection de clé dans `list_dir` limitée à 64 Kio ; ports des canaux libres ; 20 appels d'outils par réponse, 2 Kio par recherche ; SEC2-10 accepté — tous **[à relire]** ([ADR 0051](../docs/adr/0051-corrections-revue-securite-lot2.md)) |
| T18 (3/n, accessibilité) | #29 | Fait | Audit RGAA des écrans du lot 2 : 93,1 % puis 100 %, 4 NC mineures corrigées ; régénération des codes et changement d'application sans page de confirmation (code saisi = confirmation, 11.12) ; champs du triage révélés par `:has()` sans repli ; défaut d'un écran du lot 1 (fiche composant) corrigé ici ; statuts de triage cliquables conformes à 10.6 sans soulignement permanent — tous **[à relire]** |
| T18 (4/n, recette) | #30 | Terminé, **lot 2 terminé** (mesure de l'IA avec une clé et `v0.2.0` : actions de l'utilisateur) | Critère « zéro composant IA sans preuve » coché sur modèles fictifs et contrôle indépendant `checkProof` ; échantillon pilote = les quatre dépôts du lot 1, non recopiés, « ignoré » pour ce que Syft voit ; mode `credulous` de `make eval-ai` ; composants IA toujours `library` ; envois de notification réservés (migration 023, [ADR 0052](../docs/adr/0052-envois-de-notification-reserves.md)) ; jeu de mesure complété des équipes et conteneurs ; recette sur une mise à jour réelle 0.1.0 → 0.2.0, temps de l'état « absent » simulé, outillage hors dépôt ; `CHANGELOG.md` daté du 1er novembre — tous **[à relire]** ([T18](lots/T18-recette-lot-2.md#partie-4--recette-mesures-et-préversion)) |

### Décisions à relire, par thème

#### Équipes, droits et isolement

- Filtre d'équipe par réglage de transaction (`db.Visible`, `lotor.teams`) et fonction
  `lotor_team_visible`, qui échoue sans déclaration ; politiques RLS par équipe écartées
  ([ADR 0034](../docs/adr/0034-equipes-et-droits.md), [T16](lots/T16-equipes-droits.md#décisions)).
- Matrice des droits ([`permissions.md`](../docs/security/permissions.md)) : rôles
  minimaux de chaque permission, liste des membres visible de tout membre,
  `finding.triage` déclaré pour T14 ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- 404 pour une ressource d'une équipe invisible, 403 pour un droit manquant
  ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Agents : équipe facultative, agents dépôt existants d'organisation, agents serveur dans
  « Général » ; équipe supprimée : agents rendus à l'organisation, jetons d'inscription
  supprimés ; rattachement d'un dépôt qui perd un agent d'équipe, d'un serveur qui emmène
  le sien ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Équipe « Général » créée aussi avec chaque nouvelle organisation ; « General » pour une
  organisation en anglais ([T16](lots/T16-equipes-droits.md#décisions)).
- Tableau de bord d'un membre : tendance additionnée par projet ; fiche composant en 404
  hors des équipes visibles ([ADR 0034](../docs/adr/0034-equipes-et-droits.md)).
- Point d'essai `routeStub` pour le test des droits dérivé de la matrice
  ([T16](lots/T16-equipes-droits.md#décisions)).

#### Historique, différences et rétention

- Différences des instantanés consécutifs enregistrées par couple d'ensembles (job
  `inventory.diff`), comparaison quelconque à la demande, appariement par `purl_base`
  et version, versions incomparables « approchées »
  ([ADR 0038](../docs/adr/0038-differences-d-instantanes.md), [T17](lots/T17-differences-instantanes.md#décisions)).
- Effet sur la sécurité calculé à la lecture (vulnérabilité présente des deux côtés ni
  résolue ni introduite, `not_matched` exclu, 200 constats au plus de chaque côté)
  ([ADR 0038](../docs/adr/0038-differences-d-instantanes.md)).
- Rétention : dernier instantané de chaque mois (UTC) au-delà de 90 jours, instantané en
  vigueur au début de la fenêtre toujours gardé, fenêtre sur la date de scan et la date
  de réception, instantané de la dernière analyse gardé, `retention.count` en plus de la
  fenêtre ([ADR 0039](../docs/adr/0039-retention-des-instantanes.md)).
- Purge : réceptions terminées hors fenêtre, ensembles et SBOM orphelins (même rétention
  désactivée), composants jamais purgés ; constat et historique gardés sans instantané
  (`ON DELETE SET NULL`, migration 017) ; horizon `snapshot_retention` pour T21
  ([ADR 0039](../docs/adr/0039-retention-des-instantanes.md)).

#### Sécurité et identité

- SEC-09 corrigé par des invitations : 30 jours, 200 en attente par organisation, une par
  adresse, sans équipe, adresse déjà membre non invitée ; ajout direct gardé pour
  l'administration de l'instance ; nouvelle fonction `crossorg`
  `lotor_user_invitations` ([ADR 0034](../docs/adr/0034-equipes-et-droits.md),
  [modèle de menace](../docs/security/threat-model.md)).

#### Enrichissement IA (T12)

- SDK Go officiel d'Anthropic v2.4.0 validé (six lignes de plus dans `go.mod`), construit
  par `option.WithoutEnvironmentDefaults()` ; client HTTP maison écarté ; pas de repli de
  modèle côté serveur sur refus ; Ollama par `/api/chat`
  ([ADR 0042](../docs/adr/0042-fournisseurs-de-modeles.md)).
- Réglage `disabled`/`local`/`external` par dépôt, permission d'organisation
  `ai.external`, audit `project.ai_mode_changed`, `ai.forbid_external` qui transmet
  `external` comme `local` sans réécrire les projets ; l'agent prend le fournisseur externe,
  à défaut le modèle local ([ADR 0043](../docs/adr/0043-enrichissement-ia-prouve.md)).
- Vérificateur : preuve refusée dans la documentation, un manifeste que Syft lit, un
  fichier qui s'adresse à un modèle, ou un extrait qui cite un purl ; tolérance de trois
  lignes ; cohérence type/fichier limitée ([ADR 0043](../docs/adr/0043-enrichissement-ia-prouve.md)).
- Statut `lotor:enrichment` dans les métadonnées CycloneDX (`complete`, `incomplete`,
  `carried`), commits intermédiaires d'un rattrapage sans appel au modèle, analyse
  complète tous les 7 jours ([ADR 0043](../docs/adr/0043-enrichissement-ia-prouve.md)).
- Analyse confinée par la surface d'outils et `os.Root`, sans processus fils
  ([ADR 0044](../docs/adr/0044-confinement-de-l-analyse-ia.md)).
- Liste d'exclusion intégrée, détection des clés privées, budgets par défaut (40 tours,
  600 000 / 40 000 jetons, 1 Mio lu, 20 min), prompt système en anglais, écarts à la
  maquette ([T12](lots/T12-enrichissement-ia.md#décisions)).

#### Triage et VEX (T14)

- Statut effectif rangé sur chaque constat, recalculé à chaque décision et classé par
  l'analyse sous un verrou consultatif ; journal `triage_decisions` en ajout seul avec
  retrait explicite ; échéance qui ramène « à analyser » à sa portée ; décision de projet
  sur le purl exact ; permission `triage.org` pour les administrateurs ; échéance par un
  job par décision, risque accepté borné à 3 ans ; un événement d'audit par import ;
  tableau de bord et effet sur la sécurité des comparaisons d'instantanés (T17) sans les
  constats non affectés ni faux positifs
  ([ADR 0035](../docs/adr/0035-decisions-de-triage.md)).
- VEX : OpenVEX par des structures propres (`openvex/go-vex` écarté), marques
  `[lotor:…]` et propriétés `lotor:`, justification d'origine toujours notée quand elle
  change de liste, export des seuls constats ouverts qui ont une décision, import de
  projet par famille, version et qualificatifs compatibles, bornes 1 Mio et 5 000
  déclarations, pas d'import par l'API ([ADR 0036](../docs/adr/0036-echanges-vex.md)).
- Écrans : fiche du constat en page au lieu du tiroir de la maquette, justification et
  commentaire exigés, deux vocabulaires proposés, onglet VEX, rubrique Triage
  ([ADR 0037](../docs/adr/0037-ecrans-du-triage.md)).

#### Conteneurs (T13)

- API Docker de Docker et Podman par un client HTTP sur socket Unix, sans bibliothèque
  cliente, plutôt que le client moby du graphe de stereoscope (écart au § 5 de
  l'architecture, mis à jour) ; moteur détecté par `/version`
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Image exportée (`docker save`) dans `<state_dir>/images` et scannée par la source
  `docker-archive` de Syft, une fois par image, 4 096 Mio au plus ; empreintes d'images
  gardées par l'agent et confirmées par le serveur, jamais de SBOM sur le disque
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Catalogueurs de Syft hors ligne pour le scan de l'hôte aussi (plus de `go list` sous
  `/`) : un hôte qui porte des modules Go renvoie une fois son SBOM
  ([ADR 0041](../docs/adr/0041-inventaire-des-conteneurs-par-l-agent.md)).
- Équipe du conteneur imposée par une clé étrangère `ON UPDATE CASCADE` vers l'hôte ;
  conteneur sans agent propre ; nom `hôte/identité`
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Signalement `POST /api/v1/agent/containers` (500 identités, 1 Mio), qui vaut signal de
  vie et porte les comptes rendus d'inventaire ; l'hôte vient du jeton
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Conteneur archivé à la main : reste archivé, l'agent l'ignore ; archivé pour absence :
  revient seul, pas de réactivation à la main
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Conteneurs écartés par défaut des listes et de la recherche (`containers=1` s'ajoute à
  `type`), comptés dans le tableau de bord de l'organisation
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
- Fiche hôte : vulnérabilités distinctes par projet à la plus haute sévérité, conteneurs
  archivés hors du total ; état « absent » d'un conteneur non signalé depuis le dernier
  inventaire de l'hôte, à une heure près
  ([ADR 0040](../docs/adr/0040-conteneurs-en-projets-enfants.md)).
#### Politiques, alertes et statuts de commit (T15)

- Dépendance `cel.dev/cel-go` v0.32.0 : `github.com/google/cel-go` sous son nouveau chemin
  de module (le chemin GitHub s'arrête à v0.31.0), version la plus récente de plus de deux
  semaines, `antlr4-go` en transitive ([ADR 0045](../docs/adr/0045-politiques-cel-et-verdicts.md)).
- Règles sur un contexte typé (constat ou agent), `finding.actionable` = « à analyser » ou
  « affecté », coût borné (50 000), 100 politiques par organisation ; « correctif disponible
  depuis » = première vue par lotor (`findings.fixed_seen_at`) ; modèle « licence AGPL »
  indisponible jusqu'à T20, « production » = étiquette `env=production`
  ([ADR 0045](../docs/adr/0045-politiques-cel-et-verdicts.md)).
- Violations par couple (règle, sujet), résolues dès que la règle cesse d'être vraie ;
  verdict d'un instantané sur l'état courant de sa référence, en attente tant qu'il n'est
  pas analysé et évalué ; règles d'agent jamais bloquantes ; objectifs de délai du tableau
  de bord exprimés par des règles, section « Alertes » livrée
  ([ADR 0045](../docs/adr/0045-politiques-cel-et-verdicts.md)).
- Notifications : un envoi par couple (canal, violation), regroupés, 30 tentatives puis
  relance quotidienne, violation résolue écartée, identifiant de message stable ; clé HMAC
  fournie par l'administrateur ; garde SSRF sans mandataire
  (`notify.allow_private_networks`) ; résumé à 7 h UTC ; rotation des secrets des canaux
  au démarrage ([ADR 0046](../docs/adr/0046-notifications.md)).
- Conteneurs : étiquettes de l'hôte héritées, violations d'un conteneur archivé hors des
  listes ouvertes puis résolues à l'évaluation suivante
  ([ADR 0045](../docs/adr/0045-politiques-cel-et-verdicts.md)).
- Statut de commit : attente synchrone bornée, « en attente » laissé à l'expiration,
  `canceled` sur GitLab pour une ingestion refusée, désactivé par défaut, jeton GitHub
  séparé limité à `statuses: write` ([ADR 0047](../docs/adr/0047-statut-de-commit.md)).

#### Recette du lot 2, compléments (T18, partie 1)

- Codes de secours dans mfax (open-go-base v1.4.0) : codes de 16 caractères de Crockford
  (80 bits), empreinte SHA-256 liée au compte, 10 par défaut (`mfa.recovery_codes`),
  `RecoveryRenderer` facultative, codes faux dans le verrouillage par compte
  ([ADR 0048](../docs/adr/0048-codes-de-secours.md)).
- Régénération après un code TOTP, codes montrés une seule fois ; reconfiguration de
  l'application par le titulaire (code TOTP ou code de secours, sessions fermées, nouvel
  enrôlement ; mot de passe et jetons gardés ; sans page de confirmation) ; comptes enrôlés
  avant la mise à jour invités depuis la page du second facteur
  ([ADR 0048](../docs/adr/0048-codes-de-secours.md)).
- Recherche : filtre `team`, statut de triage de tous les constats d'une recherche par
  vulnérabilité, filtre `triage` refusé ailleurs, recherche par composant sans les
  constats « non affecté » ni « faux positif », colonnes ajoutées en fin d'export
  ([ADR 0050](../docs/adr/0050-equipe-et-triage-dans-la-recherche.md)).
- Purge des conteneurs archivés pour absence depuis `containers.purge_after` (180 jours,
  au moins `retention.days`) par la rétention nocturne, jamais archivés à la main ni
  porteurs d'une décision de triage, audit `project.purged`
  ([ADR 0049](../docs/adr/0049-purge-des-conteneurs-archives.md)).
- Boutons « Confirmer la détection » / « Signaler une erreur » de T12 non livrés (fonction
  nouvelle, hors T18) ([T18](lots/T18-recette-lot-2.md#écarts)).

#### Revue de sécurité du lot 2 (T18, partie 2)

- Second facteur : `POST /account/totp/enable` refusé sur un TOTP actif (dans mfax v1.4.1
  et, en défense en profondeur, dans lotor), codes faux comptés dans le verrouillage ;
  échecs d'enrôlement non journalisés un par un
  ([ADR 0051](../docs/adr/0051-corrections-revue-securite-lot2.md) § 1).
- Reconfiguration de l'application par le titulaire : **nouveau mot de passe exigé**,
  validé avant la consommation du code ; jetons personnels gardés (ADR 0051 § 2, modifie
  ADR 0048).
- Inscription d'un agent serveur par le nom d'hôte bornée à l'équipe du jeton ; homonyme
  d'une autre équipe (avec ou sans agent, archivé) répondu « hôte déjà suivi » ; projet
  désigné passé dans une autre équipe refusé (ADR 0051 § 3).
- IA externe ramenée à « désactivé » (pas « local ») quand un acteur sans `ai.external`
  change l'URL du dépôt (ADR 0051 § 4).
- Secret d'un canal à ressaisir quand le serveur Matrix ou l'URL du webhook change ; salon
  Matrix modifiable sans ressaisie (ADR 0051 § 5).
- `containers.max_per_host` (1 000) : signalement refusé en entier au-delà, pas de quota
  quotidien (ADR 0051 § 6).
- Détection de clé privée dans `list_dir` limitée aux fichiers de 64 Kio (ADR 0051 § 7).
- Garde SSRF étendue (plages réservées, NAT64, 6to4) ; ports des canaux non restreints,
  oracle de balayage accepté (ADR 0051 § 8).
- 20 appels d'outils exécutés par réponse du modèle, 2 Kio par recherche (ADR 0051 § 9).
- `lotor_user_invitations` sans garde SQL : accepté comme SEC-12 (ADR 0051 § 10).

#### Audit RGAA du lot 2 (T18, partie 3)

- Régénération des codes de secours et changement d'application d'authentification sans
  page de confirmation : le code exigé tient lieu de confirmation (RGAA 11.12)
  ([grille, § 5](../docs/accessibilite/grille-rgaa-lot2.md#5-actions-irréversibles),
  [T18](lots/T18-recette-lot-2.md#partie-3--audit-rgaa)).
- Champs complémentaires du triage révélés par `:has()`, sans JavaScript ni repli
  ([T18](lots/T18-recette-lot-2.md#partie-3--audit-rgaa)).
- Débordement à 320 px de la fiche composant (écran du lot 1) corrigé dans l'audit du
  lot 2 ; redistribution repassée sur toutes les pages à chaque audit
  ([T18](lots/T18-recette-lot-2.md#partie-3--audit-rgaa)).
- Statuts de triage cliquables (pastilles) jugés conformes à 10.6 sans soulignement
  permanent ([grille, § 3](../docs/accessibilite/grille-rgaa-lot2.md#3-grille-des-écrans-du-lot-2-106-critères)).

#### Recette du lot 2 : évaluation, mesures et préversion (T18, partie 4)

- Critère « aucun composant IA sans preuve vérifiée » coché sur des modèles fictifs
  (crédule, hostile, adverse) et le contrôle indépendant `checkProof`, rejoué par chaque
  `make eval-ai` ; les seuils (faux positifs, rappel) restent à mesurer avec un vrai modèle
  ([T18](lots/T18-recette-lot-2.md#décisions-4)).
- Échantillon pilote : les quatre dépôts publics du lot 1 aux mêmes commits, clonés par
  `scripts/ai-pilot-fetch.sh` et non recopiés ; règles d'annotation (attendu, ignoré,
  piège) dans `testdata/ai-pilot/README.md` ; mode `credulous` pour un contrôle à blanc
  sans clé ([T18](lots/T18-recette-lot-2.md#décisions-4)).
- Composants IA émis en type `library`, image comprise, plutôt qu'un décodeur du serveur
  élargi aux composants `container` ([T18](lots/T18-recette-lot-2.md#décisions-4)).
- Envois de notification réservés sous le verrou du canal avant l'appel réseau
  (`claimed_at`, 10 minutes, réessai par la file) plutôt qu'une transaction tenue pendant
  l'envoi ([ADR 0052](../docs/adr/0052-envois-de-notification-reserves.md)).
- Mesures sur le jeu de référence complété (10 équipes, 50 hôtes × 10 conteneurs, triage
  d'un constat ouvert sur dix), « membre » = une équipe sur dix, agent serveur sur
  4 cycles ; cibles tenues sur 4 cœurs, valant pour la référence ; cibles du cahier des
  charges toujours « proposées » ([`benchmarks.md`](../docs/benchmarks.md#t18--mesures-consolidées-du-lot-2-avec-les-équipes-et-les-conteneurs)).
- Recette sur une mise à jour réelle 0.1.0 → 0.2.0 (binaires publiés), parc en
  conteneurs Docker, Compose et Podman, temps de l'état « absent » simulé en base,
  outillage hors dépôt ; `CHANGELOG.md` daté du 1er novembre 2026
  ([T18](lots/T18-recette-lot-2.md#recette-fonctionnelle)).


#### Écarts

- T12 : **mesure de la précision, du rappel et du coût avec un vrai modèle non faite**
  (aucune clé d'API ni modèle local), reprise et préparée par T18 (corpus étendu,
  échantillon pilote, contrôle à blanc) : critère des seuils non coché ; captures clair et
  sombre non faites ([T12](lots/T12-enrichissement-ia.md#écarts),
  [T18](lots/T18-recette-lot-2.md#écarts-3)).
- T13 : Podman **rootful** essayé par la recette de T18 (Podman 4.9.3, avec Docker 29.9
  et Compose) ; **Podman sans root non essayé** ; purge des conteneurs archivés livrée en
  T18 (partie 1) ([T13](lots/T13-conteneurs.md#écarts)).
- T14 : triage livré en page (pas en tiroir) ; statut de triage dans la recherche livré
  en T18 (partie 1) ; import de VEX d'éditeur non rejoué par la recette (tests
  d'intégration) ([T14](lots/T14-triage-vex.md#écarts)).
- T15 : statut de commit vérifié contre des forges simulées seulement ; canaux Matrix,
  Slack, Mattermost et e-mail non essayés sur de vrais services (webhook générique essayé
  par la recette, signature vérifiée) ; pas de réglage d'objectifs de délai ; aperçu
  d'une politique exercé sur l'instance de recette, non mesuré sur le jeu de référence
  ([T15](lots/T15-politiques-alertes.md#écarts)).
- T16 : filtre « équipe » de la recherche livré en T18 (partie 1) ; captures d'écran non
  faites, audit RGAA du lot 2 fait en T18 ([T16](lots/T16-equipes-droits.md#écarts)).
- T17 : réceptions hors fenêtre supprimées en plus des orphelins ; rétention non rejouée
  en temps réel par la recette (tests d'intégration) ([T17](lots/T17-differences-instantanes.md#écarts)).
- T18 : boutons de revue des détections IA de T12 non livrés (fonction nouvelle) ;
  recommandations R-L2-01 à R-L2-05 de la grille RGAA ouvertes ; `make bench-search`
  cassé depuis T16 dans son dernier pas, corrigé ([T18](lots/T18-recette-lot-2.md#écarts)).

### Actions pour l'utilisateur

Le mandataire git de la session refuse les pushs d'étiquettes (HTTP 403). Dans l'ordre :

1. **Fait** : étiquettes d'open-go-base `v1.4.0` (commit `a0f777f`, PR #5 : codes de
   secours de mfax) et `v1.4.1` (commit `0900e0c`, PR #6 : `EnablePOST` sous verrouillage,
   SEC2-01) poussées.
2. **Fait** : lotor passé de la pseudo-version à `v1.4.1` (même code que
   `v1.3.1-0.20261101111845-0900e0c6a132`).
3. **Mesurer l'enrichissement IA avec une clé** (critère de T18 non coché), pas à pas dans
   [`docs/operations.md`](../docs/operations.md#évaluer-lenrichissement-ia) :
   `scripts/ai-pilot-fetch.sh /tmp/lotor-ai-pilot`, contrôle à blanc
   (`LOTOR_EVAL_AI_PROVIDER=credulous`), puis
   `LOTOR_EVAL_AI_PROVIDER=anthropic LOTOR_EVAL_AI_API_KEY_FILE=<fichier 0600>
   LOTOR_EVAL_AI_PILOT_DIR=/tmp/lotor-ai-pilot LOTOR_EVAL_AI_RUNS=3
   LOTOR_EVAL_AI_REPORT=/tmp/eval-ai.json make eval-ai`. Reporter, pour le corpus **et**
   le pilote, faux positifs, rappel et coût moyen dans le Journal de T18 ; cocher le
   critère s'ils tiennent (faux positifs ≤ 5 %, rappel ≥ 80 %) ; **confirmer ou changer le
   modèle par défaut** `claude-sonnet-5-5` ; sinon ajuster le prompt (nouvelle version)
   avant d'activer l'IA sur des projets. Facultatif : la même mesure avec Ollama.
4. **Fait** (4 novembre 2026, étiquette sur `78fca4e`, puis `v0.2.1`) : **publier la préversion `v0.2.0`**, après les étapes 1 et 2 (et 3 si le résultat doit
   figurer dans les notes) :
   1. vérifier la section `## [0.2.0] - 2026-11-04` de `CHANGELOG.md` (date du jour de la
      pose ; ajouter le résultat de l'IA s'il y a lieu) et la CI de `main` ;
   2. `git fetch origin && git tag -a v0.2.0 origin/main -m "lotor 0.2.0 — préversion du lot 2"` ;
   3. `git push origin v0.2.0` ;
   4. suivre le workflow **release** ; vérifier sur *Releases* une **préversion** `v0.2.0`
      avec six archives, quatre paquets et `SHA256SUMS` (`sha256sum -c --ignore-missing
      SHA256SUMS` sur un téléchargement) ;
   5. cocher « `v0.2.0` publiée » dans [T18](lots/T18-recette-lot-2.md). En cas d'échec :
      corriger sur `main` et poser `v0.2.1` (ne jamais déplacer une étiquette poussée).
5. **Avant de mettre à jour une instance réelle en 0.2.0** (`docs/operations.md`, « Mise
   à jour ») : régler `retention.*` (la première nuit réduit l'historique antérieur à
   90 jours à un instantané par mois) et `containers.purge_after` si d'autres durées sont
   voulues ; sauvegarder. Après : vérifier la page **Équipes** de chaque organisation
   (chaque membre dans « Général » avec son ancien rôle, essai fait par la recette sur une
   copie 0.1.0) ; inviter les comptes à générer leurs codes de secours (**Mon compte ›
   Second facteur**) ; prévenir que « Changer d'application d'authentification » demande
   un nouveau mot de passe ; un administrateur qui change le serveur Matrix ou l'URL d'un
   webhook doit ressaisir le secret ; vérifier `containers.max_per_host` (1 000) sur les
   hôtes très chargés ; laisser passer 1 Mio sur les routes d'import VEX derrière un
   mandataire inverse (`docs/operations.md`, « Triage et VEX »).
6. **Essais sur des services réels**, non faisables dans la session :
   - conteneurs : **Podman sans root** avec son ACL et Docker avec docker compose sur un
     hôte réel (`docs/operations.md`, « Conteneurs »), en connaissance de l'équivalence
     root de la socket ;
   - **statut de commit** : accorder *Commit statuses : Read and write* à la GitHub App
     (et l'accepter sur chaque installation), donner la portée `api` et le rôle Developer
     au compte de service GitLab, poser `status.enabled: true` sur l'agent dépôt et
     `notify.public_url` sur le serveur, puis vérifier un statut sur un vrai commit
     ([`operations.md`](../docs/operations.md#statut-de-commit)) ;
   - **canaux** Matrix, Slack, Mattermost et e-mail (`smtp.*`) : créer un canal de chaque
     nature et « Envoyer un test » ;
   - agent dépôt sur une vraie forge (action du lot 1, toujours ouverte :
     [`operations.md`](../docs/operations.md#recette-sur-une-vraie-forge)).
7. **Relire les décisions [à relire]** ci-dessus, en particulier les ADR 0034 à 0052, la
   matrice [`docs/security/permissions.md`](../docs/security/permissions.md), la
   correspondance des justifications VEX (ADR 0036), le choix d'une page plutôt que du
   tiroir (ADR 0037), le modèle de menace version 3, et confirmer (ou corriger) au cahier
   des charges les cibles de performance encore « proposées » (mesures : Journal de T18,
   `docs/benchmarks.md`).
8. Décider si les boutons « Confirmer la détection » / « Signaler une erreur » d'un
   composant trouvé par l'IA (maquette de T12, non livrés) doivent entrer dans un lot
   ultérieur.

## Lot 1

Journal de bord de la réalisation autonome du lot 1 (T00 à T11), demandée le
31 octobre 2026. Chaque entrée renvoie au Journal de la fiche, qui fait foi pour le détail
des décisions. Les décisions prises sans validation explicite de l'utilisateur sont
marquées **[à relire]**.

### Synthèse

Le lot 1 est **réalisé** : le critère du cahier des charges, « un parc pilote inventorié
et interrogé », est passé (recette de T11) sur trois serveurs (Debian 12, Rocky Linux 9,
Alpine 3.18) et quatre dépôts publics réels (deux de GitHub, deux de GitLab, servis par une
forge simulée) : chaque projet a un instantané de moins de 24 h analysé avec la vraie base
Grype, et la recherche (écran et API) renvoie exactement les listes de projets établies à
la main pour les trois CVE de contrôle. Toutes les cibles chiffrées sont tenues sur une
machine moins puissante que la référence. Restent à l'utilisateur : la relecture des
décisions ci-dessous et l'essai de l'agent dépôt sur une vraie forge (voir « Actions pour
l'utilisateur ») ; `v0.1.0` est publiée depuis le 1er novembre 2026.

| Lot | PR | Statut | Décisions à relire |
| --- | --- | --- | --- |
| T00 | #1, #2 | Terminé | `modernc.org/sqlite` ajouté au § 5 **[à relire]** ; OpenAPI 3.1 ; SQL à la main |
| T01 | #3 | Terminé | Migrations et rôles (ADR 0010) ; fragments de config au fil des lots, fragment `HTTP` ; `Seal`/`Open` avec données associées ; en-têtes de sécurité (`base-uri`, HSTS sans sous-domaines) ; thème `light-dark()` + cookie ; polices droites seulement ; pied de page hors planche — tous **[à relire]** |
| T02 | #4 | Terminé | Conception de la file (ADR 0011 : horloge Go, `synchronous_commit = off` pour les transitions d'état, plafond strict, libération sans tentative comptée…) ; valeurs par défaut des workers ; correction de `PoolConfig.MaxIdleConns` (T01) — **[à relire]** |
| T03 | #5 | Terminé | Propriétaire `BYPASSRLS` pour `crossorg` (ADR 0012) ; secrets TOTP chiffrés, `secrets.keys` obligatoire (ADR 0013) ; secours par ticket (deux variables) ; TOTP avant changement de mot de passe ; 404 pour l'administration, 403 dans l'organisation ; `jobs.org_id` sans clé étrangère ; open-go-base en pseudo-version, étiquette `v1.1.0` à pousser — tous **[à relire]** |
| T04 | #6 | Terminé | Format des jetons et deux fonctions `crossorg` pour l'organisation d'un jeton (ADR 0014) ; `ratelimit.WithKeyFunc` dans open-go-base (étiquette `v1.2.0` à pousser) et suppression d'`internal/ratelimit` ; refus de jetons limités par IP ; hôte déjà suivi refusé à l'inscription ; jeton d'agent d'inscription sans expiration ; « muet » sur le dernier contact ; écriture réservée aux administrateurs ; valeurs par défaut — tous **[à relire]** |
| T05 | #7 | Terminé | Décodage dans le worker, sous-processus écarté (ADR 0015) ; règles de l'inventaire (ADR 0016 : purl de packageurl-go, identification faible par élément, CPE hors empreinte, commit renvoyé = ensemble remplacé, courant = date de scan, refus stockés en `failed`, doublon de dépôt en 200) ; validation sans l'énumération des licences SPDX de CycloneDX à la réception ; bornes par défaut (32/64 Mio, profondeur 64, 50 000 composants, 5 min, 2 par organisation) ; directive `go` 1.26.8 (Syft) — tous **[à relire]** |
| T06 | #9 | Terminé | Base Grype commune en blocs dans PostgreSQL, téléchargement par `internal/download` (ADR 0017) ; correspondance hors transaction et écriture sous verrou, identifiants CVE, réanalyse par organisation sans nouvelle fonction `crossorg` (ADR 0018) ; jeu synthétique et autoanalyse par `go run` des commandes Syft et Grype (ADR 0019) ; valeurs par défaut `vulndb.*` ; mesures faites sur 4 cœurs, pas sur la machine de référence — tous **[à relire]** |
| T07 | #10 | Terminé | Envoi conditionnel confirmé par le serveur, Syft JSON, demande de scan remise une fois, muet sur le dernier inventaire pour un agent serveur (ADR 0020) ; unités, secrets, mTLS par middleware, paquets nfpm (ADR 0021) ; scan à la demande ouvert aux analystes ; valeurs par défaut ; cibles 5 min de CPU et 1 Gio par scan ; agent dépôt branché sur le client commun (adresse https exigée) — tous **[à relire]** |
| T08 | #8 | Terminé | Agent dépôt (ADR 0023) : webhook = signal, tête résolue auprès de la forge ; `git fetch --depth 1` du commit au lieu de `clone --single-branch` ; SBOM déterministe (ni numéro de série ni horodatage) ; Syft sans `go list` ni réseau ; échecs définitifs non retentés avant redémarrage ; secrets par `credential:<nom>` ou fichier 0600 ; jeton GitHub restreint à `contents: read` ; valeurs par défaut ; droits GitLab vérifiables seulement sur forge réelle — tous **[à relire]** |
| T09 | #12 | Terminé | Recherche (ADR 0024) : deux nouvelles fonctions `crossorg` de recherche par nom et empreinte (organisation lue dans `lotor.org_id`, contournent la RLS pour les index GIN), sous-chaîne puis trigrammes, bornes, export en flux borné en nombre et durée ; jetons personnels en table globale valables sur les organisations du compte, expiration obligatoire, sans session dans l'API (ADR 0025) ; comparateurs de Grype corrigés et plages vers maison (ADR 0026) ; défauts `user_api` ; écarts à la maquette ; mesures sur 4 cœurs — tous **[à relire]** |
| T10 | #11 | Terminé | Tableau de bord (ADR 0027) : constats des références actives des projets actifs ; statistiques réécrites toutes les heures sous la date du jour ; `project_daily_stats` en plus d'`org_daily_stats` ; pas de nouvelle fonction `crossorg` ; seuil « muet » de 7 jours pour toute l'interface ; périodes 30/90/365 j ; tuiles sans lien (pas de liste transverse avant T09) ; section « Alertes » et objectifs de délai renvoyés à T15 ; mesures sur 4 cœurs partagés — tous **[à relire]** |
| T11 (1/2, administration) | #13 | Terminé | Administration de l'instance (ADR 0028) : archive téléversée rangée dans PostgreSQL puis installée par un job, jeton CSRF en tête du formulaire présenté à csrfx, archive importée cible même plus ancienne, un import à la fois, état par instance (`vulndb_instances`), purge de toutes les archives non cibles avec confirmation ; `download_timeout` borne aussi le téléversement ; test instable corrigé dans le test (bail simulé complet) ; codes de secours de mfax absents d'open-go-base, reportés à T18 — tous **[à relire]** |
| T11 (accessibilité) | #14 | Terminé | Audit RGAA : 13 NC corrigées, 100 % des critères applicables ; page de confirmation commune pour les actions irréversibles (abandon d'un traitement compris) ; plan du site plutôt que la recherche pour 12.1 ; préfixe « Erreur : » sur tout écran en 4xx ; abréviations des sévérités — tous **[à relire]** |
| T11 (sécurité) | #15 | Terminé | Revue de sécurité du lot 1 (14 constats, 0 haut ni critique) : 3 Medium, 6 Low et 2 Note corrigés (SEC-11 et SEC-14 en partie), SEC-13 accepté, SEC-09 (Low) accepté jusqu'à T16 ; open-go-base v1.3.0 (PR #3 fusionnée, étiquette à pousser) ; ADR 0029 à 0031 — tous **[à relire]** |
| T11 (recette) | #16 | Terminé (v0.1.0 publiée le 1er novembre 2026) | Parc pilote en conteneurs et forge simulée ; CVE de contrôle ; cibles tenues sur 4 cœurs, valant pour la référence ; publication des versions (ADR 0032) et unité systemd du serveur ; guides de démarrage FR et EN séparés de `utilisation.md` ; outillage de recette hors dépôt — tous **[à relire]** |
| Renommage en lotor | — | Terminé | Correspondance unique `open-go-sbom`/`ogsbom` → `lotor` partout, migrations réécrites en place avant toute publication, identité visuelle dans `docs/logo/` et l'interface (ADR 0033) — **[à relire]** |

### Décisions à relire, par thème

Chaque point renvoie à l'ADR ou au Journal qui le détaille.

#### Architecture, base de données et file

- Migrations sous verrou, immuables, deux rôles PostgreSQL ([ADR 0010](../docs/adr/0010-migrations-et-roles-postgresql.md), [T01](lots/T01-socle-serveur.md)).
- Conception de la file : horloge Go, `synchronous_commit = off` pour les transitions, plafond strict par organisation, libération sans tentative comptée, défauts des workers ([ADR 0011](../docs/adr/0011-conception-de-la-file.md), [T02](lots/T02-file-de-traitements.md)).
- Isolement : propriétaire `BYPASSRLS` pour `crossorg`, `jobs.org_id` sans clé étrangère ([ADR 0012](../docs/adr/0012-isolement-des-organisations.md), [T03](lots/T03-comptes-organisations.md)) ; fonctions `crossorg` des jetons ([ADR 0014](../docs/adr/0014-jetons-et-api-des-agents.md)) et de la recherche ([ADR 0024](../docs/adr/0024-recherche-transverse.md)).
- Journal d'audit en ajout seul, rôle d'exécution sans `CREATE`, quotas d'ingestion (200 envois par référence et par jour, 10 Gio par organisation), plafonds par compte ([ADR 0030](../docs/adr/0030-durcissement-base-et-quotas.md)).

#### Sécurité et identité

- Secrets TOTP chiffrés, `secrets.keys` obligatoire, secours par ticket ([ADR 0013](../docs/adr/0013-comptes-et-second-facteur.md), [T03](lots/T03-comptes-organisations.md)).
- Verrouillage par compte des codes TOTP (10 en 15 min, 15 min doublées jusqu'à 24 h), révocation d'office des jetons, réinitialisation du TOTP avec mot de passe temporaire, `bootstrap.rescue_password`, durée absolue de session de 7 jours ([ADR 0029](../docs/adr/0029-remediation-des-identifiants.md)).
- CSRF lié à la session, `http.CrossOriginProtection`, cookies `__Host-` avec `cookie_secure: on` ([ADR 0031](../docs/adr/0031-csrf-cookies-et-perimetre-de-l-agent-depot.md)).
- Constats acceptés : SEC-09 (énumération des comptes par un administrateur d'organisation, jusqu'à T16) et SEC-13 ([revue de sécurité](lots/T11-recette-lot-1.md#revue-de-sécurité)).
- En-têtes de sécurité (`base-uri`, HSTS sans sous-domaines), `Seal`/`Open` avec données associées ([T01](lots/T01-socle-serveur.md)) ; 404 pour l'administration, 403 dans l'organisation ([T03](lots/T03-comptes-organisations.md)).
- Codes de secours de mfax reportés à T18 ([T11, partie 1](lots/T11-recette-lot-1.md#partie-1--administration-de-linstance-et-corrections)).

#### Ingestion et inventaire

- Décodage dans le worker ([ADR 0015](../docs/adr/0015-decodage-des-sbom-dans-le-worker.md)) ; règles de l'inventaire ([ADR 0016](../docs/adr/0016-ingestion-et-inventaire.md)) ; validation sans l'énumération des licences SPDX, bornes par défaut ([T05](lots/T05-ingestion.md)).

#### Analyse de vulnérabilités

- Base Grype commune en blocs dans PostgreSQL ([ADR 0017](../docs/adr/0017-base-grype-commune.md)) ; correspondance et constats, identifiants CVE ([ADR 0018](../docs/adr/0018-analyse-et-constats.md)) ; import d'archive, cible même plus ancienne, purge ([ADR 0028](../docs/adr/0028-administration-de-la-base-et-des-traitements.md)) ; défauts `vulndb.*` ([T06](lots/T06-analyse-vulnerabilites.md)).

#### Agents

- Agent serveur : envoi conditionnel, Syft JSON, « muet » sur le dernier inventaire ([ADR 0020](../docs/adr/0020-agent-serveur-envoi-conditionnel.md)) ; unités, mTLS par middleware, paquets nfpm ([ADR 0021](../docs/adr/0021-deploiement-agent-serveur.md)) ; cibles 5 min de CPU et 1 Gio par scan ([T07](lots/T07-agent-serveur.md)).
- Jetons et API des agents, jeton d'agent sans expiration, hôte déjà suivi refusé ([ADR 0014](../docs/adr/0014-jetons-et-api-des-agents.md), [T04](lots/T04-projets-agents.md)).
- Agent dépôt : webhook = signal, `git fetch --depth 1` du commit, SBOM déterministe, Syft sans `go list` ni réseau, jeton GitHub restreint ([ADR 0023](../docs/adr/0023-agent-depot.md)) ; `allowed_namespaces` obligatoire ([ADR 0031](../docs/adr/0031-csrf-cookies-et-perimetre-de-l-agent-depot.md)).

#### Recherche et tableau de bord

- Recherche : sous-chaîne puis trigrammes, bornes, export en flux ([ADR 0024](../docs/adr/0024-recherche-transverse.md)) ; jetons personnels ([ADR 0025](../docs/adr/0025-jetons-d-acces-personnels.md)) ; comparaison de versions et plages `vers` ([ADR 0026](../docs/adr/0026-comparaison-de-versions.md)).
- Tableau de bord : statistiques horaires sous la date du jour, seuil « muet » de 7 jours, périodes, renvois à T15 ([ADR 0027](../docs/adr/0027-tableau-de-bord.md)).

#### Interface et accessibilité

- Thème `light-dark()` et cookie, polices droites, pied de page ([T01](lots/T01-socle-serveur.md)) ; écarts à la maquette ([T09](lots/T09-recherche.md)).
- Page de confirmation commune, plan du site, préfixe « Erreur : », abréviations des sévérités ([audit RGAA](lots/T11-recette-lot-1.md#audit-rgaa)).

#### Exploitation, mesures et publication

- Cibles chiffrées tenues sur 4 cœurs (machine moins puissante que la référence), cibles du cahier des charges encore « proposées » à confirmer ([mesures de T11](lots/T11-recette-lot-1.md#mesures-consolidées), [`benchmarks.md`](../docs/benchmarks.md)).
- Publication des versions : étiquette sur `main`, préversions seulement, archives et paquets, unité systemd du serveur ([ADR 0032](../docs/adr/0032-publication-des-versions.md)).
- Recette : parc pilote en conteneurs, forge simulée, outillage gardé hors dépôt ([recette de T11](lots/T11-recette-lot-1.md#recette)).

#### Dépendances et open-go-base

- `modernc.org/sqlite` ([T00](lots/T00-fondations.md)) ; directive `go` 1.26.8 imposée par Syft ([T05](lots/T05-ingestion.md)).
- Évolutions d'open-go-base `v1.1.0` (T03), `v1.2.0` (`ratelimit.WithKeyFunc`, T04), `v1.3.0` (verrouillage de mfax, `csrfx.WithSessionBinding`, T11), utilisées par l'étiquette `v1.3.0`.

### Actions pour l'utilisateur

Le mandataire git de la session refuse les pushs d'étiquettes (HTTP 403). À faire, dans
l'ordre (les étapes 1 à 3 et 6 sont faites) :

1. **Fait.** Renommer le dépôt GitHub `leblanc-simon/open-go-sbom` en `leblanc-simon/lotor`
   (*Settings* → *General* → *Repository name*), puis `git remote set-url origin
   https://github.com/leblanc-simon/lotor.git` dans le clone local (et renommer le
   dossier si souhaité). Si `leblanc.io` sert des métadonnées `go-import`, ajouter celle de
   `leblanc.io/lotor` ([ADR 0033](../docs/adr/0033-renommage-en-lotor.md)).
2. **Fait.** Pousser les étiquettes annotées d'open-go-base créées localement :
   `git -C ../open-go-base push origin v1.1.0` (commit `b9ccc67`, T03),
   `git -C ../open-go-base push origin v1.2.0` (commit `3534c14`, `ratelimit.WithKeyFunc`),
   `git -C ../open-go-base push origin v1.3.0` (commit `9a7b91f`, PR #3 : verrouillage par
   compte de mfax, `Confirm`, `WithChallengeCookieName`, `csrfx.WithSessionBinding`).
   Toutes compatibles.
3. **Fait.** Dans lotor, sur une branche : `go get leblanc.io/open-go-base@v1.3.0 && go mod
   tidy` (même code que la pseudo-version actuelle `v1.0.2-0.20261031121913-9a7b91fdbbfe` ;
   ne pas utiliser `v1.1.0` ni `v1.2.0`), `make ci`, PR, fusion quand la CI est verte.
4. Relire les décisions **[à relire]** ci-dessus, et confirmer (ou corriger) au cahier des
   charges les cibles de performance encore « proposées » (§ objectifs et § volumétrie ;
   mesures : Journal de T11). Une cible changée se reporte dans `docs/benchmarks.md`.
5. Essayer l'agent dépôt sur une vraie GitHub App et un vrai projet GitLab : procédure pas
   à pas dans [`docs/operations.md`](../docs/operations.md#recette-sur-une-vraie-forge)
   (une demi-heure). La recette n'a pu l'exercer que contre une forge simulée.
6. **Fait** (étiquette sur `109fa20`, préversion publiée le 1er novembre 2026 à
   01:10 UTC). Publier la préversion **v0.1.0**, une fois les étapes 1 à 3 sur `main` :
   1. vérifier que la section `## [0.1.0] - 2026-11-01` de `CHANGELOG.md` est à jour (date
      du jour de la pose, ajouts éventuels) et que la CI de `main` est verte ;
   2. `git fetch origin && git tag -a v0.1.0 origin/main -m "lotor 0.1.0 — préversion du lot 1"` ;
   3. `git push origin v0.1.0` ;
   4. suivre le workflow **release** (onglet *Actions*) ; vérifier sur la page *Releases*
      une **préversion** `v0.1.0` portant six archives `.tar.gz` (trois rôles × amd64,
      arm64), quatre paquets (`.deb`, `.rpm` × amd64, arm64) et `SHA256SUMS` ; contrôler
      un téléchargement par `sha256sum -c --ignore-missing SHA256SUMS` ;
   5. cocher le critère « `v0.1.0` publiée » de [T11](lots/T11-recette-lot-1.md).
   En cas d'échec du workflow : corriger par un commit sur `main` et poser `v0.1.1` (ne
   jamais déplacer une étiquette poussée).
7. Facultatif : rejouer les mesures sur la machine de référence (16 cœurs) par les
   commandes de [`docs/benchmarks.md`](../docs/benchmarks.md) ; elles tiennent déjà sur
   4 cœurs.

### Organisation

- Chaque lot est réalisé par un agent au contexte neuf, qui lit `CLAUDE.md`,
  l'architecture, `specs/lecons.md`, sa fiche et le Journal des lots dont il dépend.
- Les lots indépendants avancent en parallèle (T02 et T03 ; T06, T07 et T08 ; T09 et T10),
  chacun sur sa branche `lot/<id>-<sujet>` et sa PR.
- Une PR est fusionnée en « squash » dès que la CI est verte et les critères cochés.
