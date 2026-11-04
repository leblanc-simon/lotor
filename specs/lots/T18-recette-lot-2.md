# T18 — Recette du lot 2

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 2 · IA et triage | T12, T13, T14, T15, T16, T17 | Terminé (mesure de l'IA avec une clé et publication de `v0.2.0` : actions de l'utilisateur) |

## Objectif

Passer le critère du lot 2 : **aucun composant ajouté par l'IA sans preuve vérifiée**, avec
un taux de faux positifs mesuré et tenu, et publier une préversion `v0.2.0` durcie.

## Périmètre

**Inclus**

- Évaluation finale de l'enrichissement IA sur le corpus annoté étendu et sur un
  échantillon annoté des dépôts pilotes ; rapport (précision, rappel, taux de faux positifs,
  coût, motifs de rejet).
- Revue de sécurité ciblée par un relecteur distinct de l'auteur, gravité selon l'OWASP Risk
  Rating : agent dépôt (injection d'instructions, sorties vers le fournisseur, secrets des
  forges), notifications (webhooks, SMTP), droits par équipe ; mise à jour du modèle de
  menace.
- Audit RGAA des écrans du lot 2.
- Nouvelle mesure des cibles de performance avec les équipes et les conteneurs, selon
  `docs/benchmarks.md`.
- Codes de secours TOTP : évolution de mfax dans open-go-base (§ 23 de l'architecture :
  codes à usage unique, hachés, régénérables ; étiquette semver), puis adoption dans lotor.
- Documentation utilisateur et exploitation du lot 2 ; `CHANGELOG.md` ; `v0.2.0`.

**Exclu** : toute autre nouvelle fonction.

## Critères d'acceptation

- [x] Zéro composant d'origine IA accepté sans preuve vérifiée, sur le corpus et le pilote.
      (Partie 4 : par construction — le vérificateur est le seul juge — et contrôlé de
      l'extérieur par `checkProof` sur chaque composant IA du SBOM relu par le décodeur
      du serveur : corpus, 467 candidats adverses, 47 acceptés, tous revérifiés
      (`TestNoAIComponentWithoutVerifiedProof`, en CI) ; échantillon pilote,
      2 234 candidats d'un modèle fictif crédule, 101 acceptés, tous revérifiés
      (`make eval-ai` en mode `credulous`). `make eval-ai` refait ce contrôle sur chaque
      composant accepté par le vrai modèle **[à relire]**.)
- [ ] Taux de faux positifs et rappel dans les seuils validés en T12, sur le corpus et sur
      l'échantillon pilote annoté. (**Non mesuré** : aucune clé d'API ni modèle local dans
      l'environnement ; corpus étendu (11 cas), échantillon pilote annoté (4 dépôts) et
      harnais prêts ; mesure à faire par l'utilisateur, pas à pas dans
      `docs/operations.md`, « Évaluer l'enrichissement IA ».)
- [x] Aucune faiblesse de gravité haute ou critique ouverte. (Aucune trouvée par la revue
      du lot 2 ; les 2 Medium et les 5 Low sont corrigés, 2 des 3 Note aussi, voir « Revue
      de sécurité ».)
- [x] Grille RGAA remplie pour chaque nouvel écran, sans non-conformité bloquante
      (partie 3, [grille](../../docs/accessibilite/grille-rgaa-lot2.md) : 100 % des
      critères applicables après corrections, aucune NC bloquante ni majeure ni avant ni
      après).
- [x] Un utilisateur peut se connecter avec un code de secours, à usage unique
      (partie 1, `TestRecoveryCodes`).
- [ ] `v0.2.0` publiée. (Prête : `CHANGELOG.md` section `[0.2.0] - 2026-11-04`,
      `make release VERSION=v0.2.0` vérifié ; la pose de l'étiquette est refusée dans la
      session, action de l'utilisateur décrite dans `specs/avancement.md`.)

## Décisions

Prises le 1er novembre 2026 :

- Seuils de l'enrichissement IA : faux positifs inférieurs ou égaux à 5 %, rappel
  supérieur ou égal à 80 % (décidés pour T12).
- Codes de secours TOTP livrés dans ce lot, par une évolution de mfax dans open-go-base.

## Journal

### Partie 1 — compléments

Réalisée le 1er novembre 2026, branche `lot/T18-complements`, en autonomie (lot 2
enchaîné sans attendre l'utilisateur, après la fusion de T12 à T17) : les décisions
marquées **[à relire]** n'ont pas été validées explicitement. Les parties suivantes (revue
de sécurité, audit RGAA, mesures, évaluation de l'IA, recette et `v0.2.0`) sont confiées à
d'autres agents.

#### Livré

- **open-go-base v1.4.0** (PR #5, fusionnée en squash, commit `a0f777f`, étiquette
  `v1.4.0` créée en local, à pousser) : codes de secours dans mfax, facultatifs
  (`WithRecoveryCodes`, `RecoveryStore` et son implémentation `database/sql` SQLite et
  PostgreSQL, migration `004`, `RecoveryRenderer` facultative, champ `recovery_code` de
  `VerifyPOST`, `RegenerateRecoveryPOST`, `GenerateRecoveryCodes`, `RecoveryRemaining`,
  `ConfirmRecovery`, `DisablePOST` qui accepte un code de secours, `WithRecoveryHook`,
  `WithRecoveryLanding`, `appconf.MFA.RecoveryCodes`) ; codes faux comptés dans le plafond
  du défi et dans le verrouillage par compte ; tests (`go vet ./...`, `go test -race ./...`
  verts), exemple testable, `doc.go`, README, CLAUDE.md.
- lotor monté sur la pseudo-version du commit fusionné
  (`v1.3.1-0.20261101100848-a0f777f827c9`) ; migration **022** (droits du rôle
  d'exécution sur `mfa_recovery_codes`).
- **Codes de secours** (`internal/web` : `auth_pages.go`, `security_pages.go` ;
  `internal/account/recovery.go`) : jeu de 10 codes montré une seule fois après
  l'activation du TOTP (`auth/recovery_codes`) ; formulaire « Utiliser un code de secours »
  à la connexion, arrivée sur la page du second facteur ; page **Mon compte › Second
  facteur** (`/account/security`) : codes restants (alerte à trois ou moins, invitation à
  générer pour un compte enrôlé avant la mise à jour), régénération après un code TOTP,
  reconfiguration de l'application par un code TOTP ou un code de secours
  (`account.ReconfigureTOTP` : secret, défis et codes retirés, sessions fermées, nouvel
  enrôlement à la connexion suivante) ; message sur la page de connexion. Codes supprimés
  aussi par la réinitialisation du TOTP (administrateur, procédure de secours). Audit :
  `account.recovery_codes_generated`, `auth.recovery_code_used`,
  `auth.recovery_code_failed`, `account.totp_reconfigured`. Réglage `mfa.recovery_codes`
  (5 à 50). Traductions FR et EN.
- **Recherche** (reliquats de T14 et T16) : filtre `team` (écran, API, export) ;
  équipe de chaque projet dans les résultats ; statut de triage de chaque constat d'une
  recherche par vulnérabilité (lien vers la fiche du constat) et filtre `triage`, refusé
  hors recherche par vulnérabilité (`error.search.triage_vulnerability_only`) ; recherche
  par composant sans les constats « non affecté » ni « faux positif » ; colonnes `team` et
  `triage_status` en fin d'export, `team`, `team_id` et `triage_status` en JSON ;
  `api/openapi.yaml` (paramètres `SearchTeam`, `SearchTriage`, schéma `TeamRef`) et code
  régénéré.
- **Purge des conteneurs archivés** (reliquat de T13) : étape de la rétention nocturne
  (`inventory.History.purgeContainers`), réglage `containers.purge_after` (180 jours,
  `0` : jamais, au moins `retention.days`), audit `project.purged`.
- Documentation : ADR 0048 à 0050, architecture (§ 8, § 10, § 13, § 23),
  `docs/utilisation.md` (section « Second facteur et codes de secours », filtres de la
  recherche, conteneurs), guides de démarrage FR et EN, `docs/operations.md`, modèle de
  menace, `config.example.yaml`, `CHANGELOG.md`.
- Tests : unitaires (mfax, requête de recherche, configuration) ; intégration PostgreSQL
  `TestRecoveryCodes` (critère « un utilisateur peut se connecter avec un code de secours,
  à usage unique », bout en bout : génération, connexion, refus du rejeu, reconfiguration,
  nouvel enrôlement, ancien jeu caduc, audit, aucun code dans les journaux),
  `TestReconfigureWithTOTPCode`, store de mfax sous PostgreSQL (`internal/account`),
  `TestSearchTeamFilter`, `TestSearchTriageStatus`, écran et API de la recherche
  (`TestSearchScreenAndAPI`), `TestRetentionPurgesLongArchivedContainers` ; nouvelles
  pages dans les balayages d'accessibilité (FR, EN, clair, sombre) et de titres ; routes
  ajoutées à la liste des routes globales du test d'isolement.

#### Décisions

- Format des codes (16 caractères de Crockford, 80 bits), empreinte SHA-256 liée au compte
  plutôt que bcrypt, 10 codes par défaut ([ADR 0048](../../docs/adr/0048-codes-de-secours.md)) **[à relire]**.
- Régénération soumise à un code TOTP, comme la création d'un jeton personnel ; codes
  montrés dans la réponse (`no-store`), jamais réaffichés (ADR 0048) **[à relire]**.
- **Reconfiguration de l'application par le titulaire**, au-delà de la fiche : sans elle,
  un code de secours ne sert qu'une connexion et la perte du téléphone exige encore un
  administrateur ; mot de passe et jetons gardés ; pas de page de confirmation (le code
  exigé en tient lieu) (ADR 0048) **[à relire]**.
- Comptes enrôlés avant la mise à jour : invités à générer leurs codes depuis la page du
  second facteur, sans bannière globale (ADR 0048) **[à relire]**.
- Recherche : statut de triage montré pour tous les constats d'une recherche par
  vulnérabilité, « non affecté » compris ; filtre `triage` refusé hors recherche par
  vulnérabilité ; recherche par composant sans les constats masqués
  ([ADR 0050](../../docs/adr/0050-equipe-et-triage-dans-la-recherche.md)) **[à relire]**.
- Purge : conteneurs archivés **pour absence** depuis 180 jours, jamais ceux archivés à la
  main ni ceux qui portent une décision de triage, dans la rétention nocturne, que
  `retention.enabled` soit vrai ou non, durée au moins égale à `retention.days`
  ([ADR 0049](../../docs/adr/0049-purge-des-conteneurs-archives.md)) **[à relire]**.

#### Écarts

- Reliquat de T17 (« tri des constats de T14 dans l'effet sur la sécurité ») : déjà fait
  par T14 (`finding/effect.go` écarte les statuts masqués) ; rien à reprendre.
- Reliquat de T12 (boutons « Confirmer la détection » / « Signaler une erreur » d'un
  composant trouvé par l'IA) : **non livré** ; c'est une fonction nouvelle (revue humaine
  des composants, distincte du triage des constats), exclue de T18 (« toute autre nouvelle
  fonction ») ; à reprendre dans un lot ultérieur s'il est voulu **[à relire]**.
- Les critères de T18 ne sont pas cochés ici, sauf « Un utilisateur peut se connecter avec
  un code de secours, à usage unique ».
- Parties suivantes, non traitées ici : revue de sécurité (qui relira ADR 0048 et la
  reconfiguration), audit RGAA (nouvelles pages : connexion par code de secours, codes de
  secours, second facteur ; filtres de la recherche), captures, mesures (dont la recherche
  avec les nouveaux filtres), évaluation de l'IA, essais Podman et Compose réels,
  `v0.2.0`.

#### ADR créés

- [0048 — Codes de secours du second facteur](../../docs/adr/0048-codes-de-secours.md).
- [0049 — Purge des conteneurs archivés depuis longtemps](../../docs/adr/0049-purge-des-conteneurs-archives.md).
- [0050 — Équipe et statut de triage dans la recherche](../../docs/adr/0050-equipe-et-triage-dans-la-recherche.md).

Aucune nouvelle fonction `crossorg`, aucune nouvelle dépendance tierce (open-go-base
monte de version).

### Partie 2 — revue de sécurité

Réalisée le 1er novembre 2026, branche `lot/T18-securite`, en autonomie : les décisions
marquées **[à relire]** n'ont pas été validées explicitement. Revue indépendante
(relecteur distinct des auteurs, OWASP Risk Rating) de `lot/T18-complements` à `a9b5cf4`
(T12 à T17 et partie 1 de T18) et d'open-go-base `a0f777f` (mfax v1.4.0) ; chaque
constat a été démontré par un test de reproduction, transformé ici en test de
non-régression qui échoue sans le correctif et passe avec (vérifié pour chacun ; SEC2-09
n'avait pas de test de reproduction, ses tests sont nouveaux). Bilan de la revue :
0 Critical, 0 High, 2 Medium, 5 Low, 3 Note ; aucune fuite entre organisations.

#### Constats

| Id | Titre | Gravité | Statut | Commit ou justification |
| --- | --- | --- | --- | --- |
| SEC2-01 | `EnablePOST` hors verrouillage par compte : force brute du TOTP depuis une session volée, qui délivre un nouveau jeu de codes de secours | Medium | Corrigé | open-go-base v1.4.1 (PR #6, `0900e0c`) : TOTP actif refusé sans examen du code, codes faux comptés dans le verrouillage ; lotor `8658ac6` : montée de version, enveloppe de la route (défense en profondeur), message du verrouillage à l'enrôlement ; tests `TestEnablePOSTOnActiveTOTPDoesNothing`, `TestEnablePOSTCountsFailures` (mfax), `TestEnableOnActiveTOTPDeliversNothing`, `TestEnrollmentCodesCountInLockout` ; ADR 0051 |
| SEC2-02 | Inscription : un jeton d'une équipe prend, par le nom d'hôte, le projet hôte d'une autre équipe | Medium | Corrigé | `4c82c65` : rattachement par le nom borné à l'équipe du jeton, homonyme d'une autre équipe répondu « hôte déjà suivi », projet désigné passé dans une autre équipe refusé ; `TestEnrollmentByHostnameStaysInTheTokenTeam` ; ADR 0051 |
| SEC2-03 | Changer le dépôt d'un projet garde l'IA « externe » | Low | Corrigé | `2a64942` : URL de forge changée sans le droit `ai.external` → réglage « désactivé », journalisé (`forge_url_changed`) ; `TestForgeURLChangeRevokesExternalAI` ; ADR 0051 |
| SEC2-04 | Canal Matrix : changer le serveur sans ressaisir le jeton envoie le jeton au nouveau serveur | Low | Corrigé | `64913b3`, `77c8741` : secret à ressaisir quand le serveur Matrix ou l'URL du webhook change, changement de destination journalisé ; `TestChannelSecretNeverFollowsNewDestination` ; ADR 0051 |
| SEC2-05 | Projets enfants de conteneurs sans borne par hôte | Low | Corrigé | `0c9f4ec` : `containers.max_per_host` (1 000), signalement refusé en entier au-delà (409) ; `TestContainerChildrenBoundedPerHost` ; ADR 0051 |
| SEC2-06 | Reconfiguration du TOTP : le mot de passe seul enrôle un nouveau second facteur jusqu'à la reconnexion | Low | Corrigé | `8658ac6` : nouveau mot de passe exigé (validé avant la consommation du code) ; `TestReconfigureClosesPasswordOnlyWindow` ; ADR 0051 (modifie 0048) |
| SEC2-07 | IA : noms des fichiers exclus envoyés au fournisseur dans le prompt incrémental | Low | Corrigé | `a1bc95b` : périmètre filtré par les exclusions et la détection de clé privée, `list_dir` sans fichier à clé privée (64 Kio au plus : reste accepté au-delà), description de l'outil corrigée ; `TestIncrementalPromptOmitsExcludedFiles` ; ADR 0051 |
| SEC2-08 | Garde SSRF : préfixes de traduction et plages réservées non refusés ; ports libres | Note | Corrigé, ports acceptés | `f9db5f5` : plages réservées, NAT64, 6to4, IPv4-compatibles jugés sur l'IPv4 portée ; `TestForbiddenAddresses` étendu ; ports non restreints, risque accepté et documenté **[à relire]** ; ADR 0051 |
| SEC2-09 | Outil `search` de l'IA : contexte ignoré, recherche sans résultat gratuite, appels par tour non bornés | Note | Corrigé | `d666ebb` : délai vérifié pendant la recherche et entre deux outils, 2 Kio par recherche, 20 appels par réponse ; `TestRunBoundsToolCallsPerTurn`, `TestSearchIsChargedAndCancellable` ; ADR 0051 |
| SEC2-10 | `lotor_user_invitations` (`SECURITY DEFINER`) sans garde SQL | Note | Accepté **[à relire]** | Même nature que SEC-12 : appelée avec l'identifiant de la session seulement, acceptation revérifiée sous la RLS, métadonnées seules ; consigné au modèle de menace ; ADR 0051 |

#### Livré

- **open-go-base v1.4.1** (PR #6 fusionnée en squash, commit `0900e0c`, étiquette `v1.4.1`
  créée en local, à pousser) : `EnablePOST` refuse un TOTP actif et passe par le
  verrouillage par compte (`?error=2fa_locked`, repris par `SetupGET`) ; tests, `doc.go`,
  README, CLAUDE.md. `go vet ./...` et `go test -race ./...` verts. lotor monté sur
  `v1.3.1-0.20261101111845-0900e0c6a132`.
- lotor : enveloppe `enableTOTP`, message `totp_setup.error.locked` ; reconfiguration avec
  nouveau mot de passe (`account.CheckReconfigurePassword`, `ReconfigureTOTP` avec mot de
  passe, formulaire de `/account/security`) ; inscription bornée à l'équipe du jeton ;
  `project.Service.Update(…, externalAI)` ; `notify.UpdateChannel` et destination ;
  `containers.max_per_host` (`agent.WithMaxContainersPerHost`,
  `project.ErrContainerLimit`, `error.agent.containers_limit`, OpenAPI) ; filtre du
  périmètre incrémental et `list_dir` ; `delivery.Forbidden` ; `llm.Budget.MaxCallsPerTurn`,
  recherche sous délai et budget.
- Traductions FR et EN : `security.reconfigure_password`, `security.reconfigure_password_hint`,
  `security.reconfigure_text`, `login.totp_reconfigured`, `totp_setup.error.locked`,
  `channel_form.secret_keep`, `error.agent.containers_limit`.
- Documentation : ADR 0051 (et statut de 0048), modèle de menace version 3 (acteurs selon
  T16, administrateur d'équipe, porteur d'un jeton d'inscription, fournisseur de modèle ;
  frontières 9 « équipe A ↔ équipe B » et 10 « agent dépôt ↔ fournisseur de modèle » ;
  actifs codes de secours, secrets des canaux, code lu par l'IA ; toutes les mises à jour
  proposées par la revue), `specs/architecture.md` (second facteur, agents, § 23), `docs/operations.md`,
  `docs/utilisation.md`, `docs/notifications.md`, guides de démarrage, `config.example.yaml`,
  `CHANGELOG.md`.

#### Décisions

- Reconfiguration du second facteur : nouveau mot de passe exigé, jetons personnels gardés
  ([ADR 0051](../../docs/adr/0051-corrections-revue-securite-lot2.md) § 2) **[à relire]**.
- Défense en profondeur de SEC2-01 gardée dans lotor malgré mfax v1.4.1 ; échecs
  d'enrôlement non journalisés un par un (verrouillage journalisé) (ADR 0051 § 1)
  **[à relire]**.
- Inscription : homonyme d'une autre équipe répondu « hôte déjà suivi », archivé compris ;
  projet désigné passé dans une autre équipe refusé (ADR 0051 § 3) **[à relire]**.
- IA externe ramenée à « désactivé » (pas « local ») au changement de dépôt (ADR 0051 § 4)
  **[à relire]**.
- Canaux : ressaisie du secret au changement de serveur Matrix ou d'URL de webhook ; salon
  Matrix libre (ADR 0051 § 5) **[à relire]**.
- `containers.max_per_host` = 1 000, refus du signalement entier, pas de quota quotidien
  (ADR 0051 § 6) **[à relire]**.
- Détection de clé privée dans `list_dir` limitée aux fichiers de 64 Kio (ADR 0051 § 7)
  **[à relire]**.
- Ports des canaux non restreints ; SEC2-10 accepté (ADR 0051 § 8 et § 10) **[à relire]**.
- 20 appels d'outils par réponse, 2 Kio par recherche (ADR 0051 § 9) **[à relire]**.

#### Écarts

- Aucune migration : le numéro 023 réservé n'a pas servi (SEC2-10 accepté sans garde SQL).
- `make ci` vert en local (toutes les cibles, intégration PostgreSQL comprise).
- L'étiquette `v1.4.1` d'open-go-base ne peut pas être poussée depuis la session (action de
  l'utilisateur, `specs/avancement.md`).

#### ADR créés

- [0051 — Corrections de la revue de sécurité du lot 2](../../docs/adr/0051-corrections-revue-securite-lot2.md).

### Partie 3 — Audit RGAA

Réalisée le 1er novembre 2026, branche `lot/T18-accessibilite`, en autonomie : les
décisions marquées **[à relire]** n'ont pas été validées explicitement. Grille finale :
[`docs/accessibilite/grille-rgaa-lot2.md`](../../docs/accessibilite/grille-rgaa-lot2.md).

#### Résultat

Audit initial sur `main` (f53536f) : 93,1 % (67 critères conformes sur 72 applicables ;
non conformes : 8.2, 8.6, 8.7, 10.11, 11.2), 4 constats, tous mineurs, aucun bloquant ni
majeur, plus trois défauts de rédaction hors grille. Après corrections : **100 %** (72 sur
72), aucun constat ouvert. Instance réelle (routeur complet, CSS embarquées) sur une base
PostgreSQL de démonstration peuplée de toutes les données du lot 2 ; 179 pages découvertes
par cinq sessions, 158 pages après réduction par forme d'URL et 23 états choisis, en
français et en anglais, thèmes clair et sombre : axe-core 4.10.2 sans aucun écart sur les
724 rendus de l'audit initial comme du contre-audit, aucun défilement horizontal à 320 et
390 px ni à 200 % de texte après corrections ; 16 soumissions réelles de formulaires
(13 erreurs) en deux langues : « Erreur : » dans le titre, message en `role="alert"`,
`aria-invalid` sur le champ fautif ; parcours au clavier des écrans nouveaux sans piège,
focus visible dans les deux thèmes ; captures de contrôle à 1 280 et 390 px.

| NC | Gravité | Critère | Statut |
| --- | --- | --- | --- |
| NC-01 champs du triage dans l'étiquette du radio | mineure | 8.2, 11.2 | corrigé, vérifié |
| NC-02 répartition des versions à 320 px (version longue) | mineure | 10.11 | corrigé, vérifié |
| NC-03 titres identiques des fiches de constat | mineure | 8.6 | corrigé, vérifié |
| NC-04 statut VEX brut sur la confirmation de retrait | mineure | 8.6, 8.7 | corrigé, vérifié |
| décomptes et état mal accordés | défaut | — | corrigé, vérifié |

#### Livré

- **Panneau de triage** (NC-01, `projects/finding.html`, `components/choice.css`) : les
  champs complémentaires (justification VEX, échéance, plage `vers`) sortent de
  l'étiquette du bouton radio, dans l'élément de liste `li.choice-item`, qui porte la
  boîte, l'état coché et le focus ; révélation inchangée par `:has()`. Le nom du radio se
  limite à son statut et sa description.
- **Fiche composant** (NC-02, `screens/vulnerabilities.css`) : le décompte de la
  répartition des versions passe à la ligne, barre réduite sous 30 rem.
- **Titres** : fiche d'un constat « CVE sur composant — projet (référence) » (NC-03,
  `triage.title`) ; confirmation du retrait d'une décision avec le libellé traduit du
  statut (NC-04, `identity.decisionArgs`).
- **Rédaction** : « 2 membres », « 1 projet actif » (fiche d'équipe, `Tn`) ; « État :
  Ouvert / Résolu » sur la fiche d'un constat (`triage.state_open`,
  `triage.state_resolved`) ; « Ouvertes : 1 · bloquantes : 1 » (alertes du tableau de
  bord, `dashboard.alerts_meta`).
- Recommandations traitées : tableaux de l'effet sur la sécurité titrés par leur `h3`
  (`aria-labelledby`) ; « Retirer la décision « … » » en texte masqué dans l'historique
  d'un constat (`triage.withdraw_object`).
- Garde-fous : `webtest.CheckAccessibility` refuse une `<label>` qui contient une autre
  étiquette ou plus d'un champ (vérifié : `TestTriageScreens` échoue sur l'ancien
  gabarit) ; `TestTriageScreens` vérifie le titre de la fiche, l'état au singulier et le
  statut traduit de la confirmation (fr, en) ; `TestTeamScreens` les décomptes ;
  `TestPolicyScreens` le décompte des alertes.
- `architecture.md` § 14 : conventions « une étiquette, un champ », « valeurs
  traduites », titre d'une fiche rattachée à un projet ; référence à la grille du lot 2.
- Après la fusion de la partie 2 (PR #28) : page du second facteur auditée de nouveau
  (deux champs « nouveau mot de passe ») : conforme, sans correction.

#### Décisions

- **Régénération des codes de secours et changement d'application sans page de
  confirmation** : le code exigé (TOTP ou code de secours) tient lieu de confirmation au
  sens de 11.12, conformément à la décision de la partie 1 (ADR 0048) **[à relire]**.
- **Champs complémentaires toujours révélés par `:has()`**, sans JavaScript : sans
  `:has()` (navigateurs antérieurs à 2022-2023), la justification n'est pas saisissable à
  l'écran ; choix gardé de T14, limite notée dans la grille **[à relire]**.
- **NC-02 rattachée au lot 2** bien que l'écran soit du lot 1 : défaut révélé par les
  données des conteneurs, corrigé ici ; la redistribution est repassée sur toutes les
  pages à chaque audit **[à relire]**.
- **Statuts de triage cliquables jugés conformes à 10.6** (pastille distincte du texte,
  soulignée au survol et au focus) plutôt que soulignés en permanence **[à relire]**.
- Pas d'ADR : pas de décision structurante au-delà des conventions du § 14.
- Pas de test Playwright dans le dépôt (même raison qu'au lot 1 : pas de navigateur en CI,
  pas de nouvelle dépendance) ; scripts et captures hors dépôt.

#### Écarts

- Recommandations R-L2-01 à R-L2-05 non traitées (§ 6 de la grille) ; celles du lot 1
  restent ouvertes.
- Pas de lecteur d'écran réel ni d'autre navigateur que Chromium (§ 7 de la grille).

#### ADR créés

Aucun. Aucune migration, aucune nouvelle dépendance.

### Partie 4 — Recette, mesures et préversion

Réalisée le 1er novembre 2026, branche `lot/T18-recette`, en autonomie : les décisions
marquées **[à relire]** n'ont pas été validées explicitement. Environnement : 4 cœurs
partagés Intel Xeon 2,8 GHz, 15 Gio, PostgreSQL 16.15, Docker 29.9.2 et Docker Compose
5.6.1 (démarrés pour la recette puis arrêtés), Podman 4.9.3 (installé pour la recette puis
retiré).

#### Évaluation de l'enrichissement IA

Sans clé d'API ni modèle local, rien n'a été mesuré avec un vrai modèle : aucun chiffre
de précision, de rappel ou de coût n'est donné ici. Fait :

- **Contrôle indépendant du critère « zéro composant sans preuve vérifiée »** :
  `checkProof` revérifie chaque composant IA du SBOM final (fusionné, encodé, relu par le
  décodeur du serveur) contre le dépôt, sans réutiliser le vérificateur : chemin propre,
  fichier ordinaire atteint sans lien, jamais exclu ni porteur d'un secret, extrait à la
  ligne annoncée, version et nom dans la preuve, empreinte exacte.
  `TestNoAIComponentWithoutVerifiedProof` (en CI) fait soumettre, sur chaque cas du
  corpus, tout ce qu'un modèle crédule ou détourné pourrait proposer : composants annotés,
  pièges, versions inventées, demandes des instructions malveillantes, centaines de
  lignes porteuses d'un numéro, mutations (ligne hors tolérance, version voisine, `../`,
  chemin absolu, nom ou type changé) et liens symboliques plantés dans le dépôt : 467
  candidats, 47 acceptés, **tous revérifiés**, 420 rejetés, aucun par un lien.
- **Défaut trouvé et corrigé** par ce contrôle : les composants IA d'image de conteneur
  (`FROM` d'un Dockerfile) étaient émis en type CycloneDX `container`, que le décodeur de
  Syft du serveur ignore : acceptés par le vérificateur, ils disparaissaient à
  l'ingestion (`ai_merge.go` : toujours `library`, le purl `pkg:docker/…` dit la nature).
- **Corpus étendu** à 11 cas : `vendored-python` (`__version__.py` de requests recopié ;
  version de l'application, mise à jour citée en commentaire) et `ci-makefile-vars`
  (version d'outil dans une variable du `Makefile`, images d'intégration continue dont
  une par variable ; `latest`, image sans étiquette, version du dépôt), calqué sur
  l'échantillon pilote. Modèle crédule sur le corpus : 14 acceptés à raison, 5 pièges à
  preuve réelle, rappel 100 % — **pour ce modèle fictif**, pas une mesure.
- **Échantillon pilote annoté** (`testdata/ai-pilot`) : les quatre dépôts publics du
  parc pilote du lot 1 aux mêmes commits (cobra `adbc881`, sftp `5bdc2b0`, gitlab-shell
  `09ef3a7`, jekyll `3137780`), clonés par `scripts/ai-pilot-fetch.sh` (tête vérifiée) ;
  annotation à la main, confrontée au SBOM de Syft (même version que l'agent) :
  **4 composants attendus**, tous dans gitlab-shell (gotestsum 1.10.0 et golangci-lint
  1.55.2 par variables du `Makefile`, images `docker:20.10.15` et
  `sourcegraph/lsif-go:v1.9`) ; actions GitHub vues par Syft et cas discutables
  « ignorés » ; pièges (version du dépôt, `latest`, manifestes). Règles d'annotation dans
  son README.
- **`make eval-ai` par jeu** (`corpus`, `pilote` avec `LOTOR_EVAL_AI_PILOT_DIR`), seuils
  sur chacun, revérification de chaque preuve pour tout fournisseur, et mode
  `LOTOR_EVAL_AI_PROVIDER=credulous` (contrôle à blanc sans clé). Joué ici en
  `credulous` : corpus 47 composants revérifiés ; **pilote 2 234 candidats, 101 acceptés,
  tous revérifiés**, chaque composant annoté prouvable (aucun oubli), 6 « ignorés ».
- Procédure de la mesure réelle, pas à pas : `docs/operations.md`, « Évaluer
  l'enrichissement IA » (clé, clonage du pilote, contrôle à blanc, mesure, lecture,
  report et choix du modèle).

#### Mesures consolidées

Mêmes commandes que T11 (`docs/benchmarks.md`, section T18), sur le jeu de référence
**complété des équipes, des conteneurs et du triage** (`benchdata.AddTeamsAndContainers` :
10 équipes, 50 hôtes de 10 conteneurs, 1 550 projets, 1,11 million de liens, 83 270
constats, environ 7 400 décisions de triage), base Grype réelle v6.1.10 du 1er novembre
2026 ; machine : **4 cœurs partagés**, moins puissante que la référence (16 cœurs).

| Mesure (commande) | Cible | Résultat (p95) | Verdict |
| --- | --- | --- | --- |
| Ingestion et analyse de 5 000 composants, vraie base (`make bench-ingest`) | 30 s | **5,62 s** (froid 5,54 s, p50 5,24 s, dont ingestion 0,60 s) | tenue |
| Recherche, pire cas : page suivante du nom large (`make bench-search`) | 2 s | **446 ms** (nom large 437 ms) | tenue |
| Recherche, membre d'une équipe / filtre équipe / conteneurs compris | 2 s | 339 / 232 / 386 ms | tenue |
| Recherche par vulnérabilité, membre d'une équipe / filtre triage | 2 s | 22 / 29 ms | tenue |
| Export CSV (16 837 lignes ; 18 507 avec les conteneurs) | — | 810 ms ; 945 ms | — |
| Tableau de bord, 12 mois, administrateur (`make bench`) | 1 s | **841 ms** (90 jours : 814 ms) | tenue |
| Tableau de bord, membre d'une équipe (12 mois / 90 jours) | 1 s | 567 / 752 ms | tenue |
| Fiche hôte et ses 10 conteneurs / fiche conteneur / fiche projet | 1 s | 39 / 29 / 36 ms | tenue |
| Scan de l'agent serveur, `/` sans `/root`, `/home`, `/tmp` (protocole de T07) | 5 min de CPU, 1 Gio | **2 min 13 s de CPU, 819 Mio** au plus sur 4 cycles | tenue |
| Inventaire d'une image de conteneur (recette, Docker et Podman) | — | 1,5 à 3 s par image | — |

Par rapport au lot 1 : la recherche large passe de 288-344 à 437-446 ms et le tableau de
bord de 663 à 841 ms (marge de 16 %, la plus serrée), sur un jeu plus gros et avec les
filtres d'équipe et de triage ; l'agent serveur, hors ligne depuis T13, consomme moins
(2 min 13 s et 819 Mio contre 3 min 8 s et 921 Mio). Le plan du nom large a changé
(boucle sur les 1 050 projets visibles, 301 ms pour le décompte contre 15,6 ms) : noté
dans `docs/benchmarks.md`, sans action (cible tenue avec une marge d'un facteur 4,5).
Les cibles du cahier des charges restent « proposées », à confirmer par l'utilisateur.

#### Recette fonctionnelle

Parc de démonstration fixé avant les vérifications ; listes attendues établies hors de
l'application (contenu réel des images, `apk info`, avis des distributions) :

- serveur `srv-recette` (racine minimale : `os-release` et base dpkg d'Ubuntu 24.04,
  838 composants), agent serveur ;
- Docker : projet Compose `shop` (`web` nginx 1.25.3-alpine sur Alpine 3.18.6, `cache`
  redis 7.0.0-alpine sur Alpine 3.16.0, `worker` alpine 3.18.0 en **deux répliques**) et
  conteneur `outil` (alpine 3.18.0) ; Podman : conteneur `batch` (alpine 3.18.0) ;
- CVE de contrôle **CVE-2023-2650** (OpenSSL) : attendu **outil, shop/cache,
  shop/worker** (libcrypto3/libssl3 3.1.0-r4, corrigé en 3.1.1-r0 ; libcrypto1.1/libssl1.1
  1.1.1o-r0, corrigé en 1.1.1u-r0) ; pas shop/web (3.1.4-r5), pas l'hôte.

Instance réelle (binaires, TLS par une autorité de test, rôles PostgreSQL séparés, base
Grype téléchargée par le serveur lui-même), pilotée par l'interface comme un navigateur
(formulaires, jeton CSRF, codes TOTP calculés) et par les API ; outillage hors dépôt.

Exercé, tout conforme sauf le défaut corrigé plus bas :

- **Mise à jour 0.1.0 → 0.2.0** : instance montée avec les binaires **publiés** de
  `v0.1.0` (archives vérifiées par `SHA256SUMS`), organisation, administrateur, lecteur
  (`viewer`) et analyste (`analyst`) ajoutés directement, jeton d'inscription, hôte
  inscrit par l'agent 0.1.0 ; puis serveur 0.2.0 sur la même base : migrations 016 à 022
  (puis 023) appliquées, chaque membre dans « Général » avec son ancien rôle (admin,
  analyst → analyste, viewer → lecteur ; rôle d'organisation « membre »), projet, agent
  et jeton d'inscription dans « Général » ; l'agent **0.1.0** continue (inventaire
  inchangé, confirmé), puis l'agent 0.2.0 reprend son état et son inscription.
- **Codes de secours** : administrateur enrôlé en 0.1.0 invité depuis **Second facteur**,
  10 codes générés contre un code TOTP ; nouveau compte : codes montrés à l'enrôlement ;
  connexion par un code de secours (arrivée sur la page du second facteur), **même code
  refusé** ensuite ; audit `auth.recovery_code_used`.
- **Équipes et droits** : équipe « Web », compte invité qui accepte depuis **Mon compte ›
  Invitations**, ajouté lecteur de l'équipe ; il reçoit **404** sur l'hôte et ses
  conteneurs et une recherche vide ; le lecteur de « Général » voit tout ; le lecteur n'a
  pas de panneau de triage et son `POST` est refusé (**403**) ; l'hôte rattaché à « Web »
  **emmène ses 4 conteneurs** (5 projets), qui deviennent visibles du compte de « Web » et
  invisibles (404) du lecteur de « Général ».
- **Conteneurs enfants** : 4 identités pour 5 conteneurs Docker (les deux répliques de
  `shop/worker` forment un projet), l'image alpine partagée par `outil` et `shop/worker`
  scannée **une fois** ; conteneur **Podman** (rootful, socket `/run/podman/podman.sock`)
  inventorié à côté de Docker, moteur `podman` ; fiche hôte avec les conteneurs par
  périmètre ; conteneurs absents de la recherche sans « Inclure les conteneurs » ;
  `outil` supprimé : **« Absent »** sur la fiche hôte une fois l'heure de tolérance
  passée (temps simulé : `seen_at` reculé de 2 h en base).
- **CVE de contrôle** : CVE-2023-2650 avec les conteneurs → exactement **outil,
  shop/cache, shop/worker**, à l'écran et par l'API utilisateur (jeton personnel) ; sans
  les conteneurs, aucun projet.
- **Triage et VEX** : l'analyste déclare le constat CVE-2023-2650 / libcrypto3 de `outil`
  « non affecté » (`vulnerable_code_not_in_execute_path`) ; le même couple de
  `shop/worker` reste « à analyser » (portée projet) ; recherche `triage=not_affected` →
  `outil` seul, `triage=in_triage` → les trois (libssl3 de `outil` reste à analyser) ;
  filtre `triage` sur une recherche par nom → 400 ; export **OpenVEX** par l'API : une
  déclaration `not_affected` avec la justification d'origine.
- **Politiques, alertes, verdict** : canal webhook (récepteur local, signature HMAC
  vérifiée), « Envoyer un test » reçu et signé ; politique bloquante « critique ou élevée,
  à traiter, sur un conteneur » : aperçu, 195 violations, écran **Violations**, messages
  `violations.opened` signés ; **verdict** par l'API des agents : `fail` sur `shop/web`
  (99 violations bloquantes, résumé traduit), `pass` sur l'hôte, 404 sur un instantané
  inconnu.
- **Différences** : `shop/cache` passé de redis 7.0.0 à 7.0.15 ; nouvel instantané ;
  frise avec montées de version ; comparaison avec le précédent : 13 montées, 8 ajouts,
  5 retraits, **104 constats résolus** (dont CVE-2023-36824 sur redis, CVE-2023-0286 sur
  libcrypto1.1).

**Défaut trouvé et corrigé : doublons de notification.** La politique ci-dessus a fait
partir 295 violations pour 195 (le premier lot de 100 deux fois, à 3 ms d'écart, même
`X-Lotor-Delivery`) : deux jobs d'envoi du même canal tournaient en même temps, la clé
d'unicité des jobs ne valant que pour les jobs en attente. Correctif : réservation du lot
sous le verrou du canal avant l'appel réseau (migration 023, ADR 0052,
`TestConcurrentSendsNeverDuplicate`, qui échoue sans elle) ; serveur reconstruit,
migration 023 appliquée sur l'instance de recette, nouvelle politique ouvrant 224
violations : **4 messages, 224 violations reçues, aucune en double**.

Non exercé ici (et pourquoi) :

- **rétention, archivage après 7 jours, purge après 180 jours** : demandent l'écoulement
  du temps ; couverts par les tests d'intégration de T17, T13 et T18 (partie 1) ;
- **enrichissement IA par un vrai modèle** et **agent dépôt** : pas de clé ni de forge ;
  l'agent dépôt a été recetté au lot 1 (forge simulée) et l'enrichissement de bout en bout
  par `TestRepoAgentAIEnrichmentAgainstServer` (faux fournisseur) ;
- **Podman sans root**, **statut de commit** sur une vraie forge, canaux **e-mail,
  Matrix, Mattermost, Slack** réels, **import de VEX** d'éditeur à l'écran, **résumé
  quotidien**, **mTLS** (recetté au lot 1, non rejoué) : actions de l'utilisateur ou
  couverts par les tests.

#### Documentation et préversion

- Guides de démarrage FR et EN : invitations et équipes, inscription par équipe,
  conteneurs, enrichissement IA, section « Trier, comparer, être alerté ».
- `docs/operations.md` : passage de 0.1.0 à 0.2.0 (migrations, rétention, purge, codes de
  secours, agents), évaluation de l'IA pas à pas ; `docs/notifications.md` (envois
  simultanés) ; `docs/benchmarks.md` (complément du jeu, mesures du lot 2, agent
  serveur) ; `docs/utilisation.md`, `docs/notifications.md` et `config.example.yaml`
  relus : à jour.
- `CHANGELOG.md` : section `## [0.2.0] - 2026-11-01` (introduction, mise à jour depuis
  0.1.0, liens vers les PR #21 à #29), « Corrigé » (composants IA d'image, doublons de
  notification, `make bench-search`).
- `make release VERSION=v0.2.0 RELEASE_DIR=…` (répertoire temporaire vide) : six
  archives, quatre paquets (`lotor-host-agent_0.2.0_amd64.deb`…), `SHA256SUMS` vérifié
  par `sha256sum -c`, `lotor-server --version` donne `v0.2.0` ; extraction des notes de
  la section `[0.2.0]` rejouée. Étiquette non posée (refusée par le mandataire) : action
  de l'utilisateur.
- `v0.1.0` constatée publiée (préversion du 1er novembre 2026, 01:10 UTC) : critère de
  T11 coché, statuts mis à jour.

#### Décisions

- **Critère « zéro composant sans preuve » coché sur des modèles fictifs** (crédule,
  hostile, adverse) et le contrôle indépendant `checkProof`, le vrai modèle restant à
  mesurer ; le contrôle est rejoué à chaque `make eval-ai` **[à relire]**.
- **Échantillon pilote = les quatre dépôts publics du lot 1 aux mêmes commits**, non
  recopiés dans le dépôt (clonés par script, tête vérifiée) ; annotation « ignoré » pour
  ce que Syft voit déjà et les cas discutables (chaîne d'outils, image formée de
  variables) ; purl au type le plus précis, comme le demande le prompt **[à relire]**.
- **Mode `credulous` de `make eval-ai`** : contrôle à blanc des annotations et des preuves
  sans clé, explicitement pas une mesure (seuils non appliqués) **[à relire]**.
- **Composants IA toujours de type `library`** (image comprise), plutôt qu'adapter le
  décodeur du serveur aux composants `container` des SBOM tiers (changement d'ingestion
  plus large) **[à relire]**.
- **Réservation des envois de notification** (migration 023, 10 minutes, réessai par la
  file pour l'envoi qui trouve un lot réservé) plutôt qu'une transaction tenue pendant
  l'appel réseau ([ADR 0052](../../docs/adr/0052-envois-de-notification-reserves.md))
  **[à relire]**.
- **Jeu de mesure complété** (10 équipes, 50 hôtes × 10 conteneurs de 200 composants, une
  décision de triage sur dix constats ouverts), mesures « membre » avec une équipe sur
  dix ; agent serveur mesuré sur 4 cycles (pas 20 : 2 min de CPU chacun) **[à relire]**.
- **Recette sur une mise à jour réelle 0.1.0 → 0.2.0** plutôt que sur une instance neuve,
  pour vérifier la migration des équipes et la compatibilité de l'agent 0.1.0 ; parc en
  conteneurs Docker et Podman ; temps de l'état « absent » simulé en base ; outillage
  hors dépôt (client de l'interface, récepteur de webhook, scripts) **[à relire]**.
- `CHANGELOG.md` daté du 1er novembre 2026 ; à ajuster au jour de la pose de l'étiquette
  **[à relire]**.

#### Écarts

- Seuils de l'IA non mesurés (critère non coché) ; `v0.2.0` non publiée (critère non
  coché) : actions de l'utilisateur.
- `make bench-search` cassé depuis T16 dans son dernier pas (plans) : corrigé dans le
  test (visibilité déclarée), sans effet sur le produit.
- Rétention, archivage et purge non rejoués en temps réel ; Podman sans root, forges,
  canaux réels non essayés (voir « Non exercé »).
- Deux défauts du produit trouvés et corrigés (composants IA d'image perdus, doublons de
  notification).

#### ADR créés

- [0052 — Envois de notification réservés avant l'appel réseau](../../docs/adr/0052-envois-de-notification-reserves.md).

Migration **023** (`notification_deliveries.claimed_at`). Aucune nouvelle dépendance,
aucune nouvelle fonction `crossorg`.
