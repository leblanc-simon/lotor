# Modèle de menace

Version 4 (inscription, T28, 4 novembre 2026 ; version 3 : revue de sécurité du lot 2,
T18, 1er novembre 2026 ; version 2 : revue du lot 1, T11 ; version 1 : T00). Tenu à jour à chaque lot qui ajoute une frontière de
confiance, un actif ou un acteur (§ 19 de l'architecture). Gravité évaluée selon l'OWASP
Risk Rating au moment où une faiblesse est trouvée ; ce document liste les menaces et les
parades prévues, et le lot qui les porte. Les constats de la revue du lot 1 (SEC-01 à
SEC-14) et du lot 2 (SEC2-01 à SEC2-10) sont rappelés entre parenthèses ; leur suivi est
dans les Journaux de T11 et de T18 (ADR 0051).

## Actifs

| Actif | Pourquoi il compte |
| --- | --- |
| Inventaires (SBOM bruts, composants, instantanés) | Cartographie précise du parc : versions vulnérables, paquets internes, noms d'hôtes. Très utile à un attaquant. |
| Constats et décisions de triage | Liste des failles non corrigées, et de celles qu'on a jugées acceptables. |
| Comptes, mots de passe, secrets TOTP, sessions | Accès à l'interface et aux données de toutes les organisations d'un compte. |
| Codes de secours du second facteur | Remplacent un code TOTP à la connexion et pour reconfigurer le second facteur. |
| Jetons d'agent, d'inscription, personnels | Envoi de faux inventaires, lecture par l'API. |
| Secrets des forges (clé de GitHub App, jetons GitLab) | Lecture du code des dépôts ; détenus par l'agent dépôt seul. |
| Secrets des canaux de notification (clé HMAC, jeton Matrix, URL de webhook entrant) | Envoi de messages au nom de lotor, lecture des salons où le robot Matrix se trouve. |
| Clés de chiffrement des secrets stockés | Déchiffrement des secrets de canaux, OIDC (lots suivants). |
| Code des dépôts lu par l'IA | Envoyé au fournisseur de modèle externe pour les seuls dépôts autorisés. |
| Base de vulnérabilités Grype | Une base altérée masque des vulnérabilités ou en invente. |
| Journal d'audit | Preuve des actions ; doit rester complet et non modifiable par l'application. |

## Acteurs

- **Visiteur anonyme** sur Internet, face à l'interface et aux API.
- **Membre d'une organisation** (rôle d'organisation `member` ou `admin`, rôles d'équipe
  `reader`, `analyst`, `admin` : T16) : légitime dans ses équipes, hostile ou curieux
  envers les autres équipes de son organisation et envers les autres organisations.
- **Administrateur d'équipe** : gère les projets, agents et jetons d'inscription de son
  équipe, distinct de l'administrateur d'organisation (paramètres, membres, canaux, IA
  externe) ; tenté d'élargir son périmètre.
- **Porteur d'un jeton d'inscription d'une équipe** : outillage de déploiement où le jeton
  circule, qui choisit le nom d'hôte déclaré.
- **Administrateur d'instance** : rôle privilégié assumé, audité.
- **Inscrit** (T28) : toute personne qui crée son compte sur une instance ouverte (code
  d'inscription ou mode public) ; administrateur de sa seule organisation, inconnu de
  l'exploitant. **Porteur d'un lien** : quiconque détient un lien de vérification ou
  d'invitation, ou un code d'inscription, transmis par courriel ou à la main.
- **Agent compromis** : un hôte ou l'agent dépôt dont le jeton est volé.
- **Contenu hostile** : dépôt analysé, SBOM envoyé, fichier de l'hôte scanné (injection
  d'instructions pour l'IA au lot 2, bombe de décompression, JSON profond, liens
  symboliques piégés).
- **Fournisseur amont compromis** : distribution de la base Grype, dépendance Go.
- **Fournisseur de modèle externe** : reçoit ce que l'agent dépôt lui envoie (prompt,
  extraits, noms de fichiers) ; à ne pas exposer au-delà des dépôts autorisés.
- **Exploitant de la base** : accès PostgreSQL hors application.

## Frontières de confiance

1. Navigateur ↔ serveur (interface) : session, CSRF, CSP.
2. Agents ↔ serveur (API agent) : jeton d'agent, mTLS facultatif, limitation par jeton.
3. Clients ↔ serveur (API utilisateur) : jeton personnel ou session + en-tête CSRF.
4. Serveur ↔ PostgreSQL : rôle d'exécution sans contournement de la RLS.
5. Serveur ↔ distribution de la base Grype : téléchargement vérifié.
6. Agent dépôt ↔ forges : application installée en lecture seule, webhooks signés.
7. Agent dépôt ↔ contenu d'un dépôt cloné ; agent serveur ↔ système de fichiers de l'hôte.
8. Organisation A ↔ organisation B, dans le même serveur et la même base.
9. Équipe A ↔ équipe B dans une organisation : filtre d'équipe des lectures, matrice des
   droits, inscription des agents (T16, T18).
10. Agent dépôt ↔ fournisseur de modèle : ce qui sort (prompt, extraits, noms de
    fichiers), borné par les exclusions et le réglage par dépôt (T12, T18).
11. Visiteur anonyme ↔ création de compte et d'organisation : inscription, liens de
    vérification et d'invitation (T28).
12. Serveur ↔ serveur SMTP et boîtes des destinataires : courriels porteurs de liens
    secrets (T28).

## Menaces et parades

### Serveur — interface web

| Menace | Parade | Lot |
| --- | --- | --- |
| Vol de session par XSS | `html/template`, CSP sans script ni style en ligne, cookies `HttpOnly`, `Secure`, `SameSite` | T01, T03 |
| Requête forgée (CSRF) | csrfx sur l'interface et l'API utilisateur par session ; jeton lié à la session (HMAC du cookie et du secret de session : écrire le cookie depuis un sous-domaine ou une réponse en clair ne suffit plus) ; protection inter-origines (`Sec-Fetch-Site`, `Origin`) avant csrfx ; cookies `__Host-` quand `auth.cookie_secure` vaut `on` (SEC-08, ADR 0031) | T03, T11 |
| Cookie de session volé et rejoué indéfiniment | session glissante (`auth.session_ttl`) bornée par une durée absolue depuis la connexion (`login.session_max_age`, 7 jours) (SEC-08) | T11 |
| Force brute du mot de passe | limitation par IP dédiée à `/login` et `/login/2fa` (une IPv6 compte pour son /64), comparaison bcrypt, journal d'audit des échecs ; pas de verrouillage sur le mot de passe (il laisserait n'importe qui verrouiller un compte par son e-mail) | T03, T11 |
| Force brute du TOTP avec un mot de passe connu | le plafond de codes par défi ne borne pas l'attaque (un nouveau défi s'obtient en rejouant le mot de passe) : verrouillage **par compte**, tous défis et réauthentifications confondus, **confirmation d'enrôlement comprise** (`EnablePOST`, open-go-base v1.4.1) (10 codes faux en 15 min, verrouillage de 15 min doublé à chaque récidive, 24 h au plus), journalisé (`account.locked`), levé par la réinitialisation du TOTP ; un TOTP actif ne peut pas être « réactivé » (route refusée sans examen du code, dans mfax et dans lotor) ; IPv6 regroupée par /64 (SEC-01, SEC2-01, ADR 0029, 0051) | T11, T18 |
| Journal d'audit alimenté par un anonyme (échecs de connexion) | une ligne par échec, avec l'e-mail saisi ; borné par la limitation par IP (/64 en IPv6) — risque résiduel accepté (SEC-14) | T11 |
| Énumération des comptes | message d'échec unique (e-mail inconnu, mot de passe faux, compte désactivé), temps égalisé par une comparaison bcrypt factice | T03 |
| Énumération des comptes de l'instance par un administrateur d'organisation, ajout d'un compte sans son consentement | **corrigé en T16** (SEC-09, ADR 0034) : un administrateur d'organisation **invite** une adresse, avec la même réponse et le même journal que le compte existe ou non (l'invitation n'est pas liée à `users`) ; le compte ne devient membre qu'en acceptant depuis `/account/invitations` ; une invitation ne vaut que pour l'adresse invitée, une fois, 30 jours au plus, et les invitations en attente sont bornées (200 par organisation). Seul l'administrateur d'instance, qui connaît déjà les comptes, ajoute directement un membre | T11, T16 |
| Lecture des invitations d'un autre compte | la fonction `crossorg` `lotor_user_invitations` ne renvoie que les invitations adressées à l'e-mail du compte appelant (actif), d'organisations actives dont il n'est pas membre ; l'acceptation revérifie l'e-mail et l'échéance sous verrou dans `InOrg` ; tests d'intégration (autre compte, expirée, archivée, seconde acceptation) | T16 |
| Membre qui lit les projets d'une autre équipe de son organisation | filtre d'équipe déclaré à la transaction (`db.Visible`, `lotor_team_visible`) sur toutes les lectures : listes, fiches, recherche et exports, API utilisateur (jetons personnels compris), tableau de bord et statistiques, vulnérabilités, composants, agents ; échec de la requête si la visibilité n'est pas déclarée (un oubli ne montre jamais tout) ; 404 pour une ressource d'une équipe invisible ; test unique des surfaces (`TestTeamFilterOnEverySurface`) | T16 |
| Membre qui agit au-delà de son rôle d'équipe | matrice des droits unique (`internal/tenant`, `docs/security/permissions.md` généré) ; chaque route de l'organisation déclarée avec sa permission et la ressource qui porte l'équipe, garde unique ; test dérivé de la matrice sur chaque route et chaque rôle (`TestRoutePermissionsFollowMatrix`) ; un rattachement de projet exige le droit dans les deux équipes | T16 |
| Escalade par un administrateur d'équipe | il ne crée ni ne supprime d'équipe, n'invite ni ne retire de membre de l'organisation, ne touche ni aux paramètres ni au journal ; il n'ajoute à son équipe que des membres de l'organisation (clé étrangère composite) ; les agents d'organisation lui restent invisibles | T16 |
| Constat dangereux masqué par un triage abusif (« non affecté », « faux positif ») | trier exige le rôle analyste dans l'équipe du projet (`finding.triage`), décider pour toute l'organisation le rôle d'administrateur (`triage.org`) ; commentaire et justification exigés ; journal des décisions en ajout seul pour le rôle d'exécution (vérifié au démarrage), chaque décision au journal d'audit ; historique complet sur la fiche du constat ; un risque accepté échoit automatiquement | T14 |
| VEX d'éditeur malveillant ou trop gros à l'import | document borné (1 Mio, 5 000 déclarations), lu en mémoire sans fichier temporaire, compte authentifié seul à pouvoir envoyer ce corps, droit vérifié avant l'import ; valeurs inconnues écartées ; décisions signées `vex:<source>` et compte importateur noté ; import réservé aux analystes (projet) ou aux administrateurs (organisation) | T14 |
| Décision d'un projet qui fuit vers une autre organisation ou une autre équipe | décisions sous la RLS standard ; une décision de projet ne vaut que pour ce projet ; la liste des décisions d'organisation et la portée d'une décision d'organisation, qui révèlent des composants d'autres équipes, sont réservées aux administrateurs de l'organisation ; tests d'isolement SQL et par route | T14 |
| Session ouverte sans second facteur | enrôlement obligatoire ; session authentifiée refusée sans méthode enregistrée (`session_auth`) ou sans TOTP actif | T03 |
| Réinitialisation du second facteur : le mot de passe seul ouvre l'enrôlement (premier arrivé) | réinitialiser le TOTP impose un mot de passe temporaire (montré une fois à l'administrateur) ; la procédure de secours exige `bootstrap.rescue_password` ; sessions fermées et jetons personnels révoqués (SEC-03, ADR 0029) | T11 |
| Mot de passe temporaire conservé | `must_change_pwd` impose le changement avant toute page ; affiché une seule fois, jamais dans une URL ni un journal | T03 |
| Texte arbitraire injecté par un lien (`?error=`) | seuls des codes connus sont affichés (open-go-base v1.1.0, messages `?done=` en liste fermée) | T03 |
| Usurpation de l'IP journalisée | `X-Forwarded-For` réécrit avec l'IP résolue par les seuls mandataires de confiance | T03 |
| Rejeu d'un code TOTP | mfax refuse un code déjà utilisé | T03 |
| Code de secours volé, deviné ou rejoué | 80 bits d'aléa par code, seule l'empreinte SHA-256 liée au compte est gardée ; usage unique (consommation atomique) ; codes faux comptés dans le verrouillage par compte et dans le plafond du défi, compte verrouillé qui refuse aussi les codes de secours ; affichage unique (`Cache-Control: no-store`), régénération soumise à un code TOTP et qui rend caduc l'ancien jeu ; **aucun jeu n'est délivré sans un code TOTP compté dans le verrouillage** (SEC2-01) ; chaque code utilisé ou refusé et chaque jeu généré au journal d'audit ; jamais dans les journaux (open-go-base v1.4.0, ADR 0048) | T18 |
| Second facteur remplacé depuis une session volée, ou par l'ancien mot de passe pendant une reconfiguration | la reconfiguration exige un code TOTP ou un code de secours **et un nouveau mot de passe** (validé avant la consommation du code), ferme toutes les sessions et impose, à la connexion suivante, ce nouveau mot de passe puis un nouvel enrôlement : **aucun état intermédiaire où l'ancien mot de passe seul enrôle un second facteur** ; journalisée (`account.totp_reconfigured`) (SEC2-06, ADR 0048, 0051) | T18 |
| Accès à une autre organisation (IDOR) | garde d'organisation, RLS forcée, 404 uniforme, tests d'isolement par route | T03 → |
| Clickjacking | `frame-ancestors 'none'` | T01 |
| Compte administrateur unique perdu | procédure de secours auditée, une fois par ticket ; avertissement s'il n'y a qu'un administrateur | T03 |
| Variable de secours oubliée en configuration | sans effet après application (ticket déjà journalisé), rappel à chaque démarrage | T03 |
| Administrateur d'instance qui lit une organisation | non membre : 404 ; il ne voit que les métadonnées (liste, administrateurs) et chaque réinitialisation est auditée — rôle privilégié assumé | T03 |

### Serveur — inscription et courriels transactionnels (T28, ADR 0056)

| Menace | Parade | Lot |
| --- | --- | --- |
| Création massive de comptes et d'organisations sur une instance ouverte | privée par défaut ; mode public réservé à une instance qui envoie des courriels, adresse vérifiée avant toute création, domaines restreignables ; mode invitation : code d'instance à usage unique, échéance de 1 à 365 jours, révocable ; `POST` de l'inscription bornés par la limitation par IP de la connexion (/64 en IPv6) ; chaque étape au journal d'audit. Pas de captcha ni de validation par un administrateur — risque résiduel accepté (le mode public ouvre l'instance à qui le choisit) | T28 |
| Énumération des comptes par l'inscription | avec envoi : même réponse et même page, qu'un compte existe ou non ; l'adresse inscrite reçoit « vous avez déjà un compte » au lieu du lien ; sans envoi (mode invitation) : une adresse prise donne le même refus qu'un code faux, et le code n'est pas consommé (retour arrière) — seul le porteur d'un code valide l'apprend, ce qu'il pourrait tenter de toute façon en s'inscrivant | T28 |
| Boîte de courriels inondée par des demandes au nom d'un tiers | trois liens au plus par adresse sur 24 h (au-delà : même réponse, rien n'est envoyé), plus la limitation par IP | T28 |
| Lien ou code deviné, volé dans un journal ou rejoué | format commun des jetons (identifiant public de 128 bits, secret de 256 bits), empreinte SHA-256 seule en base, comparaison en temps constant ; lien de vérification 24 h et consommé avec tous ceux de l'adresse, lien d'invitation remplacé à chaque nouvelle invitation et consommé à l'acceptation, code à usage unique sous verrou ; jamais dans un journal ; destinataire, lien et code chiffrés par `secrets.keys` dans la file `mail.send`, erreur SMTP réduite à sa clé ; pages à jeton en `Cache-Control: no-store`, `Referrer-Policy: same-origin` | T28 |
| Deux inscriptions simultanées avec un même code, ou état partiel après un échec | une seule transaction `InOrg` (nouvelle organisation) crée le compte, consomme le code et les liens, crée l'organisation, l'adhésion et l'équipe ; code consommé par `UPDATE … WHERE used_at IS NULL` ; test de concurrence et test d'échec simulé | T28 |
| Compte d'un tiers créé à son insu, ou adresse usurpée par un lien d'invitation | la vérification prouve la possession de l'adresse (mode public, et invitation avec envoi) ; le lien d'une invitation crée le compte **à l'adresse invitée**, imposée ; un compte connecté d'une autre adresse est arrêté ; sans envoi, l'adresse d'une inscription sur code n'est pas vérifiée — assumé (l'exploitant a choisi de transmettre les codes à la main) | T28 |
| Titulaire d'un lien qui lit une autre organisation | `lotor_invitation_by_token` ne renvoie que l'invitation non expirée d'une organisation active désignée par l'identifiant public du lien ; le secret est comparé puis revérifié sous verrou dans `InOrg` ; l'inscrit n'a accès qu'à l'organisation qu'il rejoint ou crée | T28 |
| Session ouverte sans second facteur après une inscription | la création n'ouvre qu'une session de configuration (`authx.PurposeSetup`), qui ne mène qu'à l'enrôlement du TOTP, obligatoire ; aucun mot de passe temporaire | T28 |
| Adresse saisie par un administrateur pour l'envoi d'un code conservée ou divulguée | envoi sur-le-champ, adresse absente des tables, du journal d'audit, de la file et des journaux (test) | T28 |
| Courriel piégé ou contenu externe chargé à l'ouverture | gabarit commun, textes traduits échappés par `html/template`, logo joint au message (`cid:`), aucune image ni police externe, aucun script | T28 |

### Serveur — politiques et notifications

| Menace | Parade | Lot |
| --- | --- | --- |
| Requête vers le réseau interne par une URL de canal (SSRF) : un administrateur d'organisation vise `169.254.169.254`, `localhost` ou un service interne | adresse vérifiée à la connexion, après la résolution DNS (un nom qui change d'adresse ne contourne rien) : bouclage, privé, lien local, partagé, non spécifié, multidiffusion et plages réservées refusés sauf `notify.allow_private_networks` ; une adresse IPv6 qui porte une IPv4 (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible) est jugée sur cette IPv4, NAT64 d'usage local et Teredo refusés (SEC2-08) ; aucune redirection suivie, aucun mandataire ; durée et réponse bornées ; l'erreur ne cite pas l'URL. Ports non restreints : le test d'un canal permet à un administrateur d'organisation de savoir si un port d'un hôte public répond depuis le serveur — risque accepté (ADR 0046, 0051) | T15, T18 |
| Vol des secrets des canaux (clé HMAC, jeton Matrix, URL de webhook entrant) | chiffrés par `internal/secret`, ligne en données associées (un chiffré recopié ne se déchiffre pas), rechiffrés au démarrage ; jamais réaffichés, jamais journalisés, absents de l'audit (`TestChannelSecretsAreSealed`) ; **un secret ne suit jamais une nouvelle destination sans être ressaisi** (serveur Matrix, URL du webhook générique), changement de destination journalisé (SEC2-04, ADR 0051) | T15, T18 |
| Faux message de lotor ou message rejoué chez le destinataire d'un webhook | `HMAC-SHA256(clé, horodatage + "." + corps)` dans `X-Lotor-Signature`, horodatage dans `X-Lotor-Timestamp`, identifiant de message stable pour écarter un doublon ; vérification documentée (`docs/notifications.md`) | T15 |
| Règle CEL qui épuise le worker | coût estimé borné à l'enregistrement, même limite au coût réel de chaque évaluation, interruption dans les boucles, expression de 4 000 caractères au plus, 100 politiques par organisation (ADR 0045) | T15 |
| Injection dans un message (en-têtes de courriel, liens ou mentions Slack) par un nom de projet ou de règle | retours à la ligne retirés des en-têtes, objet encodé ; `& < >` échappés pour Slack et Mattermost ; Matrix en texte brut | T15 |
| Un membre voit les violations d'une autre équipe | filtre d'équipe sur la liste et le tableau de bord (projet du constat, équipe de l'agent) ; règles et canaux réservés aux administrateurs (`policy.manage`, `channel.manage`) | T15 |

### Serveur — API agent et ingestion

| Menace | Parade | Lot |
| --- | --- | --- |
| Jeton d'agent volé | jeton haché (SHA-256), révocation immédiate, date de dernier usage, projets et références confiés à l'agent seuls ; jeton d'inscription borné en durée et en usages | T04 |
| Énumération ou force brute de jetons | secret de 256 bits, comparaison en temps constant, refus uniforme tant que le secret n'est pas vérifié, jetons refusés limités par IP | T04 |
| Faux inventaire pour masquer une faille | un agent n'écrit que sur ses références ; instantanés historisés et attribués ; signature au lot 3 | T04, T05, T24 |
| Déni de service par SBOM énorme ou piégé | corps multipart borné ; bornes en flux (taille reçue, taille décompressée — bombe gzip —, profondeur JSON, nombre de composants, clés comparées sans casse comme le décodeur) avant tout décodage complet ; validation par le schéma officiel avant les décodeurs tiers ; décodage dans un job (jamais dans la requête) ; son délai interrompt la lecture en flux et coupe entre les étapes, mais la validation et le décodage de Syft, linéaires en taille, vont au bout de l'étape commencée (SEC-11) ; panique d'un décodeur convertie en refus ; plafond de jobs par organisation (ADR 0015) | T05, T11 |
| Déni de service par stockage (agent compromis qui envoie des SBOM tous différents) | quota d'envois stockés par référence sur 24 h (`ingest.max_per_ref_per_day`) et de volume par organisation (`ingest.max_org_storage_mib`), 429 sans rien stocker (SEC-05, ADR 0030) ; rétention des anciens instantanés et des ensembles orphelins | T11, T17 |
| SBOM d'une autre organisation ou d'une autre référence | référence vérifiée par `project.RefForAgent` avant la lecture du SBOM puis dans la transaction qui le stocke ; composants, blobs et ensembles propres à chaque organisation (RLS, clés composites) | T05 |
| Contenu de SBOM dans les journaux ou les erreurs | seuls l'identifiant d'ingestion, la clé d'erreur et des compteurs sont journalisés ; le détail d'une violation de schéma est un pointeur JSON, jamais une valeur | T05 |
| Injection SQL | requêtes paramétrées uniquement (ADR 0004) | tous |
| Saturation de l'API par un hôte | limitation par jeton (`agent_api.rate_limit`), sans gêner les autres hôtes de la même IP | T04 |
| Point compatible Dependency-Track (`/dt`) comme contournement | mêmes middlewares que l'API des agents (limiteurs, refus uniformes, mTLS), jeton d'agent dépôt seul (agent serveur refusé), envoi passé par `ingest.Authorize` et `ingest.Receive` ; corps borné (SBOM admis × 4/3 en JSON base64) ; jeton de suivi d'un autre agent répondu comme inconnu (ADR 0057) | T19 |
| Archive hors ligne forgée, modifiée ou d'une autre organisation (T23) | HMAC-SHA256 du manifeste (qui couvre le SBOM par son empreinte), de clé l'empreinte du secret du jeton de l'agent, vérifié en temps constant ; organisation du jeton égale à celle de l'import ; jeton actif ; puis mêmes contrôles qu'un envoi réseau ; lecture bornée et entrées dans l'ordre ; import réservé à qui gère des agents (écran, API) ; répertoire surveillé réservé à l'exploitant (ADR 0059) | T23 |
| Inscription d'un faux hôte par archive | bloc d'inscription signé par l'empreinte du jeton d'inscription (même jeton, mêmes bornes de durée et d'utilisations qu'en ligne) ; jeton d'agent proposé refusé s'il existe déjà ; rejeu d'une archive dédoublonné par l'empreinte de son manifeste | T23 |
| Agent dépôt compromis qui crée des projets à volonté (`autoCreate`) | création refusée par défaut, autorisée par agent par qui gère les agents, seulement pour un agent d'équipe (projet dans son équipe), auditée ; 200 versions actives au plus par dépôt ; verrou par agent contre les doublons simultanés | T19 |

### Serveur — recherche et API utilisateur

| Menace | Parade | Lot |
| --- | --- | --- |
| Jeton personnel volé, ou créé depuis une session volée | lecture seule, expiration obligatoire (365 jours au plus), révocation manuelle immédiate, appartenance aux organisations vérifiée à chaque requête (404 sinon), compte désactivé ou en attente (mot de passe temporaire, TOTP absent) refusé, date de dernier usage, création et révocation au journal ; **révocation d'office** à la réinitialisation du mot de passe ou du TOTP et au changement de mot de passe (case cochée par défaut) ; **création soumise à un code TOTP** (SEC-02, ADR 0029) | T09, T11 |
| Recherche qui sort de l'organisation | exécution sous la RLS ; les deux fonctions qui la contournent pour les index (nom, empreinte) lisent l'organisation dans `lotor.org_id`, jamais en paramètre, et échouent hors `InOrg` (test d'isolement) | T09 |
| Saturation par des recherches ou des exports | requête bornée (1 024 octets), composants bornés (1 000 par nom ou empreinte, 5 000 par paquet), pages bornées, exports simultanés et durée bornés (`user_api.max_exports`, `export_timeout`) avec un export à la fois par compte (SEC-07), limitation par jeton | T09, T11 |
| Saturation mémoire par le réencodage de SBOM téléchargés | réencodages simultanés bornés (`ingest.max_reencodes`), un par compte, 429 au-delà ; client parti avant le calcul ignoré (SEC-06) | T11 |
| Injection de formules dans un export CSV | cellule commençant par `=`, `+`, `-`, `@` préfixée d'une apostrophe (noms et versions viennent de SBOM non fiables) | T09 |

### Serveur — base de données

| Menace | Parade | Lot |
| --- | --- | --- |
| Requête qui oublie le filtre d'organisation | RLS forcée sur toute table d'organisation, `InOrg` seul accès, échec franc hors organisation | T01, T03 |
| Ligne qui référence une autre organisation | clés étrangères composites | T03 → |
| Rôle d'exécution trop puissant | refus de démarrer si superutilisateur, `BYPASSRLS` ou propriétaire des tables | T01 |
| Migration altérée après publication | somme SHA-256 vérifiée au démarrage | T01 |
| Fuite de secrets stockés | AES-256-GCM, clé hors base, rotation ; données associées liant chaque chiffré à sa ligne (un chiffré recopié ailleurs ne se déchiffre plus) ; secrets TOTP chiffrés (T03) | T01, T03 |
| Lecture de la base : jetons de session | jetons en clair dans `sessions` (choix d'authx) : une lecture de la base permet de reprendre une session jusqu'à son expiration ; à faire évoluer dans open-go-base (jeton haché) | ouvert |
| Journal d'audit modifié ou effacé par l'application (injection SQL, exécution de code, identifiant du rôle d'exécution volé) | `UPDATE`, `DELETE` et `TRUNCATE` retirés au rôle d'exécution sur les deux journaux, vérifiés au démarrage (`CheckRuntimeRole`) (SEC-04, ADR 0030) | T11 |
| Rôle d'exécution qui crée des objets hors RLS | `CREATE` retiré sur `public` à `PUBLIC`, refus de démarrer si le rôle a `CREATE` sur la base ou sur `public` (SEC-12) | T11 |
| Fonction inter-organisations trop bavarde | fonctions listées (ADR 0012, 0024), métadonnées seulement, toute nouvelle relue comme un changement de sécurité ; `lotor_list_organizations`, `lotor_org_id_by_slug` et `lotor_user_invitations` (identifiant du compte en paramètre) n'ont aucune garde SQL (l'appelant vérifie en Go, l'acceptation d'une invitation revérifie tout sous la RLS) : une injection SQL future les exposerait, risque accepté (SEC-12, SEC2-10) | T03, T16 |
| Fuite par les journaux | jamais de mot de passe, jeton, secret ni contenu de SBOM dans les journaux | tous |

### Base de vulnérabilités

| Menace | Parade | Lot |
| --- | --- | --- |
| Archive altérée en transit | HTTPS, somme de contrôle de la liste de distribution vérifiée, ouverture validée avant bascule | T06 |
| Base périmée qui masque de nouvelles CVE | alerte d'administration au-delà de 5 jours | T06 |
| Base différente selon les instances | version cible commune en base, synchronisation avant toute analyse | T06 |
| Archive altérée dans PostgreSQL | SHA-256 et taille revérifiées à chaque synchronisation, avant toute installation ; une archive altérée n'est jamais installée | T06 |
| Archive démesurée (épuisement du disque ou de la mémoire) | taille bornée (`vulndb.max_archive_mib`), téléchargement en flux sur disque, lecture par blocs de 8 Mio | T06 |
| Distribution amont compromise : liste non signée, extraction non bornée | la liste n'est authentifiée que par HTTPS (aucune signature amont) et l'archive par la somme annoncée dans cette même liste ; l'extraction (`curator.Import` d'Anchore) n'est pas bornée en taille décompressée — risque amont accepté, surveillé par l'alerte d'espace disque de l'exploitant (SEC-14) | — |
| Contenu de la base injecté dans les écrans (description, références) | échappement de `html/template`, références limitées aux adresses http(s), texte de la source affiché sans interprétation | T06 |

### Agent serveur

| Menace | Parade | Lot |
| --- | --- | --- |
| Lecture de l'hôte au-delà du nécessaire | utilisateur dédié, seule capacité `CAP_DAC_READ_SEARCH` (lecture), unité systemd durcie (`ProtectSystem=strict`, `NoNewPrivileges`, filtre d'appels système ; `systemd-analyze security` 1,9) ; rien d'autre ne sort que le SBOM et le contexte de l'hôte | T07 |
| Jeton lisible par d'autres comptes | répertoire d'état en `0700`, fichier en `0600` écrit atomiquement, ou credentials systemd chiffrés ; un fichier secret ouvert au groupe ou aux autres est refusé | T07 |
| Jeton envoyé à un tiers | HTTPS seulement, aucune redirection suivie, jeton jamais journalisé | T07 |
| Saturation de l'hôte par le scan | `GOMAXPROCS` et `GOMEMLIMIT` bas, `Nice=19`, `IOSchedulingClass=idle`, `MemoryMax`, durée maximale de scan ; montages réseau et autofs non parcourus | T07 |
| Jeton d'inscription partagé qui choisit son nom d'hôte | sans `project_id`, l'agent est rattaché au projet hôte non affecté qui porte le nom d'hôte **déclaré**, **dans l'équipe du jeton seulement** : un homonyme d'une autre équipe répond « hôte déjà suivi », sans être pris ni révéler son équipe ou son état ; un projet désigné passé dans une autre équipe n'est plus confié (SEC2-02, ADR 0051). Dans l'équipe, un porteur du jeton peut prendre un projet hôte créé à la main ou libéré et encore sans agent : risque accepté sous l'hypothèse « hôtes non compromis à l'inscription » ; jetons d'inscription bornés en durée et en usages, inscription auditée (SEC-13) | T07, T18 |
| Jeton d'agent sans expiration | accepté (ADR 0014) : révocation immédiate, date de dernier usage, rotation documentée (SEC-14) | T04 |
| Confirmation d'inventaire usurpée | un compte rendu n'avance que la date de dernière analyse d'une référence d'hôte confiée à l'agent, et seulement si l'empreinte est celle de l'ensemble courant | T07 |
| Socket Docker = root | inventaire des conteneurs désactivé par défaut (`containers.enabled`) : sans lui, aucune socket n'est ouverte (testé) ; documenté comme équivalent à root, socket Podman sans root recommandée ; l'unité fournie ne donne aucun accès, à ajouter par un complément explicite (ADR 0041) | T13 |
| Image de conteneur piégée (contenu tiers) | image exportée puis lue comme fichier par Syft, sans moteur ni registre ; catalogueurs hors ligne (aucun outil exécuté, aucun accès réseau) ; export borné (`containers.max_image_mib`) dans un répertoire `0700`, archive supprimée après le scan ; réponses du moteur bornées ; mêmes bornes d'ingestion qu'un SBOM d'hôte côté serveur | T13 |
| Agent qui crée ou alimente les conteneurs d'un autre hôte | le signalement ne désigne pas l'hôte : le serveur prend l'hôte actif confié au jeton ; un envoi vers un conteneur passe par `project.RefForAgent`, qui exige l'agent de son hôte (testé) ; 500 identités au plus par signalement, corps borné à 1 Mio (ADR 0040) | T13 |
| Conteneur visible d'une autre équipe | l'équipe d'un conteneur est celle de son hôte, imposée par une clé étrangère en cascade (ADR 0040) ; elle ne protège que si l'hôte lui-même ne peut pas être pris par une autre équipe : inscription bornée à l'équipe du jeton (SEC2-02) | T13, T18 |
| Déni de service par création de conteneurs (jeton d'agent volé, hôte compromis) | projets enfants d'un hôte, actifs ou archivés, bornés (`containers.max_per_host`, 1 000) : un signalement qui en créerait davantage est refusé sans rien créer ni journaliser ; seule la purge supprime un enfant, la borne totale borne donc les créations dans le temps ; 500 identités par signalement, limitation par jeton (SEC2-05, ADR 0051) | T18 |
| Serveur usurpé | TLS vérifié (autorité privée possible) ; mTLS facultatif, exigé alors sur toute l'API des agents avant la lecture du jeton | T07 |
| Clé d'API de Dependency-Track volée ou envoyée à un tiers | sortie désactivée par défaut ; clé en fichier `0600` ou credential systemd, jamais en configuration ni dans les journaux ; HTTPS seulement, aucune redirection suivie (ADR 0057) | T19 |

### Agent dépôt

| Menace | Parade | Lot |
| --- | --- | --- |
| Faux webhook | signature vérifiée (`X-Hub-Signature-256`, `X-Gitlab-Token` en temps constant) ; récepteur en HTTP par défaut : `X-Gitlab-Token` doit passer par un mandataire TLS (documenté) (SEC-14) | T08 |
| Délégué abusé : un administrateur d'organisation (ou un serveur compromis) fait analyser un dépôt hors périmètre | liste blanche obligatoire côté agent (`forges[].allowed_namespaces`, ou `*` explicite), jeton GitHub restreint au seul dépôt ; l'URL de clonage reste reconstruite depuis la base configurée (SEC-10, ADR 0031) | T11 |
| Dépôt piégé (liens symboliques, chemins) | tout accès par `os.Root`, aucun lien suivi hors de l'arborescence, aucun script du dépôt exécuté | T08 |
| Webhook rejoué ou en retard | un webhook n'est qu'un signal : l'agent résout la tête de la référence ; livraisons déjà vues écartées (ADR 0023) | T08 |
| Saturation du récepteur exposé | corps borné, débit limité par IP, réponse immédiate, file bornée | T08 |
| Dépôt trop gros ou trop lent | taille mesurée pendant le clonage (git tué au-delà), délais de clonage et de scan, répertoire supprimé quoi qu'il arrive | T08 |
| Exécution de code du dépôt | aucun crochet git, LFS inerte, Syft sans `go list` ni réseau (`golang.UsePackagesLib=false`) | T08 |
| Statut de commit falsifié ou droit d'écriture abusé | statut publié par l'agent seul, à partir du verdict du serveur ; jeton GitHub de statut séparé, restreint au dépôt et à `statuses: write` (le jeton du clonage reste en lecture) ; désactivé par défaut (ADR 0047) | T15 |
| Vol des secrets de forge | détenus par l'agent seul, jamais en base ni en configuration en clair ; credentials systemd ou fichiers `0600` ; jamais dans les arguments de git, l'URL ni les journaux ; jeton GitHub restreint à `contents: read` et au dépôt analysé ; les droits du jeton GitLab bornent ce qu'une organisation peut faire analyser | T08, T11 |
| Injection d'instructions vers l'IA : le dépôt fait lire au modèle des fichiers hors de l'arborescence ou des secrets | quatre outils seulement (lecture seule, sans réseau ni écriture), tout accès par un `os.Root` sur l'arborescence de l'analyse, chemins absolus et remontées refusés, fichiers sensibles (motifs, clés privées détectées) ni listés, ni lus, ni fouillés, **ni nommés dans le prompt** (périmètre incrémental filtré, SEC2-07) et indiscernables d'un fichier absent (sauf un fichier de plus de 64 Kio qui contiendrait une clé privée : listé puis refusé à la lecture, reste accepté) ; l'analyse ne reçoit aucun secret de l'agent ; prouvé par les dépôts hostiles du corpus avec un faux fournisseur enregistré (ADR 0043, 0044) | T12 |
| Injection d'instructions vers l'IA : le dépôt fait inventer ou accepter un composant | seule sortie acceptée : `submit_candidates` validé par schéma ; vérificateur déterministe seul juge (extrait relu à la ligne, nom et version présents, purl cohérent) ; aucune preuve tirée de la documentation, d'un manifeste ou d'un fichier qui s'adresse au modèle, ni d'un extrait qui cite un purl (ADR 0043) | T12 |
| Fuite de code vers un fournisseur externe non autorisé | IA désactivée par défaut ; fournisseur externe autorisé projet par projet par un administrateur d'organisation, audité ; **l'autorisation vaut pour un dépôt : changer l'URL du dépôt sans le droit `ai.external` la retire** (réglage ramené à « désactivé », journalisé, SEC2-03) ; `ai.forbid_external` sur l'instance ; réglage effectif transmis à l'agent ; client Anthropic sans aucune valeur lue dans l'environnement (ADR 0042, 0043) | T12 |
| Coût ou durée d'analyse incontrôlés (dépôt piège, boucle du modèle) | budget de tours, de jetons, d'octets lus et de durée ; délai vérifié entre deux appels d'outils et pendant une recherche, chaque recherche décomptée du budget de lecture, 20 appels d'outils au plus par réponse du modèle (SEC2-09) ; au-delà, SBOM Syft seul marqué incomplet ; analyse incrémentale ; commits intermédiaires sans appel au modèle | T12, T18 |
| Clé d'API du modèle volée | credential systemd ou fichier `0600`, jamais en configuration ni dans les journaux ; erreurs du fournisseur résumées sans corps de réponse | T12 |
| Clé d'API de Dependency-Track volée | même traitement que les autres secrets de l'agent (credential ou `0600`), HTTPS seulement, aucune redirection suivie ; sortie désactivée par défaut (ADR 0057) | T19 |

### Chaîne d'approvisionnement du projet

| Menace | Parade | Lot |
| --- | --- | --- |
| Dépendance Go vulnérable | `govulncheck` en CI, dépendances validées une à une | T00 → |
| Vulnérabilité activement exploitée dans un binaire publié | SBOM des trois binaires analysés par Grype à chaque build, échec sur une vulnérabilité KEV | T06 |
| Action GitHub détournée | actions épinglées par SHA, permissions `contents: read` | T00 |
| Binaire publié altéré | sommes de contrôle publiées ; signature au lot 3 | T11, T24 |

## Hypothèses

- TLS est terminé par le serveur ou par un mandataire inverse de confiance.
- L'exploitant de PostgreSQL et l'administrateur d'instance sont de confiance ; la RLS
  protège des erreurs de l'application, pas d'un superutilisateur de la base.
- Les hôtes qui portent un agent ne sont pas compromis au moment de l'inscription. Cette
  hypothèse ne couvre que l'équipe du jeton d'inscription : une autre équipe ne peut pas
  prendre un hôte par son nom (SEC2-02).
- Derrière un mandataire, seuls les mandataires de `web.trusted_proxies` fournissent l'IP
  du client ; un mandataire de confiance qui ne pose pas `X-Forwarded-For` doit écraser
  `X-Real-IP` (repli d'open-go-base) (SEC-14).
- Tant que `auth.cookie_secure` ne vaut pas `on`, aucun sous-domaine du site n'est hostile :
  sans `__Host-`, un sous-domaine peut écraser les cookies (le jeton CSRF lié à la session
  et la protection inter-origines restent actifs).
