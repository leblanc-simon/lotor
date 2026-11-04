# T28 — Inscription

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé |

## Objectif

Permettre de créer son compte local sans passer par un administrateur d'instance, selon un mode
choisi par l'exploitant (privé par défaut), et de rejoindre une organisation depuis son
invitation.

## Périmètre

**Inclus**

- Réglage `signup.mode` : `private` (défaut), `invitation`, `public` ; `signup.allowed_domains`
  (mode public). Fichier ou variables `LOTOR_SIGNUP_*`.
- `web.public_url` (`LOTOR_PUBLIC_URL`) remplace `notify.public_url` (liens des notifications,
  des verdicts et des courriels de l'inscription), sans repli sur l'ancienne clé.
- **Mode public** : SMTP et URL publique exigés au démarrage ; adresse vérifiée par un lien ;
  domaines restreints si la liste n'est pas vide ; chaque inscription crée une organisation
  dont le compte est administrateur.
- **Mode invitation** : codes d'inscription créés par un administrateur d'instance (libellé,
  validité en jours, 30 par défaut, 1 à 365), à usage unique, révocables. Le code n'est lié à
  aucune adresse. Avec un envoi possible, le code part par e-mail à une adresse saisie, ni
  conservée ni imposée à l'inscription, et l'adresse de l'inscription est vérifiée par un
  lien ; sans envoi possible, le code est affiché une fois et l'adresse n'est pas vérifiée.
  Chaque inscription crée une organisation dont le compte est administrateur.
- **Invitations d'organisation, tous modes** : l'invitation porte un lien secret, envoyé par
  e-mail dans la langue de l'invitant ou affiché une fois à l'administrateur. Le lien mène à
  la connexion (compte existant) ou à la création du compte, à l'adresse invitée, rattaché à
  l'organisation avec le rôle de l'invitation.
- Déroulé commun : mot de passe choisi (aucun mot de passe temporaire), enrôlement immédiat du
  TOTP, codes de secours.
- Réponse neutre sur l'existence d'un compte (courriel « vous avez déjà un compte » avec envoi ;
  sans envoi, même message qu'un code refusé, code non consommé).
- Limitation des tentatives par IP, comme la connexion ; audit de chaque étape.

**Exclu** : file de validation par un administrateur, captcha, plusieurs organisations par
compte inscrit, inscription par SSO (T25), changement d'adresse.

## Conception

Voir l'[ADR 0056](../../docs/adr/0056-inscription.md).

- **Courriels** : paquet `internal/mailer`, job `mail.send` mis en file dans la transaction qui
  produit le lien ; le lien (porteur du jeton) est chiffré par `secrets.keys` dans la charge
  du job et n'est jamais journalisé ; gabarits texte `mail.*` traduits. « Envoi possible » :
  SMTP configuré (`smtp.host` et `smtp.from`) et `web.public_url` renseignée.
- **Paquet `internal/signup`** : codes, vérifications d'adresse, inscription atomique (compte,
  organisation, équipe « Général », adhésion, consommation du code et de la vérification dans
  une seule transaction déclarée pour la nouvelle organisation), inscription par invitation
  d'organisation (transaction de l'organisation invitante), purge.
- **Tables globales** `signup_codes`, `signup_verifications` ; colonnes `public_id` et
  `secret_hash` de `org_invitations` ; fonction inter-organisations
  `lotor_invitation_by_token`.
- **Écrans** : `/signup`, `/signup/verify/{jeton}`, `/invitation/{jeton}`,
  `/admin/signup` ; liens « Créer un compte » ou « J'ai un code » sur la connexion et la
  présentation ; lien d'invitation affiché sur la page des membres sans envoi possible.

## Critères d'acceptation

- [x] `private` par défaut : `/signup` répond 404 ; une invitation d'organisation permet de créer
      son compte.
- [x] `public` sans SMTP ou sans `web.public_url` : refus de démarrer, message explicite.
- [x] `public` : adresse vérifiée avant toute création ; domaine hors liste refusé ; adresse déjà
      inscrite : même réponse, courriel « vous avez déjà un compte ».
- [x] `invitation` : un code ne sert qu'une fois, ni expiré ni révoqué ; deux inscriptions
      simultanées avec le même code n'en créent qu'une.
- [x] Inscription atomique : un échec à n'importe quelle étape ne laisse ni compte, ni
      organisation, ni code consommé.
- [x] Le compte inscrit choisit son mot de passe, enrôle son TOTP, reçoit ses codes de secours et
      arrive sur son organisation, dont il est administrateur.
- [x] Invitation d'organisation : courriel dans la langue de l'invitant, ou lien affiché une fois ;
      adresse imposée ; compte existant : connexion puis acceptation.
- [x] Jetons et liens jamais journalisés ni stockés en clair ; liens à usage unique ; purge des
      vérifications expirées ; invitation expirée refusée.
- [x] Limitation par IP des POST de l'inscription ; audit de chaque étape.
- [x] Écrans accessibles (webtest), traduits, sans code en ligne.
- [x] Modèle de menace, architecture, `docs/operations.md`, guides et `CHANGELOG.md` à jour ;
      `make ci` vert.

## Tests attendus

Unitaires : configuration (modes, domaines, refus au démarrage), domaines, gabarits de courriel.
Intégration : chaque mode de bout en bout (formulaires, courriels capturés par un faux
expéditeur, TOTP, arrivée sur l'organisation), neutralité des réponses, code consommé une fois
sous concurrence, atomicité (échec simulé), invitation d'organisation (nouveau compte, compte
existant, adresse imposée, expiration), routes globales recensées, accessibilité des écrans.

## Points à trancher

Tranchés avec l'utilisateur le 4 novembre 2026 : voir la section « Décisions ».

## Décisions

- Modes, défaut `private`, réglage par fichier ou variable.
- Public : vérification obligatoire, SMTP exigé, domaines facultatifs (liste vide : aucune
  restriction), une organisation par inscription, compte administrateur.
- Invitation : codes d'instance, libellé, validité en jours (30 par défaut), usage unique, aucun
  lien code → adresse, une organisation par inscription demandée à l'inscription.
- Invitation d'organisation dans tous les modes, adresse imposée, courriel dans la langue de
  l'invitant.
- Sans SMTP : codes et liens transmis à la main ; adresse d'inscription non vérifiée ; adresse
  déjà prise : même message qu'un code refusé, code non consommé.
- Domaines restreints en mode public seulement ; un compte ne crée pas d'autre organisation.
- `web.public_url` remplace `notify.public_url` sans repli.
- Une seule PR.

## Journal

### 4 novembre 2026

- **Configuration** : `signup.mode` et `signup.allowed_domains` (`LOTOR_SIGNUP_*`),
  `web.public_url` à la place de `notify.public_url`, sans repli ; `Config.MailConfigured`
  (SMTP et URL publique) ; refus de démarrer en mode public sans envoi.
- **Courriels** : gabarit HTML fourni par l'utilisateur intégré dans `internal/delivery`
  (`mailhtml.go`, `templates/`), logo généré depuis `docs/logo/lotor-icon.svg` (une queue,
  PNG transparent 51 × 120, affiché 17 × 40) faute de PNG joint ; structure
  `multipart/alternative { text/plain, multipart/related { text/html, image/png } }`,
  couleurs de la contrainte 5 et contraintes vérifiées par test (luminance, contraste,
  aucun texte en dur, aucune ressource externe). Les notifications l'utilisent
  (`notify.HTML`). Rendu vérifié dans un vrai Thunderbird 153.6.0esr (Xvfb), clair et sombre :
  la carte perd son fond en sombre, textes éclaircis, étiquettes, KEV, bouton et logo
  intacts. Gmail, Outlook et Apple Mail restent non testés.
- **Paquets** : `internal/mailer` (file `mail.send` chiffrée, `Send` sans stockage),
  `internal/signup` (modes, codes, vérifications, `Complete`, `Direct`, `JoinByLink`,
  `AcceptByLink`, purge), `account.Register`, `org.CreateIn`, `org.InviteWithLink`,
  migration 024, `crossorg.InvitationByToken`, jetons `sgn`, `vrf`, `inv`.
- **Écrans** : `/signup`, `/signup/verify/{jeton}`, `/invitation/{jeton}`,
  `/admin/signup` (mode, codes, révocation confirmée, envoi du code sans conserver
  l'adresse), lien d'invitation montré une fois sur la page des membres, liens sur la
  connexion et la présentation. Session de configuration (`authx.PurposeSetup`) ouverte
  après chaque création : enrôlement du TOTP puis codes de secours.
- **Tests** : intégration du paquet `signup` (modes, concurrence sur un code, atomicité par
  révocation en cours de route, purge) et de l'interface (chaque mode de bout en bout avec
  enrôlement réel du TOTP, neutralité, adresse du destinataire absente de la base et des
  journaux, langue de l'invitant, lien d'un autre compte, accessibilité et absence de code
  en ligne de chaque nouvel écran). Un test de rupture (consommation du code retirée) a
  confirmé qu'ils échouent.
- **Écart corrigé en route** : la page des membres renvoie désormais le lien (200) au lieu
  d'une redirection quand l'envoi n'est pas configuré ; `TestRolesInOrganization` vérifie la
  neutralité sur les deux pages (compte existant ou non).
- **Paquet deb** : `public_url_update` réécrit la clé dans la section `web:` (ajoutée si
  absente), au lieu d'un `sed` qui aurait réécrit l'ancienne clé sous `notify:`.
- **À faire par l'utilisateur** : essai avec un vrai serveur SMTP et des messageries autres
  que Thunderbird.
