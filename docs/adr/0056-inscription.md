# 0056 — Inscription : trois modes, codes, liens d'invitation et courriels transactionnels

- Statut : Accepté
- Date : 2026-11-04
- Lot : T28

## Contexte

Jusqu'ici, seul un administrateur d'instance crée un compte local (mot de passe temporaire à
changer, TOTP à la première connexion), et une invitation d'organisation ne sert qu'à un
compte qui existe déjà. L'utilisateur veut que l'exploitant choisisse entre une instance
privée (le comportement actuel, par défaut), une inscription sur code d'invitation et une
inscription publique, et qu'une invitation d'organisation permette, dans tous les modes, de
créer son compte. L'instance n'envoyait jusqu'ici que des notifications de politiques.

## Décision

### Modes et configuration

- `signup.mode` (`LOTOR_SIGNUP_MODE`) : `private` (défaut), `invitation`, `public` ;
  `signup.allowed_domains` (`LOTOR_SIGNUP_ALLOWED_DOMAINS`, séparés par `,`) restreint le mode
  public seulement (liste vide : aucune restriction).
- « Envoi possible » (`Config.MailConfigured`) : `smtp.host`, `smtp.from` **et**
  `web.public_url` renseignés. Le mode public l'exige : sans lui, le serveur refuse de
  démarrer. Le mode invitation s'en passe : codes et liens sont alors montrés une fois, à
  transmettre à la main, et l'adresse de l'inscription n'est pas vérifiée.
- `web.public_url` (`LOTOR_PUBLIC_URL`) remplace `notify.public_url` : la même URL sert aux
  notifications, aux verdicts et aux courriels de l'inscription. Pas de repli sur l'ancienne
  clé (une seule instance installée) ; la note de mise à jour du `CHANGELOG.md` le dit.

### Parcours

- **Public** : adresse (domaine vérifié) → lien de vérification (24 h) → nom de
  l'organisation et mot de passe choisi → session de configuration → enrôlement du TOTP →
  codes de secours → l'organisation, dont le compte est administrateur.
- **Invitation, avec envoi** : code + adresse → lien de vérification → idem. **Sans envoi** :
  code, adresse, organisation et mot de passe en une étape.
- **Invitation d'organisation** (tous modes) : chaque invitation porte un lien secret neuf
  (`/invitation/{jeton}`, 30 jours, remplacé à chaque nouvelle invitation de la même adresse).
  Avec envoi, il part dans la langue de l'invitant (préférence du compte, sinon langue de
  l'organisation) ; sans, il est montré une fois sur la page des membres. Le lien crée le
  compte **à l'adresse invitée** (imposée) avec le rôle de l'invitation, ou fait accepter
  l'invitation au compte connecté de cette adresse ; un autre compte connecté est arrêté.
- Aucun mot de passe temporaire : `account.Register` écrit `must_change_pwd = 0`, et
  `identity.openSetupSession` ouvre une session `authx.PurposeSetup` (celle que mfax ouvre au
  premier login) qui ne mène qu'à l'enrôlement, toujours obligatoire.

### Codes d'inscription

Créés par un administrateur d'instance (`/admin/signup`) : libellé (100 caractères), validité
de 1 à 365 jours (30 par défaut), usage unique, révocables, liés à aucune adresse. Format
commun des jetons (ADR 0025) : `lotor_sgn_…`, empreinte SHA-256 seule en base. Avec envoi, le
code peut partir sur-le-champ (`mailer.Send`) à une adresse saisie, qui n'est conservée nulle
part (ni table, ni journal d'audit, ni file) et n'est pas imposée à l'inscription.

### Données

- Tables globales `signup_codes` et `signup_verifications` (lien `lotor_vrf_…`, au plus 3
  par adresse sur 24 h, purgées toutes les heures par `signup.purge`). `org_invitations`
  gagne `public_id` et `secret_hash` (`lotor_inv_…`).
- Le titulaire d'un lien d'invitation n'est membre d'aucune organisation :
  `crossorg.InvitationByToken` (fonction `lotor_invitation_by_token`, SECURITY DEFINER) ne
  renvoie qu'une invitation non expirée d'une organisation active, par identifiant public ;
  le secret est comparé en Go, puis revérifié sous verrou dans la transaction de
  l'organisation (`db.InOrg`).
- **Atomicité** : une inscription est une seule transaction `InOrg` déclarée pour
  l'identifiant de la nouvelle organisation, qui crée le compte, consomme le code et les liens
  de l'adresse, crée l'organisation (identifiant d'URL tiré du nom, numéroté puis suffixé au
  hasard si pris, `ON CONFLICT DO NOTHING` sans abandonner la transaction), l'adhésion
  administrateur et l'équipe « Général ». Un échec n'en laisse rien, code compris.

### Neutralité et abus

- Avec envoi, la réponse ne dépend pas de l'existence d'un compte : une adresse inscrite
  reçoit un courriel « vous avez déjà un compte » (lien vers `/login`) au lieu du lien.
- Sans envoi, une adresse déjà inscrite reçoit le même refus qu'un code faux, et le code n'est
  pas consommé (retour arrière) : seul le porteur d'un code valide l'apprend.
- Les POST de `/signup`, `/signup/verify/{jeton}` et `/invitation/{jeton}` passent par la
  limite de débit par IP de la connexion ; chaque étape est auditée (`signup.requested`,
  `account.signed_up`, `signup_code.created|revoked`). Les pages à jeton sont servies
  `Cache-Control: no-store` ; le jeton n'apparaît dans aucun journal.

### Courriels transactionnels

- Paquet `internal/mailer` (domaine) : job `mail.send` mis en file dans la transaction qui
  produit le lien ; destinataire, chemin et code chiffrés par `secrets.keys` dans la charge
  (données associées `mail.send/<modèle>`) ; texte composé à l'envoi par les clés
  `mail.<modèle>.*` ; un échec d'envoi est ramené à sa clé traduisible (la réponse d'un
  serveur SMTP cite souvent le destinataire). Sans envoi configuré, un `mail.send` resté en
  file échoue définitivement.
- **Gabarit HTML commun** (`internal/delivery/templates/notification.html.tmpl`, fourni par
  l'utilisateur, validé dans Thunderbird 153 clair et sombre) pour les notifications et les
  courriels de l'inscription : `multipart/alternative { text/plain, multipart/related {
  text/html, image/png } }`, logo (une queue en PNG transparent, 17 × 40) appelé par `cid:`,
  aucune image externe, SVG, `data:` ni police embarquée ; couleurs en styles en ligne (le
  mode sombre de Thunderbird réécrit les styles et ignore `@media … !important`), choisies
  pour qu'il garde les fonds (luminance ≤ 200, contraste ≥ 3,5, vérifiés par test) : elles
  diffèrent volontairement des `tokens.css` de l'interface, sauf « Critique ». CSS à plat,
  exception à la règle du CSS imbriqué (les messageries ne le comprennent pas). Aucun texte
  en dur hormis « lotor ».

## Conséquences

- Une instance existante reste privée ; seules ses invitations d'organisation gagnent un lien
  (affiché une fois sans SMTP), qui permet aussi à une personne sans compte de rejoindre
  l'organisation.
- `notify.public_url` est à déplacer sous `web.public_url` à la mise à jour ; une ancienne clé
  restée dans le fichier est ignorée.
- Le domaine dépend de `internal/delivery` pour l'HTML seulement par l'interface
  `mailer.Sender` ; `internal/mailer` et `internal/signup` sont classés dans `archtest`.
- Hors périmètre : validation des inscriptions par un administrateur, captcha, plusieurs
  organisations par compte inscrit, inscription par SSO (T25), changement d'adresse.
