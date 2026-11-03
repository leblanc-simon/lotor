# 0053 — Paquet deb du serveur : debconf, base locale créée, site du mandataire, aucun redémarrage automatique

- Statut : Accepté
- Date : 2026-11-04
- Lot : T27

## Contexte

L'installation de production (`docs/operations.md`) compte sept étapes manuelles : binaire,
rôles PostgreSQL, configuration, secrets, TLS, démarrage, premier administrateur. Un paquet
deb peut les enchaîner sur un serveur Debian ou Ubuntu. Le serveur sait déjà créer le premier
compte (`LOTOR_BOOTSTRAP_ADMIN_*`, T03), avec changement de mot de passe et
enrôlement du TOTP imposés : le paquet n'a besoin d'aucune évolution du serveur.

## Décision

- **Paquet nfpm** `lotor-server` (amd64, arm64), à côté de celui de l'agent serveur, avec des
  questions debconf (`deploy/server/templates`, `deploy/server/config`) en anglais et en
  français. Tout se prérenseigne, pour une installation sans terminal. Les messages du script
  de post-installation sont aussi des gabarits debconf, donc traduits. Pas de rpm.
- **Base locale créée, base distante fournie.** En mode local, le script crée
  `lotor_owner`, `lotor_app` et la base par `runuser -u postgres`, sur le cluster en marche de
  plus haute version, 16 ou plus. Si l'un de ces objets existe déjà, il n'y touche pas et
  demande le mode distant : aucun mot de passe de rôle n'est changé. En mode distant,
  l'administrateur fournit les deux DSN ; aucun mot de passe de superutilisateur n'est demandé.
  Le serveur local se connecte par `127.0.0.1` avec `sslmode=disable`, le trafic restant sur la
  boucle locale.
- **PostgreSQL seulement recommandé.** Une dépendance imposerait un serveur inutile avec une
  base distante. Conséquence constatée : apt peut configurer `lotor-server` avant PostgreSQL
  installé dans le même appel. L'installation réussit alors sans démarrer le service, et
  `dpkg-reconfigure lotor-server` la termine. La documentation fait donc installer PostgreSQL
  d'abord.
- **Premier compte.** Le mot de passe temporaire (96 bits) n'est écrit dans le fichier des
  secrets que pour le premier démarrage. Le script attend au plus 60 s la trace du serveur
  (« premier administrateur créé » ou « bootstrap ignoré »), retire les variables, puis affiche
  le mot de passe. Il n'attend pas `/readyz`, qui répond 503 tant que la base de vulnérabilités
  n'est pas téléchargée.
- **Affichage.** Une note debconf de priorité critique, dont la variable est vidée aussitôt.
  Sans terminal, `db_input` renvoie 30 : le mot de passe va dans
  `/etc/lotor/initial-admin-password` (`0600`), à supprimer après la première connexion.
- **Site du mandataire.** Un fichier dédié, jamais les sites existants ; test de configuration
  (`nginx -t`, `apache2ctl configtest`) avant rechargement, et retrait du site en cas d'échec.
  Certificat existant, ou autosigné généré avec `openssl` au nom public du site (celui de
  `ssl-cert` porterait le nom de la machine). `X-Forwarded-For` et `X-Real-IP` sont écrasés,
  `Host` transmis tel quel, corps de 2 Gio et délai de 30 min pour l'import de la base de
  vulnérabilités. certbot reste une étape manuelle.
- **Aucun démarrage sur une mise à jour ou une réinstallation.** Le service n'est démarré que
  par le passage qui vient de le configurer. Sinon, un démarrage appliquerait des migrations
  irréversibles avant la sauvegarde exigée par la procédure : le script affiche un message.
- **La purge garde la base et le fichier des secrets.** Écart volontaire aux usages Debian :
  sans la clé de chiffrement, les secrets TOTP d'une base restaurée seraient perdus. La purge
  retire la configuration, le certificat autosigné et les réponses debconf.

## Conséquences

- Une installation sur une machine se fait en une commande, plus la sauvegarde de la clé.
- Le script dépend du texte de deux messages du serveur : la recette `make test-package` le
  vérifie. Passé le délai, les variables restent dans le fichier `0600` et un message l'indique.
- Le mot de passe temporaire reste présent dans `/var/log/apt/term.log` s'il est affiché au
  terminal (`root:adm`, `0640`). Il expire à la première connexion, qui impose un nouveau mot de
  passe et le TOTP.
- Le mTLS des agents reste indisponible derrière le mandataire (`docs/operations.md`).
- Debian 12 et Ubuntu 22.04 exigent PostgreSQL du dépôt PGDG : leur version livrée est refusée
  avec un message, sans rien créer.
- La recette s'appuie sur Docker et des conteneurs systemd privilégiés, hors de `make ci`.
