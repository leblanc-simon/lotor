# T27 — Paquet deb du serveur

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé |

## Objectif

Installer le serveur sur une machine Debian ou Ubuntu en une commande : base, secrets, premier
administrateur et site nginx ou Apache, selon le parcours de `docs/operations.md`.

## Périmètre

**Inclus**

- Paquet deb `lotor-server` (amd64, arm64) par nfpm, dans `make packages` et `make release`.
- Questions debconf en anglais et en français, prérenseignables.
- Création des rôles PostgreSQL et de la base en local ; chaînes de connexion en distant.
- Mot de passe temporaire du premier administrateur, généré et affiché.
- Site nginx ou Apache testé et annulé en cas d'échec ; certificat existant ou autosigné.
- Mise à jour, suppression, purge et `dpkg-reconfigure`.
- Recette `make test-package` dans des conteneurs systemd.

**Exclu** : rpm, certbot automatique, mTLS derrière le mandataire, signature du paquet (T24, T26).

## Conception

Voir l'[ADR 0053](../../docs/adr/0053-paquet-deb-du-serveur.md).

## Critères d'acceptation

- [x] Installation avec nginx et avec Apache : HTTPS, cookies `__Host-`, en-têtes du client
      écrasés, première connexion complète (TOTP, codes de secours, nouveau mot de passe).
- [x] Sans serveur web, sans e-mail, sans terminal : installation réussie et message clair.
- [x] Base distante : chaînes reprises puis effacées de debconf, aucun rôle créé.
- [x] PostgreSQL configuré après le paquet, ou trop ancien : aucune erreur de dpkg, reprise par
      `dpkg-reconfigure`, rien de créé sur un cluster refusé.
- [x] Test de configuration en échec : site lotor retiré, autres sites intacts.
- [x] Mise à jour sans redémarrage ; réinstallation sans nouveau secret ni nouveau mot de passe ;
      purge sans perte de la base ni de la clé.
- [x] Mot de passe temporaire absent de debconf et du journal systemd ; présence dans
      `/var/log/apt/term.log` constatée et documentée.

## Tests attendus

`make test-package` : chaque scénario installe le vrai paquet dans un conteneur systemd neuf,
sur Debian 13 et Ubuntu 24.04, et sur Debian 12 pour la version de PostgreSQL refusée.

## Points à trancher

Tranchés par l'utilisateur avant le lot (4 novembre 2026) : création automatique en local
seulement, certificat existant ou autosigné avec certbot manuel, aucun redémarrage automatique
à la mise à jour, `Recommends: postgresql` et `Suggests: nginx | apache2`, clé conservée à la
purge, certificat autosigné par `openssl` plutôt que `ssl-cert`.

## Journal

Décisions : [ADR 0053](../../docs/adr/0053-paquet-deb-du-serveur.md). Aucune nouvelle dépendance
Go ; aucune évolution du serveur ni d'open-go-base.

Recette (`make test-package`, 4 novembre 2026) : tous les scénarios passent sur Debian 13
(PostgreSQL 17) et Ubuntu 24.04 (PostgreSQL 16), et le refus de PostgreSQL 15 sur Debian 12.

Constats de la recette :

- **Ordre d'installation** : apt configure `lotor-server` avant le PostgreSQL installé dans le même
  appel, sur les deux distributions. L'installation réussit sans démarrer, `dpkg-reconfigure` la
  termine. La documentation fait installer PostgreSQL d'abord ; le rendre obligatoire irait contre
  le choix de l'utilisateur sur les bases distantes.
- **`/var/log/apt/term.log`** : le mot de passe affiché s'y retrouve (`root:adm`, `0640`), avec
  `dialog` comme avec `teletype`. Il est absent de debconf, du journal systemd et de `/etc/lotor`.
  Accepté et documenté : il sert une fois, et la première connexion impose le TOTP et un nouveau mot
  de passe.
- **Sans terminal** : `db_input` renvoie 30, le mot de passe va dans le fichier `0600`.

Limites : paquet arm64 construit mais non essayé (la recette tourne en amd64). Les écrans `dialog`
ne sont validés qu'à la note du mot de passe ; les réponses saisies, l'e-mail refusé compris, sont
éprouvées avec `teletype`. certbot n'est pas essayé (étape manuelle, documentée).
