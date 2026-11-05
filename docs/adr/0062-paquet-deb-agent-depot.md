# 0062 — Paquet deb de l'agent dépôt : compte dynamique, unité inactive, credentials par fichier d'extension

- Statut : Accepté
- Date : 2026-11-05
- Lot : hors lot

## Contexte

L'agent serveur a ses paquets deb et rpm (T07), le serveur son paquet deb (T27, ADR 0053).
L'agent dépôt ne se livrait qu'en archive : binaire, unité et configuration copiés à la main,
mises à jour par remplacement du binaire. Son unité tourne déjà sous un compte dynamique
(`DynamicUser=yes`) et lit ses secrets en credentials systemd chiffrés.

## Décision

- **Paquet nfpm** `lotor-repo-agent` (amd64, arm64), deb seulement comme celui du serveur,
  construit par `make packages` et publié par `make release`. Il dépend de
  `git (>= 1:2.30)`, version minimale de l'agent, et recommande systemd.
- **Aucun utilisateur créé.** L'unité fournie garde `DynamicUser=yes` et son durcissement :
  le paquet installe la même unité que l'archive, dans `/usr/lib/systemd/system`.
- **Configuration lisible de tous.** `/etc/lotor-repo-agent` en `0755` et `config.yaml` en
  `0644` (conffile) : le compte dynamique doit pouvoir lire la configuration, qui ne contient
  aucun secret. Les `*.cred` ne se déchiffrent qu'avec la clé de l'hôte. La documentation de
  l'installation manuelle, qui demandait `0700`, est corrigée : l'agent démarrait alors sans
  sa configuration.
- **Unité ni activée ni démarrée à l'installation** : serveur, forges et secrets sont à
  renseigner d'abord, comme pour l'agent serveur. Une mise à jour redémarre un agent actif
  (`try-restart`) : il ne tient aucune donnée que le redémarrage perdrait, et le rattrapage
  reprend les commits manqués.
- **Credentials des forges non utilisées retirés par un fichier d'extension**
  (`systemctl edit`) : une affectation vide de `LoadCredentialEncrypted=` remet la liste à
  zéro, puis l'administrateur déclare celle qu'il utilise. Modifier l'unité du paquet serait
  perdu à la mise à jour ; rendre les credentials facultatifs (`ImportCredential=`) demande
  systemd 254 et changerait leurs noms.
- **Désinstallation** : l'unité est arrêtée et désactivée ; la purge retire `config.yaml`,
  pas les `*.cred` ni l'état (`/var/lib/private/lotor-repo-agent`), à effacer à la main.

## Conséquences

- L'agent dépôt s'installe et se met à jour par apt, comme les deux autres rôles.
- `make test-package` vérifie aussi ce paquet (scénario `repo_agent`) : dépendance à git,
  unité valide et inactive, configuration lue par le compte dynamique, conffile gardé à la
  mise à jour, désactivation et purge.
- Pas de rpm pour l'instant : à ajouter dans `deploy/nfpm/repo-agent.yaml` si le besoin
  apparaît (aucune différence de contenu).
