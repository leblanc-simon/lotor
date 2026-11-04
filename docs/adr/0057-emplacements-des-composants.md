# 0057 — Emplacements des composants : chemins notés par Syft, rangés sur l'élément d'inventaire

- Statut : Accepté
- Date : 2026-11-04
- Lot : hors lot

## Contexte

Les listes de constats, la fiche d'un constat et la fiche d'un composant ne disaient pas
d'où venait un composant : quel fichier (base de paquets, manifeste, archive, binaire) l'a
fait trouver. L'information existe dans les SBOM reçus : Syft note, pour chaque paquet,
ses emplacements (`locations`), avec le chemin réel (`path`), le chemin d'accès
(`accessPath`, quand on l'a atteint par un lien symbolique), la couche de l'image
(`layerID`) et le rôle de la preuve (annotation `evidence` : `primary` ou `supporting`).
L'adaptateur Syft les laissait de côté, et le modèle n'avait pas de quoi les garder.

Ce qui arrive selon le format :

- **Syft JSON** (agent serveur, images) : tout (chemin, chemin d'accès, couche, annotation).
- **CycloneDX** (agent dépôt, tiers) : propriétés `syft:location:N:path` et
  `syft:location:N:layerID` ; ni chemin d'accès ni annotation.
- **SPDX** : rien d'exploitable (`sourceInfo` est un texte libre).

## Décision

- **Modèle** : `sbom.Location` (`Path`, `AccessPath` s'il diffère, `Layer`, `Supporting`)
  et `sbom.Component.Locations`. Un emplacement sans annotation est principal : CycloneDX
  n'en porte pas, et ses chemins sont ceux qui comptent. Normalisation : texte nettoyé,
  chemin de 4 Kio au plus, couche de 128 octets au plus, principaux d'abord puis ordre
  total (chemin, chemin d'accès, couche), doublons fusionnés (un emplacement à la fois
  principal et secondaire reste principal), **32 au plus**. Deux mentions du même purl
  réunissent leurs emplacements : un même paquet présent à deux endroits est justement ce
  qu'on veut voir.
- **Stockage** : colonne `locations jsonb` de `component_set_items` (migration 025). Les
  emplacements dépendent de ce qui a été analysé, pas du composant : ils vont sur l'élément
  d'ensemble, comme l'origine ou la preuve, et non sur `components`.
- **Empreinte d'inventaire** : elle compte les emplacements, et sa version passe à
  `lotor-inventory-v2`. Sinon deux instantanés aux chemins différents partageraient un
  ensemble et afficheraient de faux emplacements. Conséquence acceptée : au premier scan
  après la mise à jour, chaque référence crée un nouvel ensemble (un hôte a un instantané
  de plus à inventaire identique : différence vide, constats inchangés). Un paquet déplacé
  donne désormais un nouvel ensemble.
  L'agent serveur calcule la même empreinte pour son compte rendu d'inventaire
  (`inventory.Confirm`) : **un agent serveur antérieur** envoie une empreinte v1 que le
  serveur ne connaît pas, et renvoie donc son SBOM à chaque cycle au lieu d'un simple
  compte rendu (rangé comme inventaire inchangé). Rien ne se perd, mais l'agent est à
  mettre à jour avec le serveur ; le CHANGELOG le dit. Garder aussi l'empreinte v1 de
  chaque ensemble a été écarté : une colonne et un calcul de plus pour un état transitoire.
- **Pas de reprise de l'historique** : les ensembles sont immuables et partagés ; les
  emplacements apparaissent au scan suivant. Redécoder les SBOM stockés coûterait beaucoup
  pour un historique que la rétention éclaircit de toute façon.
- **Constat** : ses emplacements sont ceux du composant dans le dernier instantané qui l'a
  constaté (`findings.snapshot_id`) ; un constat résolu garde ceux où il était.
- **Affichage** : dans les tableaux (constats d'un projet, comparaison, fiche
  vulnérabilité, recherche, composants d'un instantané, usages d'un composant), les
  emplacements principaux, trois au plus, et le nombre des autres ; sur la fiche d'un
  constat, la liste entière, avec chemin d'accès, couche et mention « secondaire ».
  Composant d'origine IA : l'occurrence de sa preuve reste son emplacement sur la fiche
  composant.
- **API et export** : `locations` (schéma `ComponentLocation`) dans une occurrence de la
  recherche ; dans l'export, liste entière en JSON, chemins principaux séparés par « ; »
  dans une dernière colonne CSV `locations` (les colonnes existantes ne bougent pas).
- **Agent dépôt inchangé** : son CycloneDX ne transporte pas le chemin d'accès, presque
  toujours égal au chemin réel dans un dépôt cloné.

## Conséquences

- Pour un paquet de distribution, l'emplacement principal est la base de paquets
  (`/var/lib/dpkg/status`, `/lib/apk/db/installed`, base RPM) : c'est exact, et les
  fichiers propres au paquet (copyright, listes) apparaissent en secondaires.
- Un SBOM SPDX ne donne pas d'emplacement : « Non renseigné ».
- Remplace, pour la version de l'empreinte, le point correspondant de l'ADR 0016.
