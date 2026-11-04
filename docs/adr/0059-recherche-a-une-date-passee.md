# 0059 — Recherche à une date passée : instantané en vigueur, composants seulement

- Statut : Accepté
- Date : 2026-11-04
- Lot : T21

## Contexte

La réponse à incident demande « quels projets utilisaient ce composant à telle date ? ». La
recherche (ADR 0024) lit l'inventaire courant (`ref_current`). L'historique des
instantanés est conservé par la rétention de T17 (ADR 0039) : 90 jours complets, puis le
dernier instantané de chaque mois, l'horizon de la dernière coupure étant rangé dans
`snapshot_retention`. La base de vulnérabilités d'une date passée n'est pas conservée.

## Décision

- Paramètre `at` de la recherche, à l'écran (« À la date du ») et dans l'API, porté par
  `search.Filters.At` : `AAAA-MM-JJ` désigne la **fin de cette journée en UTC** (les
  instantanés scannés ce jour-là comptent) ; une date et heure RFC 3339 l'instant donné. La
  borne est exclusive : un instantané scanné exactement à l'instant n'est pas retenu. Une
  date au-delà de la journée en cours est refusée (`error.search.at_invalid`).
- Pour chaque référence des projets visibles, l'instantané **en vigueur** est le dernier
  scanné avant l'instant (ordre date de scan puis identifiant, celui de `ref_current`), lu
  par une jointure latérale `LIMIT 1` sur `snapshots_ref_idx` : aucune lecture de
  l'historique complet. La date de scan sert, pas la date de réception, comme pour l'état
  courant.
- **Projets archivés et références retirées depuis comptent** : la question porte sur
  l'état d'alors. Équipes (`lotor_team_visible`), filtres de type, d'équipe, d'étiquette et
  d'origine s'appliquent comme d'habitude.
- **Composants seulement** : ni constats, ni sévérité, ni KEV, ni versions corrigées. Une
  recherche par vulnérabilité, et les filtres de sévérité, KEV et résolution, sont refusés
  (`error.search.at_components_only`) plutôt que de mêler un état passé et des constats
  actuels. Chaque occurrence porte la date de l'instantané retenu.
- **Avertissement** : si l'instant précède l'horizon de la rétention, le résultat porte
  `Partial` et l'horizon ; sans passage de la rétention, l'historique est complet.
- Export et API utilisent les mêmes paramètres (`partial`, `retention_horizon` dans la
  réponse de l'API).

## Conséquences

- Pas de nouvelle table ni d'index : `snapshots_ref_idx` suffit (vérifié par le plan du
  jeu de mesure, `make bench-search`).
- L'exposition aux vulnérabilités d'une date passée reste hors périmètre : elle demanderait
  de garder les bases de vulnérabilités ou les constats datés.
