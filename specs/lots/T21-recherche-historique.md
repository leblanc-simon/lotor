# T21 — Recherche à une date passée

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T18 | Terminé |

## Objectif

Répondre à « quels projets utilisaient ce composant à telle date ? », par exemple pour
mesurer l'exposition passée lors d'une réponse à incident.

## Périmètre

**Inclus**

- Pour chaque référence, l'instantané en vigueur à la date demandée (le dernier reçu avant
  elle) ; recherche identique à T09 sur ces instantanés.
- Champ « à la date du » sur l'écran de recherche, paramètre dans l'API.
- Avertissement quand la date précède la rétention (T17) : les résultats sont alors partiels.

**Exclu** : constats de vulnérabilité à une date passée (la base Grype de l'époque n'est pas
conservée).

## Conception

- Index sur (référence, date de réception) ; la requête « dernier instantané avant la date »
  ne parcourt pas l'historique complet.
- Les résultats indiquent la date de l'instantané retenu pour chaque projet.
- S'appuie sur la rétention de T17 ([ADR 0039](../../docs/adr/0039-retention-des-instantanes.md)) :
  pour toute date postérieure ou égale à l'**horizon** de l'organisation
  (`inventory.ReadRetention`, table `snapshot_retention` : la plus récente coupure
  appliquée), l'instantané en vigueur de chaque référence existe encore et la recherche
  est exacte ; pour une date antérieure, il ne reste que le dernier instantané de chaque
  mois (l'état retenu est celui de la fin du mois précédent ou plus ancien) : c'est le
  cas de l'avertissement. Sans ligne, la rétention n'est jamais passée et l'historique
  est complet. Les instantanés sont ordonnés par date de scan puis identifiant
  (`snapshots_ref_idx`), comme `ref_current`.

## Critères d'acceptation

- [x] Un composant retiré le 10 n'apparaît plus pour une date du 11, mais apparaît pour le 9
      (`TestSearchAtPastDate`).
- [x] Une date antérieure à la rétention affiche l'avertissement (`TestSearchAtPastDate`,
      écran : callout « Résultat partiel », API : `partial`).
- [x] Moins de 5 s au 95e centile sur le jeu de données de T06 enrichi de 12 mois
      d'historique, selon `docs/benchmarks.md` (pire cas 1,55 s, `make bench-search`).

## Tests attendus

Intégration avec horloge simulée et instantanés datés ; isolement.

## Points à trancher

Aucun.

## Journal

### 4 novembre 2026

Réalisé à la suite de T19, sans plan validé au préalable : décisions **[à relire]**
([ADR 0058](../../docs/adr/0058-recherche-a-une-date-passee.md)).

- **Date [à relire]** : `at=AAAA-MM-JJ` vaut la fin de cette journée en UTC (les
  instantanés scannés ce jour-là comptent, borne exclusive), une date RFC 3339 l'instant
  donné ; date au-delà de la journée en cours refusée (`error.search.at_invalid`). Date de
  scan, pas de réception, comme `ref_current`.
- **Portée [à relire]** : projets archivés et références retirées depuis compris (l'état
  d'alors) ; composants seulement : recherche par vulnérabilité, sévérité, KEV et
  résolution refusées (`error.search.at_components_only`) plutôt qu'un mélange de l'état
  passé et des constats actuels ; ni versions corrigées ni risque ; date de l'instantané
  retenu sur chaque occurrence (colonne « Instantané retenu » de l'écran).
- **Requête** : jointure latérale `LIMIT 1` par référence sur `snapshots_ref_idx`, aucun
  index nouveau ni migration (`componentHitsAt`). Avertissement par
  `inventory.ReadRetention` : `Result.Partial` et l'horizon, `partial` et
  `retention_horizon` dans l'API.
- **Mesure** : `benchdata.AddHistory` (52 instantanés hebdomadaires par référence,
  ensembles réels réutilisés), `TestSearchAtBenchmark` dans `make bench-search` : pire p95
  1,55 s pour 5 s (`docs/benchmarks.md`).
- **Tests** : `TestSearchAtPastDate` (retrait le 10, date du 9, du 10, du 11, instant RFC
  3339 exclusif, projet archivé, autre organisation, export, horizon), `TestSearchAtRefusals`,
  écran et API dans `TestSearchScreenAndAPI` (accessibilité, deux langues, refus). Rupture
  vérifiée : `<` changé en `<=` fait échouer `TestSearchAtPastDate`.
