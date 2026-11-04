// Package search analyse les requêtes de la recherche transverse, les exécute sous la RLS
// et exporte les résultats (§ 13 de l'architecture, ADR 0024).
//
// Une requête (Parse) est un nom de composant, un purl éventuellement suivi d'une plage
// vers, un identifiant CVE ou GHSA, ou une empreinte SHA-256 ; « license: » est refusé
// jusqu'à T20. Une Request ajoute filtres, ordre et page, et se lit et s'écrit en
// paramètres d'URL (ParseRequest, Values) : l'écran et l'API partagent la même forme, si
// bien qu'une URL partagée redonne le même résultat.
//
// Exécution, dans une transaction InOrg en lecture seule :
//  1. la requête désigne des composants (nom et empreinte par crossorg, qui seul peut
//     servir des index trigramme et GIN sous la RLS ; purl par purl_base, puis version,
//     qualificatifs et plage filtrés en Go avec version.Comparer) ou des vulnérabilités
//     (identifiant et alias du catalogue) ;
//  2. les occurrences sont lues sur ref_current, component_set_items et findings, pour les
//     références actives des projets actifs et visibles (équipes déclarées par
//     db.Visible, filtre lotor_team_visible, ADR 0034), filtres appliqués en SQL ; les
//     conteneurs des serveurs en sont écartés sauf Filters.Containers (ADR 0040) ;
//  3. une page de projets (curseur par ordre : risque, nom, instantané), puis leurs
//     occurrences (MaxGroupHits par projet).
//
// À une date passée (Filters.At, paramètre at, T21, ADR 0059), l'étape 2 lit pour chaque
// référence l'instantané en vigueur à cet instant (le dernier scanné avant lui) au lieu de
// ref_current, projets archivés et références retirées compris, sans vulnérabilités ;
// Result.Partial signale une date antérieure à l'horizon de la rétention.
//
// Les occurrences du paquet hors de la plage, et les versions illisibles dans
// l'écosystème, sont comptées et signalées, jamais ignorées en silence. Export (CSV, JSON)
// : lecture et écriture en flux, ligne à ligne.
//
//	res, err := svc.Search(ctx, org, acc.Visibility(), req)
//	err = svc.Export(ctx, org, acc.Visibility(), req, search.FormatCSV, w)
package search
