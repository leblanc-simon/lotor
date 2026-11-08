# 0063 — Copie corrigée de `github.com/blakesmith/ar` par une directive `replace`

- Statut : Accepté
- Date : 2026-11-08
- Lot : hors lot

## Contexte

L'avis [GO-2026-6905](https://pkg.go.dev/vuln/GO-2026-6905), publié le 5 novembre 2026, vise
`github.com/blakesmith/ar` : `Reader.Next` accepte une taille de membre négative, et le
`Reader.Read` suivant panique en découpant le tampon de l'appelant. Aucune version ne le
corrige, et le module n'a plus de commit depuis 2019. Il est tiré par Syft (catalogueur des
archives `.deb`), Grype et nfpm ; Syft 1.57 en dépend toujours. `govulncheck` le signale comme
appelé : `make vuln`, et donc la CI de toutes les PR, échoue.

Exposition mesurée avant décision :

- la panique est reproduite directement sur le module ;
- l'agent dépôt, qui analyse le contenu des dépôts, sélectionne ce catalogueur. Avec un `.deb`
  piégé, son analyse aboutit et inventorie les autres composants : le catalogueur générique de
  Syft rattrape les paniques des analyseurs (`recover`), sans que ce rattrapage ait été observé
  directement ;
- l'agent serveur sélectionne l'étiquette `image`, qui n'inclut pas ce catalogueur.

Deux voies ont été comparées : une exception à l'identifiant de l'avis dans `make vuln`, ou
une copie corrigée. L'utilisateur a retenu la copie le 8 novembre 2026.

## Décision

- **Copie dans `third_party/blakesmith-ar/`**, au commit `809d4375e1fb` du graphe, sous sa
  licence MIT, branchée par `replace github.com/blakesmith/ar => ./third_party/blakesmith-ar`
  dans `go.mod`. La directive vaut pour les trois binaires et pour l'outil nfpm.
- **Écarts limités et listés** dans le `README.md` de la copie : `go.mod`, `gofmt`, tests
  rendus conformes à `go vet`, et le correctif. `Next` refuse une taille négative
  (`ErrInvalidSize`), et `Read` ne découpe plus un tampon avec un reste négatif. Un test de
  non-régression reproduit l'avis.
- **Barrières de qualité** : le module, hors de `./...`, est ajouté à `make vet`, `make test` et
  `make test-race` (`go -C`). staticcheck ne l'analyse pas, pour garder le code au plus près de
  l'amont. `make vuln` reste entier, sans exception.
- **Dépendance existante, pas nouvelle** : le module figure déjà dans le graphe ; seul son code
  source change de provenance.
- **Retrait** dès qu'une version corrigée existe en amont, ou que Syft, Grype et nfpm ne
  dépendent plus du module.

## Conséquences

- La CI repasse sans affaiblir `govulncheck` : un nouvel avis sur une autre dépendance la fait
  toujours échouer.
- La règle de [`specs/lecons.md`](../../specs/lecons.md) « jamais de `replace` commité » reste
  vraie pour les `replace` temporaires vers open-go-base. Les copies de `third_party/` en sont
  la seule exception, chacune par un ADR.
- Une montée de version de Syft, Grype ou nfpm doit vérifier que le module amont attendu est
  toujours le même : `go mod graph | grep blakesmith/ar`.
- Les binaires enregistrent la dépendance avec son remplacement
  (`=> ./third_party/blakesmith-ar (devel)`). La façon dont un scanner tiers interprète cette
  ligne n'a pas été vérifiée.
- Ajoute à l'arborescence de l'architecture (§ 3) le répertoire `third_party/`.
