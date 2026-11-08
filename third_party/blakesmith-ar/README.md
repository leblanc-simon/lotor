# Copie corrigée de `github.com/blakesmith/ar`

Lecture et écriture d'archives `ar`, tirée par Syft (catalogueur des paquets `.deb`), Grype et
nfpm. Le module amont n'a plus de commit depuis 2019 et n'a pas de version qui corrige
[GO-2026-6905](https://pkg.go.dev/vuln/GO-2026-6905) : une taille de membre négative fait
paniquer `Reader.Read`. lotor utilise cette copie par une directive `replace` de son `go.mod`
([ADR 0063](../../docs/adr/0063-copie-corrigee-de-blakesmith-ar.md)).

## Origine

- Dépôt : <https://github.com/blakesmith/ar>, commit `809d4375e1fb` (2 mai 2019), la version
  `v0.0.0-20190502131153-809d4375e1fb` du graphe de modules.
- Licence MIT, conservée dans [`COPYING`](COPYING) et dans l'en-tête des sources.

## Écarts avec l'amont

1. `go.mod` ajouté : `replace` exige un module.
2. Sources passées à `gofmt` (espaces seulement), exigé par `make fmt-check`.
3. Tests : `t.Errorf(err.Error())` devient `t.Error(err)`, que `go vet` exige depuis Go 1.24.
4. **Correctif** (`reader.go`) : `Next` refuse un membre de taille négative par
   `ErrInvalidSize`, et `Read` ne découpe plus le tampon quand le reste à lire est négatif.
   Test de non-régression : [`size_test.go`](size_test.go).

`README.md` et `.gitignore` de l'amont ne sont pas repris.

## Vérifications

`make vet`, `make test` et `make test-race` passent aussi sur ce module, qui est hors de
`./...`. staticcheck ne l'analyse pas, pour garder le code au plus près de l'amont.

## Retrait

Retirer ce répertoire et la directive `replace` dès qu'une version corrigée existe en amont, ou
dès que Syft, Grype et nfpm ne dépendent plus de ce module. Ensuite, `go mod tidy` et
`make vuln`.
