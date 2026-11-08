# Cibles de développement de lotor. `make ci` exécute exactement ce que fait la CI.

GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo develop)
LDFLAGS   := -s -w -X 'main.version=$(VERSION)'
BINARIES  := lotor-server lotor-host-agent lotor-repo-agent
GOOS      ?= $(shell $(GO) env GOOS)
GOARCH    ?= $(shell $(GO) env GOARCH)

# Code généré, vérifié à jour par generate-check.
GENERATED := internal/api/gen internal/agentclient/gen

# Connexion d'administration des tests d'intégration (deploy/compose.yaml) : chaque test
# y crée sa base et ses rôles jetables.
LOTOR_TEST_DATABASE_DSN ?= postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable
export LOTOR_TEST_DATABASE_DSN

.DEFAULT_GOAL := help

.PHONY: help
help: ## Liste les cibles
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: build
build: ## Construit les trois binaires dans bin/
	@mkdir -p bin
	@for b in $(BINARIES); do \
		echo "build $$b ($(GOOS)/$(GOARCH), $(VERSION))"; \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; \
	done

# Agent serveur : architectures livrées et version des paquets : celle de l'étiquette sans
# son « v », sinon 0.0.0~<commit> (une version deb ou rpm commence par un chiffre).
AGENT_ARCHES := amd64 arm64
PKG_VERSION  := $(shell echo '$(VERSION)' | sed -E 's/^v//; /^[0-9]+[.][0-9]/!s/^/0.0.0~/; s/-/./g')

.PHONY: packages
packages: ## Agent serveur (deb, rpm), serveur et agent dépôt (deb), amd64 et arm64, dans dist/
	@mkdir -p dist
	@for a in $(AGENT_ARCHES); do \
		echo "build lotor-host-agent (linux/$$a, $(VERSION))"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-$$a/lotor-host-agent ./cmd/lotor-host-agent || exit 1; \
		mkdir -p bin/package && cp bin/linux-$$a/lotor-host-agent bin/package/lotor-host-agent || exit 1; \
		for p in deb rpm; do \
			PKG_ARCH=$$a PKG_VERSION=$(PKG_VERSION) $(GO) tool nfpm package --config deploy/nfpm/host-agent.yaml --packager $$p --target dist/ || exit 1; \
		done; \
		echo "build lotor-server (linux/$$a, $(VERSION))"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/package/lotor-server ./cmd/lotor-server || exit 1; \
		sed 's#/usr/local/bin/lotor-server#/usr/bin/lotor-server#' deploy/systemd/lotor-server.service > bin/package/lotor-server.service || exit 1; \
		PKG_ARCH=$$a PKG_VERSION=$(PKG_VERSION) $(GO) tool nfpm package --config deploy/nfpm/server.yaml --packager deb --target dist/ || exit 1; \
		echo "build lotor-repo-agent (linux/$$a, $(VERSION))"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/package/lotor-repo-agent ./cmd/lotor-repo-agent || exit 1; \
		PKG_ARCH=$$a PKG_VERSION=$(PKG_VERSION) $(GO) tool nfpm package --config deploy/nfpm/repo-agent.yaml --packager deb --target dist/ || exit 1; \
	done
	@ls -l bin/linux-*/lotor-host-agent dist/

# Fichiers d'une version (archives des trois binaires linux amd64 et arm64, paquets deb et
# rpm, SHA256SUMS) : make release VERSION=v0.1.0 RELEASE_DIR=/chemin/vide.
RELEASE_DIR ?= dist/release

.PHONY: release
release: ## Fichiers d'une version dans RELEASE_DIR (VERSION=vX.Y.Z), comme le workflow release
	GO="$(GO)" scripts/release.sh "$(VERSION)" "$(RELEASE_DIR)"

.PHONY: run
run: build ## Lance le serveur avec config.yaml
	./bin/lotor-server -c config.yaml

.PHONY: fmt
fmt: ## Formate le code
	gofmt -w $$(git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## Échoue si un fichier n'est pas formaté
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "fichiers non formatés :"; echo "$$out"; exit 1; fi

# Étiquettes de test qui compilent en CI : vet et staticcheck passent sur chacune, pour
# que les fichiers étiquetés (tests d'intégration, base Grype réelle, mesures) soient
# analysés comme le reste.
TEST_TAGS := integration integration,grypedb measure evalai dtrack

# Copie corrigée de github.com/blakesmith/ar (ADR 0063) : module à part, hors de ./...,
# vérifiée par vet et les tests unitaires (pas par staticcheck : code amont gardé au plus près).
THIRD_PARTY_AR := third_party/blakesmith-ar

.PHONY: vet
vet: ## go vet (sans étiquette, puis avec chaque étiquette de test)
	$(GO) vet ./...
	$(GO) -C $(THIRD_PARTY_AR) vet ./...
	@set -e; for tags in $(TEST_TAGS); do echo "go vet -tags $$tags"; $(GO) vet -tags "$$tags" ./...; done

.PHONY: lint
lint: ## staticcheck (sans étiquette, puis avec chaque étiquette de test)
	$(GO) tool staticcheck ./...
	@set -e; for tags in $(TEST_TAGS); do echo "staticcheck -tags $$tags"; $(GO) tool staticcheck -tags "$$tags" ./...; done

.PHONY: vuln
vuln: ## govulncheck
	$(GO) tool govulncheck ./...

.PHONY: generate
generate: ## Régénère le code dérivé (API)
	$(GO) generate ./...

.PHONY: generate-check
generate-check: generate ## Échoue si le code généré n'est pas à jour
	@out=$$(git status --porcelain -- $(GENERATED)); if [ -n "$$out" ]; then echo "code généré obsolète : lancer make generate"; echo "$$out"; exit 1; fi

.PHONY: test
test: ## Tests unitaires
	$(GO) test ./...
	$(GO) -C $(THIRD_PARTY_AR) test ./...

.PHONY: test-race
test-race: ## Tests unitaires avec le détecteur de concurrence
	$(GO) test -race ./...
	$(GO) -C $(THIRD_PARTY_AR) test -race ./...

.PHONY: test-integration
test-integration: ## Tests d'intégration (PostgreSQL : docker compose -f deploy/compose.yaml up -d)
	$(GO) test -race -count=1 -tags integration ./...

.PHONY: test-grypedb
test-grypedb: ## Tests avec la vraie base Grype (LOTOR_TEST_GRYPEDB_DIR : base v6 installée)
	@test -n "$(LOTOR_TEST_GRYPEDB_DIR)" || { echo "LOTOR_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée"; exit 1; }
	$(GO) test -count=1 -timeout 30m -tags 'integration grypedb' ./internal/vuln/grype/ ./internal/benchdata/

.PHONY: test-dtrack
test-dtrack: ## Recette contre un vrai Dependency-Track 5, hors CI (LOTOR_TEST_DTRACK_URL, LOTOR_TEST_DTRACK_API_KEY_FILE ; docs/dependency-track.md)
	@test -n "$(LOTOR_TEST_DTRACK_URL)" || { echo "LOTOR_TEST_DTRACK_URL : adresse de base d'un Dependency-Track 5 de test"; exit 1; }
	$(GO) test -count=1 -timeout 10m -tags dtrack -run TestRealDependencyTrack -v ./internal/hostagent/

.PHONY: bench-ingest
bench-ingest: ## Mesure ingestion et analyse de 5 000 composants, vraie base Grype (LOTOR_TEST_GRYPEDB_DIR)
	@test -n "$(LOTOR_TEST_GRYPEDB_DIR)" || { echo "LOTOR_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée"; exit 1; }
	$(GO) test -count=1 -timeout 30m -tags 'integration grypedb' -v -run TestIngestAndAnalyze5000 ./internal/benchdata/

.PHONY: bench
bench: ## Mesures sur le jeu de référence (docs/benchmarks.md)
	LOTOR_BENCH=1 $(GO) test -count=1 -timeout 30m -tags integration -run TestReferenceDataset -v ./internal/benchdata/ ./internal/web/

.PHONY: bench-search
bench-search: ## Mesures de la recherche sur le jeu de référence, RLS active (docs/benchmarks.md)
	LOTOR_BENCH=1 $(GO) test -count=1 -timeout 30m -tags integration -run 'TestSearch(At)?Benchmark' -v ./internal/search/

.PHONY: eval-ai
eval-ai: ## Évalue l'enrichissement IA sur le corpus annoté avec un vrai modèle, hors CI (LOTOR_EVAL_AI_*, docs/operations.md)
	$(GO) test -count=1 -timeout 2h -tags evalai -run TestEvalAI -v ./internal/repoagent/

# Autoanalyse : SBOM des binaires par Syft, analyse par Grype, mêmes versions que les
# bibliothèques du projet (go.mod). Grype télécharge sa base, sauf GRYPE_DB_CACHE_DIR et
# GRYPE_DB_AUTO_UPDATE=false.
SYFT  := $(GO) run github.com/anchore/syft/cmd/syft@$(shell $(GO) list -m -f '{{.Version}}' github.com/anchore/syft)
GRYPE := $(GO) run github.com/anchore/grype/cmd/grype@$(shell $(GO) list -m -f '{{.Version}}' github.com/anchore/grype)

.PHONY: sbom
sbom: build ## SBOM CycloneDX des trois binaires (bin/<binaire>.cdx.json)
	@for b in $(BINARIES); do \
		echo "sbom $$b"; \
		$(SYFT) scan file:bin/$$b -q -o cyclonedx-json=bin/$$b.cdx.json || exit 1; \
	done

.PHONY: selfscan
selfscan: sbom ## Analyse les SBOM des binaires ; échec sur une vulnérabilité activement exploitée (KEV)
	@status=0; for b in $(BINARIES); do \
		$(GRYPE) sbom:bin/$$b.cdx.json --by-cve -q -o json --file bin/$$b.grype.json || exit 1; \
		echo "$$b : $$(jq '.matches | length' bin/$$b.grype.json) vulnérabilités, $$(jq '[.matches[] | select((.vulnerability.knownExploited // []) | length > 0)] | length' bin/$$b.grype.json) KEV"; \
		kev=$$(jq -r '.matches[] | select((.vulnerability.knownExploited // []) | length > 0) | "  KEV : \(.vulnerability.id) dans \(.artifact.name) \(.artifact.version)"' bin/$$b.grype.json); \
		if [ -n "$$kev" ]; then echo "$$kev"; status=1; fi; \
	done; exit $$status

.PHONY: ci
ci: fmt-check generate-check vet lint test-race test-integration vuln build packages ## Toutes les vérifications de la CI

.PHONY: test-package
test-package: packages ## Recette des paquets deb du serveur et de l'agent dépôt dans des conteneurs systemd (Docker)
	./scripts/test-package.sh

.PHONY: clean
clean: ## Supprime les artefacts
	rm -rf bin dist
