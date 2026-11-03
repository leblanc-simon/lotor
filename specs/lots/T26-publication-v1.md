# T26 — Publication de la v1.0

| Lot fonctionnel | Dépend de | Statut |
| --- | --- | --- |
| 3 · Ouverture | T19 à T25, T27 | À faire |

## Objectif

Passer le critère du lot 3 : **v1.0 publiée et documentée**, avec des artefacts vérifiables.

## Périmètre

**Inclus**

- Chaîne de publication reproductible déclenchée par une étiquette : binaires des trois
  rôles (Linux amd64 et arm64, Windows pour l'agent serveur), sommes de contrôle, paquets
  deb, rpm et MSI signés, image de conteneur du serveur (statique, utilisateur non root),
  SBOM de chaque artefact.
- Signature des artefacts et documentation de la vérification.
- Documentation finale : installation, mise à jour entre versions, exploitation, guide
  utilisateur FR et EN, référence de configuration et de l'API.
- Audit de sécurité final par un relecteur distinct des auteurs (gravité selon l'OWASP Risk
  Rating) et audit RGAA complet ; corrections.
- `CHANGELOG.md`, étiquette `v1.0.0`.

**Exclu** : dépôt de paquets hébergé (à décider).

## Critères d'acceptation

- [ ] Une installation neuve et une mise à jour depuis `v0.2.0` réussissent en suivant la
      documentation seule.
- [ ] Chaque artefact a sa signature et son SBOM, vérifiables par la procédure documentée.
- [ ] Aucune faiblesse de sévérité haute ou critique ouverte ; RGAA sans non-conformité
      bloquante.
- [ ] `v1.0.0` publiée.

## Points à trancher

- Outil de publication (goreleaser ou `Makefile` + nfpm).
- Mécanisme de signature des artefacts (GPG pour les paquets, cosign avec clé pour le reste ?).
- Hébergement d'un dépôt de paquets.

## Journal

_À remplir pendant la réalisation._
