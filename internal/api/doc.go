// Package api porte les handlers REST, qui implémentent les interfaces générées depuis
// api/openapi.yaml (internal/api/gen).
//
// MountAgent monte l'API des agents sur le routeur de /api/v1 : corps JSON borné,
// authentification par jeton (agent.Service.Authenticate), limitation par jeton
// (ratelimit d'open-go-base avec WithKeyFunc), puis le serveur strict généré. Chaque
// opération exige sa nature de jeton (requireKind) ; les erreurs sont des problèmes
// RFC 9457 traduits (internal/api/problem).
//
// MountDT monte le point compatible Dependency-Track sur le routeur de /dt (T19, ADR
// 0058) : mêmes limiteurs, même authentification (X-Api-Key au lieu de Authorization) et
// même mTLS que l'API des agents ; la cible (projet, version) est résolue par
// agent.Service.ResolveUpload, puis l'envoi suit ingest.Authorize et ingest.Receive.
package api
