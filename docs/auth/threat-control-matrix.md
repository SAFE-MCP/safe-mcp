<!-- Licensed under CC-BY-4.0 -->

# Threat → Control Matrix (SAFE-AUTH)

| Threat | Primary Controls (MUST) | Secondary (SHOULD/MAY) | Evidence to Collect |
|---|---|---|---|
| AS mix-up / CSRF | OIDC Auth Code + **PKCE**, `state`, `nonce`, **issuer pinning** | PAR/JAR | OIDC client config, redirect URI list, issuer metadata |
| Token replay | **DPoP or mTLS** binding; **TTL ≤10m** | CAEP/continuous evaluation | DPoP verification logs, TLS/mTLS policy, token lifetime |
| Token audience confusion | **`aud` = exact next tool/service** | Per-tool scope map | JWT sample with `aud`, tool registry mapping |
| Delegation drift (multi-hop) | **RFC 8693 Token Exchange** per hop; re-bind `aud` | Deny on missing `trace_id` / `aud` | Token Exchange config, hop-by-hop logs |
| JWKS staleness / `kid` collision | **JWKS cache ≤15m**; rotation SOP; deny unknown `kid` | Overlap-period alerts | JWKS headers, rotation runbook, error logs |
| Observability gap | **Structured telemetry on every tool call** | Centralized log routing | Field schema adoption, sample NDJSON |
---
Version: 1.0 • Date: 2025-08-16
Changes: Initial SAFE-AUTH threat/control matrix + conformance template
Author: secretisgratitude