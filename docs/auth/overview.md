<!-- Licensed under CC-BY-4.0 -->

# SAFE-AUTH for MCP — Overview

**Goal.** Provide a vendor-neutral authentication baseline so MCP implementations are **safe by default** for humans, headless agents, and tool servers.

## Design principles
- **Least privilege per tool**: scopes and **audience** are bound to the *next hop* (specific tool/service), never broad.
- **Short-lived tokens** bound to the caller (**DPoP or mTLS**) to kill replay.
- **Explicit delegation** across agent→agent→tool hops (token **exchange** each hop; never forward a broad token).
- **Observable by design**: structured telemetry on every tool call for audits and incident response.

## Roles in MCP auth
- **Human Operator** (user)
- **MCP Client/Agent** (orchestrates tools)
- **MCP Server / Tool Host** (executes tool calls)
- **Authorization Server (AS)** (OIDC/OAuth2 provider)

## Threats this baseline addresses
- **Authorization server mix-up / CSRF** → OIDC Authorization Code **with PKCE**, `state`, `nonce`, **issuer pinning**.
- **Token replay** → **DPoP or mTLS** token binding + access token **TTL ≤ 10 minutes**.
- **Token audience confusion** (token reused across tools) → token `aud` **must equal the exact next tool/service**.
- **Delegation drift** (multi-agent hops drop user/intent context) → **RFC 8693 Token Exchange** per hop + re-bind `aud`.
- **JWKS staleness / `kid` collision** → JWKS **cache ≤ 15m**, overlap rotation, strict deny on unknown `kid`.

## Canonical flows (mermaid)
### Human → MCP Client → MCP Server (OIDC Auth Code + PKCE)
```mermaid
sequenceDiagram
participant User
participant Client as MCP Client
participant AS as Authorization Server
participant Server as MCP Server/Tool
User->>Client: Start sign-in
Client->>AS: /authorize (response_type=code, PKCE, state, nonce)
AS-->>Client: Auth code (redirect)
Client->>AS: /token (code + code_verifier)
AS-->>Client: access_token (bound via DPoP/mTLS), id_token
Client->>Server: Tool call (Authorization: DPoP <proof>; token aud=Server)
Server-->>Client: Result (+ audit_id)

cat > docs/auth/checklist.md <<'EOF'
<!-- Licensed under CC-BY-4.0 -->

# SAFE-AUTH Checklist (MUST / SHOULD / MAY)

| Level | Control | Why |
|---|---|---|
| **MUST** | Human login uses **OIDC Authorization Code + PKCE** (no implicit) with `state`, `nonce`, issuer pinning | Prevent code interception, AS mix-up, CSRF |
| **MUST** | Machine/agent calls use **DPoP or mTLS** token binding | Prevent replay |
| **MUST** | **Audience (`aud`) per hop = exact next tool/service** | Stop token reuse across tools |
| **MUST** | **Access token TTL ≤ 10 minutes** | Shrink exfiltration window |
| **MUST** | **JWKS cache ≤ 15 minutes** and rotation SOP | Avoid stale keys / `kid` swap |
| **MUST** | **Structured telemetry** per call | Audits & forensics |
| **SHOULD** | **RFC 8693 Token Exchange** per hop | Preserve delegation context |
| **SHOULD** | Deny on context loss | Fail-safe default |
| **SHOULD** | Rate-limit auth endpoints | Abuse control |
| **MAY** | PAR/JAR, CAEP, continuous eval | Hardening options |

- Telemetry: [Schema](./telemetry-schema.md) ·
  [Validators](./telemetry-validators.md) ·
  [Sample NDJSON](../../examples/telemetry/sample.ndjson)

- JWKS Hygiene: see [docs/auth/jwks-hygiene.md](./docs/auth/jwks-hygiene.md), [alerts/jwks-hygiene.md](./alerts/jwks-hygiene.md), and [runbooks/jwks-rotation-sop.md](./runbooks/jwks-rotation-sop.md).

- DPoP policy & pseudo: see [docs/auth/dpop-policy.md](./docs/auth/dpop-policy.md) and [examples/gateway/](./examples/gateway).
