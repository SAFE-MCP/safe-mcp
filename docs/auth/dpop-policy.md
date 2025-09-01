# SAFE-AUTH: DPoP Gateway Policy

**Goal.** Bind access tokens to the caller so they cannot be replayed from another client or network hop.

## MUST
- **Require DPoP** for tool endpoints that accept OAuth access tokens over HTTP/1.1 or HTTP/2.
- **Verify DPoP proof** per request:
  - `htu` matches the request URL (scheme/host/path) and `htm` matches method.
  - `iat` within skew window (≤ 5 minutes).
  - `jti` not seen before within TTL window (replay cache).
  - DPoP proof JWT signature valid with public key in JWK thumbprint.
- **Bind access token to DPoP key**:
  - Access token contains `cnf.jkt` (SHA-256 JWK thumbprint).
  - The DPoP proof public key thumbprint equals `cnf.jkt`.
  - Deny when `cnf.jkt` missing or mismatch.
- **Emit telemetry** (see fields below) and **hard-deny** on failures.

## SHOULD
- Enforce **per-path policy** (e.g., admin tools require DPoP; read-only may allow mTLS alternative).
- Expire replay cache entries on a sliding TTL ≤ token TTL (max 10m).
- Backpressure/ratelimit on repeated DPoP failures from same client/IP.

## Telemetry fields (add to your schema v1 record)
- `dpop_jkt` (string) — DPoP key thumbprint
- `dpop_result` (`success|deny_mismatch_jkt|deny_replay|deny_invalid_proof|deny_missing`)
- `dpop_jti` (string) — proof JWT id
- `tool`, `aud`, `jti`, `trace_id`, `result` (existing)

## Deny conditions
- Missing DPoP when policy requires → `deny_missing`
- Invalid proof (sig/iat/htm/htu) → `deny_invalid_proof`
- Replay `jti` seen within window → `deny_replay`
- `cnf.jkt` missing in token or ≠ proof key thumbprint → `deny_mismatch_jkt`

## Evidence to attach
- Log excerpt showing deny on `deny_mismatch_jkt`
- Replay cache hit metric panel
- Config snippet enabling DPoP for tool routes

## References
- OAuth DPoP (draft-ietf-oauth-dpop)
- SAFE-AUTH Checklist: AUTH-003 (DPoP or mTLS binding)
- Telemetry schema v1 + validators
