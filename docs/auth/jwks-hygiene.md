# SAFE-AUTH: JWKS Hygiene & Rotation

**Why it matters.** Stale or mismatched keys let attackers replay or impersonate tokens; unknown `kid` lets rogue keys slip in; long rotation windows widen blast radius.

## MUST
- **Cache TTL ≤ 15 minutes** for issuer JWKS.
- **Deny unknown `kid`** (hard fail; emit audit).
- **Overlapping rotation window ≤ 1 hour** (old+new keys concurrently valid).
- **Alert on cache age > TTL** (fetch failures or stuck caches).

## SHOULD
- **Rotation cadence ≤ 30 days** (shorter for high-risk).
- **No static keys**; automation only.
- **Key provenance** recorded (KMS/CloudHSM).

## Telemetry (per auth decision)
Record at least:
- `trace_id`, `aud`, `jti`, `kid`, `jwks_cache_age_ms`, `jwks_source` (`remote|cache`), `result` (`success|deny_unknown_kid|deny_stale_jwks|error`).

## Alerts (see alerts/jwks-hygiene.md)
- Unknown `kid` deny.
- `jwks_cache_age_ms` > 15m for >5m.
- Rotation overlap > 60m.
- Same `kid` age > 90d.

## Runbook (see runbooks/jwks-rotation-sop.md)
- Pre-announce, rotate, verify, and rollback steps with checkpoints.

## Evidence to attach (for checklist)
- Screenshot/log of deny-on-unknown-kid.
- Monitoring panel showing JWKS cache age distribution.
- Rotation change record (ticket/PR) within 30d.

## References
- RFC 7517 (JWK), RFC 7518/7519 (JWS/JWT)
- SAFE-AUTH Checklist: AUTH-006 (JWKS cache ≤ 15m; deny unknown `kid`)
- Telemetry schema v1 + validators
