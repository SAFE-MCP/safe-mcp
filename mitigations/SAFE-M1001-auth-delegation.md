<!-- Licensed under CC-BY-4.0 -->

# SAFE-M1001: Per-Hop Delegation Mitigations

**Objective.** Ensure every hop in a delegation chain has a *fresh*, *narrow*, and *proof-of-possession* bound token for the exact next audience.

## Controls (map to checklist IDs)
- **MUST** AUTH-003: DPoP or mTLS binding on all tokens used for tool calls
- **MUST** AUTH-004: `aud` = exact next tool/service (no wildcards)
- **MUST** AUTH-005: Access token TTL ≤ 10 minutes (shorter for sensitive tools)
- **MUST** AUTH-006: JWKS cache ≤ 15 minutes; deny unknown `kid`; rotation SOP
- **SHOULD** AUTH-008: RFC 8693 Token Exchange per hop (re-bind audience)
- **SHOULD** AUTH-009: Deny on missing `aud`/`trace_id`; fail-safe default

## Implementation pattern (per hop)
1. **Token Exchange**: Exchange incoming token for a new token with `aud=<next>` and TTL ≤ 10m.
2. **Bind PoP**: Use DPoP (HTTP) or mTLS (gateway) so token is sender-constrained.
3. **Validate**: On receipt, verify `aud`, TTL, PoP, and `kid` exists in current JWKS.
4. **Emit telemetry**: Log fields from `docs/auth/telemetry-schema.md` (incl. `trace_id`, `aud`, `jti`, `dpop_jkt`).
5. **Deny on context loss**: If `aud` mismatched/missing or PoP not present → hard deny + audit event.

## Example enforcement pseudo

## Example enforcement pseudo


**References.**
- `docs/auth/threat-control-matrix.md`
- `docs/auth/flows/headless-agent.md`
- RFC 8693 (Token Exchange)
