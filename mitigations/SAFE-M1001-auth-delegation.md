# SAFE-M1001: Auth Delegation Mitigations

## Goal
Prevent replay/mix-up of delegated access tokens when MCP clients call through intermediate hops.

## MUST
- Require **sender-constrained tokens** (mTLS or DPoP) for delegated access across hops.  
- Enforce **audience validation**: delegated token audience (`aud`) must equal the target service.  
- Enforce **per-hop proof**: each forwarding hop must re-bind its token (`cnf.jkt`) and cannot reuse prior hop’s key.  
- Reject tokens missing `cnf` confirmation or with mismatched proof.

## SHOULD
- Rotate delegation keys per session; short TTLs (≤5 min).  
- Implement replay cache for delegation proofs (e.g., `jti` cache).  
- Telemetry must record delegation outcomes (`delegation_result`, `jti`, `trace_id`).

## MAY
- Support both DPoP and mTLS delegation models.  
- Allow explicit delegation scope (`scp:delegate`) to limit authority.  

## Evidence
- Logs show proof of enforcement: deny on missing/mismatched `cnf.jkt`.  
- Replay cache metrics confirm per-hop replay prevention.  
- Telemetry schema extended with `delegation_result`.

## References
- [SAFE-AUTH DPoP Gateway Policy](../docs/auth/dpop-policy.md)  
- [Conformance Template](../docs/auth/conformance-template.yaml)  
- [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) — OAuth 2.0 Proof-of-Possession  