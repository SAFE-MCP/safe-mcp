# Runbook: JWKS Rotation (SAFE-AUTH)

## Preconditions
- Dual-key signer ready (KMS/HSM).
- Monitoring: unknown `kid`, cache age, 5xx on JWKS fetch.

## Steps
1) **Prepare key**: generate new key; publish to JWKS with new `kid`; keep old key active.
2) **Announce**: change ticket; notify on-call; schedule rotation window (≤ 60m).
3) **Deploy**: roll app to sign tokens with new key; verify audience accepts.
4) **Observe** (15–30m):
   - unknown `kid`: 0
   - cache age: P95 < 15m
   - error rate: baseline
5) **Deactivate old key**: remove old key from JWKS (within the same window).
6) **Close out**: attach evidence (graphs, logs); set next rotation reminder (≤ 30d).

## Rollback
- Re-add old key to JWKS; revert signer; postmortem with cache age + error timelines.
