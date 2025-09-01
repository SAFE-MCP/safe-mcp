# Gateway DPoP Enforcement (Pseudo)

Minimal steps your gateway/filter should perform:

1) Extract `DPoP` header and access token.
2) Parse DPoP JWT: check `htm`, `htu`, `iat` (<= 300s skew), and unique `jti`.
3) Verify DPoP JWT signature against embedded JWK; compute JWK thumbprint (`jkt`).
4) Decode access token; read `cnf.jkt`; require `cnf.jkt == dpop_jkt`.
5) On success, forward request with `dpop_jkt` attached to auth context and emit telemetry.
6) On failure, return 401/403 and emit structured denial telemetry.

See `dpop-verify-pseudo.md` for language-agnostic pseudo-code.
