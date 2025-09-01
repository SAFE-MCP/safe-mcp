# SAFE-AUTH JWT Lint

Adds a lightweight lint script (`tools/jwt/jwt-lint.sh`) to catch malformed or incomplete JWTs.

## Checks
- MUST have `iss`, `aud`, `exp`, `iat`, `jti`, `trace_id`.
- Fails fast on missing claims.
- Example good/bad tokens under `examples/jwt/`.

## Usage
```bash
./tools/jwt/jwt-lint.sh examples/jwt/sample-good.jwt
./tools/jwt/jwt-lint.sh examples/jwt/sample-bad-missing-claims.jwt

