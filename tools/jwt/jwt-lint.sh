#!/usr/bin/env bash
# jwt-lint.sh — lightweight SAFE-AUTH JWT sanity checks
# Usage: ./jwt-lint.sh token.jwt

set -euo pipefail

TOKEN=$1
HEADER=$(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null || true)
PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null || true)

if [[ -z "$PAYLOAD" ]]; then
  echo "Invalid JWT (cannot parse)"
  exit 1
fi

# Check required SAFE-AUTH claims
for CLAIM in "iss" "aud" "exp" "iat" "jti" "trace_id"; do
  if ! echo "$PAYLOAD" | jq -e ".${CLAIM}" >/dev/null; then
    echo "❌ Missing claim: $CLAIM"
    exit 1
  fi
done

echo "✅ JWT passed SAFE-AUTH lint checks"
