# SAFE-AUTH Telemetry Validators (v1)

**Required per call:** `trace_id`, `ts`, `tool`, `client_id`, `sub_or_user`, `aud`, `jti`, and `dpop_jkt` when PoP policy is enabled.

## Reject if
- `aud` ≠ invoked tool/service id
- `jti` is reused within the token TTL window
- `dpop_jkt` missing when PoP is required
- `trace_id` missing or empty

## Recommended checks
- Clock skew ≤ 60s between `ts` values on same `trace_id`
- Monotonic `ts` per `trace_id`
- Result not `"success"` without an auth decision log

## Example (NDJSON)
See `examples/telemetry/sample.ndjson`.

## Quick local checks (jq)
```bash
# 1) Missing trace_id
jq -c 'select(has("trace_id")|not)' examples/telemetry/sample.ndjson

# 2) aud mismatch (expect mcp://tool/ingest)
jq -c 'select(.aud != "mcp://tool/ingest")' examples/telemetry/sample.ndjson

# 3) Duplicate jti within the file (naive local check)
jq -r .jti examples/telemetry/sample.n


---

### 3) Append a tiny “Validators” section to your existing schema (safe even if it already exists)
```bash
printf "\n## Validators\nSee [telemetry-validators](./telemetry-validators.md) and [sample NDJSON](../../examples/telemetry/sample.ndjson).\n" >> docs/auth/telemetry-schema.md

eof
