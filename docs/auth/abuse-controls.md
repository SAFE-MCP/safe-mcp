# SAFE-AUTH: Rate-limit & Abuse Controls

**Goal.** Keep auth/tool surfaces resilient under load/misuse. Prefer cheap gates early; deny safely when limits trip.

## MUST
- **Per-tool limits**: enforce a token-bucket or leaky-bucket per `tool` (target path).
- **Per-client limits**: limit by `client_id` (agent) and/or `sub_or_user` (human).
- **Fast pre-filter**: cheap per-IP or per-connection limit *before* expensive auth or token introspection.
- **Fail-safe default**: when limiter/cache is unavailable, default to conservative ceilings (deny or hard backoff).
- **Emit telemetry** on limit decisions (see fields below).

## SHOULD
- **Burst control**: allow small bursts; sustained rate must stay under ceiling.
- **Backoff on fails**: increase penalty for repeated 401/403/429 from the same key.
- **Circuit-break hot tools**: temporarily shed traffic when a tool’s 5xx spikes.
- **Separate write vs read**: stricter ceilings for mutating tools.

## Suggested ceilings (tune per env)
- Read tools: **60/min** per `(tool, client_id)` with burst 20.
- Write tools: **10/min** per `(tool, client_id)` with burst 5.
- Pre-filter per-IP: **120/min** with burst 60 (cheap SYN flood brake).

## Telemetry (recommend adding to your v1 record)
- `rl_key`  (string)  — e.g., `tool=tools/ingest|client=agent-42`
- `rl_bucket` (string) — `per_tool`, `per_client`, `per_ip`, `circuit_breaker`
- `rl_limit`  (string) — `60/m burst=20`
- `rl_result` (enum)  — `allow`, `throttle`, `deny`
- Existing: `trace_id`, `tool`, `client_id`, `sub_or_user`, `result`

## Hunting/alerts (queries)
- Spike of `rl_result=deny` grouped by `rl_key` or `client_id`.
- >3 denies/min for same `jti` or same `dpop_jkt` → blocklist or CAPTCHA.
- `result=deny` + `status=401/403` loops from same IP over 5 min → raise.

## Enforcement pseudo

```text
key_tool    = "tool=" + tool_id
key_client  = key_tool + "|client=" + client_id_or_user

if !pre_ip_limiter.allow(ip):        return 429, rl(per_ip, deny)
if !tool_limiter.allow(key_tool):    return 429, rl(per_tool, deny)
if !client_limiter.allow(key_client):return 429, rl(per_client, deny)

// Optionally: penalize on recent 401/403 from same client
if recent_denies(key_client) > N:    return 429, rl(backoff, deny)

forward_request()


## 2) Gateway examples (pseudo + tiny Envoy / NGINX samples)

```bash
cat > examples/gateway/rate-limit-pseudo.md <<'EOF'
# Rate-limit Pseudo (language/gateway agnostic)

buckets = {
  per_ip:     token_bucket(cap=120, refill=120/min, burst=60),
  per_tool:   token_bucket(cap=60,  refill=60/min,  burst=20),
  per_client: token_bucket(cap=60,  refill=60/min,  burst=20),
  per_write:  token_bucket(cap=10,  refill=10/min,  burst=5),
}

route = route_from_url(req.url)           // e.g., /tools/ingest
tool_id = canonical_tool(route)
is_write = method in ["POST","PUT","PATCH","DELETE"]

ip_key = req.ip
tool_key = tool_id
client_key = tool_id + "|" + (req.client_id || req.user_id)

if !buckets.per_ip.allow(ip_key)     -> 429
if is_write && !buckets.per_write.allow(tool_key) -> 429
if !buckets.per_tool.allow(tool_key) -> 429
if !buckets.per_client.allow(client_key) -> 429

// else allow; emit telemetry with rl_* fields
