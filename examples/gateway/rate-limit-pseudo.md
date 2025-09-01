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
