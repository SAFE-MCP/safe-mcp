# SAFE-T1602: Tool Enumeration

## Tactic

Discovery (ATK-TA0007)

## Description

Tool enumeration is a reconnaissance phase where an adversary tries to discover which tools, services, plugins, connectors, or helper components exist in a target environment, plus their versions and configurations. The goal is to learn what capabilities the environment exposes (e.g., code execution helpers, file access APIs, external connectors) so the attacker can identify follow‑on opportunities — misconfigured services, unpatched versions, or weaker authentication — to exploit later.

Typical outcomes an attacker wants from enumeration:

- Inventory of available tooling and interfaces.

- Software/firmware versions and configuration details.

- Capabilities, e.g., whether a tool can read files, call external APIs, run commands, or load plugins.

- Any exposed endpoints, telemetry, or metadata that leak internal structure.

## How It Works

#### Reconnaissance / footprinting

What the attacker does 

- Find any public or semi‑public MCP surfaces: web UIs, chatbot endpoints, API gateways, SDKs, sample clients, developer consoles, or third‑party integrations.
- Collect whatever metadata is exposed without interacting heavily: public docs, SDK examples, API spec URLs, JS bundles, HTML/JS comments that hint at tool names.

What defenders see / should log

- Unusual downloads of API docs or SDK files.
- Access to developer-only pages or large numbers of static assets.
- Requests for manifest-like URLs or `.well-known`/spec endpoints.

Defensive action

- Remove sensitive info from public assets; require auth for dev docs; log accesses.

##### Fingerprinting & information extraction

What the attacker does 

- Send benign-looking requests to elicit informative responses (error messages, version headers, descriptive text from a model) that leak tool names, versions, or registry locations.
- Use probe queries that cause models or backends to reference tool capabilities (e.g., asking the model what tools it can call, in environments where it will explain them).

What defenders see / should log

- Requests that intentionally produce errors or ask meta‑questions about the system.
- Responses containing unusual debug fields or verbose error strings sent to clients.

Defensive action

- Strip debug info from responses; redact internal names in model replies; require MFA for endpoints that return metadata.

#### Active probing / capability testing (non‑destructive)

What the attacker does 

- Systematically vary parameters or endpoints to detect which tool names are accepted, which parameters are validated, and which endpoints respond differently.
- Observe side channels: timing differences, response size, HTTP status patterns, rate limits hit, or model phrasing differences.

What defenders see / should log

- High volume of similar requests with small variations.
- Lots of 4xx/5xx responses for many different tool names or parameters.
- Requests timed to try and observe response latency differentials.

Defensive action

- Rate‑limit, add CAPTCHAs or throttling on suspicious patterns; monitor for parameter‑sweeps.

#### Correlation & inference

What the attacker does

- Aggregate results from many probes to build an inventory: which tool names exist, which capabilities they expose (read/write, exec, network), likely owners, and trust boundaries.
- Combine with external data (open‑source repos, leaked configs, job posts) to infer versions or vulnerable components.

What defenders see / should log

- Multiple different endpoints touched over time by same actor.
- Repeated token/credential validation attempts across tool APIs.

Defensive action

- Correlate logs across services; flag actors who access many disparate tool endpoints.

####  Testing for privileged behaviors (goal: plan exploits — defensive view only)

What the attacker does 

- Try to see whether invoking a discovered tool causes privileged side effects (e.g., access to storage, outbound network calls, code execution) — typically via safe, read‑only queries when possible.
- Look for chains: “this tool can call external webhooks, and this other tool can write to storage” — combine them mentally.

What defenders see / should log

- Invocations of tools that are normally internal-only, attempted from unprivileged users or from unexpected origins.
- Unusual outbound connections initiated after a model/tool invocation.

Defensive action

- Enforce allow‑lists, block tool-to-external connections by default, and require explicit approval flows for sensitive tool operations.

#### Persistence & staging (if the attacker advances)

What the attacker might attempt after enumeration (defensive perspective)

- Use discovered weakly protected interfaces to obtain credentials, pivot to other services, or exfiltrate data via a known connector.

What defenders see / should log

- New credentials created or used from strange origins, unexpected storage writes, or anomalous outbound data transfers.

Defensive action

- Alert on credential creation, enforce short credential lifetimes and multi‑party approvals for changes.

##### Observable attack signals (short checklist for detection)

- Burst of requests varying a single parameter across many values.
- Repeated “what tools do you have?” or meta‑questions routed through model/chat endpoints.
- Access to admin/registry endpoints without matching user role or from odd IP ranges.
- Latency‑based anomalies: systematic timing probes or consistent small variations correlated with different requested tool names.
- Unusual sequences: e.g., manifest request → follow‑up attempt to call named tool.

##### How defenders should instrument for visibility

- Centralize and correlate logs for: model requests, tool invocation events, registry access, auth events, and outbound network flows.
- Tag every tool invocation with caller identity, input hash, timestamp, and response code.
- Keep an allow‑list of tool actions per role and log deviations; treat mismatches as high‑priority alerts.

## Examples

An attacker with a stolen developer API key quietly probes an MCP, enumerates available tools (storage, external fetch, job runner), and uses them in low‑noise steps to steal credentials and exfiltrate sensitive data while avoiding alerts. The chain leads to high confidentiality loss, moderate integrity damage (tampered training artifacts), and temporary availability degradation (resource‑heavy jobs).


## Impact

- Confidentiality: [High]
- Integrity: [Medium]
- Availability: [Medium]

tackers have a map for high-probability follow-on attacks, making the system easier to compromise.



## Detection

Defenders can identify tool enumeration attacks on an MCP system by monitoring for patterns that indicate probing or metadata collection:

1. Unusual access patterns to tool endpoints
- Repeated queries to many different tool names or registry endpoints.
- Access from IPs, geolocations, or accounts that normally don’t interact with these services.

2. Probing via model or API inputs

- Requests that ask the model/system about its capabilities, tools, or configuration.
- Structured or patterned inputs designed to elicit error messages, verbose outputs, or metadata.

3. High-frequency, low-volume activity

- Multiple small reads, writes, or job invocations that are sequentially spread across different tools or connectors.
- Timing or size anomalies in responses that could indicate side-channel probing.

4. Unexpected tool invocation sequences

- Calls to tools in combinations or orders uncommon for legitimate users.
- Invocations that indirectly access sensitive resources or trigger workflow chains.

5. Anomalous outbound connections

- Outbound network requests initiated by tools where external connectivity is normally restricted.
- Requests to unapproved domains or endpoints immediately following internal tool activity.

6. Authentication and authorization anomalies

- Use of expired, stolen, or unusual API keys or tokens.
- Unauthorized attempts to access manifests, admin endpoints, or debug interfaces.

Defensive actions for detection:

- Centralize logging for all model, tool, and API activity.
- Correlate user identity, IP, request patterns, and tool invocation sequences.
- Set alerts for high-volume probing, unexpected combinations of tool calls, or cross-tool sequences.
- Monitor for repeated error-triggering requests or metadata requests.
- Implement rate limiting and anomaly detection for all tool/API endpoints.


## Mitigation

1. Configuration hardening

- Restrict tool manifests and metadata: Never expose full tool lists publicly; require authentication and role-based access.
- Disable verbose error messages: Avoid leaking internal tool names, versions, or stack traces in responses.
- Sandbox tool execution: Ensure each tool runs in a restricted environment with least privilege.
- Apply allow-lists instead of block-lists: Explicitly permit only approved tools and actions per model/user identity.

2. Access controls

- Enforce strong authentication: Require MFA and short-lived API keys for developer and model access.
- Implement RBAC: Limit which users or model identities can invoke specific tools.
- Segment networks: Isolate internal tools and prevent direct internet access unless explicitly allowed.
- Restrict privileged endpoints: Admin, registry, or debug endpoints should never be publicly accessible.

3. Input validation

- Sanitize model inputs: Reject or escape structured prompts that could attempt tool probing.
- Validate all tool parameters: Ensure inputs cannot cause unintended tool execution or data access.
- Reject suspicious sequences: Monitor for patterns of requests designed to map tools or trigger hidden behaviors.

4. Monitoring requirements

- Centralize logging: Capture all tool invocations, API requests, model prompts, and outbound network flows.
- Correlate events: Watch for sequences of requests across tools or unusual patterns from the same identity.
- Alert on anomalies: Trigger alerts for repeated errors, rapid probing attempts, or unexpected access to sensitive endpoints.
- Apply rate limits and quotas: Limit per-user or per-model tool usage to prevent stealthy enumeration.


## References

- https://attack.mitre.org/tactics/TA0007/?utm_source=chatgpt.com
- https://modelcontextprotocol.io/docs/getting-started/intro


## MITRE ATT&CK Mapping

ATT&CK Technique: [T1602 - Tool Enumeration]
ATT&CK Tactic: Discovery
