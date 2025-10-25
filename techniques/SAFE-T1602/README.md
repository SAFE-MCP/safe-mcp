# SAFE-T1602: Tool Enumeration

## Tactic

Discovery (ATK-TA0007)

## Description

Tool enumeration is a reconnaissance technique where an adversary attempts to discover which tools, services, plugins, connectors, or helper components exist in a target environment, including their versions and configurations. The goal is to understand the capabilities exposed by the environment (e.g., code execution helpers, file access APIs, external connectors) to identify potential follow-on attack opportunities such as misconfigured services, unpatched versions, or weak authentication.  

## How It Works

1. **Reconnaissance / Footprinting**  
   - Attacker identifies public or semi-public MCP surfaces: web UIs, chatbot endpoints, API gateways, SDKs, sample clients, developer consoles, or third-party integrations.  
   - Metadata collection via public documentation, SDK examples, API spec URLs, JS bundles, and HTML/JS comments.  

   **Defender indicators:** unusual downloads of API docs or SDK files, access to developer-only pages, requests to manifest-like URLs.  

2. **Fingerprinting & Information Extraction**  
   - Sending requests to elicit informative responses (error messages, version headers, descriptive model outputs).  
   - Crafting queries that reveal tool capabilities (e.g., asking which tools are available).  

   **Defender indicators:** requests producing errors or meta-questions, verbose debug output.  

3. **Active Probing / Capability Testing**  
   - Varying parameters or endpoints to detect accepted tool names and observable responses.  
   - Observing side channels such as timing differences or response sizes.  

   **Defender indicators:** high volume of similar requests, many 4xx/5xx responses, latency anomalies.  

4. **Correlation & Inference**  
   - Aggregating results to build an inventory of tools, capabilities, owners, and trust boundaries.  
   - Combining with external information (open-source repos, leaked configs).  

   **Defender indicators:** multiple endpoints accessed over time, repeated token/credential validation attempts.  

5. **Testing for Privileged Behaviors**  
   - Checking whether invoking a tool causes privileged effects (e.g., storage access, outbound network calls).  
   - Evaluating potential chains of tool interactions.  

   **Defender indicators:** unprivileged users invoking internal-only tools, unusual outbound connections.  

6. **Persistence & Staging**  
   - Using weakly protected interfaces to obtain credentials, pivot, or stage exfiltration.  

   **Defender indicators:** new credentials used from unusual origins, unexpected storage writes, anomalous outbound data.  

---

## Examples

An attacker with a stolen developer API key quietly probes an MCP, enumerates available tools (storage, external fetch, job runner), and uses them in low-noise steps to steal credentials and exfiltrate sensitive data. This leads to high confidentiality loss, moderate integrity damage (tampered training artifacts), and temporary availability degradation (resource-heavy jobs).  

---

## Impact

- Confidentiality: High  
- Integrity: Medium  
- Availability: Medium  

**Consequences:** Sensitive data may be exposed, system outputs can be tampered, and resources may be overloaded. Enumeration also maps high-probability follow-on attack paths.  

---

## Detection

Defenders can identify this attack by monitoring for:  

- Unusual access to tool endpoints (repeated queries, abnormal IPs/geos).  
- Requests probing model or API capabilities or structured to elicit metadata.  
- High-frequency, low-volume activity across multiple tools.  
- Unexpected sequences of tool invocations.  
- Anomalous outbound connections after tool usage.  
- Authentication anomalies (stolen or unusual API keys, unauthorized manifest access).  

**Monitoring strategies:** centralize logging, correlate user/IP patterns, alert on high-volume or suspicious sequences, apply rate limiting and anomaly detection.  

---

## Mitigation

1. **Configuration Hardening**  
   - Restrict tool manifests and metadata, disable verbose errors, sandbox tool execution, enforce allow-lists.  

2. **Access Controls**  
   - Enforce MFA, short-lived API keys, RBAC, network segmentation, restrict admin/debug endpoints.  

3. **Input Validation**  
   - Sanitize model inputs, validate tool parameters, reject suspicious sequences.  

4. **Monitoring Requirements**  
   - Centralize logging, correlate events, alert on anomalies, enforce rate limits and quotas.  

---

## References

- [MITRE ATT&CK Discovery Tactic](https://attack.mitre.org/tactics/TA0007/)  
- [MCP Getting Started Documentation](https://modelcontextprotocol.io/docs/getting-started/intro)  

---

## MITRE ATT&CK Mapping

- ATT&CK Technique: T1602 – Tool Enumeration  
- ATT&CK Tactic: Discovery
