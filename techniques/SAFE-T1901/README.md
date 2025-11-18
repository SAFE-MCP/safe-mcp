# SAFE-T1901 : Outbound Webhook C2

## Tactic  
**Command and Control (ATK-TA0011)**  

---

## Description
Outbound Webhook C2 is a technique where an adversary abuses legitimate outbound HTTP webhook mechanisms to establish covert command-and-control (C2) channels from a Model Context Protocol (MCP) environment.  
Because MCP agents and tools routinely use HTTPS for integration with external services (Slack, GitHub, Jira, etc.), malicious webhook calls blend with normal traffic, making detection difficult.  

This mirrors MITRE ATT&CK technique [T1567.004 – Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004/) and expands it to AI agent ecosystems.

---

## How It Works
1. **Initial Access** – Attacker gains code execution inside an MCP agent or server (e.g., through malicious tool registration or supply-chain package).  
2. **Webhook Setup** – They embed an attacker-controlled URL (`https://discord.com/api/webhooks/...`, `https://hooks.slack.com/services/...`, or custom endpoint) in configuration or environment variables.  
3. **Beaconing & Tasking** – The compromised component periodically issues small HTTPS POST requests to the webhook, sending status or encoded data and receiving instructions from the attacker’s channel.  
4. **Command Execution / Exfiltration** – Responses from the webhook or attacker messages drive additional actions or data uploads.  
5. **Persistence / Evasion** – Traffic appears as benign API usage; the attacker may rotate URLs or use trusted domains to avoid detection.  

---

## Examples
- **Malicious packages** in npm and PyPI (2025 reports) that exfiltrated developer tokens to Discord webhooks under benign names like “post-install analytics.”  
- **KurayStealer** and similar malware families use Slack and Discord webhooks as lightweight C2 channels to send logs and receive tasks.  
- In an enterprise MCP setup, a backdoored tool could POST conversation summaries to a remote webhook every hour, evading firewall rules because HTTPS egress is permitted.

---

## Impact
| Property | Level | Explanation |
|-----------|-------|-------------|
| Confidentiality | **High** | Sensitive data or tokens can leave the organization undetected via legitimate HTTPS channels |
| Integrity | **Medium** | External commands may alter agent behavior or workflow outputs |
| Availability | **Low** | Usually stealthy and low-bandwidth; minor resource impact |

---

## Detection
**Network Indicators**
- Frequent small HTTPS POSTs to rare domains (e.g., `discord.com`, `webhook.site`, dynamic tunnels like `*.ngrok.io`) from MCP hosts not expected to communicate externally.  
- Unusual SNI or TLS fingerprints in outbound connections.  

**Host Indicators**
- Config files or .env entries containing webhook-like URLs.  
- Tools or scripts embedding HTTP client calls without documented purpose.  

**Example SIEM rule (pseudo-Sigma)**  
```yaml
title: Outbound Webhook C2 Detection
logsource: network/proxy
detection:
  selection:
    url|contains:
      - "discord.com/api/webhooks"
      - "hooks.slack.com/services"
      - "webhook.site"
      - "ngrok.io"
    method: POST
  condition: selection
level: medium
```

---

## Mitigation
**Preventive**
1. Restrict egress from MCP agents to approved domains (HTTP allow-listing).  
2. Proxy all outbound HTTP(S) traffic through a controlled gateway with inspection and rate limits.  
3. Disallow hard-coded webhook URLs in code; require secret stores with rotation and audit trails.  
4. Require manifest review for tools requesting network capabilities.  
5. Implement signed or authenticated webhook payloads and mutual TLS for approved integrations.  

**Detective**
1. Monitor and baseline outbound destinations per server.  
2. Scan source repos and pipelines for webhook URL patterns.  
3. Correlate proxy logs with MCP task timestamps to spot covert beaconing.  

**Response**
- Block or revoke the malicious webhook URL, rotate tokens, and collect forensic logs.  

---

## References
- MITRE ATT&CK – [T1567.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004/)  
- CISA Advisory on Webhook Exfiltration (2024)  
- Invicti Research – *Securing Webhooks Against Abuse* (2023)  
- HackerOne – *Webhook Security Best Practices* (2023)  
- Reports on Malicious npm/PyPI Packages Exfiltrating to Discord (Oct 2025)  
- KurayStealer Analysis – Use of Discord Webhooks as C2 (2023)

---

## MITRE ATT&CK Mapping
**ATT&CK Technique:** T1567.004 – Exfiltration Over Webhook  
**ATT&CK Tactic:** Command and Control (TA0011)**  
