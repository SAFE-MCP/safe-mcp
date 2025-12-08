# SAFE-T1701: Cross-Tool Contamination

## Overview

**Tactic**: Lateral Movement (ATK-TA0008)  
**Technique ID**: SAFE-T1701  
**Severity**: High  
**First Observed**: June 2024 (industry incident reports)  
**Last Updated**: 2025-11-08

## Description

Cross-Tool Contamination occurs when an adversary compromises a single MCP tool and then reuses cached credentials, shared capabilities, or implicit trust relationships to act as other tools or services in the same workspace. Many MCP deployments cache OAuth refresh tokens, API keys, or signed capabilities in shared filesystems or environment variables so tools can operate without repeated user consent. Attackers exploit that convenience: once a foothold is obtained—via prompt injection, malicious packages, or tampered server registration—they silently harvest those artifacts and call downstream connectors without triggering fresh approval prompts.

OWASP’s Top 10 for LLM Applications and LangChain’s security guidance both highlight the risk of insecure plugin composition, where untrusted connectors inherit privileged context. Combined with gaps referenced in the NIST AI Risk Management Framework, the result is a lateral movement surface that lets a “low-risk” helper tool pivot into cloud administration APIs, SaaS tenants, or CI/CD pipelines that were never meant to be within scope.

## Attack Vectors

- **Primary Vector**: Compromised MCP tool reuses shared authentication material (OAuth tokens, API keys, signed capabilities) to access higher-privilege services.
- **Secondary Vectors**:
  - Misconfigured tool-to-tool delegation policies that auto-approve downstream invocations.
  - Shared scratchpads/vector memories where a poisoned tool plants follow-on instructions.
  - IDE or agent frameworks that mount identical filesystems for every tool with no sandboxing.
  - Workflow orchestrators that allow any registered tool to schedule jobs across tenants or projects.
  - Reuse of long-lived service principals whose secrets are stored in globally readable config files.

## Technical Details

### Prerequisites

- Attacker controls or coerces execution of at least one MCP tool (prompt injection, malicious server image, signed artifact hijack).
- Cached credentials or implicit trust relationships exist between tools (shared files, environment variables, secrets managers).
- Logging/monitoring does not enforce per-tool scopes, audience checks, or proof-of-possession tokens.
- Network egress or inter-process communication from the compromised tool is not tightly filtered.

### Attack Flow

1. **Entry Vector**: Gain control of a tool via prompt injection, trojanized package, or tampered MCP server registration.
2. **Credential Harvest**: Enumerate cached tokens, shared environment variables, or delegated capabilities exposed to the tool runtime.
3. **Discovery**: Use MCP discovery endpoints or local configs to map additional tools/services and their required scopes.
4. **Pivot Execution**: Replay or exchange harvested credentials to impersonate another tool, or call privileged REST/gRPC endpoints directly.
5. **Post-Pivot Actions**: Deploy persistence (cron jobs, vector payloads), exfiltrate data, or trigger workflows across tenants/projects.

```mermaid
graph TD
    A[Attacker Entry] -->|Prompt injection / malicious server| B[Compromised MCP Tool]
    B -->|Enumerates| C[Shared Credential Cache]
    C -->|Exposes| D[Cached OAuth Tokens / API Keys]
    D -->|Replay tokens / capabilities| E[Privileged Tool or API]
    E -->|Invoke| F[Target Services & Tenants]
    F -->|Return data / control| G[Extended Foothold]
    G -->|Plant| H[Automation Jobs / Vector Payloads]
    G -->|Trigger| I[Cross-Tenant Workflows]
    H -->|Updates| J[Shared Context Stores]
    J -->|Feeds secrets / instructions back to| C

    style A fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style B fill:#fc8d59,stroke:#000,stroke-width:1px,color:#000
    style C fill:#fee090,stroke:#000,stroke-width:1px,color:#000
    style D fill:#fee090,stroke:#000,stroke-width:1px,color:#000
    style E fill:#91bfdb,stroke:#000,stroke-width:1px,color:#000
    style F fill:#74add1,stroke:#000,stroke-width:1px,color:#000
    style G fill:#4575b4,stroke:#000,stroke-width:1px,color:#fff
    style H fill:#abd9e9,stroke:#000,stroke-width:1px,color:#000
    style I fill:#abd9e9,stroke:#000,stroke-width:1px,color:#000
    style J fill:#fee090,stroke:#000,stroke-width:1px,color:#000
```

### Example Scenario

```json
{
  "entry_tool": {
    "name": "markdown_helper",
    "scopes": ["read_repo"],
    "compromise": "prompt_injection"
  },
  "shared_secret_store": {
    "location": "~/.mcp/creds.json",
    "contains": ["aws_ops_role", "prod_ci_pat"],
    "permissions": "readable_by_all_tools"
  },
  "pivot": {
    "target_tool": "deployment_admin",
    "required_scope": "cloud:DeployFull",
    "method": "reuse aws_ops_role STS token"
  },
  "impact": {
    "action": "scale malicious container image across staging+prod",
    "scope": "multi-cluster"
  }
}
```

## Impact Assessment

- **Confidentiality**: High – pivot grants unauthorized access to data owned by other tools, tenants, or SaaS connectors.
- **Integrity**: High – attacker can modify infrastructure, repositories, or automation pipelines controlled by the privileged tools.
- **Availability**: Medium – misuse of deployment/automation connectors can degrade environments, but destructive impact usually requires intent.
- **Scope**: Network-wide – a single workspace compromise can fan out across multiple services, tenants, or environments.

### Current Status (2025)
LangChain’s published [security policy](https://docs.langchain.com/oss/python/security-policy) focuses on disclosure channels and baseline security expectations, underscoring that frameworks still leave per-tool credential isolation and outbound server allowlisting to the MCP operators who deploy them—defaults often remain permissive until administrators intervene.

## Detection Methods

### Indicators of Compromise (IoCs)

- Low-privilege tools invoking APIs or resources normally reserved for administrative connectors.
- Sudden reuse of OAuth tokens/audiences by unrelated tool IDs within short intervals.
- Creation of automation jobs, deployments, or file writes where the initiating tool differs from the owning policy entry.
- MCP metadata showing tool context switches without corresponding human approval events.

### Detection Rules

Use Sigma-style analytics to correlate scope changes and token reuse. A full example lives in [`detection-rule.yml`](./detection-rule.yml) for easy ingestion.

> **Important**: Field names differ across MCP implementations; treat the rule as a starting point and pair it with behavioral analytics.

```yaml
title: Cross-Tool Contamination Pivot Detection
id: 3c6bb58a-b827-4897-8fdb-2796e03bebc8
status: experimental
description: Detects low-scope MCP tools reusing cached credentials to access higher-scope services inside short sessions
logsource:
  product: mcp
  service: tool_runtime
detection:
  selection_cross_scope:
    source_tool_scope:
      - read_only
      - helper
    dest_tool_scope:
      - admin
      - cloud_superuser
  selection_token_reuse:
    oauth_audience_mismatch: true
    replayed_token: true
  condition: selection_cross_scope and selection_token_reuse
falsepositives:
  - Emergency break-glass sessions that legitimately elevate helper tools
  - Maintenance windows where automation temporarily inherits admin scopes
level: high
tags:
  - attack.lateral_movement
  - attack.t1078
  - attack.t1550
  - safe.t1701
```

### Behavioral Indicators

- Tool invocation graphs that suddenly widen (fan-out) relative to historical baselines.
- Repeated authentication failures followed by success when a tool calls unfamiliar connectors, indicating token discovery.
- Simultaneous updates to secrets/config maps by multiple tool identities tied to the same user session.
- “System” messages instructing the LLM to reuse cached credentials or ignore capability boundaries.

## Mitigation Strategies

### Preventive Controls

1. **[SAFE-M-29: Explicit Privilege Boundaries](../../mitigations/SAFE-M-29/README.md)** – Enforce deny-by-default interaction policies so tools cannot automatically call higher-privilege connectors.
2. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)** – Issue short-lived, least-privilege OAuth scopes per tool and isolate secret storage.
3. **[SAFE-M-14: Server Allowlisting](../../mitigations/SAFE-M-14/README.md)** – Restrict outbound MCP connections so compromised tools cannot register rogue servers as pivots.
4. **[SAFE-M-1: Architectural Defense](../../mitigations/SAFE-M-1/README.md)** – Separate control/data planes so untrusted tool data cannot implicitly grant execution over other connectors.

### Detective Controls

1. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)** – Baseline per-tool call patterns and alert on sudden privilege jumps or cross-tenant access.
2. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)** – Capture tool identity, audiences, and token metadata for every invocation to support forensics.
3. **[SAFE-M-3: AI-Powered Content Analysis](../../mitigations/SAFE-M-3/README.md)** – Inspect tool outputs/instructions for signs of credential harvesting or hidden pivot directives.

### Response Procedures

1. **Immediate Actions**:
   - Revoke shared tokens/credentials exposed to the contaminated tool.
   - Quarantine or disable affected tools/servers in the MCP client registry.
2. **Investigation Steps**:
   - Trace tool invocation graphs to identify impacted services post-compromise.
   - Compare audit logs to policy to find unauthorized privilege escalations or token reuse.
3. **Remediation**:
   - Rotate secrets in downstream services and reissue scoped credentials per tool.
   - Update privilege boundary policies and monitoring dashboards to close observed gaps.

## Related Techniques

- [SAFE-T1703](../SAFE-T1703/README.md): Tool-Chaining Pivot builds on similar trust relationships once contamination succeeds.
- [SAFE-T1104](../SAFE-T1104/README.md): Over-Privileged Tool Abuse supplies the excessive access required for pivots.
- [SAFE-T1501](../SAFE-T1501/README.md): Full-Schema Poisoning can plant the malicious instructions that trigger contamination.

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
- [LangChain Security Guidance](https://python.langchain.com/docs/security/)

## MITRE ATT&CK Mapping

- [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1550 – Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1528 – Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

## Version History

| Version | Date       | Changes                                                                      | Author            |
| ------- | ---------- | ---------------------------------------------------------------------------- | ----------------- |
| 1.0     | 2025-11-08 | Initial documentation covering description, flow, detection, and mitigations | Shekhar Chaudhary |
