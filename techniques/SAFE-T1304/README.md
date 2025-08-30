# SAFE-T1304: Credential Relay Chain

## Overview
**Tactic**: Privilege Escalation (ATK-TA0004)  
**Technique ID**: SAFE-T1304  
**Severity**: High  
**First Observed**: 2025 (Threat modeling)  
**Last Updated**: 2025-08-16

## Description
In a Credential Relay Chain, an attacker harvests a valid credential or token from one MCP tool/server and **reuses (relays)** it with another tool that has broader permissions or crosses a different trust boundary.  
In practice: a low-privilege tool exposes or returns a token → the model copies it into a call to a higher-privilege tool → the second tool accepts the token and performs sensitive actions (admin APIs, data export, configuration changes).

## Preconditions
- A tool/server can reveal credentials or tokens in **outputs, logs, errors, or files**.
- The receiving tool **accepts bearer-style tokens** (or similar) without strong binding to a specific client, audience, or session.
- Weak or missing controls around **audience/scope validation**, token lifetime, or proof-of-possession (e.g., no DPoP/mTLS).
- (Often) **Over-privileged** receiving tool or misconfigured permissions.

## Attack Vectors
- **Prompt-assisted exfiltration**: attacker induces a tool to print secrets/tokens (e.g., log reader, debug output).
- **Error/trace leakage**: tokens appear in stack traces or verbose error pages returned by a tool.
- **File/log scraping**: tokens stored in workspace files, temp dirs, or previous run logs.
- **Cross-server relay**: one MCP server harvests; a different server/tool **spends** the token.
- **Scope substitution**: token accepted for a broader audience or with more permissive scopes than intended.

## Technical Details

### Prerequisites
- Tool A can surface a token (output, file, log, error).
- Tool B accepts presented tokens with **insufficient verification** (audience, issuer, client binding).
- The model/runtime can pass values from Tool A into Tool B without quarantine or redaction.

### Attack Flow
1. **Reconnaissance** — Identify Tool A that can reveal tokens (log readers, debug tools, file tools).  
2. **Harvest** — Use prompt injection or normal function to have Tool A return a token/credential.  
3. **Relay** — Provide that token to Tool B (higher privilege or different trust boundary).  
4. **Abuse** — Invoke privileged operations via Tool B (admin/config/data exfiltration).  
5. **Persistence/Cover** — Reuse/refesh tokens, minimize traces, or pivot further.

### Example Scenario
- Tool A: `log_reader` returns recent application logs including an **OAuth access token**.  
- Tool B: `cloud_admin` accepts bearer tokens for the same provider and can create users, rotate keys, or export data.  
- The model copies the token from A → B; B executes high-impact admin actions.

## Impact Assessment
- **Confidentiality**: High — access to protected data/services using a legitimate token.  
- **Integrity**: High — unauthorized admin/config changes via the relayed credential.  
- **Availability**: Medium — destructive or resource-exhausting actions possible.  
- **Scope**: Potentially organization-wide if the relayed token grants broad access.

## Affected Systems / Components
- MCP tools exposing content from **logs, files, traces, error pages**.  
- Tools with **administrative APIs** and **bearer-token** authentication.  
- Multi-tool chains where outputs are not **sanitized or isolated** before reuse.

## Current Status (2025)
- Increasing awareness of **secret/credential hygiene** across MCP tools.
- Emerging guidance to **bind** tokens to client or audience and to **minimize scopes**.
- More tools adopting **output isolation** and **semantic validation** to stop secret relay.

## Detection Methods

### Indicators of Compromise (IoCs)
- Tool outputs containing **token-shaped strings** (e.g., JWT-like base64 patterns).
- Short-interval sequences where a token appears in Tool A output and is then used by Tool B.
- **Privilege jumps** (e.g., read-only → admin calls) across adjacent tool invocations.
- New/unknown **audience/issuer** combinations accepted by Tool B.

### Sigma Rule Example (illustrative)
```yaml
title: SAFE-T1304 Credential Relay Chain (Token Surfaced → Token Spent)
id: safe-t1304-credential-relay
status: experimental
description: Detects token-like strings in one tool output followed by privileged calls in another tool
author: SAFE-MCP Team
date: 2025-08-16
logsource:
  product: mcp
  service: tool_pipeline
detection:
  token_surface:
    tool_name:
      - log_reader
      - file_reader
      - debug_dumper
    output:
      - '*eyJ*.*'           # JWT-like pattern (simplified)
      - '*access_token*'
  privileged_use:
    tool_name:
      - cloud_admin
      - config_admin
      - data_exporter
    action:
      - 'create_*'
      - 'delete_*'
      - 'rotate_*'
      - 'export_*'
  timeframe: 5m
  condition: token_surface followed_by privileged_use within timeframe
falsepositives:
  - Test data containing mock tokens
  - Masked tokens that match patterns but are unusable
level: high
