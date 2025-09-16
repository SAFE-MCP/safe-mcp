# SAFE-T1707: CSRF Token Relay

## Overview
**Tactic**: Lateral Movement (ATK-TA0008)  
**Technique ID**: SAFE-T1707  
**Severity**: High  
**First Observed**: Not observed in production  
**Last Updated**: 2025-08-10

## Description
CSRF Token Relay is a lateral movement technique where an adversary reuses or relays an OAuth access token (or equivalent bearer credential) via Cross-Site Request Forgery (CSRF) to access different resources within the same Resource Server. This often manifests as cross-project or cross-tenant actions that the token technically permits due to insufficient audience or resource-context binding. For example, a token issued for user Alice’s Google Cloud Project "beta" is relayed through a CSRF request to perform actions in Project "alpha" under the same Resource Server domain.

In MCP environments, this can occur when:
- Tokens issued via MCP-integrated OAuth flows are leaked (logs, browser storage, debug tools) or can be coerced into use by a victim browser via CSRF.
- Resource Servers accept bearer tokens without sufficiently binding them to a specific resource context (e.g., project/account/tenant) or without validating anti-CSRF protections, SameSite cookie policies, and origin/referer.
- Clients and servers lack strict verification of resource identifiers against token claims.

## Attack Vectors
- **Primary Vector**: CSRF-request initiated from attacker-controlled origin leveraging a valid bearer token to execute actions against a different resource context on the same Resource Server
- **Secondary Vectors**:
  - Token leakage from logs, crash reports, local storage, or developer tools
  - OAuth flow weaknesses (mix-up, inadequate audience/resource binding)
  - Weak SameSite cookie configuration enabling cross-site requests
  - Insufficient cross-project/tenant validation on Resource Server endpoints

## Technical Details

### Prerequisites
- Valid OAuth access token (or session token) for the target Resource Server
- Victim user’s browser able to send authenticated requests (cookies or ambient auth) or exposed bearer token
- Resource Server endpoints that accept the token without strict resource-context checks or CSRF protections

### Attack Flow
1. **Token Acquisition**: Attacker obtains or can induce use of a valid token (leakage or ambient session in victim browser)
2. **Craft CSRF**: Attacker hosts a page that auto-submits requests to the Resource Server (POST/PUT/DELETE) with the token/cookies
3. **Context Mismatch**: Request targets a different project/account/tenant than the token’s intended resource context
4. **Exploitation**: Server performs privileged action due to missing or weak CSRF checks and insufficient token-to-resource binding
5. **Post-Exploitation**: Attacker pivots laterally within the same Resource Server (e.g., across projects), escalating impact

### Example Scenario
```http
POST /api/projects/alpha/storage/upload HTTP/1.1
Host: resource.example.com
Authorization: Bearer eyJhbGciOi...
Origin: https://attacker.example
Referer: https://attacker.example/csrf
Content-Type: application/json

{"path":"/configs/secrets.json","content":"..."}
```

Token claim shows `project_id: "beta"` but request targets `/projects/alpha/...`. Missing anti-CSRF token and overly-permissive SameSite cookie settings let the request succeed.

### Advanced Attack Techniques (2024–2025)
According to security guidance and prior OAuth research:
1. **Authorization Server Mix-up & Audience Drift**: Confusion between authorization and resource servers can result in tokens accepted in broader contexts than intended
2. **SameSite and Referer Origin Weaknesses**: Lax or None SameSite cookies and permissive origin/referrer checks enable CSRF execution paths
3. **Cross-Project Token Reuse**: Tokens lacking a strong resource-context claim (e.g., project/tenant) are re-used across multiple resource identifiers under the same domain

## Impact Assessment
- **Confidentiality**: High – Unauthorized access to data across projects/tenants
- **Integrity**: High – Unauthorized modifications within adjacent resource contexts
- **Availability**: Medium – Potential destructive operations across multiple projects
- **Scope**: Network-wide – Lateral movement within the same Resource Server across projects/tenants

### Current Status (2025)
Organizations are hardening OAuth and CSRF defenses:
- Adoption of strict SameSite cookie policies and anti-CSRF tokens
- Stronger token audience/resource-context binding (claims for project/account/tenant) and server-side enforcement
- Centralized monitoring of token usage patterns across resource contexts

## Detection Methods

### Indicators of Compromise (IoCs)
- Bearer token used across multiple distinct `project_id`/tenant contexts in a short time window
- Sensitive state-changing HTTP requests (POST/PUT/DELETE) without valid anti-CSRF tokens
- External `Origin`/`Referer` initiating privileged actions against Resource Server
- Mismatch between token claims (audience/resource) and targeted resource identifiers in path/headers

### Detection Rules

Important: The rule below is an example only. Detection should be paired with behavioral analytics and server-side validation.

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP CSRF Token Relay Across Resource Contexts
id: 7e4f8a10-5089-4a5c-bc0b-8f2a8c2a7c1f
status: experimental
description: Detects potential CSRF token relay where a bearer token is used across different projects/tenants on the same Resource Server
author: SAFE-MCP Team
date: 2025-08-10
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1707
logsource:
  product: mcp
  service: resource_access
detection:
  selection_csrf_like:
    http.method:
      - 'POST'
      - 'PUT'
      - 'DELETE'
    csrf.present: false
    referer.external: true
  selection_project_mismatch:
    token.project_id_mismatch: true  # Derived when token.project_id != resource.project_id/path
  selection_token_reuse_cross_project:
    token.reused_across_projects: true  # Derived when same token_id touches >1 project within 10m
  condition: selection_project_mismatch or selection_token_reuse_cross_project or selection_csrf_like
falsepositives:
  - Legitimate administrative automation that rotates through multiple projects using the same token by design
  - Testing environments with relaxed CSRF and SameSite settings
level: high
tags:
  - attack.lateral_movement
  - safe.t1707
```

### Behavioral Indicators
- Same `token_id` or `Authorization` credential rapidly touches many projects/tenants
- Privileged actions originate from unusual `Origin`/`Referer`
- Requests missing anti-CSRF tokens but succeeding on state-changing endpoints

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-13: OAuth Flow Verification](../../mitigations/SAFE-M-13/README.md)**: Validate authorization servers and callback URLs; enforce audience/resource binding
2. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)**: Minimize scopes; include resource-context (project/tenant) claims and enforce on server
3. **[SAFE-M-17: Callback URL Restrictions](../../mitigations/SAFE-M-17/README.md)**: Reduce attack surface in OAuth flows; prevent token leakage via open redirects
4. **[SAFE-M-18: OAuth Flow Monitoring](../../mitigations/SAFE-M-18/README.md)**: Monitor authorization events that could precede token relay
5. Enforce anti-CSRF tokens and strict SameSite cookie policies for state-changing endpoints
6. Validate `Origin`/`Referer` and require per-request nonces for sensitive operations

### Detective Controls
1. **[SAFE-M-19: Token Usage Tracking](../../mitigations/SAFE-M-19/README.md)**: Track token usage across resource contexts; alert on cross-project use
2. **[SAFE-M-20: Anomaly Detection](../../mitigations/SAFE-M-20/README.md)**: Behavioral analytics for rapid context switching or unusual origins
3. Server-side validation that rejects requests when `token.project_id` mismatches the targeted resource

### Response Procedures
1. **Immediate Actions**:
   - Invalidate/revoke affected tokens; force re-authentication
   - Temporarily disable sensitive endpoints exploited via CSRF
   - Enable heightened validation for project/tenant checks
2. **Investigation Steps**:
   - Correlate `token_id` usage across projects/tenants and time windows
   - Review referer/origin patterns; confirm anti-CSRF configuration gaps
   - Identify data modifications and affected resources
3. **Remediation**:
   - Strengthen token audience/resource binding and CSRF protections
   - Deploy alerts for cross-project token use
   - Conduct developer training on OAuth and CSRF hardening

## Related Techniques
- [SAFE-T1706](../SAFE-T1706/README.md): OAuth Token Pivot Replay – Cross-service replay
- [SAFE-T1007](../SAFE-T1007/README.md): OAuth Authorization Phishing – Token theft vector
- [SAFE-T1307](../SAFE-T1307/README.md): Confused Deputy Attack – Misapplied authority

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP Cheat Sheet: CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## MITRE ATT&CK Mapping
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) (conceptually similar via token replay/relay)

## Version History
| Version | Date       | Changes                                      | Author            |
|---------|------------|----------------------------------------------|-------------------|
| 1.0     | 2025-08-10 | Initial documentation of CSRF Token Relay    | SAFE-MCP Team     |


