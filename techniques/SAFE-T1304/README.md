# SAFE-T1304: Credential Relay Chain

## Overview
**Tactic**: Privilege Escalation (ATK-TA0004)  
**Technique ID**: SAFE-T1304  
**Severity**: High  
**First Observed**: Not observed in production  
**Last Updated**: 2025-01-02

## Description
Credential Relay Chain is a privilege escalation technique where adversaries use one MCP tool to steal authentication tokens or credentials, then feed those stolen credentials to a second tool that operates with higher privileges. This technique exploits the trust relationships between different MCP tools and their associated services to escalate from limited access to elevated permissions.

The attack leverages the fact that MCP tools often share authentication contexts or can be chained together to perform operations that individually would be restricted. By stealing credentials from a lower-privilege tool and relaying them to a higher-privilege tool, attackers can bypass intended access controls and gain unauthorized elevated access.

## Attack Vectors
- **Primary Vector**: OAuth token theft and relay between MCP tools
- **Secondary Vectors**: 
  - Session token interception and replay
  - API key extraction and cross-tool usage
  - JWT token manipulation and relay
  - Service account credential theft and escalation

## Technical Details

### Prerequisites
- Access to at least one MCP tool with credential access capabilities
- Knowledge of available higher-privilege tools in the MCP environment
- Understanding of authentication mechanisms used by target services

### Attack Flow

```mermaid
graph TD
    A[Attacker] -->|Discovers| B[Low-Privilege MCP Tool]
    B -->|Has Access to| C[Authentication Tokens/Credentials]
    
    C -->|Type 1| D[OAuth Access Tokens]
    C -->|Type 2| E[Session Cookies]
    C -->|Type 3| F[API Keys]
    C -->|Type 4| G[JWT Tokens]
    
    A -->|Identifies| H[High-Privilege MCP Tool]
    H -->|Requires| I[Elevated Permissions]
    
    C -->|Relay/Replay| J[Stolen Credentials]
    J -->|Used with| H
    
    H -->|With Stolen Creds| K[Unauthorized Elevated Access]
    
    K -->|Enables| L{Privilege Escalation}
    L -->|Result 1| M[Admin Operations]
    L -->|Result 2| N[Data Exfiltration]
    L -->|Result 3| O[System Modification]
    L -->|Result 4| P[Further Lateral Movement]
    
    style A fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style B fill:#fc8d59,stroke:#000,stroke-width:2px,color:#000
    style H fill:#fc8d59,stroke:#000,stroke-width:2px,color:#000
    style K fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style L fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
```

1. **Initial Stage**: Attacker identifies and gains access to a low-privilege MCP tool
2. **Credential Discovery**: Tool is used to extract or intercept authentication tokens/credentials
3. **Tool Enumeration**: Attacker identifies higher-privilege MCP tools that could use the stolen credentials
4. **Credential Relay**: Stolen credentials are fed to the higher-privilege tool
5. **Privilege Escalation**: Higher-privilege tool executes operations with elevated permissions

### Example Scenario
```json
{
  "tool_chain": {
    "step_1": {
      "tool": "github_reader",
      "privilege_level": "read_only",
      "action": "extract_oauth_token",
      "result": "gho_16C7e42F292c6912E7710c838347Ae178B4a"
    },
    "step_2": {
      "tool": "github_admin",
      "privilege_level": "admin",
      "action": "use_stolen_token",
      "stolen_credential": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
      "result": "unauthorized_admin_access"
    }
  }
}
```

### Advanced Attack Techniques (2024 Research)

According to research from [OWASP OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) and [MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550/), attackers have developed sophisticated credential relay techniques:

1. **Cross-Service Token Relay**: Using tokens intended for one service to access another service through shared authentication infrastructure ([OWASP OAuth Security](https://owasp.org/www-project-oauth-security/))
2. **Token Scope Escalation**: Exploiting insufficient scope validation to use limited-scope tokens for broader operations ([RFC 6749 OAuth 2.0](https://tools.ietf.org/html/rfc6749))
3. **JWT Token Manipulation**: Modifying JWT claims to escalate privileges while maintaining valid signatures ([JWT Security Best Practices](https://tools.ietf.org/html/rfc8725))

## Impact Assessment
- **Confidentiality**: High - Unauthorized access to sensitive data through elevated privileges
- **Integrity**: High - Ability to modify systems and data with admin-level access
- **Availability**: Medium - Potential for service disruption through unauthorized administrative actions
- **Scope**: Network-wide - Can affect multiple services and systems through privilege escalation

### Current Status (2025)
According to security researchers, organizations are implementing mitigations:
- OAuth 2.1 specification includes enhanced security measures for token handling ([OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))
- JWT Best Current Practices (RFC 8725) provide guidance on secure token handling ([RFC 8725](https://tools.ietf.org/html/rfc8725))
- MITRE ATT&CK framework includes detection techniques for credential relay attacks ([MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550/))

## Detection Methods

### Indicators of Compromise (IoCs)
- Unusual token usage patterns across different MCP tools
- Authentication tokens being used outside their intended scope
- Rapid escalation from low-privilege to high-privilege operations
- Cross-service authentication using tokens from different sources
- JWT tokens with modified claims or unusual privilege levels

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new evasion techniques and obfuscation methods. Organizations should:
- Use AI-based anomaly detection to identify novel credential relay patterns
- Regularly update detection rules based on threat intelligence
- Implement multiple layers of detection beyond pattern matching
- Consider behavioral analysis of token usage patterns

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Credential Relay Chain Detection
id: 7B67EA0A-2966-4251-8522-77FCA3434801
status: experimental
description: Detects potential credential relay attacks between MCP tools
author: SAFE-MCP Team
date: 2025-01-02
references:
  - https://github.com/pritikabista/safe-mcp/blob/main/techniques/SAFE-T1304/README.md
logsource:
  product: mcp
  service: authentication
detection:
  selection:
    token_usage:
      - '*oauth_token*'
      - '*bearer_token*'
      - '*jwt_token*'
    cross_tool_usage:
      - '*different_tool_same_token*'
      - '*token_scope_violation*'
    privilege_escalation:
      - '*rapid_privilege_increase*'
      - '*admin_operations_after_token_theft*'
  condition: selection
falsepositives:
  - Legitimate cross-service authentication with proper authorization
  - Normal token refresh operations
  - Authorized privilege escalation workflows
level: high
tags:
  - attack.privilege_escalation
  - attack.t1550
  - safe.t1304
```

### Behavioral Indicators
- MCP tools accessing resources outside their normal scope
- Authentication tokens being used by multiple tools simultaneously
- Unusual timing patterns in token usage (immediate relay after theft)
- Cross-service operations using tokens from different authentication contexts

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-1: Architectural Defense - CaMeL](../../mitigations/SAFE-M-1/README.md)**: Implement control/data flow separation to prevent unauthorized credential sharing between tools
2. **[SAFE-M-2: Cryptographic Integrity](../../mitigations/SAFE-M-2/README.md)**: Use cryptographically bound tokens that cannot be relayed to unauthorized tools
3. **[SAFE-M-6: Tool Registry Verification](../../mitigations/SAFE-M-6/README.md)**: Implement strict access controls and privilege separation between MCP tools
4. **[SAFE-M-12: Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Log all token usage and cross-tool authentication attempts
5. **Token Scope Validation**: Implement strict scope validation to prevent tokens from being used outside their intended purpose ([OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics))
6. **Proof of Possession (PoP) Tokens**: Use PoP tokens that bind authentication to specific clients and prevent relay attacks ([RFC 7800](https://tools.ietf.org/html/rfc7800))
7. **Short Token Lifetimes**: Implement short-lived tokens with frequent rotation to limit the window for relay attacks ([OAuth 2.1 Security](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))

### Detective Controls
1. **[SAFE-M-10: Automated Scanning](../../mitigations/SAFE-M-10/README.md)**: Regularly scan for unusual token usage patterns and cross-tool authentication
2. **[SAFE-M-11: Behavioral Monitoring](../../mitigations/SAFE-M-11/README.md)**: Monitor for rapid privilege escalation and unusual authentication patterns
3. **Token Usage Analytics**: Implement analytics to detect tokens being used outside their intended scope or by unexpected tools
4. **Cross-Service Authentication Monitoring**: Monitor for authentication attempts across different services using the same tokens

### Response Procedures
1. **Immediate Actions**:
   - Revoke compromised tokens immediately
   - Disable affected MCP tools
   - Alert security team of potential privilege escalation
2. **Investigation Steps**:
   - Analyze token usage logs for relay patterns
   - Identify all tools that may have used stolen credentials
   - Trace the source of credential theft
3. **Remediation**:
   - Implement additional token validation controls
   - Review and strengthen privilege separation between tools
   - Update detection rules based on attack patterns

## Related Techniques
- [SAFE-T1504](../SAFE-T1504/README.md): Token Theft via API Response - Common method for initial credential acquisition
- [SAFE-T1301](../SAFE-T1301/README.md): Cross-Server Tool Shadowing - Related privilege escalation technique
- [SAFE-T1706](../SAFE-T1706/README.md): OAuth Token Pivot Replay - Similar cross-service token usage

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OAuth 2.0 Security Best Practices - IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.1 Security Best Practices - IETF Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7800 - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7800)
- [RFC 8725 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc8725)
- [MITRE ATT&CK T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [JWT Security Best Practices - Auth0](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

## MITRE ATT&CK Mapping
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1550.002 - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) (conceptually similar)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-02 | Initial documentation of credential relay chain technique | pritikabista |
