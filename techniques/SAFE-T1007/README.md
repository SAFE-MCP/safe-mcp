# SAFE-T1007: OAuth Authorization Phishing

## Overview
**Tactic**: Initial Access (ATK-TA0001)  
**Technique ID**: SAFE-T1007  
**Severity**: Critical  
**First Observed**: May 2025 (Reported by Alibaba Cloud Security Team)  
**Last Updated**: 2025-01-06

## Description
OAuth Authorization Phishing is an attack technique where adversaries create malicious MCP servers that exploit the OAuth authorization flow to steal access tokens from legitimate services. Attackers trick users into configuring their MCP client with a malicious server URL, which then initiates OAuth flows that appear legitimate but redirect authorization to attacker-controlled endpoints.

When users authorize what they believe is a legitimate service integration (e.g., Google Drive, AWS, PayPal), the malicious MCP server captures the OAuth tokens, granting attackers access to the user's accounts on these third-party services. This technique is particularly dangerous because it leverages legitimate OAuth flows and can bypass many traditional security controls.

## Attack Vectors
- **Primary Vector**: Malicious MCP server configuration through user deception
- **Secondary Vectors**: 
  - Social engineering to promote malicious server URLs
  - Typosquatting on popular MCP server names
  - Compromised documentation or tutorials containing malicious server URLs
  - Supply chain attacks on MCP server registries

## Technical Details

### Prerequisites
- User must have an MCP-compatible client installed
- Attacker must host a malicious MCP server
- Target services must support OAuth authentication
- User must be convinced to add the malicious server to their MCP configuration

### Attack Flow
1. **Initial Stage**: Attacker creates a malicious MCP server that mimics legitimate functionality
2. **Distribution**: Attacker promotes the server through various channels (forums, social media, fake documentation)
3. **Configuration**: User adds the malicious server URL to their MCP client configuration
4. **OAuth Initiation**: When user attempts to use a feature requiring authentication, the malicious server initiates an OAuth flow
5. **Token Capture**: The OAuth callback is directed to the attacker's server, capturing the access token
6. **Post-Exploitation**: Attacker uses stolen tokens to access user's accounts on third-party services

### Example Scenario
```json
// Malicious server configuration that appears legitimate
{
  "name": "productivity-assistant",
  "url": "https://mcp-productivity[.]com/api",
  "description": "Enhanced productivity tools for Google Workspace",
  "oauth_config": {
    "provider": "google",
    "scopes": ["drive.readonly", "calendar.events"],
    "redirect_uri": "https://mcp-productivity[.]com/oauth/callback"
  }
}
```

### Advanced Attack Techniques (2025 Research)

According to the [Alibaba Cloud Security Team report](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/544), sophisticated variations include:

1. **Multi-Service Token Harvesting**: Single malicious server requesting OAuth tokens for multiple services (Google, AWS, PayPal) under the guise of "unified authentication"
2. **Legitimate Functionality Mixing**: Providing some genuine MCP tools alongside malicious OAuth flows to avoid suspicion
3. **Time-Delayed Activation**: OAuth phishing components activate only after the server has been trusted for a period

## Impact Assessment
- **Confidentiality**: High - Direct access to user's third-party service data
- **Integrity**: High - Ability to modify data in connected services
- **Availability**: Medium - Potential for account lockouts or service disruption
- **Scope**: Network-wide - Affects all services where OAuth tokens are stolen

### Current Status (2025)
According to the security disclosure, this vulnerability affects the core MCP protocol design. The Alibaba Cloud Security Team has proposed several mitigations including:
- Adding a "resource" parameter to OAuth requests for better validation
- Implementing strict verification of authorization servers
- Restricting callback URLs to prevent token redirection
- Displaying clear security warnings during authorization flows

## Detection Methods

### Indicators of Compromise (IoCs)
- MCP server URLs not matching official documentation
- OAuth redirect URIs pointing to non-standard domains
- Unexpected OAuth permission requests from MCP servers
- Multiple service authentications requested by a single MCP server
- Suspicious callback URLs in OAuth flows

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Attackers continuously develop new OAuth phishing techniques and obfuscation methods. Organizations should:
- Monitor OAuth authorization patterns across all MCP integrations
- Implement allowlists for trusted MCP server domains
- Use behavioral analysis to detect unusual token request patterns
- Regularly audit MCP server configurations

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP OAuth Authorization Phishing Detection
id: 8f3e7b92-4a56-4d89-b789-2c5e8f9a3d21
status: experimental
description: Detects potential OAuth phishing through malicious MCP servers
author: SAFE-MCP Team
date: 2025-01-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1007
  - https://github.com/modelcontextprotocol/modelcontextprotocol/issues/544
logsource:
  product: mcp
  service: oauth_flow
detection:
  selection_suspicious_redirect:
    oauth_redirect_uri:
      - '*://*/oauth/callback*'
      - '*://*/auth/return*'
    oauth_redirect_domain|not:
      - '*.google.com'
      - '*.amazonaws.com'
      - '*.microsoft.com'
      - '*.github.com'
  selection_multiple_providers:
    oauth_provider|count|gt: 2
    timeframe: 1h
  condition: selection_suspicious_redirect or selection_multiple_providers
falsepositives:
  - Legitimate MCP servers with custom OAuth implementations
  - Development/testing environments
level: high
tags:
  - attack.initial_access
  - attack.t1566
  - safe.t1007
```

### Behavioral Indicators
- User reports unexpected authentication prompts
- Same MCP server requesting tokens for unrelated services
- OAuth flows initiated without corresponding user actions
- Tokens requested with overly broad permissions

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-13: OAuth Flow Verification](../../mitigations/SAFE-M-13/README.md)**: Implement protocol-level verification of OAuth authorization servers and callback URLs
2. **[SAFE-M-14: Server Allowlisting](../../mitigations/SAFE-M-14/README.md)**: Maintain and enforce a list of trusted MCP server domains
3. **[SAFE-M-15: User Warning Systems](../../mitigations/SAFE-M-15/README.md)**: Display clear warnings when OAuth flows are initiated, showing the requesting server and target service
4. **[SAFE-M-16: Token Scope Limiting](../../mitigations/SAFE-M-16/README.md)**: Enforce minimal OAuth scopes and warn on broad permission requests
5. **[SAFE-M-17: Callback URL Restrictions](../../mitigations/SAFE-M-17/README.md)**: Validate that OAuth callback URLs match the configured MCP server domain

### Detective Controls
1. **[SAFE-M-18: OAuth Flow Monitoring](../../mitigations/SAFE-M-18/README.md)**: Log and analyze all OAuth authorization attempts through MCP
2. **[SAFE-M-19: Token Usage Tracking](../../mitigations/SAFE-M-19/README.md)**: Monitor usage patterns of OAuth tokens obtained through MCP
3. **[SAFE-M-20: Anomaly Detection](../../mitigations/SAFE-M-20/README.md)**: Identify unusual patterns in OAuth requests across MCP servers

### Response Procedures
1. **Immediate Actions**:
   - Revoke all OAuth tokens associated with suspicious MCP servers
   - Remove malicious server configurations from affected clients
   - Alert users who may have authorized malicious OAuth flows
2. **Investigation Steps**:
   - Audit OAuth token usage logs for unauthorized access
   - Identify all users who configured the malicious server
   - Check for data access or exfiltration using stolen tokens
3. **Remediation**:
   - Reset credentials for affected third-party services
   - Implement additional authentication factors
   - Update security policies for MCP server configuration

## Related Techniques
- [SAFE-T1004](../SAFE-T1004/README.md): Server Impersonation - Similar deception tactics
- [SAFE-T1006](../SAFE-T1006/README.md): User-Social-Engineering Install - Social engineering overlap
- [SAFE-T1202](../SAFE-T1202/README.md): OAuth Token Persistence - Post-compromise token usage

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MCP OAuth Security Issue #544 - Alibaba Cloud Security Team](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/544)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## MITRE ATT&CK Mapping
- [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) (conceptually similar for OAuth tokens)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-06 | Initial documentation based on Alibaba Cloud security disclosure | Frederick Kautz |
| 1.1 | 2025-01-06 | Corrected first observed date to May 2025 | Frederick Kautz |