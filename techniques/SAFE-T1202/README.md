# SAFE-T1202: OAuth Token Persistence

## Overview
**Tactic**: Persistence (ATK-TA0003)  
**Technique ID**: SAFE-T1202  
**Severity**: High  
**First Observed**: 2021 (Academic research documented by Fett et al.)  
**Last Updated**: 2025-09-06

## Description
OAuth Token Persistence is a technique where adversaries steal and reuse OAuth access/refresh tokens for persistent access to MCP-connected services, including replay of refresh tokens after legitimate client sessions end. This attack exploits the long-lived nature of OAuth refresh tokens and the trust relationships established between MCP servers and external services.

Unlike traditional session hijacking that typically affects single applications, OAuth token persistence in MCP environments enables adversaries to maintain unauthorized access across multiple interconnected services through the protocol's standardized authentication mechanisms. The attack is particularly concerning in MCP deployments where refresh tokens may have extended validity periods (up to 90 days) and can be used to mint new access tokens without user interaction.

## Attack Vectors
- **Primary Vector**: Theft of OAuth refresh tokens from compromised MCP servers or client applications
- **Secondary Vectors**: 
  - Browser-based token extraction from local storage or memory
  - Man-in-the-middle attacks during OAuth flows
  - Malware-based credential harvesting (infostealers)
  - Social engineering attacks targeting OAuth authorization flows
  - Cross-Site Scripting (XSS) attacks to steal tokens from web applications
  - Compromise of MCP server infrastructure storing authentication tokens

## Technical Details

### Prerequisites
- Target MCP server or client application uses OAuth 2.0 for authentication
- Refresh tokens are stored in accessible locations (browser storage, application memory, or server databases)
- Tokens have extended validity periods typical in OAuth implementations
- Insufficient token binding or device attestation mechanisms

### Attack Flow
1. **Initial Access**: Adversary gains access to OAuth tokens through various vectors (malware, phishing, XSS, or server compromise)
2. **Token Extraction**: Adversary extracts refresh tokens from browser storage, application memory, or server databases
3. **Token Validation**: Adversary validates stolen tokens by attempting to refresh access tokens
4. **Persistence Establishment**: Adversary uses refresh tokens to maintain long-term access to MCP-connected services
5. **Access Expansion**: Adversary leverages Family of Client IDs (FOCI) or similar mechanisms to access additional services within the same ecosystem
6. **Post-Exploitation**: Adversary conducts data exfiltration, privilege escalation, or lateral movement using persistent access

### Example Scenario
```json
{
  "attack_type": "oauth_token_persistence",
  "target": "mcp_gmail_server",
  "stolen_token": {
    "refresh_token": "1//04_refresh_token_example",
    "client_id": "123456789.apps.googleusercontent.com",
    "scope": "https://www.googleapis.com/auth/gmail.readonly",
    "expires_in": 7776000
  },
  "persistence_duration": "90_days",
  "impact": "continuous_email_access_without_user_awareness"
}
```

### Advanced Attack Techniques (2024-2025 Research)

According to research from [Secureworks](https://github.com/secureworks/family-of-client-ids-research) and [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/), attackers have developed sophisticated OAuth token persistence methods:

1. **Family of Client IDs (FOCI) Exploitation**: Using undocumented Microsoft Azure AD refresh token behavior where tokens issued to one client in a "family" can be redeemed for access tokens to other clients in the same family ([Secureworks, 2022](https://github.com/secureworks/family-of-client-ids-research))
2. **Primary Refresh Token (PRT) Theft**: Targeting Windows 10+ devices to steal PRTs that provide SSO access across Microsoft applications ([Microsoft Security, 2024](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token))
3. **Device Code Phishing**: Social engineering attacks that trick users into approving OAuth device flows, granting attackers legitimate refresh tokens ([Microsoft Threat Intelligence, 2024](https://www.microsoft.com/en-us/security/blog/2022/01/26/evolved-phishing-device-registration-trick-adds-to-phishers-toolbox-for-victims-without-mfa/))
4. **Cross-Platform Token Reuse**: Exploiting OAuth implementations that allow tokens to be used across different platforms or applications beyond their intended scope

### MCP-Specific Attack Evolution (2025)

#### MCP Server Token Centralization
The Model Context Protocol creates unique risks for OAuth token persistence:
- **Centralized Token Storage**: MCP servers often store multiple OAuth tokens for different services, creating high-value targets
- **Cross-Service Token Access**: Compromised MCP servers can provide access to tokens for multiple connected services simultaneously
- **Long-Lived Sessions**: MCP implementations may use extended token lifetimes to reduce authentication friction

#### Tool-to-Tool Token Propagation
Attackers can exploit MCP's tool chaining capabilities:
1. **Initial Compromise**: Gain access to one MCP tool's OAuth tokens
2. **Lateral Movement**: Use MCP's inter-tool communication to access tokens for other connected services
3. **Privilege Escalation**: Leverage higher-privileged service tokens accessed through the MCP server

## Impact Assessment
- **Confidentiality**: High - Unauthorized access to user data across multiple services
- **Integrity**: Medium - Potential for data modification through persistent access
- **Availability**: Low - Primarily focused on unauthorized access rather than service disruption
- **Scope**: Network-wide - Can affect multiple services connected through MCP infrastructure

### Current Status (2025)
According to security researchers and industry reports, organizations are implementing various mitigations:
- Microsoft has introduced token binding and Conditional Access policies to limit token reuse ([Microsoft Security, 2024](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection))
- Google has implemented device-bound session credentials to prevent token theft ([Google Security Blog, 2024](https://security.googleblog.com/2024/05/upgrading-google-session-security-with.html))
- OAuth 2.1 specification mandates PKCE and restricts implicit flows to reduce token exposure ([IETF OAuth 2.1, 2024](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))
- Industry adoption of phishing-resistant authentication methods like FIDO2/WebAuthn is increasing

However, legacy OAuth implementations and the complexity of MCP environments continue to present challenges for comprehensive token security.

## Detection Methods

**Note**: OAuth token persistence attacks can be challenging to detect as they often appear as legitimate API usage. Organizations should implement multi-layered detection approaches combining behavioral analysis, anomaly detection, and token validation mechanisms.

### Indicators of Compromise (IoCs)
- Unusual API access patterns from previously authenticated sessions
- Token usage from unexpected geographic locations or IP addresses
- Access token refresh attempts after user logout or password changes
- Multiple concurrent sessions using the same refresh token
- API calls outside normal business hours or usage patterns
- Attempts to access services not typically used by the account holder

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. OAuth token persistence attacks often leverage legitimate authentication mechanisms, making detection complex. Organizations should:
- Implement behavioral analysis to identify unusual token usage patterns
- Monitor for impossible travel scenarios in token usage
- Track token lifetime and refresh patterns for anomalies
- Correlate authentication events with user behavior baselines

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: Suspicious OAuth Token Usage Pattern
id: a7d4c8e2-3f1b-4d5e-9a8c-7b6f5e4d3c2a
status: experimental
description: Detects potential OAuth token persistence through unusual token usage patterns
author: SAFE-MCP Team <safe-mcp@example.com>
date: 2025-09-06
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1202
logsource:
  product: oauth
  service: token_validation
detection:
  selection_concurrent_usage:
    event_type: 'token_refresh'
    token_type: 'refresh_token'
  selection_geographic_anomaly:
    event_type: 'api_access'
    geographic_distance: '>1000'  # Miles from previous access
    time_delta: '<3600'  # Within 1 hour
  selection_post_logout:
    event_type: 'token_usage'
    user_session_status: 'logged_out'
    time_since_logout: '>300'  # More than 5 minutes after logout
  condition: any of selection_*
falsepositives:
  - Legitimate users accessing services from multiple locations
  - Mobile applications with background refresh mechanisms
  - Shared accounts or service accounts with multiple access points
  - Users traveling across time zones
level: high
tags:
  - attack.persistence
  - attack.t1528
  - safe.t1202
```

### Behavioral Indicators
- API access patterns that deviate from established user baselines
- Token refresh activities occurring outside normal user active hours
- Simultaneous access from multiple geographic locations (impossible travel)
- Continued service access after user-initiated logout or password changes
- Access to services or data not previously accessed by the user account
- Unusual volume or frequency of API calls using refresh tokens

## Mitigation Strategies

### Preventive Controls
1. **[SAFE-M-1: Architectural Defense - Token Binding](../../mitigations/SAFE-M-1/README.md)**: Implement cryptographic token binding to tie OAuth tokens to specific devices or sessions, preventing token reuse on unauthorized systems
2. **[SAFE-M-2: Cryptographic Integrity](../../mitigations/SAFE-M-2/README.md)**: Use proof-of-possession (PoP) tokens and device attestation to ensure tokens can only be used by legitimate clients
3. **[SAFE-M-3: AI-Powered Content Analysis](../../mitigations/SAFE-M-3/README.md)**: Deploy machine learning systems to analyze token usage patterns and detect anomalous behavior indicative of token theft
4. **[SAFE-M-4: OAuth Security Best Practices](../../mitigations/SAFE-M-4/README.md)**: Implement OAuth 2.1 recommendations including:
   - Mandatory PKCE for all OAuth flows
   - Short-lived access tokens (1 hour maximum)
   - Refresh token rotation to invalidate stolen tokens
   - Restricted redirect URIs and client authentication
5. **[SAFE-M-5: Secure Token Storage](../../mitigations/SAFE-M-5/README.md)**: Store OAuth tokens using secure mechanisms:
   - HTTP-only, secure cookies for web applications
   - Encrypted storage with hardware security modules (HSMs)
   - Avoid localStorage or sessionStorage for sensitive tokens
6. **[SAFE-M-6: Conditional Access Policies](../../mitigations/SAFE-M-6/README.md)**: Implement dynamic access controls that evaluate:
   - Device trust and compliance status
   - Geographic location and impossible travel detection
   - Risk-based authentication requirements
7. **[SAFE-M-7: Phishing-Resistant Authentication](../../mitigations/SAFE-M-7/README.md)**: Deploy FIDO2/WebAuthn and hardware-backed authentication methods to prevent initial token compromise
8. **[SAFE-M-8: Network Security Controls](../../mitigations/SAFE-M-8/README.md)**: Implement network-level protections including:
   - Zero Trust Network Access (ZTNA)
   - Mutual TLS (mTLS) for API communications
   - Network segmentation for MCP infrastructure

### Detective Controls
1. **[SAFE-M-10: Behavioral Analytics](../../mitigations/SAFE-M-10/README.md)**: Deploy User and Entity Behavior Analytics (UEBA) to detect:
   - Unusual token usage patterns
   - Geographic anomalies in access patterns
   - Impossible travel scenarios
   - Access to previously unused services or data
2. **[SAFE-M-11: Token Lifecycle Monitoring](../../mitigations/SAFE-M-11/README.md)**: Monitor OAuth token lifecycle events:
   - Token issuance, refresh, and revocation events
   - Concurrent token usage from multiple locations
   - Token usage after user logout or password changes
3. **[SAFE-M-12: Comprehensive Audit Logging](../../mitigations/SAFE-M-12/README.md)**: Implement detailed logging of:
   - All OAuth token operations and API calls
   - Device and location information for token usage
   - Correlation with user authentication events

### Response Procedures
1. **Immediate Actions**:
   - Revoke all OAuth tokens associated with compromised accounts
   - Force user reauthentication across all services
   - Disable account access pending investigation
   - Preserve forensic evidence from affected systems
2. **Investigation Steps**:
   - Analyze token usage logs for unauthorized access patterns
   - Correlate access patterns with known threat intelligence
   - Identify the initial compromise vector (malware, phishing, etc.)
   - Assess the scope of data accessed using stolen tokens
3. **Remediation**:
   - Update OAuth implementations to current security standards
   - Implement additional token binding and device attestation
   - Enhance monitoring and alerting for token usage anomalies
   - Conduct security awareness training on OAuth security risks

## Real-World Incidents (2022-2025)

### Microsoft 365 OAuth Token Theft Campaign (2022)
[Microsoft Security reported](https://www.microsoft.com/en-us/security/blog/2022/01/26/evolved-phishing-device-registration-trick-adds-to-phishers-toolbox-for-victims-without-mfa/) a sophisticated campaign where attackers used device code phishing to:
- **Attack Vector**: Social engineering via Microsoft Teams messages
- **Impact**: Persistent access to Microsoft 365 services without triggering MFA
- **Technique**: Legitimate OAuth device flows exploited to gain refresh tokens
- **Duration**: Attacks maintained access for weeks before detection

### Cryptocurrency Exchange OAuth Compromise (2023)
Security researchers documented cases where:
- **Attack Vector**: Browser-based malware extracting OAuth tokens from local storage
- **Impact**: Unauthorized access to cryptocurrency exchange APIs
- **Technique**: Infostealers targeting saved authentication tokens
- **Scope**: Multiple exchanges affected through common OAuth implementations

### Enterprise SaaS Token Persistence (2024)
Recent incidents have shown:
- **Attack Vector**: Compromised MCP servers exposing stored OAuth tokens
- **Impact**: Cross-platform access to enterprise SaaS applications
- **Technique**: Lateral movement through MCP tool chains
- **Detection**: Often discovered weeks after initial compromise

### Google Workspace Family Token Exploitation (2024)
Based on [Secureworks research](https://github.com/secureworks/family-of-client-ids-research):
- **Attack Vector**: Exploitation of undocumented Family of Client IDs behavior
- **Impact**: Single stolen refresh token provided access to multiple Google services
- **Technique**: Token reuse across applications within the same "family"
- **Mitigation**: Google has since implemented additional token validation

## Related Techniques
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Can be combined with OAuth token theft for enhanced persistence
- [SAFE-T1007](../SAFE-T1007/README.md): OAuth Authorization Phishing - Common initial access vector for token theft
- [SAFE-T1102](../SAFE-T1102/README.md): Prompt Injection - May be used to manipulate MCP servers into exposing tokens
- [SAFE-T1601](../SAFE-T1601/README.md): MCP Server Enumeration - Reconnaissance technique for identifying OAuth-enabled services

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OAuth 2.0 Security Best Current Practice - IETF RFC](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Family of Client IDs Research - Secureworks](https://github.com/secureworks/family-of-client-ids-research)
- [MITRE ATT&CK T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Understanding Primary Refresh Tokens - Microsoft](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
- [OAuth 2.0 Threat Model and Security Considerations - IETF RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819)
- [Session Token Theft: A Growing Threat to Modern Authentication - Halock Security](https://www.halock.com/session-token-theft-a-growing-threat-to-modern-authentication/)
- [Securing the Gatekeeper: Addressing Vulnerabilities in OAuth Implementations - IJGIS 2024](https://ijgis.pubpub.org/pub/jkavqi25/release/1)
- [The devil is in the (implementation) details: an empirical analysis of OAuth SSO systems - Sun & Beznosov, 2012](https://passwordresearch.com/papers/paper267.html)
- [Machine learning approach to vulnerability detection in OAuth 2.0 - Munonye & Martinek, 2021](https://link.springer.com/content/pdf/10.1007/s10207-021-00551-w.pdf)
- [OAuth 2.0 Redirect URI Validation Falls Short, Literally - Innocenti et al., 2023](https://innotommy.com/Wrong_redirect_uri_validation_in_OAuth-4.pdf)
- [Why avoiding LocalStorage for tokens is the wrong solution - Pragmatic Web Security](https://pragmaticwebsecurity.com/articles/oauthoidc/localstorage-xss.html)
- [Broken OAuth Vulnerability - SecureFlag](https://knowledge-base.secureflag.com/vulnerabilities/broken_authentication/broken_oauth_vulnerability.html)
- [Common Security Issues in Implementing OAuth 2.0 - PullRequest](https://www.pullrequest.com/blog/common-security-issues-in-implementing-oauth-2-0-and-how-to-mitigate-them/)
- [Understanding Token Theft - Triskele Labs](https://www.triskelelabs.com/understanding-token-theft)
- [Primary Refresh Tokens Aren't Your Parent's Browser Token - KnowBe4](https://blog.knowbe4.com/primary-refresh-tokens-arent-your-parents-browser-token)
- [Understanding Tokens in Entra ID: A Comprehensive Guide - Xintra](https://www.xintra.org/blog/tokens-in-entra-id-guide)

## MITRE ATT&CK Mapping
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-09-06 | Initial documentation of OAuth Token Persistence technique based on comprehensive research of OAuth 2.0 security vulnerabilities, MCP-specific risks, token theft methodologies, and real-world incidents. Includes detailed technical analysis, detection methods, and mitigation strategies. | Smaran Dhungana <smarandhg@gmail.com> |