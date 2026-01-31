# SAFE-T1005: Exposed Endpoint Exploit

## Overview

**Tactic**: Initial Access (ATK-TA0001)
**Technique ID**: SAFE-T1005
**Last Updated**: 2026-01-28

## Description

Adversaries may gain initial access to an environment by interacting with MCP servers that are exposed beyond their intended trust boundary. This often occurs when an MCP server:

- Listens on a network-accessible interface (e.g., 0.0.0.0), making it reachable from a LAN or the public internet, or
- Listens on localhost using a browser-reachable transport (HTTP/SSE/WebSocket) without adequate protections (authentication, origin validation, and DNS rebinding defenses)

If exposed endpoints allow capability discovery (tool enumeration) and tool invocation, attackers can potentially trigger sensitive operations (file access, code execution, credential access) depending on the tools available and the host’s security controls.

This technique focuses on *initial access* via endpoint exposure and misconfiguration, whether “public” (internet/LAN) or “local” (browser-to-localhost).

## How It Works

1. **Exposure occurs**
  - An MCP server is started with a transport that is reachable outside the intended scope (public network exposure, LAN exposure, or browser-accessible localhost transport).
  - Docker/container port mapping: binding to 0.0.0.0 inside a container is standard practice for port mapping to work, but -p 8080:8080 (vs. -p 127.0.0.1:8080:8080) exposes the server to the host's network interfaces.
  - Reverse tunneling tools: A developer running a reverse proxy to test an unrelated service can inadvertently expose a co-hosted MCP server to the public internet. This creates internet exposure without any server misconfiguration.

2. **Insufficient access controls**
  - Missing or weak authentication (e.g., no auth on localhost because it is assumed "safe")
  - Missing origin/host validation for browser-originating traffic
  - Missing DNS rebinding protections for HTTP-based servers
  - Misplaced trust in browser-side protections: CORS does not prevent cross-origin requests from being sent, it only restricts the browser from reading the response. "Simple" requests (e.g., POST with `text/plain` and no custom headers) bypass preflight entirely, so the server processes the request and any side effects (such as tool invocation) still occur. WebSocket connections are not subject to CORS at all; the browser includes an `Origin` header in the upgrade handshake but enforces nothing, leaving servers vulnerable to Cross-Site WebSocket Hijacking (CSWH) unless they explicitly validate the Origin.

3. **Adversary reaches the endpoint**
  - For public/LAN exposure: an attacker can directly connect over the network. Internet-facing endpoints may be discovered through automated scanning (e.g., Shodan, Censys) or passive reconnaissance of exposed services.
  - For localhost exposure: a malicious website can sometimes interact with a localhost MCP server through browser mechanics if protections are absent.

4. **Discovery and interaction**
  - The adversary performs capability discovery (e.g., enumerating available tools).
  - If sensitive tools exist (file system, shell/exec, IDE integration, cloud APIs), they attempt to invoke them or exploit tool/server weaknesses.

5. **Foothold and escalation**
  - Successful tool invocation can lead to code execution, sensitive data access, credential theft, or pivoting into connected services.

## Examples

### Example 1: Network-exposed MCP servers without authorization

Researchers have reported MCP servers exposed to the internet with no authorization in place, allowing retrieval of tool listings and other metadata. This demonstrates the practical risk of “public” endpoint exposure when MCP servers are deployed with insecure defaults or misconfigurations.

### Example 2: CVE-2025-66416 (DNS rebinding against localhost HTTP-based MCP servers)

The MCP Python SDK did not enable DNS rebinding protection by default for certain HTTP-based MCP server configurations prior to version 1.23.0. When an HTTP-based MCP server is run on localhost without authentication using FastMCP (streamable HTTP or SSE transport) and transport security settings are not configured, a malicious website can exploit DNS rebinding to bypass same-origin restrictions and interact with the local MCP server.

> Note: reports indicate this issue does not affect servers using `stdio` transport.

> The standard `stdio` transport is inherently immune to DNS Rebinding and External Network Exposure because it doesn't expose a network listener.

### Example 3: CVE-2025-52882 (Unauthenticated local WebSocket access to IDE agent tooling)

Claude Code IDE extensions (including VS Code and JetBrains plugin variants in affected version ranges) were vulnerable to unauthorized WebSocket connections from attacker-controlled webpages. This class of issue illustrates how a “local” WebSocket endpoint can still become attacker-reachable if origin/authentication checks are missing, enabling exposure of IDE context and potentially dangerous actions.

## Impact

- Confidentiality: **High**
  - Tool enumeration and tool calls can expose local files, workspace data, tokens, or connected SaaS data. MCP servers typically inherit the spawning user's full credential context. This means a single exposed endpoint can provide access to everything the user can reach, not just the tools explicitly registered.
- Integrity: **High**
  - If write/exec-capable tools exist, attackers may modify code, configs, or systems.
  - MCP servers connected to development environments or CI/CD pipelines introduce supply chain risk: modifications may propagate to production undetected.
- Availability: **Medium**
  - Attackers may crash the MCP server or force expensive actions (rate-limits, resource exhaustion), but impact depends on tooling and deployment.

## Detection
Defenders can look for signals of unintended access paths, especially:

- **Unexpected inbound connections**
  - Public/LAN: inbound network connections to MCP ports from untrusted IPs
  - Localhost: abnormal localhost requests with suspicious browser-related headers (e.g., Origin/Referer) or unusual User-Agent patterns

- **Unusual capability discovery patterns**
  - Frequent or repeated tool enumeration and metadata requests
  - Rapid follow-on tool invocation after enumeration

- **Indicators of browser-to-localhost abuse**
  - Requests including unexpected `Origin` values
  - Host/header patterns inconsistent with the configured server name or expected client behavior
  - DNS anomalies that suggest rebinding attempts (rapid resolution shifts for the same hostname)

- **Process and traffic identity mismatch**
  - Connections to MCP ports from unexpected processes (e.g., a browser PID rather than the expected IDE or agent process) indicate unauthorized access. On local systems, correlating socket ownership with the expected parent process surfaces this signal.
  - Browser-characteristic traffic on endpoints expected to receive only programmatic calls — full browser User-Agent strings, cookies, or Referer headers — is a strong indicator of browser-mediated attack (DNS rebinding, CSWH).

- **Missing protocol handshake metadata**
  - Connections that lack MCP-specific markers (e.g., required `Sec-WebSocket-Protocol` sub-protocol, custom headers, or startup handshake tokens) suggest scanning, unauthorized clients, or replay attempts rather than legitimate MCP traffic.

- **Correlation and triage**
  - A tool enumeration request followed by targeted tool invocation within the same session is a high-confidence indicator of exploitation.
  - Cross-reference connection source IPs/origins with known legitimate clients to surface unauthorized access.

## Mitigation

1. **Do not trust localhost by default**
    - Treat localhost endpoints as attacker-reachable in browser-mediated scenarios.

2. **Require authentication for MCP servers**
    - Enforce strong authentication even for local transports when feasible (tokens, mTLS, or brokered auth).
    - For network-based local transports, require a single-use or short-lived handshake token passed via environment variables or stdin at server startup to authenticate the subsequent connection. This leverages the parent process's ability to inject secrets before any network listener is active.

3. **Minimize browser-reachable transports**
    - Prefer stdio or OS-level IPC (e.g., named pipes / Unix domain sockets) for local MCP where practical.

4. **Harden HTTP/SSE/WebSocket servers**
    - Enable DNS rebinding protections where available.
    - Validate `Origin` (and `Host` where applicable) against an allowlist.
    - Apply strict CORS policies and avoid permissive defaults.

5. **Reduce exposure and attack surface**
    - Bind to the narrowest interface required (avoid 0.0.0.0 unless explicitly needed).
    - Place MCP servers behind a gateway that enforces authn/z and request validation.
    - Disable debug endpoints and development-only features in production.

6. **Continuous exposure monitoring**
    - Maintain asset inventory and continuously audit for unintentionally exposed MCP services.

7. **Apply tool-level access controls**
    - Follow the principle of least privilege: only register tools that are required for the server's intended purpose.
    - Where supported, implement per-tool authorization so that server-level access does not automatically grant invocation rights to all tools.

8. **Rate-limit and throttle requests**
    - Apply rate limiting on tool enumeration and invocation endpoints to slow automated exploitation and reduce the window for brute-force tool discovery.

## References

- [CVE-2025-66416](https://nvd.nist.gov/vuln/detail/CVE-2025-66416)
- [GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f)
- [SNYK-PYTHON-MCP-14171912](https://security.snyk.io/vuln/SNYK-PYTHON-MCP-14171912)
- [CVE-2025-52882](https://nvd.nist.gov/vuln/detail/CVE-2025-52882)
- [CVE-2025-54073](https://nvd.nist.gov/vuln/detail/CVE-2025-54073)

## MITRE ATT&CK Mapping

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-28 | Initial documentation of Exposed Endpoint Exploit technique | Felipe Hlibco |
