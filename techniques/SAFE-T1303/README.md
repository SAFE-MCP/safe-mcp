# SAFE-T1303: Container Sandbox Escape via Runtime Exec

## Overview
**Tactic**: Privilege Escalation (ATK-TA0004)  
**Technique ID**: SAFE-T1303  
**Severity**: Critical  
**First Observed**: 2024 (see CVE-2024-21626)  
**Last Updated**: 2025-08-30

## Description
This technique describes escaping a container sandbox by abusing container runtime "exec" behavior with a manipulated working directory. By supplying a path-traversal working directory (for example, using sequences like `../`), an attacker may influence where the runtime resolves file paths and process context during `exec`, enabling access outside the intended container filesystem boundary.

In MCP environments, compromised or malicious tools/servers that orchestrate containerized tasks can craft runtime execution parameters that exploit this behavior. Once the sandbox is bypassed, the adversary can access host resources or processes, pivot to additional systems, and elevate privileges.

## Attack Vectors
- **Primary Vector**: Malicious or compromised MCP server/tool invoking container runtime `exec` with a traversal working directory.
- **Secondary Vectors**: 
  - Vulnerable container runtime versions or misconfigurations
  - Excessive host mounts or writable host paths exposed to containers

## Technical Details

### Prerequisites
- MCP workflow that executes tasks inside containers using a runtime (e.g., `runc`)
- Ability to influence or control `exec` parameters (working directory) via a tool/server
- Vulnerable runtime or insecure runtime configuration

### Attack Flow
1. **Access**: Attacker gains control of an MCP tool/server or tricks an operator into using a malicious one.
2. **Parameter Control**: Attacker sets `exec` working directory to a traversal path (for example, `../../..`).
3. **Runtime Invocation**: MCP workload triggers container runtime `exec` with the crafted `-w`/working directory.
4. **Boundary Violation**: Runtime resolves paths outside the container filesystem, breaking isolation.
5. **Post-Exploitation**: Attacker reads/writes host files, enumerates processes, or installs persistence.

### Example Scenario
```json
{
  "runtime": "runc",
  "action": "exec",
  "args": [
    "--workdir", "../../..",
    "--", "sh", "-c", "id; cat /etc/hostname"
  ],
  "note": "Illustrative only; actual exploitation depends on runtime/version"
}
```

### Advanced Attack Techniques (2024–2025)
According to public analyses of "Leaky Vessels" and related research on container escapes, attackers may:
1. Use encoded or alternate traversal sequences to evade simple pattern checks.  
2. Target alternate runtimes or orchestrators where similar resolution bugs exist.  
3. Combine with host mount abuses to access sensitive paths more reliably.  

## Impact Assessment
- **Confidentiality**: High - Potential access to host files and secrets.
- **Integrity**: High - Host filesystem and processes may be modified.
- **Availability**: High - Host or cluster stability can be impacted.
- **Scope**: Adjacent/Network-wide - Breakout from one container to host enables lateral movement.

### Current Status (2025)
Container runtime vendors have released patches and guidance for path-resolution issues (see CVE references). Organizations should update to patched runtime versions and apply hardening guidance from vendor and community resources.

## Detection Methods

### Indicators of Compromise (IoCs)
- `runc exec` or equivalent runtime invocations with traversal in working directory (e.g., `../`, `..\\`).
- Unexpected file access attempts on host paths shortly after container exec.
- Anomalous logs indicating container processes interacting with host-level resources.

### Detection Rules
Important: The standalone Sigma rule for this technique is provided in `detection-rule.yml`. It contains example patterns only. Attackers continuously develop new injection and obfuscation methods. Organizations should:
- Use behavioral analytics to profile normal container exec behavior
- Regularly update rules based on threat intelligence
- Employ multiple data sources (process, file, and container runtime telemetry)

### Behavioral Indicators
- Sudden spikes in container exec events with unusual working directories
- Processes spawned in containers accessing host-specific paths or devices

## Mitigation Strategies

### Preventive Controls
1. **SAFE-M-9: Sandboxed Testing**: Run new/updated MCP tools/servers in tightly isolated environments; disable privileged modes and restrict host mounts during evaluation.
2. **SAFE-M-6: Tool Registry Verification**: Enforce provenance and review for tools/servers that can invoke container runtimes; verify configuration and runtime versions.
3. **SAFE-M-14: Server Allowlisting**: Limit which MCP servers may be attached or invoked, reducing exposure to malicious orchestrators.

### Detective Controls
1. **SAFE-M-12: Audit Logging**: Log runtime invocations, including working directory and mount details, to support detection and forensics.
2. **SAFE-M-11: Behavioral Monitoring**: Alert on abnormal container `exec` patterns and host-path access from containerized processes.

### Response Procedures
1. **Immediate Actions**:
   - Revoke access to suspected MCP servers/tools
   - Quarantine affected hosts/nodes and rotate secrets
2. **Investigation Steps**:
   - Review runtime/audit logs for traversal indicators and host access
   - Validate container runtime versions and configuration across fleet
3. **Remediation**:
   - Patch runtime and apply hardening guidance
   - Reduce host mounts, remove unnecessary privileges, enforce policy

## Related Techniques
- [SAFE-T1105](../SAFE-T1105/README.md): Path Traversal via File Tool
- [SAFE-T1109](../SAFE-T1109/README.md): Debugging Tool Exploitation

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [NVD: CVE-2024-21626](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
- [Leaky Vessels: Container Escape Vulnerabilities - Wiz (2024)](https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities)

## MITRE ATT&CK Mapping
- [T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)

## Version History
| Version | Date       | Changes                 | Author             |
|---------|------------|-------------------------|--------------------|
| 1.0     | 2025-08-30 | Initial documentation   | Shekhar Chaudhary |
