
# SAFE-T1004: Server Impersonation / Name-Collision

## Overview

**Tactic**: Credential Access (ATK-TA0006), Initial Access (ATK-TA0001)  
**Technique ID**: SAFE-T1004  
**Severity**: High  
**First Observed**: Documented in DNS cache poisoning attacks (Kaminsky, 2008)  
**Last Updated**: November 2025  

## Description

Server Impersonation / Name-Collision is an adversary-in-the-middle technique where attackers register or advertise a malicious server using the same name or identifier as a trusted one. By exploiting weaknesses in naming systems (DNS, mDNS, or MCP’s On-Device Agent Registry), clients are tricked into connecting to the attacker-controlled endpoint.

### What is ODR?

The **On‑Device Agent Registry (ODR)** is a Windows component of the **Model Context Protocol (MCP)**. It acts as a secure local registry where MCP servers and connectors are registered so that AI agents and applications can automatically discover them in a standardized way.  Contains metadata, endpoints and certificates.

## Attack Vectors

- **Primary Vector**: Malicious server registration with identical name/URL in DNS, mDNS, or ODR  
- **Secondary Vectors**:  
  - DNS cache poisoning or hijacking  
  - Rogue DHCP servers distributing malicious DNS settings
  - ODR Poisoning
  - Certificate misuse / Weak validation
  - Service Redeployment windows
  - ARP (Address Resolution Protocol) cache poisoning

## Technical Details

### Prerequisites

- **Network Access**: Attacker must be positioned on the same network (for ARP/mDNS/DHCP poisoning) or have upstream control (for DNS hijacking).
- **Weak Discovery Protections**: DNS without DNSSEC validation; mDNS or ODR responses trusted without controls.
- **Client Trust Assumptions**: Clients equate “name = identity” without verifying certificates or a lack of mutual TLS or certificate pinning.
- **Legacy Protocols Enabled**: LLMNR/NBT‑NS, DHCP clients, ARP cache updates accepted are active without controls.
- **Attacker Capabilities**: Ability to forge or inject responses, register malicious services, or impersonate trusted endpoints.

### Attack Flow

1. **Initial Stage**: Attacker sets up a malicious server with the same identifier as a trusted one.  
2. **Discovery Hijack**: Attacker poisons DNS/mDNS responses or registers duplicate entries in ODR.  
3. **Connection Stage**: Client connects to the attacker’s server, believing it is legitimate.  
4. **Exploitation Stage**: Attacker intercepts credentials, sensitive data, or injects malicious commands.  
5. **Post-Exploitation**: Attacker pivots laterally using harvested credentials or maintains persistence via poisoned registry entries.  

### Example Scenario

```json
// Example malicious ODR registration
{
  "service_name": "analytics-hub.local",
  "endpoint": "192.168.1.50",
  "certificate": "self-signed"
}
```

### Advanced Attack Techniques (Research Published)

According to research from [Kaminsky, 2008](https://en.wikipedia.org/wiki/Dan_Kaminsky) and [Sea Turtle Campaign, 2019](https://attack.mitre.org/campaigns/C0022/), attackers have developed sophisticated variations:

1. **DNS Cache Poisoning**: Injecting false records into resolvers to redirect traffic (Kaminsky, 2008).  
2. **Registrar Hijacking**: Compromising DNS registrars to reroute traffic at scale (Sea Turtle, 2019). 
3. **Chained Attacks (Hybrid Poisoning)**: Combining multiple attacks into a single attack vector for greater impact (Kaminsky, 2019).
 
## Impact Assessment

- **Confidentiality**: High – Credentials and sensitive data can be intercepted.  
- **Integrity**: High – Malicious responses can alter system behavior.  
- **Availability**: Medium – Services may be disrupted by impersonation.  
- **Scope**: Network-wide – Affects all clients relying on poisoned discovery.  

### Current Status (2025)

DNSSEC adoption is increasing globally, and MCP’s ODR is evolving with new security features, but deployment remains uneven. According to security researchers, organizations are beginning to implement certificate pinning and mutual TLS in MCP environments.

- **DNSSEC** is being actively adopted, with Microsoft and EU regulators pushing for stronger protections ([Internet Society – DNSSEC Deployment Maps](https://www.internetsociety.org/deploy360/dnssec/maps/)).  
- **Global adoption remains partial** — less than half of DNS queries are validated, leaving room for cache poisoning and hijacking ([European Commission JRC Report on DNSSEC Adoption (2025)](https://publications.jrc.ec.europa.eu/repository/handle/JRC143100)).  
- **MCP’s ODR** is evolving, but organizations should already enforce **certificate pinning, signed entries, and monitoring for duplicates** to mitigate impersonation risks ([Model Context Protocol Roadmap (Oct 2025)](https://modelcontextprotocol.io/development/roadmap)).  

## Detection Methods

### Indicators of Compromise (IoCs)

- **DNS/Name resolution** anomalies such as unexpected, unknown, or unsigned requests with frequent cache updates
- **ODR** anomalies such as unexpected changes, duplicate services, or unsigned requests
- **ARP** anomalies such as frequent changes or duplicate entries
- **DHCP** anomalies such as new leases or multiple servers
- **TLS / Certificate** anomalies such as handshake failure, unknown or self signed certificates
- **Traffic Pattern** anomalies such as sensitive data flows, auth failure spikes, known attacker infrastructure requests

### Detection Rules

```yaml
title: Detection of Server Impersonation / Name-Collision (SAFE-T1004)
id: 9f3c2a8e-7d4b-4c2f-9a1e-8e2b7f9c1d23
status: experimental
description: Detects indicators of server impersonation or name-collision attacks across DNS, ARP, and ODR
author: Ryan
date: 2025-11-22
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1004
  - https://attack.mitre.org/techniques/T1557/
  - https://attack.mitre.org/techniques/T1565/002/
logsource:
  product: windows
  service: system
detection:
  selection_dns:
    EventID: 1014
    Provider_Name: "Microsoft-Windows-DNS-Client"
    Message|contains:
      - "resolved to unexpected IP"
      - "DNSSEC validation failed"
  selection_odr:
    service_name|count: ">1"   # duplicate service names in ODR
  selection_arp:
    EventID: 2022
    Provider_Name: "Microsoft-Windows-TCPIP"
    Message|contains:
      - "duplicate ARP entry"
      - "MAC address mismatch"
  selection_tls:
    EventID: 36882
    Provider_Name: "Schannel"
    Message|contains:
      - "certificate mismatch"
      - "self-signed certificate"
  condition: selection_dns or selection_odr or selection_arp or selection_tls
falsepositives:
  - Legitimate redeployment of services causing duplicate names
  - Test environments with self-signed certificates
level: high
tags:
  - attack.credential_access
  - attack.t1557
  - attack.t1565.002
  - attack.t1557.002
  - safe.t1004
```

### Behavioral Indicators

- Duplicate service names in ODR  
- Unexpected ODR changes — new MCP services appearing
- Clients connecting to endpoints outside expected IP ranges
- Sudden changes in DNS resolution for trusted domains
- Frequent DNS cache flushes or anomalies
- Unsigned DNS responses where DNSSEC validation should be present
- Multiple conflicting DNS responses for the same query
- TLS handshake failures due to certificate mismatches
- Clients accepting self‑signed certificates
- Frequent or duplicate ARP table changes
- New DHCP leases assigning DNS servers
- Sudden spikes in authentication failures
- Outbound traffic to attacker infrastructure
- Clients connecting to unexpected IP ranges  
- Multiple mDNS responses for the same hostname 

## Mitigation Strategies

### Preventive Controls

1. **[SAFE-M-000: Mutual TLS](../../mitigations/SAFE-M-000/README.md)**: Enforce mutual authentication between clients and servers.  
2. **[SAFE-M-000: DNSSEC](../../mitigations/SAFE-M-000/README.md)**: Validate DNS records cryptographically.  
3. **[SAFE-M-000: Registry Hardening](../../mitigations/SAFE-M-000/README.md)**: Require signed entries in ODR and enforce unique identifiers.  
4. **[SAFE-M-000: Disable Legacy Protocols](../../mitigations/SAFE-M-000/README.md)**: Disable LLMNR/NBT‑NS and ARP where possible.  
5. **[SAFE-M-000: Network Segmentation](../../mitigations/SAFE-M-000/README.md)**: Isolate critical MCP servers and DNS infrastructure from general user subnets.  

### Detective Controls

1. **[SAFE-M-000: Duplicate Name Monitoring](../../mitigations/SAFE-M-000/README.md)**: Alert on duplicate service names in ODR.  
2. **[SAFE-M-000: DNS Anomaly Detection](../../mitigations/SAFE-M-000/README.md)**: Detect sudden resolution changes for trusted domains.  
3. **[SAFE-M-000: ARP/DHCP Monitoring](../../mitigations/SAFE-M-000/README.md)**: Detect duplicate servers and suspicious ARP entries.  
4. **[SAFE-M-000: Certificate Validation Logs](../../mitigations/SAFE-M-000/README.md)**: Detect clients accepting untrusted or self‑signed certificates.  

### Response Procedures

1. **Immediate Actions**:  
   - Block malicious IPs at the firewall  
   - Remove rogue ODR entries  
   - Flush poisoned DNS/ARP caches on affected hosts  

2. **Investigation Steps**:  
   - Review DNS logs, ODR audit trails, and ARP tables  
   - Identify compromised accounts or systems  

3. **Remediation**:  
   - Rotate exposed credentials  
   - Patch discovery protocols  
   - Enforce secure registration  
   - Deploy long‑term monitoring for anomalies  

## Related Techniques

- [SAFE‑T1001](../SAFE-T1001/) – DNS Cache Poisoning
- [SAFE-T1002](../SAFE-T1002/): DNS Manipulation – closely related to impersonation via poisoned records.  
- [SAFE-T1003](../SAFE-T1003/): Adversary-in-the-Middle – broader category encompassing impersonation attacks.
- [SAFE-T1402](../SAFE-T1402/): Instruction Stenography for registry manipulation 

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)  
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
- [Kaminsky DNS Cache Poisoning - 2008](https://en.wikipedia.org/wiki/Dan_Kaminsky)  
- [Sea Turtle DNS Hijacking Campaign - 2019](https://attack.mitre.org/campaigns/C0022/)  
- [Microsoft 365 DNS Provisioning Change – DNSSEC Adoption](https://mc.merill.net/message/MC1048624)  
- [Internet Society – DNSSEC Deployment Maps](https://www.internetsociety.org/deploy360/dnssec/maps/)  
- [Model Context Protocol Roadmap (Oct 2025)](https://modelcontextprotocol.io/development/roadmap)  
- [M365 Admin DNSSEC Provisioning Change](https://d365hub.com/Posts/Details/ce776f51-54d3-42d5-a97f-b8537eef4fb4/dns-provisioning-change)  
- [European Commission JRC Report on DNSSEC Adoption (2025)](https://publications.jrc.ec.europa.eu/repository/handle/JRC143100)  

## MITRE ATT&CK Mapping

- [T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)  
- [T1565.002 – Data Manipulation: DNS Manipulation](https://attack.mitre.org/techniques/T1565/002/)  
- [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1565 - Data Manipulation](https://attack.mitre.org/techniques/T1565/)

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-22 | Initial documentation with ODR explanation | Ryan Jennings |