# SAFE-M-45: Tool Manifest Signing & Server Attestation

**Category**: Supply Chain & Identity Controls  
**Status**: Draft  
**Primary Objective**: Establish cryptographic authenticity and integrity for MCP tool metadata and the servers that publish it, so that clients/agents can verify that tool descriptors (names, descriptions, schemas, annotations) have not been tampered with and originate from a trusted server.

---

## Threats Mitigated (Technique Tags)

- **[SAFE-T1001](../../techniques/SAFE-T1001/README.md)** Tool Poisoning Attack (TPA) — malicious instructions hidden in tool descriptions/annotations
- **[SAFE-T1402](../../techniques/SAFE-T1402/README.md)** Instruction Steganography — hidden directives via zero-width chars/comments in metadata
- **[SAFE-T1102](../../techniques/SAFE-T1102/README.md)** Prompt Injection (Multiple Vectors) — when delivered through tool annotations
- **SAFE-T1701** Cross-Tool Contamination — when tainted tools are propagated between servers/agents

**Tactics Impacted**:  
- **ATK-TA0001** Initial Access (blocks accepting poisoned tools on load)
- **ATK-TA0005** Defense Evasion (thwarts hidden/altered metadata persisting undetected)

---

## Problem

MCP clients typically **trust tool descriptors** delivered by an MCP server. Even with linting (schema validation), sanitization, and scanners, a determined adversary can still ship **authentic-looking but malicious** tool metadata from a rogue or compromised server. Without a cryptographic trust layer, clients have no strong guarantee that:

1. The server is who it claims to be, and  
2. The tool metadata is unmodified, publisher-authorized content

Independent research and community guidance emphasize treating tool annotations as **untrusted** without stronger provenance controls, and recommend layered defenses around MCP server trust. Security analyses consistently highlight the need for cryptographic verification of tool metadata to prevent supply chain attacks in the MCP ecosystem.

---

## Mitigation Overview

SAFE-M-45 requires two complementary controls:

### 1) Server Attestation / Strong Identity

Issue and verify **workload identities** for MCP servers (e.g., SPIFFE/SPIRE SVIDs) so clients can cryptographically authenticate the server process and its trust domain before ingesting any tool metadata.

**SPIFFE/SPIRE** (Secure Production Identity Framework For Everyone) provides:
- Workload attestation through kernel-based or node-based verification
- Automatic credential rotation with short-lived X.509 SVIDs
- Federation across trust domains
- Platform-agnostic identity issuance

Reference: [SPIFFE/SPIRE Documentation](https://spiffe.io/docs/)

### 2) Tool Manifest Signing (Attestations)

Publish a versioned **Tool Manifest** (e.g., `tools.manifest.json`) that enumerates each tool's:
- Stable identifier and version
- Descriptors: name, description, schema (or digest of these fields)
- Artifact digests (if applicable)
- Publisher metadata and issuance time

Sign the manifest using **in-toto/DSSE-style attestations** and provide **SLSA-aligned provenance** for the build/publish pipeline of the MCP server. Clients verify the signature and refuse tools whose descriptors do not match signed digests or come from an untrusted key.

**in-toto Attestation Framework** provides:
- Standardized format for software supply chain metadata
- DSSE (Dead Simple Signing Envelope) for signature wrapping
- Predicate types for various attestation purposes (SLSA provenance, vulnerability scans, etc.)

Reference: [in-toto Attestation Framework](https://in-toto.io/docs/specs/)

**SLSA (Supply chain Levels for Software Artifacts)** provides:
- Framework for build integrity and provenance
- Graduated levels (L0-L4) for supply chain security
- Build provenance attestations
- Distribution verification

Reference: [SLSA Framework v1.0](https://slsa.dev/spec/v1.0/)

> **Note**: Sender-constrained tokens (e.g., OAuth DPoP per RFC 9449) add replay resistance for access tokens when the client later calls resource servers via tools, but are not a substitute for manifest signing; they are a complementary hardening when tokens flow through MCP.

---

## Implementation (Server Side)

### 1. Adopt Workload Identity for MCP Servers

- Deploy SPIRE to issue SPIFFE IDs to your MCP server workloads (e.g., `spiffe://org.example/mcp/tools`)
- Configure node and workload attestation; register workloads and distribute SVIDs
- Implement automatic SVID rotation (typically 1-hour TTL)

**Example SPIRE Server Configuration**:
```hcl
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  trust_domain = "org.example"
  data_dir = "/opt/spire/data/server"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }
  
  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "production" = {
          service_account_allow_list = ["spire:spire-agent"]
        }
      }
    }
  }
}
```

### 2. Generate a Tool Manifest

- Enumerate all tool descriptors (name, description, schema JSON, version)
- Compute deterministic digests (e.g., SHA-256) for the descriptor payloads (normalize JSON)
- Include: `publisher`, `issuedAt`, `tool[i].id`, `tool[i].version`, `tool[i].descriptorDigest`

**Example Tool Manifest**:
```json
{
  "version": "1.0",
  "publisher": "org.example.mcp-tools",
  "issuedAt": "2025-11-02T10:00:00Z",
  "tools": [
    {
      "id": "file-reader-v1",
      "version": "1.2.3",
      "name": "read_file",
      "descriptorDigest": "sha256:a1b2c3d4...",
      "schema": {
        "type": "object",
        "properties": {
          "path": {"type": "string"}
        }
      }
    }
  ]
}
```

### 3. Create an Attestation for the Manifest

Use **in-toto Attestation Framework** with **DSSE** envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(TOOL_MANIFEST_JSON)>",
  "signatures": [{
    "keyid": "sha256:abc123...",
    "sig": "<base64(SIGNATURE)>"
  }]
}
```

If your server is containerized, attach an **SLSA provenance** attestation to the container image and reference the manifest by digest (SLSA v1.0 describes provenance and distribution options).

### 4. Publish and Rotate Keys

- Publish your **verification key / certificate chain** (PKIX or Sigstore key material)
- Define rotation cadence (recommended: 90 days for long-term keys, 1 hour for SVIDs)
- Implement revocation process with CRL or OCSP

**Key Management Best Practices**:
- Store signing keys in HSM or cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
- Use separate keys for different trust levels
- Implement automated rotation with overlap periods
- Maintain audit logs of all key operations

### 5. Expose Discovery Endpoint

Serve the current manifest **digest** and attestation reference (e.g., via a well-known endpoint or within MCP server `capabilities` metadata) so clients can fetch/verify prior to listing tools.

**Example Endpoint**:
```
GET /.well-known/mcp-manifest
Response:
{
  "manifestDigest": "sha256:a1b2c3d4...",
  "attestationUrl": "https://server.example/attestations/manifest-2025-11-02.json",
  "verificationKeys": [
    {
      "keyid": "sha256:abc123...",
      "algorithm": "ECDSA-P256",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n..."
    }
  ]
}
```

---

## Enforcement (Client/Gateway Side)

### Early Gate

Before `tools/list`, fetch the server's identity (SPIFFE) and the manifest + attestation:

1. **Verify Server Identity**:
   - Request server's SVID (X.509-SVID or JWT-SVID)
   - Validate SPIFFE ID matches expected trust domain
   - Verify certificate chain against SPIRE trust bundle
   - Check certificate is not expired or revoked

2. **Fetch and Verify Manifest**:
   - Retrieve manifest from `/.well-known/mcp-manifest`
   - Download attestation bundle
   - Verify DSSE signature using published verification keys
   - Validate manifest timestamps and freshness

3. **Verify Tool Descriptors**:
   - For each tool in `tools/list` response
   - Compute descriptor digest (normalize JSON)
   - Compare against signed manifest entry
   - Reject tools with mismatched digests

### Policy Enforcement

- Refuse to load tools if identity verification or signature checks fail
- Require **pinning** to a publisher key fingerprint in enterprise settings
- Implement allowlist of trusted SPIFFE trust domains
- Log all verification failures for security review

### Combine with Existing Controls

Run after authenticity is established:
- **[SAFE-M-37](../SAFE-M-37/README.md)** Metadata Sanitization
- **[SAFE-M-38](../SAFE-M-38/README.md)** Schema Validation  
- **[SAFE-M-43](../SAFE-M-43/README.md)** Steganography Scanner
- **[SAFE-M-44](../SAFE-M-44/README.md)** Behavioral Monitoring

This layered approach ensures both authenticity (who published it) and content safety (what it contains).

---

## Detection & Telemetry

### Signals to Log

- Manifest verification result (pass/fail) and key fingerprint
- Mismatch events (descriptor digest vs. signed digest)
- Server identity (SPIFFE ID) and trust domain
- Rate/sequence anomalies (e.g., frequent manifest changes)
- SVID validation results and certificate chain details
- Key rotation events and verification key changes

### Alert On

- Unsigned manifests or missing attestations
- Invalid signatures or verification failures
- Expired or revoked keys/certificates
- Server identity mismatch or unexpected trust domain
- Descriptor digests differing from signed values (possible poisoning attempt)
- Frequent manifest updates (possible compromise or testing)
- SVID from unexpected trust domain

### Telemetry Schema

```json
{
  "timestamp": "2025-11-02T10:15:30Z",
  "event_type": "manifest_verification",
  "server_spiffe_id": "spiffe://org.example/mcp/tools",
  "manifest_digest": "sha256:a1b2c3d4...",
  "verification_result": "success|failure",
  "verification_key_id": "sha256:abc123...",
  "tools_verified": 15,
  "tools_rejected": 0,
  "mismatch_details": []
}
```

Community guidance emphasizes treating untrusted tool annotations cautiously and layering identity + integrity with runtime analyzers; these signals feed those detectors.

---

## Operational Considerations

### Key Management

- Store signing keys in HSM/KMS with access controls
- Automate rotation with grace periods
- Maintain backup keys and recovery procedures
- Document key compromise response plan

### Developer Experience

- Make manifest generation part of CI pipeline
- Fail builds on manifest drift or validation errors
- Provide tools for local manifest generation and testing
- Integrate with existing release processes

### Compatibility

- Clients that don't implement SAFE-M-45 can still read tools, but **won't be protected** against T1001/T1402 origin-tampering
- Design for graceful degradation (warning vs. hard failure)
- Provide migration path for existing deployments
- Document compatibility matrix

### Token Misuse

When tools call third-party APIs, consider **OAuth 2.0 DPoP (RFC 9449)** to bind tokens and reduce replay in downstream services:

- DPoP proof binds token to client key
- Prevents token replay at authorization server
- Reduces impact of token theft
- Complementary to manifest signing

---

## Implementation Checklist

See [CHECKLIST.md](./CHECKLIST.md) for detailed implementation steps.

---

## References

### SAFE-MCP Framework
- [SAFE-MCP Repository](https://github.com/SAFE-MCP/safe-mcp) - Overview & technique index (for T1001 and related TTPs)
- [SAFE-MCP Pull Requests](https://github.com/SAFE-MCP/safe-mcp/pulls) - Related mitigations (SAFE-M-37/38/39/40/41/42/43/44)

### Standards & Specifications
- [in-toto Attestation Framework](https://in-toto.io/docs/specs/) - Attestation format and DSSE signing
- [SLSA Framework v1.0](https://slsa.dev/spec/v1.0/) - Supply chain levels and provenance
- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe/) - Workload identity specification
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire/) - Implementation guide for SPIFFE
- [RFC 9449 - OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449) - Demonstrating Proof of Possession

### Security Resources
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification) - MCP protocol details
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - LLM security guidance
- [Supply Chain Integrity, Transparency and Trust (SCITT)](https://scitt.io/) - Supply chain security architecture

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-02 | Initial documentation | lilipant10 |

