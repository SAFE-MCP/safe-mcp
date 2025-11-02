# SAFE-M-45: Tool Manifest Signing & Server Attestation - Implementation Checklist

## Scope
- [ ] Applies to: MCP servers, MCP gateways/proxies, MCP clients
- [ ] Targets techniques: SAFE-T1001, SAFE-T1402, SAFE-T1102 (annotation vector), SAFE-T1701

---

## Preconditions

- [ ] Organizational trust domain defined (CA, Sigstore root, or enterprise PKI)
- [ ] Key management solution selected (HSM/KMS) and rotation policy documented
- [ ] CI/CD pipeline identified for build/publish automation
- [ ] Security team trained on SPIFFE/SPIRE concepts
- [ ] Budget allocated for infrastructure (SPIRE servers, key management)

---

## Server Implementation

### SPIFFE/SPIRE Deployment

- [ ] SPIRE server deployed in production environment
- [ ] Node attestation configured (K8s, AWS, GCP, or custom)
- [ ] Workload attestation policy defined
- [ ] MCP server workloads registered with SPIFFE IDs (e.g., `spiffe://org.example/mcp/tools`)
- [ ] SVIDs distributed to MCP server processes
- [ ] Automatic SVID rotation configured (recommended: 1-hour TTL)
- [ ] SPIRE trust bundle published for client validation
- [ ] Federation configured (if multi-domain deployment)
- [ ] Monitoring and alerting for SPIRE health

### Tool Manifest Generation

- [ ] Tool inventory complete (all tools documented with versions)
- [ ] JSON normalization algorithm selected for deterministic digests
- [ ] Manifest generation script created
- [ ] Manifest schema validated (version, publisher, issuedAt, tools[])
- [ ] Descriptor digests computed (SHA-256 recommended)
- [ ] Manifest generation integrated into CI pipeline
- [ ] Build fails on manifest validation errors
- [ ] Manifest versioning strategy documented

### Attestation Creation

- [ ] in-toto/DSSE library integrated into build pipeline
- [ ] Attestation signing key generated and secured
- [ ] DSSE envelope created for manifest
- [ ] SLSA provenance attestation added (if containerized)
- [ ] Attestation includes all required fields (predicate, subject, materials)
- [ ] Attestation validation tested in CI
- [ ] Attestation published alongside manifest

### Key Management

- [ ] Signing keys stored in HSM or cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
- [ ] Verification keys (public keys) published
- [ ] Key rotation schedule defined (recommended: 90 days for long-term keys)
- [ ] Key rotation automation implemented
- [ ] Overlap period configured during rotation
- [ ] Key revocation process documented
- [ ] CRL or OCSP configured for revocation checking
- [ ] Key compromise response plan documented
- [ ] Key access audit logging enabled
- [ ] Backup and recovery procedures tested

### Discovery Endpoint

- [ ] `/.well-known/mcp-manifest` endpoint implemented
- [ ] Endpoint returns current manifest digest
- [ ] Attestation URL included in response
- [ ] Verification keys (public keys) published in response
- [ ] Endpoint secured with HTTPS/TLS
- [ ] Rate limiting applied to prevent abuse
- [ ] Caching strategy implemented (with proper TTL)
- [ ] Endpoint monitoring and alerting configured

---

## Client/Gateway Enforcement

### Pre-Tool-List Verification

- [ ] SPIFFE ID verification implemented before `tools/list`
- [ ] Server SVID requested and validated
- [ ] SPIFFE ID matches expected trust domain
- [ ] Certificate chain validated against SPIRE trust bundle
- [ ] Certificate expiration checked
- [ ] Certificate revocation checked (CRL or OCSP)
- [ ] Manifest fetched from discovery endpoint
- [ ] Attestation bundle downloaded
- [ ] Attestation freshness validated (timestamp check)

### Signature Verification

- [ ] DSSE signature verification implemented
- [ ] Public key fetched and validated
- [ ] Key fingerprint pinned (enterprise setting)
- [ ] Signature algorithm validated (ECDSA-P256, RSA-PSS, etc.)
- [ ] Payload extracted and parsed
- [ ] Manifest digest verified

### Tool Descriptor Validation

- [ ] For each tool in `tools/list` response:
  - [ ] Tool descriptor extracted
  - [ ] JSON normalized (same algorithm as server)
  - [ ] Descriptor digest computed
  - [ ] Digest compared against signed manifest entry
  - [ ] Tool rejected if mismatch detected
  - [ ] Rejection logged with details

### Policy Configuration

- [ ] Policy defined: fail/warn/allow on verification failure
- [ ] Trusted SPIFFE trust domains allowlist configured
- [ ] Publisher key fingerprint pinning configured (enterprise)
- [ ] Fallback behavior documented (for compatibility)
- [ ] Policy exceptions documented (if any)
- [ ] Policy review schedule established

### Chained Controls

Post-authenticity verification, ensure these controls run:
- [ ] [SAFE-M-37](../SAFE-M-37/README.md) Metadata Sanitization applied
- [ ] [SAFE-M-38](../SAFE-M-38/README.md) Schema Validation applied
- [ ] [SAFE-M-43](../SAFE-M-43/README.md) Steganography Scanner applied
- [ ] [SAFE-M-44](../SAFE-M-44/README.md) Behavioral Monitoring applied
- [ ] Control execution order documented
- [ ] Control failures handled gracefully

---

## Telemetry & Response

### Logging

- [ ] Manifest verification results logged (pass/fail)
- [ ] Key fingerprints logged
- [ ] Server SPIFFE ID and trust domain logged
- [ ] Mismatch events logged with full details:
  - [ ] Tool name
  - [ ] Expected digest
  - [ ] Actual digest
  - [ ] Manifest version
  - [ ] Timestamp
- [ ] Rate/sequence anomalies detected and logged
- [ ] All logs sent to centralized SIEM
- [ ] Log retention policy defined (minimum 90 days)

### Alerting

- [ ] Alert: Unsigned manifests detected
- [ ] Alert: Invalid signatures detected
- [ ] Alert: Expired keys/certificates detected
- [ ] Alert: Revoked keys detected
- [ ] Alert: Server identity mismatch
- [ ] Alert: Unexpected SPIFFE trust domain
- [ ] Alert: Descriptor digest mismatches
- [ ] Alert: Frequent manifest changes (possible compromise)
- [ ] Alert: SVID validation failures
- [ ] Alert severity levels configured
- [ ] Alert escalation paths defined
- [ ] On-call runbooks created

### Incident Response

- [ ] Playbook: Quarantine offending server/tool on verification failure
- [ ] Playbook: Block server on repeated failures
- [ ] Playbook: Investigate manifest tampering
- [ ] Playbook: Key compromise response
- [ ] Playbook: SPIFFE ID spoofing attempt
- [ ] Security team contact list updated
- [ ] Incident response drills scheduled
- [ ] Post-incident review process documented

---

## Validation (Test Cases)

### Positive Tests

- [ ] Valid signature, descriptor digest match → tool loads successfully
- [ ] Valid SPIFFE ID from trusted domain → connection allowed
- [ ] Fresh manifest with valid timestamp → accepted
- [ ] Proper key rotation → old and new keys both work during overlap
- [ ] All supported signature algorithms tested

### Negative Tests

- [ ] Modified description text → digest mismatch → tool load blocked
- [ ] Invalid signature → verification fails → tools rejected
- [ ] Expired certificate → validation fails → connection refused
- [ ] Revoked key → verification fails → tools rejected
- [ ] Key rotation without publishing → verification fails → load blocked
- [ ] Server SPIFFE ID from unexpected trust domain → connection refused
- [ ] Manifest timestamp too old → rejected as stale
- [ ] Missing attestation → tools rejected
- [ ] Tampered attestation envelope → verification fails

### Performance Tests

- [ ] Verification latency measured (target: <100ms per tool)
- [ ] Manifest fetch latency tested
- [ ] SVID validation latency tested
- [ ] Load testing: 100+ tools verified without timeout
- [ ] Caching effectiveness validated

### Compatibility Tests

- [ ] Non-compliant clients can still connect (graceful degradation)
- [ ] Warning mode tested (logs but doesn't block)
- [ ] Migration path validated (existing deployments upgrade smoothly)

---

## Documentation

- [ ] Architecture diagram created (showing SPIRE, MCP server, clients)
- [ ] Configuration guide written (for server operators)
- [ ] Integration guide written (for client developers)
- [ ] Troubleshooting guide created
- [ ] FAQ document created
- [ ] Security considerations documented
- [ ] Performance tuning guide written
- [ ] Migration guide from non-attested deployments
- [ ] Training materials prepared for DevOps team

---

## Maintenance

- [ ] Key rotation schedule in calendar (every 90 days)
- [ ] SPIRE server maintenance windows scheduled
- [ ] Monitoring dashboard created
- [ ] Quarterly security review scheduled
- [ ] Dependency updates automated (SPIRE, in-toto libraries)
- [ ] Vulnerability scanning enabled for dependencies
- [ ] Annual penetration testing scheduled

---

## Compliance & Audit

- [ ] Control effectiveness documented for audit
- [ ] Compliance mapping completed (SOC 2, ISO 27001, etc.)
- [ ] Audit logs reviewed regularly
- [ ] Key access audit trail maintained
- [ ] Control testing evidence collected
- [ ] Third-party audit preparation completed

---

## References

For detailed implementation guidance, see:
- [SAFE-M-45 README](./README.md)
- [in-toto Attestation Framework](https://in-toto.io/docs/specs/)
- [SLSA Framework v1.0](https://slsa.dev/spec/v1.0/)
- [SPIFFE/SPIRE Documentation](https://spiffe.io/docs/)
- [RFC 9449 - OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Lead | | | |
| DevOps Lead | | | |
| Product Owner | | | |
| Compliance Officer | | | |

