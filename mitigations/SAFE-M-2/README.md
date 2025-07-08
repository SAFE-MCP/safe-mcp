# SAFE-M-2: Cryptographic Integrity for Tool Descriptions

## Overview
**Mitigation ID**: SAFE-M-2  
**Category**: Cryptographic Control  
**Effectiveness**: High  
**Implementation Complexity**: Medium  
**First Published**: 2025-01-03

## Description
Cryptographic Integrity ensures that MCP tool descriptions cannot be tampered with by implementing digital signatures and hash verification. Tool descriptions are signed by trusted authorities, and clients verify these signatures before loading any tool, preventing unauthorized modifications at any point in the supply chain.

## Mitigates
- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1002](../../techniques/SAFE-T1002/README.md): Supply Chain Compromise
- [SAFE-T1003](../../techniques/SAFE-T1003/README.md): Malicious MCP-Server Distribution

## Technical Implementation

### Signing Process
```
Tool Developer                    Certificate Authority              Tool Registry
     │                                      │                             │
     ├─1. Create tool description──────────►│                             │
     │                                      │                             │
     ├─2. Request signing cert─────────────►│                             │
     │                                      │                             │
     │◄─3. Issue certificate────────────────┤                             │
     │                                      │                             │
     ├─4. Sign tool description─────────────────────────────────────────►│
     │   (description + signature)          │                             │
     │                                      │                             │
                                           Client
                                              │
                                              ├─5. Download tool──────────┤
                                              │                             │
                                              ├─6. Verify signature────────┤
                                              │                             │
                                              └─7. Load if valid
```

### Implementation Requirements

#### 1. Key Management
- Use X.509 certificates or similar PKI
- Implement certificate revocation lists (CRL)
- Support key rotation procedures

#### 2. Signature Format
```json
{
  "tool": {
    "name": "file_reader",
    "description": "Reads files from the filesystem",
    "version": "1.0.0",
    "inputSchema": { ... }
  },
  "signature": {
    "algorithm": "RS256",
    "keyId": "dev-key-2025-01",
    "signature": "base64-encoded-signature",
    "timestamp": "2025-01-03T10:00:00Z"
  }
}
```

#### 3. Verification Process
```python
def verify_tool_description(tool_data):
    # Extract components
    tool_content = tool_data['tool']
    signature_data = tool_data['signature']
    
    # Verify timestamp is recent
    if not verify_timestamp(signature_data['timestamp']):
        raise SecurityError("Signature timestamp expired")
    
    # Get public key for keyId
    public_key = get_trusted_key(signature_data['keyId'])
    if not public_key:
        raise SecurityError("Unknown signing key")
    
    # Verify signature
    canonical_content = canonicalize_json(tool_content)
    if not verify_signature(
        canonical_content, 
        signature_data['signature'], 
        public_key,
        signature_data['algorithm']
    ):
        raise SecurityError("Invalid signature")
    
    return tool_content
```

## Implementation Steps

### Phase 1: Infrastructure Setup
1. Deploy Certificate Authority (CA) or use existing PKI
2. Create key management procedures
3. Set up secure key storage (HSM recommended)

### Phase 2: Tool Signing
1. Implement signing tools for developers
2. Create CI/CD integration for automated signing
3. Establish code review before signing

### Phase 3: Client Verification
1. Update MCP clients to require signatures
2. Implement signature verification
3. Add signature status to UI

### Phase 4: Monitoring
1. Log all signature verifications
2. Alert on verification failures
3. Track certificate usage

## Best Practices

### DO:
- Use hardware security modules (HSM) for private keys
- Implement certificate pinning for critical tools
- Verify entire tool schema, not just descriptions
- Include version information in signed content
- Use timestamp servers to prove signing time

### DON'T:
- Store private keys in version control
- Use self-signed certificates in production
- Skip timestamp verification
- Allow signature downgrade attacks
- Trust expired certificates

## Testing and Validation

### Security Tests
1. **Tamper Detection**: Modify signed content and verify rejection
2. **Replay Prevention**: Attempt to use old signatures
3. **Key Compromise**: Test certificate revocation
4. **Downgrade Attacks**: Try to bypass signature requirements

### Operational Tests
1. **Performance**: Measure signature verification overhead
2. **Availability**: Test behavior when CA is unreachable
3. **Compatibility**: Ensure backward compatibility

## References
- [NIST Special Publication 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-204D: Software Supply Chain Security in DevSecOps](https://csrc.nist.gov/pubs/sp/800/204/d/final)
- [in-toto: Framework for Supply Chain Integrity](https://in-toto.io/)
- [DSSE: Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [PASETO: Platform-Agnostic Security Tokens](https://paseto.io/)
- [COSE: CBOR Object Signing and Encryption - RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 5652: Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
- [JSON Web Signature (JWS) - RFC 7515](https://tools.ietf.org/html/rfc7515)
- [MCP Security Best Practices](https://modelcontextprotocol.io/security)

## Related Mitigations
- [SAFE-M-6](../SAFE-M-6/README.md): Tool Registry Verification
- [SAFE-M-9](../SAFE-M-9/README.md): Sandboxed Testing

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-03 | Initial documentation | Frederick Kautz |