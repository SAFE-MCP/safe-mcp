

# SAFE-T1306: Rogue Authentication Server

## Security Principles Applied

---

## Description

Attack highlights violations of:

* **Least Privilege**: excessive `scope` claims without enforcement.
* **Fail Safe Defaults**: default trust of dynamically discovered issuers.
* **Complete Mediation**: missing validation of every token claim at every access.
* **Defense in Depth**: absence of layered controls (e.g., PoP enforcement, static issuer pinning).

---

## Technical Details

| Principle            | Application in Context                                                               |
| -------------------------- | ------------------------------------------------------------------------------------ |
| **Least Privilege**        | Scope enforcement and PoP binding restrict privileges to required functions only.    |
| **Defense in Depth**       | Combine issuer pinning, PoP tokens, JWKS integrity, HTTP Message signing, and anomaly detection.           |
| **Fail Safe Defaults**     | Reject unknown issuers or missing `cnf` claims by default. Reject invalid HTTP message signatures                          |
| **Economy of Mechanism**   | Simplify token validation code to reduce logic complexity and attack surface.        |
| **Complete Mediation**     | Verify each token’s `iss`, `aud`, `scope`, `cnf`, expiry and message signature on *every* API request. |
| **Open Design**            | Follow public OAuth 2.1 / OIDC PoP standards instead of proprietary shortcuts.       |
| **Separation of Duties**   | Isolate the authorization service (AS) from the model server runtime.  Client side request signing.            |
| **Least Common Mechanism** | Prevent multiple services from sharing token validation caches or signing keys.      |

### Response

* **Fail Safe Defaults**: Revoke rogue AS trust immediately.
* **Separation of Duties**: Ensure incident response and signing key rotation are handled by independent teams.
* **Defense in Depth**: Review all downstream systems accepting the compromised tokens.

---

## Integration with Lifecycle Phases

| Phase              | Application                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| **Requirements**   | Define token trust boundaries and issuer policies explicitly.              |
| **Design**         | Architect PoP enforcement and JWKS validation layers.                      |
| **Implementation** | Harden libraries (avoid auto-discovery, validate claims fully).            |
| **Testing**        | Include unit and integration tests for token validation and issuer checks. |
| **Deployment**     | Configure key rotation and issuer lists via secure CI/CD.                  |
| **Maintenance**    | Continuously monitor for new token substitution exploits.                  |

---

## Security Summary

**Root Cause**: Overtrust in federated discovery and insufficient PoP enforcement.
**Primary Violations**:

* **Least Privilege** (excessive scopes)
* **Fail Safe Defaults** (trusting unknown issuers)
* **Complete Mediation** (incomplete claim validation)

**Recommended Safeguard Alignment**:
Apply *Defense in Depth* by combining cryptographic binding (PoP), static trust anchors, and layered validation.
