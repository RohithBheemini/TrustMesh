# TrustMesh: Enterprise Compliance & Threat Mapping

This document provides a formal mapping of the **TrustMesh Dynamic Agent-to-Agent Authorization Protocol** to the **NIST SP 800-207 Zero Trust Architecture** and the **OWASP Top 10 for Large Language Model (LLM) Applications**.

---

## 1. NIST SP 800-207 Zero Trust Architecture (ZTA) Mapping

TrustMesh treats autonomous AI agents as zero-trust actors. Agents never assume trust based on network co-location (e.g. running in the same Python process, container, or private VPC).

| NIST SP 800-207 Tenet | Principle Description | TrustMesh Implementation |
| :--- | :--- | :--- |
| **Tenet 1: All data sources and computing services are resources** | Any tool, API, database, or LLM agent endpoint is treated as an individual resource. | Capabilities use explicit hierarchical resource URIs (e.g., `travel:flights:book`, `cloud:vm:provision`). |
| **Tenet 2: All communication is secured regardless of network location** | Internal agent-to-agent calls are authenticated with equal rigor as external calls. | Proof-of-Possession (PoP) digital signatures are required on every hop, whether in-process or across HTTP microservices. |
| **Tenet 3: Access is granted on a per-session basis** | No persistent or ambient authorization. | Every single action requires a fresh PoP envelope containing single-use nonces and short expiration windows ($TTL \le 2\text{h}$). |
| **Tenet 4: Dynamic policy determines access** | Access is governed by dynamic behavioral and contextual rules rather than static credentials. | Policy Engine dynamically evaluates spend limits, action whitelist, time bounds, parameter predicates, and revocation state. |
| **Tenet 5: The enterprise monitors integrity and security posture** | Verifies identity and posture before granting access. | Agents must prove possession of private keys corresponding to their stated `did:key` identity. |
| **Tenet 6: Dynamic and strictly enforced authorization** | Strict enforcement prior to resource mutation. | Policy engine interceptors evaluate requests *before* underlying tools, databases, or ledger calls execute. |
| **Tenet 7: Continuous telemetry and audit logging** | Collects detailed evidence for incident response and compliance. | Every decision generates an immutable cryptographic receipt signed by the Policy Engine verifier key. |

---

## 2. OWASP Top 10 for LLM Applications Mitigation

Autonomous agents driven by LLMs present unique attack surfaces. TrustMesh provides hard cryptographic boundaries to contain LLM vulnerabilities:

### LLM06: Excessive Agency
- **Risk**: An LLM agent is granted overly broad permissions, autonomous functionality, or access to sensitive tools. If the model hallucinates or is coerced via prompt injection, it executes catastrophic actions (e.g., spending thousands of dollars or deleting databases).
- **TrustMesh Mitigation**: 
  1. **Monotonic Capability Attenuation**: An agent can *never* execute actions outside its explicit UCAN token scope, even if prompted by an adversary.
  2. **Mathematical Caveats**: Spend ceilings (e.g. maximum $600) and allowed parameter whitelists are enforced cryptographically, mathematically preventing budget overruns.

### LLM01: Prompt Injection (Indirect & Direct)
- **Risk**: Malicious prompt injections inside unstructured data coerce a worker agent into attacking other agents or exfiltrating data.
- **TrustMesh Mitigation**:
  1. A compromised agent *cannot* elevate its own privileges or generate tokens with broader scopes than what its parent granted.
  2. The compromised agent's identity can be instantly blacklisted across the mesh using TrustMesh's runtime Revocation Engine without restarting services.

### LLM08: Vector and Embedding Weaknesses & Data Leakage
- **Risk**: Unauthorized inter-agent data scraping or query escalation.
- **TrustMesh Mitigation**:
  1. Data query capabilities require explicit resource matching (e.g., `db:users:read_only`).
  2. Multi-hop delegation chains ensure that specialized agents only receive the minimum necessary clearance required for their specific subtask.
