"""
TrustMesh Dynamic Policy Engine & Cryptographic Verifier
Enforces runtime zero-trust authorization, cryptographic chain verification,
monotonic caveat attenuation, replay defense, and audit logging.
"""

from __future__ import annotations
import threading
import time
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair, canonical_json, hash_payload
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession
from trustmesh.merkle_audit import MerkleAuditTree
from trustmesh.abac import ABACPolicyEvaluator


class PolicyDecision(BaseModel):
    """
    Immutable cryptographic audit receipt generated for every authorization request.
    """
    decision: str  # "APPROVED" | "BLOCKED"
    code: str      # e.g., "AUTH_OK", "ERR_PRIVILEGE_ESCALATION", "ERR_REPLAY_ATTACK", etc.
    reason: str
    invoking_agent: str
    target_resource: str
    target_action: str
    chain_depth: int = 0
    token_id: Optional[str] = None
    evaluated_caveats: Dict[str, Any] = Field(default_factory=dict)
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    verifier_did: str = ""
    receipt_signature: str = ""
    merkle_leaf_index: Optional[int] = None
    merkle_root: Optional[str] = None
    trace_id: Optional[str] = None

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("receipt_signature", None)
        return d

    def sign(self, verifier_key: AgentKeypair) -> None:
        self.verifier_did = verifier_key.did
        raw = canonical_json(self.to_signable_dict())
        self.receipt_signature = verifier_key.sign(raw)


class DynamicPolicyEngine:
    """
    Zero-Trust Policy Enforcement Engine for AI Agent interactions.
    Maintains replay cache, revocation lists, and evaluates delegation DAGs.
    """

    def __init__(
        self,
        trusted_root_dids: Optional[Set[str]] = None,
        clock_skew_seconds: int = 60,
        verifier_keypair: Optional[AgentKeypair] = None,
        storage: Optional[Any] = None,
    ):
        self.trusted_roots: Set[str] = trusted_root_dids or set()
        self.clock_skew: int = clock_skew_seconds
        self.verifier_key: AgentKeypair = verifier_keypair or AgentKeypair.generate(name="TrustMeshPolicyEngine")
        self.storage: Optional[Any] = storage
        
        # Merkle Audit Transparency Tree & ABAC Engine
        self.merkle_tree: MerkleAuditTree = MerkleAuditTree()
        self.abac_evaluator: ABACPolicyEvaluator = ABACPolicyEvaluator()

        # Replay protection: map of nonce -> timestamp
        self._seen_nonces: Dict[str, int] = {}
        # Revocation sets
        self._revoked_tokens: Set[str] = set()
        self._revoked_agents: Set[str] = set()
        # Audit log history
        self._audit_log: List[PolicyDecision] = []
        # Thread re-entrant lock for safe state updates
        self._lock = threading.RLock()

    def add_trusted_root(self, did: str) -> None:
        with self._lock:
            self.trusted_roots.add(did)

    def revoke_token(self, token_id: str) -> None:
        with self._lock:
            self._revoked_tokens.add(token_id)

    def revoke_agent(self, agent_did: str) -> None:
        with self._lock:
            self._revoked_agents.add(agent_did)

    def unrevoke_agent(self, agent_did: str) -> None:
        with self._lock:
            self._revoked_agents.discard(agent_did)

    def get_audit_log(self, limit: int = 50) -> List[PolicyDecision]:
        with self._lock:
            if self.storage:
                try:
                    return self.storage.get_recent_decisions(limit=limit)
                except Exception:
                    pass
            return list(reversed(self._audit_log[-limit:]))

    def _cleanup_nonces(self, current_time: int) -> None:
        threshold = current_time - (self.clock_skew * 2)
        to_del = [k for k, ts in self._seen_nonces.items() if ts < threshold]
        for k in to_del:
            del self._seen_nonces[k]

    def _block(
        self,
        code: str,
        reason: str,
        invoking_agent: str,
        resource: str,
        action: str,
        token_id: Optional[str] = None,
        chain_depth: int = 0,
        caveats: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> PolicyDecision:
        receipt = PolicyDecision(
            decision="BLOCKED",
            code=code,
            reason=reason,
            invoking_agent=invoking_agent,
            target_resource=resource,
            target_action=action,
            chain_depth=chain_depth,
            token_id=token_id,
            evaluated_caveats=caveats or {},
            trace_id=trace_id,
        )
        receipt.sign(self.verifier_key)
        with self._lock:
            leaf_idx, _ = self.merkle_tree.append_decision(receipt.model_dump())
            receipt.merkle_leaf_index = leaf_idx
            receipt.merkle_root = self.merkle_tree.get_root_hash()
            self._audit_log.append(receipt)
            if self.storage:
                try:
                    self.storage.record_decision(receipt)
                except Exception:
                    pass
        return receipt

    def _approve(
        self,
        invoking_agent: str,
        resource: str,
        action: str,
        token_id: str,
        chain_depth: int,
        caveats: Dict[str, Any],
        reason: str = "Authorized by verified delegation chain and monotonic caveats",
        trace_id: Optional[str] = None,
    ) -> PolicyDecision:
        receipt = PolicyDecision(
            decision="APPROVED",
            code="AUTH_OK",
            reason=reason,
            invoking_agent=invoking_agent,
            target_resource=resource,
            target_action=action,
            chain_depth=chain_depth,
            token_id=token_id,
            evaluated_caveats=caveats,
            trace_id=trace_id,
        )
        receipt.sign(self.verifier_key)
        with self._lock:
            leaf_idx, _ = self.merkle_tree.append_decision(receipt.model_dump())
            receipt.merkle_leaf_index = leaf_idx
            receipt.merkle_root = self.merkle_tree.get_root_hash()
            self._audit_log.append(receipt)
            if self.storage:
                try:
                    self.storage.record_decision(receipt)
                except Exception:
                    pass
        return receipt

    def evaluate_request(
        self,
        token: DelegationToken,
        pop: ProofOfPossession,
        resource: str,
        action: str,
        payload: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate an incoming agent invocation against zero-trust cryptographic guarantees.
        """
        now = int(time.time())
        ctx = context or {}
        trace_id = ctx.get("trace_id")

        # 1. Revocation checks
        if pop.agent_did in self._revoked_agents:
            return self._block(
                "ERR_AGENT_REVOKED",
                f"Invoking agent {pop.agent_did} has been revoked by policy administrator",
                pop.agent_did, resource, action, token.token_id,
                trace_id=trace_id,
            )
        if token.token_id in self._revoked_tokens:
            return self._block(
                "ERR_TOKEN_REVOKED",
                f"Delegation token {token.token_id} has been revoked",
                pop.agent_did, resource, action, token.token_id,
                trace_id=trace_id,
            )

        # 2. Replay attack & sliding window protection
        with self._lock:
            self._cleanup_nonces(now)
            # Timestamp validity
            if abs(now - pop.timestamp) > self.clock_skew:
                return self._block(
                    "ERR_TIMESTAMP_SKEW",
                    f"Proof-of-Possession timestamp out of bounds ({pop.timestamp} vs current {now}, drift exceeds {self.clock_skew}s)",
                    pop.agent_did, resource, action, token.token_id,
                )
            # Nonce uniqueness
            if pop.nonce in self._seen_nonces:
                return self._block(
                    "ERR_REPLAY_ATTACK",
                    f"Replay attack detected! Nonce '{pop.nonce}' has already been consumed",
                    pop.agent_did, resource, action, token.token_id,
                )
            self._seen_nonces[pop.nonce] = now

        # 3. Impersonation & Proof-of-Possession signature check
        if not pop.verify():
            return self._block(
                "ERR_IMPERSONATION",
                f"Cryptographic signature on Proof-of-Possession invalid for agent {pop.agent_did}",
                pop.agent_did, resource, action, token.token_id,
            )

        if pop.agent_did != token.aud:
            return self._block(
                "ERR_AUDIENCE_MISMATCH",
                f"Impersonation detected: Invoking agent {pop.agent_did} is not authorized audience ({token.aud}) of presentation token",
                pop.agent_did, resource, action, token.token_id,
            )

        # 4. Action and Resource match in PoP envelope
        if pop.action != action or pop.resource != resource:
            return self._block(
                "ERR_SCOPE_MISMATCH",
                f"PoP envelope parameters ({pop.action}, {pop.resource}) do not match request ({action}, {resource})",
                pop.agent_did, resource, action, token.token_id,
            )

        # 5. Payload tampering check
        expected_hash = hash_payload(payload)
        if pop.payload_hash != expected_hash:
            return self._block(
                "ERR_PAYLOAD_TAMPERED",
                f"Payload spoofing detected! Payload SHA-256 ({expected_hash}) does not match signed PoP hash ({pop.payload_hash})",
                pop.agent_did, resource, action, token.token_id,
            )

        # 6. Leaf token temporal validity
        if now > token.expires_at:
            return self._block(
                "ERR_TOKEN_EXPIRED",
                f"Delegation token expired at timestamp {token.expires_at} (current: {now})",
                pop.agent_did, resource, action, token.token_id,
            )
        if now < token.issued_at - self.clock_skew:
            return self._block(
                "ERR_TOKEN_NOT_YET_VALID",
                f"Delegation token issued in future timestamp {token.issued_at}",
                pop.agent_did, resource, action, token.token_id,
            )

        # 7. Delegation Chain Cryptographic Verification
        chain = token.get_delegation_chain()
        chain_depth = len(chain)

        # Check all links from root down to leaf
        for i, curr_tok in enumerate(chain):
            # Signature verification on the token itself
            if not curr_tok.verify_token_signature():
                return self._block(
                    "ERR_CHAIN_TAMPERED",
                    f"Token at delegation depth {i+1} has invalid signature by issuer {curr_tok.iss}",
                    pop.agent_did, resource, action, curr_tok.token_id, chain_depth,
                )

            # Check if any token in chain is revoked
            if curr_tok.token_id in self._revoked_tokens:
                return self._block(
                    "ERR_TOKEN_REVOKED",
                    f"Delegation token at depth {i+1} ({curr_tok.token_id}) was revoked",
                    pop.agent_did, resource, action, curr_tok.token_id, chain_depth,
                )

            # Check delegation link continuity: child.iss must equal parent.aud
            if i > 0:
                parent_tok = chain[i - 1]
                if curr_tok.iss != parent_tok.aud:
                    return self._block(
                        "ERR_CHAIN_BROKEN",
                        f"Delegation chain broken at depth {i+1}: Issuer {curr_tok.iss} does not match parent audience {parent_tok.aud}",
                        pop.agent_did, resource, action, curr_tok.token_id, chain_depth,
                    )

                # Monotonic attenuation verification
                # Each child capability must be tighter than or equal to a corresponding parent capability
                for child_cap in curr_tok.capabilities:
                    parent_match = None
                    for p_cap in parent_tok.capabilities:
                        if p_cap.matches(child_cap.resource, child_cap.action):
                            parent_match = p_cap
                            break

                    if not parent_match:
                        return self._block(
                            "ERR_PRIVILEGE_ESCALATION",
                            f"Privilege Escalation: Child token claims capability '{child_cap.action} on {child_cap.resource}' not granted by parent token",
                            pop.agent_did, resource, action, curr_tok.token_id, chain_depth,
                        )

                    # Check caveat monotonicity
                    is_tighter, reason = child_cap.caveats.is_tighter_or_equal_to(parent_match.caveats)
                    if not is_tighter:
                        return self._block(
                            "ERR_PRIVILEGE_ESCALATION",
                            f"Privilege Escalation at depth {i+1}: {reason}",
                            pop.agent_did, resource, action, curr_tok.token_id, chain_depth,
                        )

        # 8. Root Authority verification
        root_token = chain[0]
        if self.trusted_roots and root_token.iss not in self.trusted_roots:
            return self._block(
                "ERR_UNTRUSTED_ROOT",
                f"Root delegation token issued by untrusted authority: {root_token.iss}",
                pop.agent_did, resource, action, root_token.token_id, chain_depth,
            )

        # 9. Capability & Caveat matching on the leaf token for this specific invocation
        matched_cap: Optional[Capability] = None
        for cap in token.capabilities:
            if cap.matches(resource, action):
                matched_cap = cap
                break

        if not matched_cap:
            return self._block(
                "ERR_UNAUTHORIZED_ACTION",
                f"No capability in token grants action '{action}' on resource '{resource}'",
                pop.agent_did, resource, action, token.token_id, chain_depth,
            )

        # 10. Runtime Caveats & Spend Limit Enforcement
        caveats = matched_cap.caveats
        evaluated_caveats_dict = caveats.model_dump()

        # Check spend limit
        spend_amount = ctx.get("spend_amount")
        if spend_amount is not None and caveats.max_spend is not None:
            if float(spend_amount) > float(caveats.max_spend):
                return self._block(
                    "ERR_SPEND_LIMIT_EXCEEDED",
                    f"Spend limit exceeded: Requested ${float(spend_amount):.2f} exceeds authorized ceiling of ${caveats.max_spend:.2f}",
                    pop.agent_did, resource, action, token.token_id, chain_depth,
                    evaluated_caveats_dict,
                )

        # Check custom ABAC predicates in context (time windows, CIDRs, rate limits, operators)
        if caveats.predicates:
            is_valid, abac_reason = self.abac_evaluator.evaluate(
                caveats.predicates, ctx, pop.agent_did
            )
            if not is_valid:
                return self._block(
                    "ERR_PREDICATE_VIOLATION",
                    f"Predicate violation: {abac_reason}",
                    pop.agent_did, resource, action, token.token_id, chain_depth,
                    evaluated_caveats_dict,
                    trace_id=trace_id,
                )

        # All 10 security checks passed!
        return self._approve(
            pop.agent_did,
            resource,
            action,
            token.token_id,
            chain_depth,
            evaluated_caveats_dict,
            reason=f"Authorized: verified {chain_depth}-step delegation chain and all caveat bounds",
            trace_id=trace_id,
        )
