"""
TrustMesh Red-Team Security Validation Suite
Simulates 6 real-world adversarial attacks against autonomous AI agent networks:
  1. Impersonation Attack (Identity forgery / Fake keypair)
  2. Replay Attack (Nonce / PoP envelope reuse)
  3. Privilege Escalation (Scope widening / Spend ceiling tampering)
  4. Payload Spoofing / MITM (Tampering with action parameters)
  5. Expired / Stale Token Abuse (Temporal validity breach)
  6. Delegation Chain Tampering / Broken Continuity (Unauthorized delegatee)
"""

from __future__ import annotations
import copy
import time
from rich.console import Console
from rich.table import Table

from trustmesh.crypto import AgentKeypair, canonical_json
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision

console = Console(highlight=False, emoji=False)


class SecurityAttackHarness:
    """Automated Red-Team Security Test Runner for TrustMesh."""

    def __init__(self):
        self.policy_engine = DynamicPolicyEngine()
        self.root_authority = AgentKeypair.generate(name="EnterpriseRootAuthority")
        self.policy_engine.add_trusted_root(self.root_authority.did)

        # Baseline authorized agents
        self.coordinator_agent = AgentKeypair.generate(name="CoordinatorAgent")
        self.worker_agent = AgentKeypair.generate(name="WorkerAgent")
        self.rogue_agent = AgentKeypair.generate(name="AdversaryRogueAgent")

        # Setup standard valid delegation chain: Root -> Coordinator -> Worker
        self._setup_baseline_chain()

    def _setup_baseline_chain(self):
        root_caveat = Caveat(
            max_spend=1000.00,
            allowed_actions=["purchase", "query"],
            allowed_resources=["cloud:*"],
            expiry=int(time.time()) + 3600,
        )
        root_cap = Capability(resource="cloud:*", action="*", caveats=root_caveat)
        self.root_token = DelegationToken(
            iss=self.root_authority.did,
            aud=self.coordinator_agent.did,
            capabilities=[root_cap],
            expires_at=int(time.time()) + 3600,
        )
        self.root_token.sign(self.root_authority)

        # Sub-delegation to worker ($250 ceiling)
        worker_caveat = Caveat(
            max_spend=250.00,
            allowed_actions=["purchase"],
            allowed_resources=["cloud:vm:provision"],
            expiry=int(time.time()) + 1800,
        )
        worker_cap = Capability(resource="cloud:vm:provision", action="purchase", caveats=worker_caveat)
        self.valid_worker_token = self.root_token.attenuate(
            audience_did=self.worker_agent.did,
            restricted_capabilities=[worker_cap],
            keypair=self.coordinator_agent,
            validity_seconds=1800,
        )

    def run_all_attacks(self) -> dict:
        console.print("[bold red]====================================================================[/bold red]")
        console.print("[bold red]   TrustMesh: Red-Team Security Validation & Attack Harness         [/bold red]")
        console.print("[bold red]====================================================================[/bold red]\n")

        results = {
            "ATTACK_1_IMPERSONATION": self.test_impersonation_attack(),
            "ATTACK_2_REPLAY": self.test_replay_attack(),
            "ATTACK_3_PRIVILEGE_ESCALATION": self.test_privilege_escalation_attack(),
            "ATTACK_4_PAYLOAD_SPOOFING": self.test_payload_spoofing_attack(),
            "ATTACK_5_EXPIRED_TOKEN": self.test_expired_token_attack(),
            "ATTACK_6_CHAIN_TAMPERING": self.test_chain_tampering_attack(),
        }

        self.print_summary(results)
        return results

    def test_impersonation_attack(self) -> PolicyDecision:
        """
        Attack 1: Rogue Agent attempts to execute an action using WorkerAgent's token,
        either by signing PoP with rogue key or claiming Worker's DID.
        """
        payload = {"vm_size": "c5.xlarge", "amount": 100.00}
        # Rogue agent signs PoP using their own keypair but presents Worker's token
        pop = ProofOfPossession(
            token_id=self.valid_worker_token.token_id,
            agent_did=self.rogue_agent.did,  # Mismatch with token.aud (WorkerAgent)
            action="purchase",
            resource="cloud:vm:provision",
            payload_hash=self.valid_worker_token.generate_pop(
                self.worker_agent, "purchase", "cloud:vm:provision", payload
            ).payload_hash,
            timestamp=int(time.time()),
            nonce="rogue_impersonate_nonce_01",
        )
        pop.sign(self.rogue_agent)

        decision = self.policy_engine.evaluate_request(
            token=self.valid_worker_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 100.00},
        )
        return decision

    def test_replay_attack(self) -> PolicyDecision:
        """
        Attack 2: Adversary captures a valid legitimate token + PoP envelope
        and replays the identical request to duplicate the transaction.
        """
        payload = {"vm_size": "t3.medium", "amount": 50.00}
        pop = self.valid_worker_token.generate_pop(
            keypair=self.worker_agent,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
            nonce="single_use_legit_nonce_42",
        )

        # 1st execution: Legitimate request succeeds
        decision_first = self.policy_engine.evaluate_request(
            token=self.valid_worker_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 50.00},
        )
        assert decision_first.decision == "APPROVED", "Baseline request failed unexpectedly"

        # 2nd execution: Attacker replays identical envelope (Same nonce)
        decision_replay = self.policy_engine.evaluate_request(
            token=self.valid_worker_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 50.00},
        )
        return decision_replay

    def test_privilege_escalation_attack(self) -> PolicyDecision:
        """
        Attack 3: Worker Agent attempts to escalate spend from $250 to $5,000,
        or coordinator attempts to delegate beyond root ceiling.
        """
        escalated_caveat = Caveat(
            max_spend=5000.00,  # Parent ceiling is $1,000!
            allowed_actions=["purchase"],
            allowed_resources=["cloud:vm:provision"],
            expiry=int(time.time()) + 1800,
        )
        escalated_cap = Capability(resource="cloud:vm:provision", action="purchase", caveats=escalated_caveat)

        # Sub-delegation with illegal escalation
        illegal_token = self.root_token.attenuate(
            audience_did=self.worker_agent.did,
            restricted_capabilities=[escalated_cap],
            keypair=self.coordinator_agent,
            validity_seconds=1800,
        )

        payload = {"vm_size": "p4d.24xlarge", "amount": 4500.00}
        pop = illegal_token.generate_pop(
            keypair=self.worker_agent,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
        )

        decision = self.policy_engine.evaluate_request(
            token=illegal_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 4500.00},
        )
        return decision

    def test_payload_spoofing_attack(self) -> PolicyDecision:
        """
        Attack 4: Attacker intercepts request and tampers with payload parameters
        (e.g., changes payment recipient or cluster count) without re-signing.
        """
        legit_payload = {"recipient_account": "AWS_Official_Billing", "amount": 150.00}
        # Legitimate agent signs PoP for legit_payload
        pop = self.valid_worker_token.generate_pop(
            keypair=self.worker_agent,
            action="purchase",
            resource="cloud:vm:provision",
            payload=legit_payload,
        )

        # Adversary alters payload in transit
        tampered_payload = {"recipient_account": "Adversary_Secret_Account", "amount": 150.00}

        decision = self.policy_engine.evaluate_request(
            token=self.valid_worker_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=tampered_payload,
            context={"spend_amount": 150.00},
        )
        return decision

    def test_expired_token_attack(self) -> PolicyDecision:
        """
        Attack 5: Adversary attempts to use an expired token.
        """
        past_time = int(time.time()) - 3600
        expired_token = copy.deepcopy(self.valid_worker_token)
        expired_token.expires_at = past_time
        # Sign with issuer
        expired_token.sign(self.coordinator_agent)

        payload = {"vm_size": "t3.micro", "amount": 10.00}
        pop = expired_token.generate_pop(
            keypair=self.worker_agent,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
        )

        decision = self.policy_engine.evaluate_request(
            token=expired_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 10.00},
        )
        return decision

    def test_chain_tampering_attack(self) -> PolicyDecision:
        """
        Attack 6: Broken delegation chain (e.g. Rogue Agent inserts itself
        as issuer without having been delegated to by parent).
        """
        tampered_token = copy.deepcopy(self.valid_worker_token)
        # Rogue agent replaces issuer with its own DID, breaking parent.aud == child.iss
        tampered_token.iss = self.rogue_agent.did
        tampered_token.sign(self.rogue_agent)

        payload = {"vm_size": "m5.large", "amount": 80.00}
        pop = tampered_token.generate_pop(
            keypair=self.worker_agent,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
        )

        decision = self.policy_engine.evaluate_request(
            token=tampered_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 80.00},
        )
        return decision

    def print_summary(self, results: dict):
        table = Table(title="TrustMesh Red-Team Security Validation Summary")
        table.add_column("Attack Vector", style="cyan")
        table.add_column("Threat Description", style="white")
        table.add_column("Policy Result", style="bold")
        table.add_column("Security Code", style="yellow")
        table.add_column("Status", style="bold green")

        descriptions = {
            "ATTACK_1_IMPERSONATION": "Agent forging DID or PoP signature",
            "ATTACK_2_REPLAY": "Duplicate envelope replayed across network",
            "ATTACK_3_PRIVILEGE_ESCALATION": "Child token exceeding parent budget",
            "ATTACK_4_PAYLOAD_SPOOFING": "Body tampered in transit (MITM)",
            "ATTACK_5_EXPIRED_TOKEN": "Token used past validity window",
            "ATTACK_6_CHAIN_TAMPERING": "Broken delegation continuity",
        }

        all_blocked = True
        for attack_name, decision in results.items():
            is_blocked = (decision.decision == "BLOCKED")
            if not is_blocked:
                all_blocked = False
            status_badge = "[bold green]BLOCKED (PASS)[/bold green]" if is_blocked else "[bold red]BREACHED (FAIL)[/bold red]"
            table.add_row(
                attack_name,
                descriptions.get(attack_name, ""),
                decision.decision,
                decision.code,
                status_badge,
            )

        console.print(table)
        if all_blocked:
            console.print("\n[bold green][100% PASS][/bold green] [white]All 6 attack vectors were mathematically blocked and logged.[/white]\n")
        else:
            console.print("\n[bold red][FAIL][/bold red] [white]One or more attack vectors were not blocked.[/white]\n")


if __name__ == "__main__":
    harness = SecurityAttackHarness()
    harness.run_all_attacks()
