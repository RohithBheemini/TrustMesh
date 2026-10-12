"""
TrustMesh Flagship Demo: Cross-Framework Corporate Travel & Procurement Mesh
Demonstrates end-to-end zero-trust capability delegation across:
  Human Root Authority -> CrewAI Coordinator -> AutoGen Booking Agent -> FastAPI Payment Service.
Includes automated verification of legitimate authorization and dynamic rejection of violations.
"""

from __future__ import annotations
import time
from rich.console import Console
from rich.table import Table

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken
from trustmesh.policy import DynamicPolicyEngine
from trustmesh.adapters.crewai_adapter import TrustMeshCrewAgent
from trustmesh.adapters.autogen_adapter import TrustMeshAutoGenAgent

# Configure console to ensure clean rendering on all operating systems without emoji parsing
console = Console(highlight=False, emoji=False)


def run_corporate_travel_mesh():
    console.print("[bold cyan]====================================================================[/bold cyan]")
    console.print("[bold cyan]   TrustMesh: Cross-Framework Authorization Mesh Demonstration      [/bold cyan]")
    console.print("[bold cyan]====================================================================[/bold cyan]\n")

    # 1. Initialize Policy Engine & Verifier
    policy_engine = DynamicPolicyEngine()

    # 2. Keypairs for actors in the mesh
    human_exec = AgentKeypair.generate(name="HumanExecutive_Alice")
    crew_coordinator = AgentKeypair.generate(name="CrewAI_TravelCoordinator")
    autogen_booker = AgentKeypair.generate(name="AutoGen_FlightSpecialist")
    payment_service = AgentKeypair.generate(name="FastAPI_PaymentGateway")

    policy_engine.add_trusted_root(human_exec.did)

    console.print("[bold green][OK][/bold green] [yellow]Identities Established:[/yellow]")
    console.print(f"  * Human Executive Root DID : [dim]{human_exec.did}[/dim]")
    console.print(f"  * CrewAI Coordinator DID   : [dim]{crew_coordinator.did}[/dim]")
    console.print(f"  * AutoGen Flight Agent DID : [dim]{autogen_booker.did}[/dim]")
    console.print(f"  * Payment Gateway DID      : [dim]{payment_service.did}[/dim]\n")

    # 3. Root Delegation: Human Executive -> CrewAI Coordinator
    console.print("[bold blue]Step 1: Human Executive grants Root Delegation to CrewAI Coordinator[/bold blue]")
    root_caveat = Caveat(
        max_spend=1000.00,
        allowed_actions=["search", "book", "cancel"],
        allowed_resources=["travel:*"],
        predicates={"allowed_airlines": ["American", "Delta", "United"]},
        expiry=int(time.time()) + 86400,
    )
    root_capability = Capability(resource="travel:*", action="*", caveats=root_caveat)
    root_token = DelegationToken(
        iss=human_exec.did,
        aud=crew_coordinator.did,
        capabilities=[root_capability],
        expires_at=int(time.time()) + 86400,
    )
    root_token.sign(human_exec)
    console.print(f"  -> Root Token Issued: ID [bold]{root_token.token_id[:8]}...[/bold] (Limit: $1,000.00, Scope: travel:*)\n")

    # 4. Attenuation & Sub-Delegation: CrewAI Coordinator -> AutoGen Flight Agent
    console.print("[bold blue]Step 2: CrewAI Coordinator attenuates and sub-delegates to AutoGen Agent[/bold blue]")
    coordinator_agent = TrustMeshCrewAgent(
        role="Travel Coordinator",
        goal="Plan and delegate corporate trip itinerary",
        keypair=crew_coordinator,
        token=root_token,
    )

    flight_caveat = Caveat(
        max_spend=600.00,  # Attenuated down from $1,000
        allowed_actions=["book"],
        allowed_resources=["travel:flights:book"],
        predicates={"allowed_airlines": ["American", "Delta"]},  # Sub-scoped from ["American", "Delta", "United"]
        expiry=int(time.time()) + 7200,
    )
    flight_capability = Capability(resource="travel:flights:book", action="book", caveats=flight_caveat)

    flight_token = coordinator_agent.delegate_to(
        target_agent_did=autogen_booker.did,
        capabilities=[flight_capability],
        validity_seconds=7200,
    )
    console.print(f"  -> Child Token Issued: ID [bold]{flight_token.token_id[:8]}...[/bold]")
    console.print(f"    * Attenuated Spend Ceiling: [green]$600.00[/green] (Parent: $1,000.00)")
    console.print(f"    * Attenuated Airlines: [green]['American', 'Delta'][/green] (Parent: ['American', 'Delta', 'United'])")
    console.print(f"    * Chain Depth: [cyan]{flight_token.chain_depth}[/cyan]\n")

    # 5. Legitimate Booking: AutoGen Agent invokes Payment Gateway
    console.print("[bold blue]Step 3: AutoGen Agent books legitimate flight for $450.00[/bold blue]")
    autogen_agent = TrustMeshAutoGenAgent(
        name="FlightSpecialist",
        keypair=autogen_booker,
        policy_engine=policy_engine,
        token=flight_token,
    )

    legit_payload = {
        "flight_no": "AA-1042",
        "airline": "American",
        "origin": "SFO",
        "destination": "JFK",
        "amount": 450.00,
        "passenger": "Alice Smith",
    }
    legit_pop = flight_token.generate_pop(
        keypair=autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=legit_payload,
    )

    legit_decision = policy_engine.evaluate_request(
        token=flight_token,
        pop=legit_pop,
        resource="travel:flights:book",
        action="book",
        payload=legit_payload,
        context={"spend_amount": 450.00, "allowed_airlines": "American"},
    )

    console.print(f"  -> Decision: [bold green]{legit_decision.decision}[/bold green] ({legit_decision.code})")
    console.print(f"  -> Audit Receipt: [dim]Signed by {legit_decision.verifier_did[:24]}...[/dim]\n")

    # 6. Violation Test A: Out-of-Scope Spend ($750 exceeds $600 limit)
    console.print("[bold red]Violation Scenario A: Overspend Attempt ($750.00 vs $600.00 Limit)[/bold red]")
    overspend_payload = {**legit_payload, "amount": 750.00}
    overspend_pop = flight_token.generate_pop(
        keypair=autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=overspend_payload,
    )
    overspend_decision = policy_engine.evaluate_request(
        token=flight_token,
        pop=overspend_pop,
        resource="travel:flights:book",
        action="book",
        payload=overspend_payload,
        context={"spend_amount": 750.00, "allowed_airlines": "American"},
    )
    console.print(f"  -> Decision: [bold red]{overspend_decision.decision}[/bold red] ({overspend_decision.code})")
    console.print(f"  -> Block Reason: [yellow]{overspend_decision.reason}[/yellow]\n")

    # 7. Violation Test B: Disallowed Airline ("Lufthansa" not in ["American", "Delta"])
    console.print("[bold red]Violation Scenario B: Unauthorized Airline Predicate ('Lufthansa')[/bold red]")
    airline_payload = {**legit_payload, "airline": "Lufthansa", "amount": 350.00}
    airline_pop = flight_token.generate_pop(
        keypair=autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=airline_payload,
    )
    airline_decision = policy_engine.evaluate_request(
        token=flight_token,
        pop=airline_pop,
        resource="travel:flights:book",
        action="book",
        payload=airline_payload,
        context={"spend_amount": 350.00, "allowed_airlines": "Lufthansa"},
    )
    console.print(f"  -> Decision: [bold red]{airline_decision.decision}[/bold red] ({airline_decision.code})")
    console.print(f"  -> Block Reason: [yellow]{airline_decision.reason}[/yellow]\n")

    # 8. Summary Table
    table = Table(title="TrustMesh Dynamic Policy Enforcement Audit Log")
    table.add_column("Timestamp", style="dim")
    table.add_column("Invoking Agent", style="cyan")
    table.add_column("Action / Resource", style="white")
    table.add_column("Decision", style="bold")
    table.add_column("Code / Reason", style="yellow")

    for entry in policy_engine.get_audit_log():
        status_style = "green" if entry.decision == "APPROVED" else "red"
        table.add_row(
            str(entry.timestamp),
            entry.invoking_agent[:24] + "...",
            f"{entry.target_action} on {entry.target_resource}",
            f"[{status_style}]{entry.decision}[/{status_style}]",
            f"{entry.code}: {entry.reason[:40]}...",
        )

    console.print(table)
    return True


if __name__ == "__main__":
    run_corporate_travel_mesh()
