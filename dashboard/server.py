"""
TrustMesh Visual Policy Enforcement Dashboard Server
FastAPI backend providing real-time SSE audit streams, mesh topology introspection,
A2A Agent Card discovery, MCP tool gatekeeping, and Human-in-the-Loop Step-Up Escalation.
"""

from __future__ import annotations
import asyncio
import copy
import json
import os
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision
from trustmesh.adapters.crewai_adapter import TrustMeshCrewAgent
from trustmesh.adapters.autogen_adapter import TrustMeshAutoGenAgent
from trustmesh.adapters.mcp_adapter import TrustMeshMCPToolGuard, MCPToolResponse
from trustmesh.agent_card import AgentCard, AgentSkill, create_agent_card
from trustmesh.escalation import EscalationManager, EscalationRequest

app = FastAPI(title="TrustMesh Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Mesh State
class MeshContext:
    def __init__(self):
        self.reset()

    def reset(self):
        self.policy_engine = DynamicPolicyEngine()
        self.human_root = AgentKeypair.generate(name="Human Executive (Root Principal)")
        self.coordinator = AgentKeypair.generate(name="CrewAI Coordinator")
        self.autogen_booker = AgentKeypair.generate(name="AutoGen Flight Specialist")
        self.payment_gw = AgentKeypair.generate(name="FastAPI Payment Gateway")
        self.rogue_agent = AgentKeypair.generate(name="Adversary Rogue Agent")

        self.policy_engine.add_trusted_root(self.human_root.did)
        self.current_spend_ceiling = 600.00
        self.escalation_mgr = EscalationManager(supervisor_keypair=self.human_root)
        self._build_tokens()
        self._build_agent_cards()
        self._init_mcp_guard()
        self.event_subscribers: List[asyncio.Queue] = []

    def _build_tokens(self):
        # Root Token ($1000)
        root_caveat = Caveat(
            max_spend=1000.00,
            allowed_actions=["search", "book", "cancel"],
            allowed_resources=["travel:*"],
            predicates={"allowed_airlines": ["American", "Delta", "United"]},
            expiry=int(time.time()) + 86400,
        )
        self.root_token = DelegationToken(
            iss=self.human_root.did,
            aud=self.coordinator.did,
            capabilities=[Capability(resource="travel:*", action="*", caveats=root_caveat)],
            expires_at=int(time.time()) + 86400,
        )
        self.root_token.sign(self.human_root)

        # Child Token ($600 ceiling or dynamic)
        child_caveat = Caveat(
            max_spend=self.current_spend_ceiling,
            allowed_actions=["book"],
            allowed_resources=["travel:flights:book"],
            predicates={"allowed_airlines": ["American", "Delta"]},
            expiry=int(time.time()) + 7200,
        )
        self.flight_token = self.root_token.attenuate(
            audience_did=self.autogen_booker.did,
            restricted_capabilities=[Capability(resource="travel:flights:book", action="book", caveats=child_caveat)],
            keypair=self.coordinator,
            validity_seconds=7200,
        )

    def _build_agent_cards(self):
        self.agent_cards = {
            "root": create_agent_card(
                self.human_root,
                "Human Executive (Root Authority)",
                "Master organizational principal issuing top-level delegations.",
                "https://mesh.enterprise.internal/root",
                [AgentSkill(id="sk_admin", name="Enterprise Authority", description="Root governance", resource="*")],
            ),
            "coord": create_agent_card(
                self.coordinator,
                "Travel Coordinator (CrewAI)",
                "Autonomous planner breaking trips into flight, hotel, and transport sub-tasks.",
                "https://mesh.enterprise.internal/crewai-coord",
                [AgentSkill(id="sk_plan", name="Travel Planning", description="Plan itineraries", resource="travel:*", allowed_actions=["search", "book"])],
            ),
            "booker": create_agent_card(
                self.autogen_booker,
                "Flight Specialist (AutoGen / LangGraph)",
                "Negotiates ticket inventory and invokes payment settlement APIs.",
                "https://mesh.enterprise.internal/autogen-booker",
                [AgentSkill(id="sk_flight", name="Airline Booking", description="Execute seat reservations", resource="travel:flights:book", allowed_actions=["book"])],
            ),
            "pay": create_agent_card(
                self.payment_gw,
                "Payment Gateway (FastAPI / MCP Server)",
                "Protected enterprise ledger settling financial charges upon cryptographic proof.",
                "https://mesh.enterprise.internal/payment",
                [AgentSkill(id="sk_settle", name="Ledger Settlement", description="Charge accounts", resource="payment:charge", allowed_actions=["charge"])],
            ),
            "rogue": create_agent_card(
                self.rogue_agent,
                "Rogue Impersonator",
                "Unapproved adversarial agent attempting token theft and escalation.",
                "https://adversary.darknet/agent",
            ),
        }

    def _init_mcp_guard(self):
        def book_flight_tool(flight_no: str, airline: str, amount: float):
            return {"reservation_id": "RES-88910", "flight": flight_no, "status": "CONFIRMED", "cost": amount}

        self.mcp_guard = TrustMeshMCPToolGuard(
            tool_name="book_flight",
            resource_pattern="travel:flights:book",
            action_name="book",
            handler=book_flight_tool,
            policy_engine=self.policy_engine,
            spend_arg_name="amount",
        )

    async def broadcast_event(self, event_data: dict):
        for q in self.event_subscribers:
            try:
                await q.put(event_data)
            except Exception:
                pass


mesh = MeshContext()


# A2A Standard Endpoint: /.well-known/agent-card.json
@app.get("/.well-known/agent-card.json")
async def get_well_known_agent_card():
    """Linux Foundation A2A Standard Agent Discovery Endpoint."""
    return mesh.agent_cards["pay"].model_dump()


@app.get("/api/a2a/agent-cards")
async def get_all_a2a_cards():
    """Discover all published A2A Signed Agent Cards in the mesh."""
    return {k: v.model_dump() for k, v in mesh.agent_cards.items()}


@app.get("/api/status")
async def get_mesh_status():
    """Return mesh topology, identities, token chain, and policy status."""
    chain = mesh.flight_token.get_delegation_chain()
    return {
        "agents": [
            {"id": "root", "name": mesh.human_root.name, "did": mesh.human_root.did, "role": "Root Principal", "framework": "Human / Org"},
            {"id": "coord", "name": mesh.coordinator.name, "did": mesh.coordinator.did, "role": "Workflow Coordinator", "framework": "CrewAI"},
            {"id": "booker", "name": mesh.autogen_booker.name, "did": mesh.autogen_booker.did, "role": "Execution Specialist", "framework": "AutoGen"},
            {"id": "pay", "name": mesh.payment_gw.name, "did": mesh.payment_gw.did, "role": "Settlement Service", "framework": "FastAPI / HTTP"},
            {"id": "rogue", "name": mesh.rogue_agent.name, "did": mesh.rogue_agent.did, "role": "Malicious Adversary", "framework": "Rogue Agent"},
        ],
        "spend_ceiling": mesh.current_spend_ceiling,
        "revoked_agents": list(mesh.policy_engine._revoked_agents),
        "tokens": [t.model_dump() for t in chain],
        "stats": {
            "total_requests": len(mesh.policy_engine._audit_log),
            "approved": sum(1 for d in mesh.policy_engine._audit_log if d.decision == "APPROVED"),
            "blocked": sum(1 for d in mesh.policy_engine._audit_log if d.decision == "BLOCKED"),
            "pending_escalations": len(mesh.escalation_mgr.get_pending()),
        },
    }


@app.get("/api/audit-logs")
async def get_audit_logs():
    return mesh.policy_engine.get_audit_log(limit=50)


@app.get("/api/stream")
async def sse_event_stream(request: Request):
    """Server-Sent Events endpoint streaming real-time policy decisions to UI."""
    q: asyncio.Queue = asyncio.Queue()
    mesh.event_subscribers.append(q)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                data = await q.get()
                yield f"data: {json.dumps(data)}\n\n"
        finally:
            if q in mesh.event_subscribers:
                mesh.event_subscribers.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class SpendUpdateReq(BaseModel):
    max_spend: float


@app.post("/api/policy/spend-limit")
async def update_spend_limit(req: SpendUpdateReq):
    mesh.current_spend_ceiling = req.max_spend
    mesh._build_tokens()
    await mesh.broadcast_event({"type": "POLICY_UPDATED", "spend_ceiling": req.max_spend})
    return {"status": "ok", "spend_ceiling": req.max_spend}


class RevokeAgentReq(BaseModel):
    agent_id: str
    revoked: bool


@app.post("/api/policy/revoke-agent")
async def toggle_revoke_agent(req: RevokeAgentReq):
    target_did = mesh.autogen_booker.did if req.agent_id == "booker" else mesh.coordinator.did
    if req.revoked:
        mesh.policy_engine.revoke_agent(target_did)
    else:
        mesh.policy_engine.unrevoke_agent(target_did)

    await mesh.broadcast_event({"type": "REVOCATION_CHANGED", "did": target_did, "revoked": req.revoked})
    return {"status": "ok", "did": target_did, "revoked": req.revoked}


@app.post("/api/reset")
async def reset_mesh():
    mesh.reset()
    await mesh.broadcast_event({"type": "RESET"})
    return {"status": "ok"}


@app.post("/api/action/legitimate-booking")
async def trigger_legitimate_booking():
    """Trigger valid $450 flight booking."""
    payload = {
        "flight_no": "AA-1042",
        "airline": "American",
        "origin": "SFO",
        "destination": "JFK",
        "amount": 450.00,
        "passenger": "Alice Smith",
    }
    pop = mesh.flight_token.generate_pop(
        keypair=mesh.autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=payload,
    )
    decision = mesh.policy_engine.evaluate_request(
        token=mesh.flight_token,
        pop=pop,
        resource="travel:flights:book",
        action="book",
        payload=payload,
        context={"spend_amount": 450.00, "allowed_airlines": "American"},
    )
    event_payload = {
        "type": "TRANSACTION_EVALUATED",
        "scenario": "Legitimate Flight Booking ($450.00)",
        "source": "booker",
        "target": "pay",
        "decision": decision.model_dump(),
    }
    await mesh.broadcast_event(event_payload)
    return decision


# Human-in-the-Loop Step-Up Escalation Endpoints
@app.post("/api/escalation/trigger-overspend")
async def trigger_overspend_challenge():
    """Simulates an agent requesting $750 flight when ceiling is $600, queueing a step-up challenge."""
    payload = {
        "flight_no": "AA-772",
        "airline": "American",
        "amount": 750.00,
        "reason": "Direct non-stop flight required for emergency executive meeting",
    }
    pop = mesh.flight_token.generate_pop(
        keypair=mesh.autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=payload,
    )
    decision = mesh.policy_engine.evaluate_request(
        token=mesh.flight_token,
        pop=pop,
        resource="travel:flights:book",
        action="book",
        payload=payload,
        context={"spend_amount": 750.00},
    )

    # Queue an escalation challenge
    req = mesh.escalation_mgr.create_escalation(
        agent_name="FlightSpecialist (AutoGen)",
        invoking_agent_did=mesh.autogen_booker.did,
        action="book",
        resource="travel:flights:book",
        requested_amount=750.00,
        current_ceiling=mesh.current_spend_ceiling,
        payload=payload,
    )

    event_payload = {
        "type": "ESCALATION_TRIGGERED",
        "challenge": req.model_dump(),
        "decision": decision.model_dump(),
    }
    await mesh.broadcast_event(event_payload)
    return {"decision": decision, "escalation": req}


@app.get("/api/escalation/pending")
async def get_pending_escalations():
    return [r.model_dump() for r in mesh.escalation_mgr.get_pending()]


@app.post("/api/escalation/approve/{challenge_id}")
async def approve_escalation(challenge_id: str):
    success, waiver_token, msg = mesh.escalation_mgr.approve_escalation(
        challenge_id=challenge_id,
        approver_keypair=mesh.human_root,
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    # Execute the formerly blocked action now with the waiver token!
    payload = {"flight_no": "AA-772", "amount": 750.00, "waiver": challenge_id}
    pop = waiver_token.generate_pop(
        keypair=mesh.autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=payload,
    )
    decision = mesh.policy_engine.evaluate_request(
        token=waiver_token,
        pop=pop,
        resource="travel:flights:book",
        action="book",
        payload=payload,
        context={"spend_amount": 750.00},
    )

    event_payload = {
        "type": "ESCALATION_APPROVED",
        "challenge_id": challenge_id,
        "decision": decision.model_dump(),
    }
    await mesh.broadcast_event(event_payload)
    return {"status": "APPROVED", "decision": decision, "waiver_token_id": waiver_token.token_id}


@app.post("/api/escalation/reject/{challenge_id}")
async def reject_escalation(challenge_id: str):
    success, msg = mesh.escalation_mgr.reject_escalation(challenge_id)
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    event_payload = {"type": "ESCALATION_REJECTED", "challenge_id": challenge_id}
    await mesh.broadcast_event(event_payload)
    return {"status": "REJECTED", "message": msg}


# MCP Tool Gatekeeper Endpoint
@app.post("/api/mcp/tool-call")
async def execute_mcp_tool_call(req: Dict[str, Any]):
    """
    Demonstrates zero-trust tool execution for Anthropic Model Context Protocol (MCP).
    """
    args = req.get("arguments", {"flight_no": "AA-1042", "airline": "American", "amount": 450.00})
    pop = mesh.flight_token.generate_pop(
        keypair=mesh.autogen_booker,
        action="book",
        resource="travel:flights:book",
        payload=args,
    )
    resp = mesh.mcp_guard.handle_call(
        token_data=mesh.flight_token.model_dump(),
        pop_data=pop.model_dump(),
        arguments=args,
    )
    return resp.model_dump()


@app.post("/api/action/attack/{attack_id}")
async def trigger_attack(attack_id: str):
    """Trigger specific Red-Team attack scenario."""
    if attack_id == "impersonation":
        payload = {"flight_no": "AA-999", "amount": 200.00}
        pop = ProofOfPossession(
            token_id=mesh.flight_token.token_id,
            agent_did=mesh.rogue_agent.did,
            action="book",
            resource="travel:flights:book",
            payload_hash=mesh.flight_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", payload).payload_hash,
            timestamp=int(time.time()),
            nonce=f"rogue_pop_{time.time()}",
        )
        pop.sign(mesh.rogue_agent)
        decision = mesh.policy_engine.evaluate_request(
            token=mesh.flight_token,
            pop=pop,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 200.00},
        )
        src = "rogue"

    elif attack_id == "replay":
        payload = {"flight_no": "AA-1042", "amount": 450.00}
        fixed_nonce = "replay_target_nonce_123"
        pop1 = mesh.flight_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", payload, nonce=fixed_nonce)
        mesh.policy_engine.evaluate_request(
            token=mesh.flight_token,
            pop=pop1,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 450.00},
        )
        decision = mesh.policy_engine.evaluate_request(
            token=mesh.flight_token,
            pop=pop1,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 450.00},
        )
        src = "rogue"

    elif attack_id == "privilege_escalation":
        payload = {"flight_no": "AA-FIRST-CLASS", "amount": 2500.00}
        pop = mesh.flight_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", payload)
        decision = mesh.policy_engine.evaluate_request(
            token=mesh.flight_token,
            pop=pop,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 2500.00},
        )
        src = "booker"

    elif attack_id == "payload_spoofing":
        legit_payload = {"flight_no": "AA-100", "destination": "JFK", "amount": 100.00}
        pop = mesh.flight_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", legit_payload)
        tampered_payload = {"flight_no": "AA-100", "destination": "Secret_Island", "amount": 900.00}
        decision = mesh.policy_engine.evaluate_request(
            token=mesh.flight_token,
            pop=pop,
            resource="travel:flights:book",
            action="book",
            payload=tampered_payload,
            context={"spend_amount": 900.00},
        )
        src = "rogue"

    elif attack_id == "expired_token":
        expired_token = copy.deepcopy(mesh.flight_token)
        expired_token.expires_at = int(time.time()) - 3600
        expired_token.sign(mesh.coordinator)
        payload = {"flight_no": "AA-STALE", "amount": 50.00}
        pop = expired_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", payload)
        decision = mesh.policy_engine.evaluate_request(
            token=expired_token,
            pop=pop,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 50.00},
        )
        src = "rogue"

    elif attack_id == "chain_tampering":
        tampered_token = copy.deepcopy(mesh.flight_token)
        tampered_token.iss = mesh.rogue_agent.did
        tampered_token.sign(mesh.rogue_agent)
        payload = {"flight_no": "AA-BROKEN", "amount": 80.00}
        pop = tampered_token.generate_pop(mesh.autogen_booker, "book", "travel:flights:book", payload)
        decision = mesh.policy_engine.evaluate_request(
            token=tampered_token,
            pop=pop,
            resource="travel:flights:book",
            action="book",
            payload=payload,
            context={"spend_amount": 80.00},
        )
        src = "rogue"

    else:
        raise HTTPException(status_code=400, detail="Unknown attack scenario")

    event_payload = {
        "type": "ATTACK_EVALUATED",
        "scenario": attack_id,
        "source": src,
        "target": "pay",
        "decision": decision.model_dump(),
    }
    await mesh.broadcast_event(event_payload)
    return decision


@app.get("/healthz")
async def health_check():
    """Kubernetes/Docker liveness & readiness probe."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": "1.0.0",
        "engine": "TrustMesh Zero-Trust",
    }


@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus-compatible monitoring endpoint."""
    total = len(mesh.policy_engine._audit_log)
    approved = sum(1 for d in mesh.policy_engine._audit_log if d.decision == "APPROVED")
    blocked = sum(1 for d in mesh.policy_engine._audit_log if d.decision == "BLOCKED")
    return {
        "trustmesh_requests_total": total,
        "trustmesh_requests_approved": approved,
        "trustmesh_requests_blocked": blocked,
        "trustmesh_active_agents": 5,
        "trustmesh_spend_ceiling": mesh.current_spend_ceiling,
        "trustmesh_revoked_count": len(mesh.policy_engine._revoked_agents),
        "trustmesh_pending_escalations": len(mesh.escalation_mgr.get_pending()),
    }


# Mount static files and serve index.html
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TrustMesh Dashboard Loading...</h1>"
