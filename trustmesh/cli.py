"""
TrustMesh Developer Command Line Interface (CLI)
Provides enterprise tooling for agent key generation, token issuance,
security testing, benchmarking, and dashboard serving.
"""

from __future__ import annotations
import argparse
import json
import time

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken


def cmd_keygen(args):
    kp = AgentKeypair.generate(name=args.name)
    print(json.dumps(kp.to_dict(), indent=2))


def cmd_issue(args):
    root_kp = AgentKeypair.generate(name="Issuer")
    caveat = Caveat(
        max_spend=args.spend,
        allowed_actions=[args.action] if args.action != "*" else None,
        allowed_resources=[args.resource] if args.resource != "*" else None,
        expiry=int(time.time()) + args.ttl,
    )
    cap = Capability(resource=args.resource, action=args.action, caveats=caveat)
    token = DelegationToken(
        iss=root_kp.did,
        aud=args.aud,
        capabilities=[cap],
        expires_at=int(time.time()) + args.ttl,
    )
    token.sign(root_kp)
    print(json.dumps(token.model_dump(), indent=2))


def cmd_benchmark(args):
    from benchmarks.benchmark_throughput import run_benchmarks
    run_benchmarks(iterations=args.iterations)


def cmd_attack_test(args):
    from security.attack_harness import SecurityAttackHarness
    harness = SecurityAttackHarness()
    harness.run_all_attacks()


def cmd_serve(args):
    import uvicorn
    print(f"Starting TrustMesh Dashboard on http://127.0.0.1:{args.port} ...")
    uvicorn.run("dashboard.server:app", host="127.0.0.1", port=args.port, reload=False)


def main():
    parser = argparse.ArgumentParser(prog="trustmesh", description="TrustMesh Zero-Trust Agent Authorization CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate a new Ed25519 Agent Keypair and did:key")
    p_keygen.add_argument("--name", default="AutonomousAgent", help="Human-readable agent name")
    p_keygen.set_defaults(func=cmd_keygen)

    # issue
    p_issue = subparsers.add_parser("issue", help="Issue a new DelegationToken to an audience DID")
    p_issue.add_argument("--aud", required=True, help="Audience agent DID (did:key:...)")
    p_issue.add_argument("--action", default="execute", help="Authorized action pattern")
    p_issue.add_argument("--resource", default="*", help="Authorized resource pattern")
    p_issue.add_argument("--spend", type=float, default=None, help="Maximum spend ceiling")
    p_issue.add_argument("--ttl", type=int, default=3600, help="Token validity in seconds")
    p_issue.set_defaults(func=cmd_issue)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run high-throughput performance stress tests")
    p_bench.add_argument("--iterations", type=int, default=300, help="Number of benchmark iterations")
    p_bench.set_defaults(func=cmd_benchmark)

    # attack-test
    p_attack = subparsers.add_parser("attack-test", help="Run automated 6-scenario Red-Team security harness")
    p_attack.set_defaults(func=cmd_attack_test)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch visual policy enforcement web dashboard")
    p_serve.add_argument("--port", type=int, default=8000, help="HTTP server port")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
