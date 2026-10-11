"""
TrustMesh High-Throughput Performance & Benchmarking Suite
Measures cryptographic operations per second, end-to-end policy evaluation throughput,
and latency percentiles (P50, P90, P99) under heavy agent load.
"""

from __future__ import annotations
import statistics
import time
from rich.console import Console
from rich.table import Table

from trustmesh.crypto import AgentKeypair, canonical_json
from trustmesh.tokens import Capability, Caveat, DelegationToken
from trustmesh.policy import DynamicPolicyEngine

console = Console(highlight=False, emoji=False)


def run_benchmarks(iterations: int = 500):
    console.print("[bold cyan]====================================================================[/bold cyan]")
    console.print("[bold cyan]   TrustMesh: High-Throughput Performance & Stress Benchmark        [/bold cyan]")
    console.print("[bold cyan]====================================================================[/bold cyan]\n")
    console.print(f"Running [yellow]{iterations}[/yellow] iterations per benchmark operation...\n")

    results = []

    # 1. Benchmark: Ed25519 Keypair Generation
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = AgentKeypair.generate()
    t1 = time.perf_counter()
    keygen_duration = t1 - t0
    keygen_rate = iterations / keygen_duration
    results.append(("Keypair Generation (Ed25519 + did:key)", keygen_rate, (keygen_duration / iterations) * 1000))

    # Pre-generate keypairs for subsequent tests
    root = AgentKeypair.generate(name="RootAuthority")
    coord = AgentKeypair.generate(name="Coordinator")
    worker = AgentKeypair.generate(name="Worker")

    # 2. Benchmark: UCAN Delegation Token Creation & Signing
    root_cap = Capability(resource="cloud:*", action="*", caveats=Caveat(max_spend=1000.0))
    root_token = DelegationToken(
        iss=root.did,
        aud=coord.did,
        capabilities=[root_cap],
        expires_at=int(time.time()) + 3600,
    )
    root_token.sign(root)

    worker_cap = Capability(resource="cloud:vm:provision", action="purchase", caveats=Caveat(max_spend=250.0))

    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = root_token.attenuate(
            audience_did=worker.did,
            restricted_capabilities=[worker_cap],
            keypair=coord,
            validity_seconds=1800,
        )
    t1 = time.perf_counter()
    attenuate_duration = t1 - t0
    attenuate_rate = iterations / attenuate_duration
    results.append(("Token Attenuation & JCS Signing", attenuate_rate, (attenuate_duration / iterations) * 1000))

    # 3. Benchmark: Proof-of-Possession Generation
    leaf_token = root_token.attenuate(
        audience_did=worker.did,
        restricted_capabilities=[worker_cap],
        keypair=coord,
        validity_seconds=1800,
    )
    payload = {"vm_size": "c5.xlarge", "amount": 100.0}

    t0 = time.perf_counter()
    for i in range(iterations):
        _ = leaf_token.generate_pop(
            keypair=worker,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
            nonce=f"bench_nonce_{i}",
        )
    t1 = time.perf_counter()
    pop_duration = t1 - t0
    pop_rate = iterations / pop_duration
    results.append(("PoP Generation (SHA-256 + Ed25519 Sig)", pop_rate, (pop_duration / iterations) * 1000))

    # 4. Benchmark: End-to-End Policy Engine Evaluation Latency & Throughput
    engine = DynamicPolicyEngine(trusted_root_dids={root.did})
    latencies = []

    for i in range(iterations):
        # Fresh unique nonce for each request to avoid replay rejection
        pop = leaf_token.generate_pop(
            keypair=worker,
            action="purchase",
            resource="cloud:vm:provision",
            payload=payload,
            nonce=f"eval_bench_{i}",
        )
        s0 = time.perf_counter()
        decision = engine.evaluate_request(
            token=leaf_token,
            pop=pop,
            resource="cloud:vm:provision",
            action="purchase",
            payload=payload,
            context={"spend_amount": 100.0},
        )
        s1 = time.perf_counter()
        assert decision.decision == "APPROVED"
        latencies.append((s1 - s0) * 1000)

    total_eval_duration = sum(latencies) / 1000.0
    eval_rate = iterations / total_eval_duration
    results.append(("Full Zero-Trust Policy Evaluation", eval_rate, statistics.mean(latencies)))

    # Compute percentiles
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p90 = latencies[int(len(latencies) * 0.90)]
    p99 = latencies[int(len(latencies) * 0.99)]

    # Display results table
    table = Table(title="TrustMesh Cryptographic Throughput Benchmark")
    table.add_column("Operation", style="cyan")
    table.add_column("Throughput (ops/sec)", style="bold green")
    table.add_column("Mean Latency", style="yellow")

    for name, rate, avg_lat in results:
        table.add_row(name, f"{rate:,.1f} ops/s", f"{avg_lat:.3f} ms")

    console.print(table)

    console.print(f"\n[bold green][Latency Percentiles for End-to-End Evaluation][/bold green]")
    console.print(f"  * P50 Latency : [bold]{p50:.3f} ms[/bold]")
    console.print(f"  * P90 Latency : [bold]{p90:.3f} ms[/bold]")
    console.print(f"  * P99 Latency : [bold]{p99:.3f} ms[/bold]\n")

    return results


if __name__ == "__main__":
    run_benchmarks(iterations=500)
