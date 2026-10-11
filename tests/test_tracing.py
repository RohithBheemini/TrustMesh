"""
Tests for TrustMesh Distributed Tracing (W3C TraceContext & OpenTelemetry Standard).
Validates traceparent header formatting, parsing, child span correlation, and header injection.
"""

import pytest
from trustmesh.tracing import TrustMeshTraceContext


def test_trace_context_generation_and_formatting():
    ctx = TrustMeshTraceContext()
    assert len(ctx.trace_id) == 32
    assert len(ctx.parent_id) == 16
    tp = ctx.to_traceparent()
    assert tp.startswith("00-")
    assert tp.endswith("-01")
    assert len(tp) == 55  # 00-32hex-16hex-01


def test_trace_context_parsing():
    raw_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = TrustMeshTraceContext.from_traceparent(raw_header)
    assert parsed is not None
    assert parsed.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parsed.parent_id == "00f067aa0ba902b7"
    assert parsed.sampled is True

    # Invalid header format
    assert TrustMeshTraceContext.from_traceparent("invalid-header-string") is None
    assert TrustMeshTraceContext.from_traceparent("01-wrongversion-00") is None


def test_child_span_correlation():
    parent = TrustMeshTraceContext()
    child = parent.create_child_span()

    # Child keeps parent's trace_id for end-to-end distributed tracing correlation
    assert child.trace_id == parent.trace_id
    # Child gets fresh parent_id (span id)
    assert child.parent_id != parent.parent_id


def test_trace_header_injection():
    ctx = TrustMeshTraceContext()
    headers = {"Content-Type": "application/json"}
    injected = ctx.inject_headers(headers)
    assert "traceparent" in injected
    assert "X-TrustMesh-Trace-ID" in injected
    assert injected["X-TrustMesh-Trace-ID"] == ctx.trace_id
