"""
TrustMesh Distributed Tracing (W3C TraceContext & OpenTelemetry Standard)
Enables end-to-end multi-agent observability across asynchronous network boundaries.
Injects and propagates W3C traceparent headers to correlate delegations with SIEM logs.
"""

from __future__ import annotations
import os
import re
import time
from typing import Dict, Optional
from pydantic import BaseModel, Field


TRACEPARENT_REGEX = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


class TrustMeshTraceContext(BaseModel):
    """W3C TraceContext representation for distributed agent observability."""
    trace_id: str = Field(default_factory=lambda: os.urandom(16).hex())
    parent_id: str = Field(default_factory=lambda: os.urandom(8).hex())
    sampled: bool = True
    created_at: float = Field(default_factory=time.time)

    def to_traceparent(self) -> str:
        flags = "01" if self.sampled else "00"
        return f"00-{self.trace_id}-{self.parent_id}-{flags}"

    @classmethod
    def from_traceparent(cls, header: str) -> Optional["TrustMeshTraceContext"]:
        match = TRACEPARENT_REGEX.match(header.strip().lower())
        if not match:
            return None
        trace_id, parent_id, flags = match.groups()
        sampled = (flags == "01")
        return cls(trace_id=trace_id, parent_id=parent_id, sampled=sampled)

    def create_child_span(self) -> "TrustMeshTraceContext":
        """Spawns child span context keeping trace_id but generating a new parent_id."""
        return TrustMeshTraceContext(
            trace_id=self.trace_id,
            parent_id=os.urandom(8).hex(),
            sampled=self.sampled,
        )

    def inject_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        headers["traceparent"] = self.to_traceparent()
        headers["X-TrustMesh-Trace-ID"] = self.trace_id
        return headers
