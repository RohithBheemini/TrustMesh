"""
TrustMesh Attribute-Based Access Control (ABAC) & Velocity Engine
Provides rich context evaluation: time windows, network CIDR geofencing,
sliding-window rate limiting per agent DID, and mathematical predicate evaluation.
"""

from __future__ import annotations
import ipaddress
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class AgentRateLimiter:
    """
    Sliding-window request velocity limiter.
    Prevents agent runaway loops, hallucinated spam, and denial-of-service attempts.
    """

    def __init__(self, default_limit_per_minute: int = 120):
        self.default_limit = default_limit_per_minute
        self._request_timestamps: Dict[str, List[float]] = {}
        self._lock = threading.RLock()

    def check_and_record(self, agent_did: str, limit_per_minute: Optional[int] = None) -> Tuple[bool, int, int]:
        """
        Checks if agent_did is within rate limits.
        Returns (is_allowed, current_count, limit).
        """
        limit = limit_per_minute if limit_per_minute is not None else self.default_limit
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            history = self._request_timestamps.setdefault(agent_did, [])
            # Prune timestamps older than 60 seconds
            valid_history = [t for t in history if t > window_start]
            self._request_timestamps[agent_did] = valid_history

            if len(valid_history) >= limit:
                return False, len(valid_history), limit

            valid_history.append(now)
            return True, len(valid_history), limit

    def reset(self):
        with self._lock:
            self._request_timestamps.clear()


class ABACPolicyEvaluator:
    """
    Evaluates enterprise context predicates against token caveats and request environment.
    Supports time windows, CIDR network validation, rate limits, and custom operator expressions.
    """

    def __init__(self, rate_limiter: Optional[AgentRateLimiter] = None):
        self.rate_limiter = rate_limiter or AgentRateLimiter()

    def evaluate(
        self,
        predicates: Dict[str, Any],
        context: Dict[str, Any],
        agent_did: str,
    ) -> Tuple[bool, str]:
        """
        Evaluates dynamic predicates.
        Returns (is_valid, failure_reason_if_any).
        """
        if not predicates:
            return True, "No ABAC predicates defined"

        # 1. Rate Limiting Check
        if "rate_limit_per_minute" in predicates:
            max_rate = int(predicates["rate_limit_per_minute"])
            allowed, current, limit = self.rate_limiter.check_and_record(agent_did, max_rate)
            if not allowed:
                return False, f"ERR_RATE_LIMIT_EXCEEDED: Agent velocity ({current} req/min) exceeded limit ({limit} req/min)"
        else:
            # Check default rate limiter
            allowed, current, limit = self.rate_limiter.check_and_record(agent_did)
            if not allowed:
                return False, f"ERR_RATE_LIMIT_EXCEEDED: Agent velocity exceeded default limit ({limit} req/min)"

        # 2. Network CIDR Geofencing Check
        if "allowed_cidrs" in predicates:
            client_ip = context.get("client_ip")
            if not client_ip:
                return False, "ERR_NETWORK_ISOLATION: Request missing required client_ip in context"
            allowed_cidrs = predicates["allowed_cidrs"]
            if isinstance(allowed_cidrs, str):
                allowed_cidrs = [allowed_cidrs]

            ip_obj = ipaddress.ip_address(client_ip)
            match_found = False
            for cidr in allowed_cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        match_found = True
                        break
                except ValueError:
                    continue

            if not match_found:
                return False, f"ERR_NETWORK_ISOLATION: Client IP {client_ip} not within allowed CIDRs ({allowed_cidrs})"

        # 3. Time Window Check (Hours and Days)
        if "time_window" in predicates:
            tw = predicates["time_window"]
            now_dt = datetime.now(timezone.utc)
            current_hour = now_dt.hour
            current_day = now_dt.strftime("%a").upper()  # e.g. "MON", "TUE"

            if "start_hour" in tw and "end_hour" in tw:
                start_h = int(tw["start_hour"])
                end_h = int(tw["end_hour"])
                if not (start_h <= current_hour < end_h):
                    return False, f"ERR_OUTSIDE_TIME_WINDOW: Current UTC hour ({current_hour}:00) is outside allowed range ({start_h}:00 - {end_h}:00)"

            if "allowed_days" in tw:
                allowed_days = [d.upper() for d in tw["allowed_days"]]
                if current_day not in allowed_days:
                    return False, f"ERR_OUTSIDE_TIME_WINDOW: Current day ({current_day}) not in allowed days ({allowed_days})"

        # 4. Custom Predicate Expressions
        for key, expected_rule in predicates.items():
            if key in {"rate_limit_per_minute", "allowed_cidrs", "time_window"}:
                continue

            if key not in context:
                continue

            actual_val = context[key]

            # Dict operator format: e.g. {"<=": 500}, {"in": ["American", "Delta"]}, {"regex": "^AA-[0-9]+$"}
            if isinstance(expected_rule, dict):
                for op, val in expected_rule.items():
                    if op == "<=" and not (actual_val <= val):
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) must be <= {val}"
                    elif op == "<" and not (actual_val < val):
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) must be < {val}"
                    elif op == ">=" and not (actual_val >= val):
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) must be >= {val}"
                    elif op == ">" and not (actual_val > val):
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) must be > {val}"
                    elif op == "in" and actual_val not in val:
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) not in allowed set {val}"
                    elif op == "regex" and not re.search(val, str(actual_val)):
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) does not match pattern '{val}'"
                    elif op == "==" and actual_val != val:
                        return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) != {val}"
            elif isinstance(expected_rule, list):
                if actual_val not in expected_rule:
                    return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) not in {expected_rule}"
            else:
                if actual_val != expected_rule:
                    return False, f"ERR_PREDICATE_VIOLATION: '{key}' ({actual_val}) != {expected_rule}"

        return True, "All ABAC predicates satisfied"
