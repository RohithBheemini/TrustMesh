"""
Tests for TrustMesh Attribute-Based Access Control (ABAC) & Rate Limiting Engine.
Validates sliding-window agent velocity, network CIDR isolation, and predicate operators.
"""

import pytest
from trustmesh.abac import AgentRateLimiter, ABACPolicyEvaluator


def test_agent_rate_limiter_burst_enforcement():
    limiter = AgentRateLimiter(default_limit_per_minute=3)
    agent = "did:key:z6MkTestRateLimit"

    # 1st, 2nd, 3rd requests succeed
    assert limiter.check_and_record(agent)[0] is True
    assert limiter.check_and_record(agent)[0] is True
    assert limiter.check_and_record(agent)[0] is True

    # 4th request exceeds rate limit of 3
    allowed, count, limit = limiter.check_and_record(agent)
    assert allowed is False
    assert count == 3
    assert limit == 3

    # Different agent is unaffected
    other_agent = "did:key:z6MkOtherAgent"
    assert limiter.check_and_record(other_agent)[0] is True


def test_abac_network_cidr_isolation():
    evaluator = ABACPolicyEvaluator()
    predicates = {"allowed_cidrs": ["10.0.0.0/8", "172.16.0.0/12"]}

    # Allowed internal IP
    ok, _ = evaluator.evaluate(predicates, {"client_ip": "10.150.1.25"}, "did:key:test")
    assert ok is True

    # Forbidden external IP
    ok2, reason2 = evaluator.evaluate(predicates, {"client_ip": "203.0.113.195"}, "did:key:test")
    assert ok2 is False
    assert "ERR_NETWORK_ISOLATION" in reason2

    # Missing IP in context
    ok3, reason3 = evaluator.evaluate(predicates, {}, "did:key:test")
    assert ok3 is False
    assert "ERR_NETWORK_ISOLATION" in reason3


def test_abac_operator_expressions():
    evaluator = ABACPolicyEvaluator()
    predicates = {
        "user_tier": {"in": ["VIP", "PLATINUM"]},
        "risk_score": {"<=": 25},
        "flight_code": {"regex": r"^AA-\d{3,4}$"},
    }

    # Valid context
    valid_ctx = {
        "user_tier": "VIP",
        "risk_score": 15,
        "flight_code": "AA-1042",
    }
    ok, _ = evaluator.evaluate(predicates, valid_ctx, "did:key:test")
    assert ok is True

    # Risk score violation
    invalid_ctx1 = {
        "user_tier": "VIP",
        "risk_score": 85,  # Exceeds <= 25
        "flight_code": "AA-1042",
    }
    ok1, reason1 = evaluator.evaluate(predicates, invalid_ctx1, "did:key:test")
    assert ok1 is False
    assert "must be <= 25" in reason1

    # Regex violation
    invalid_ctx2 = {
        "user_tier": "VIP",
        "risk_score": 10,
        "flight_code": "INVALID-FLIGHT",
    }
    ok2, reason2 = evaluator.evaluate(predicates, invalid_ctx2, "did:key:test")
    assert ok2 is False
    assert "does not match pattern" in reason2


def test_abac_time_window_check():
    evaluator = ABACPolicyEvaluator()
    # 24-hour window (0 to 24) must always pass
    wide_window = {"time_window": {"start_hour": 0, "end_hour": 24}}
    ok, _ = evaluator.evaluate(wide_window, {}, "did:key:test")
    assert ok is True
