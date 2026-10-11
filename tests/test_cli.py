"""
Unit tests for TrustMesh Developer CLI
Verifies keygen, issue, and CLI arguments.
"""

import json
import subprocess
import sys
import pytest


def test_cli_keygen():
    result = subprocess.run(
        [sys.executable, "-m", "trustmesh.cli", "keygen", "--name", "TestCliAgent"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["name"] == "TestCliAgent"
    assert data["did"].startswith("did:key:z6Mk")


def test_cli_issue():
    # Generate DID first
    res_key = subprocess.run(
        [sys.executable, "-m", "trustmesh.cli", "keygen", "--name", "AudienceAgent"],
        capture_output=True,
        text=True,
    )
    aud_did = json.loads(res_key.stdout)["did"]

    # Issue token
    result = subprocess.run(
        [
            sys.executable, "-m", "trustmesh.cli", "issue",
            "--aud", aud_did,
            "--action", "book",
            "--resource", "flights:*",
            "--spend", "500",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    token_data = json.loads(result.stdout)
    assert token_data["aud"] == aud_did
    assert token_data["capabilities"][0]["action"] == "book"
    assert token_data["capabilities"][0]["caveats"]["max_spend"] == 500.0
    assert len(token_data["signature"]) > 0
