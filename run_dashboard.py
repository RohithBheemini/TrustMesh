"""
TrustMesh Visual Dashboard Launcher
Runs the interactive zero-trust agent authorization web application on http://localhost:8000
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("  TrustMesh: Dynamic Agent-to-Agent Authorization Protocols")
    print("  Visual Dynamic Policy Enforcement Web Dashboard")
    print("=" * 70)
    print("\nStarting local server on http://127.0.0.1:8000 ...")
    print("Open http://localhost:8000 in your browser to inspect the live mesh.")
    print("Press Ctrl+C to stop the dashboard server.\n")

    uvicorn.run("dashboard.server:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
