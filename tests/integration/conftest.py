"""Durable, truthful results for actual network verification."""
import json
import os
from pathlib import Path
import time

RESULTS = {}


def pytest_runtest_logreport(report):
    if report.when == "call" or report.failed:
        RESULTS[report.nodeid] = {
            "outcome": report.outcome, "phase": report.when,
            "duration_seconds": report.duration,
        }
        root = Path(__file__).resolve().parents[2]
        destination = root / "verification/integration-results.json"
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(json.dumps({
            "network": "studionet", "chain_id": 61999,
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "complete": False, "tests": RESULTS,
        }, indent=2) + "\n")
        os.replace(temporary, destination)
