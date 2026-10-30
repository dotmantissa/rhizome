"""Durable, truthful results for actual network verification."""
import json
import os
from pathlib import Path
import time

from scripts.studio import VERIFICATION

RESULTS = {}
EXPECTED = []


def save_results(complete=False):
    destination = VERIFICATION / "integration-results.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps({
        "network": "studionet", "chain_id": 61999,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "complete": complete, "expected_tests": EXPECTED, "tests": RESULTS,
    }, indent=2) + "\n")
    os.replace(temporary, destination)


def pytest_collection_finish(session):
    global EXPECTED
    EXPECTED = [item.nodeid for item in session.items]
    previous = VERIFICATION / "integration-results.json"
    if previous.exists():
        RESULTS.update(json.loads(previous.read_text()).get("tests", {}))


def pytest_sessionfinish(session, exitstatus):
    if not session.config.option.collectonly:
        complete = exitstatus == 0 and all(
            RESULTS.get(nodeid, {}).get("outcome") == "passed" for nodeid in EXPECTED
        )
        save_results(complete)


def pytest_runtest_logreport(report):
    if report.when == "call" or report.failed:
        RESULTS[report.nodeid] = {
            "outcome": report.outcome, "phase": report.when,
            "duration_seconds": report.duration,
        }
        save_results()
