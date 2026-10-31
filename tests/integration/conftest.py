"""Durable, truthful results for actual network verification."""
import json
import os
from pathlib import Path
import time

from scripts.studio import VERIFICATION, write_json
import pytest

RESULTS = {}
EXPECTED = []
RESUME = False


def pytest_addoption(parser):
    parser.addoption("--rhizome-resume", action="store_true", help="retain verified passing live scenarios")


def save_results(complete=False):
    destination = VERIFICATION / "integration-results.json"
    write_json(destination, {
        "network": "studionet", "chain_id": 61999,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "complete": complete, "expected_tests": EXPECTED, "tests": RESULTS,
    })


def pytest_collection_finish(session):
    global EXPECTED, RESUME
    RESUME = session.config.getoption("--rhizome-resume")
    EXPECTED = [item.nodeid for item in session.items]
    previous = VERIFICATION / "integration-results.json"
    if previous.exists():
        RESULTS.update(json.loads(previous.read_text()).get("tests", {}))
    if RESUME:
        for item in session.items:
            if RESULTS.get(item.nodeid, {}).get("outcome") == "passed":
                item.add_marker(pytest.mark.skip(reason="previously verified in this live run"))


def pytest_sessionfinish(session, exitstatus):
    if not session.config.option.collectonly:
        complete = exitstatus == 0 and all(
            RESULTS.get(nodeid, {}).get("outcome") == "passed" for nodeid in EXPECTED
        )
        save_results(complete)


def pytest_runtest_logreport(report):
    if RESUME and report.skipped and RESULTS.get(report.nodeid, {}).get("outcome") == "passed":
        return
    if report.when == "call" or report.failed:
        RESULTS[report.nodeid] = {
            "outcome": report.outcome, "phase": report.when,
            "duration_seconds": report.duration,
        }
        with (VERIFICATION / "integration-history.jsonl").open("a") as stream:
            stream.write(json.dumps({"test": report.nodeid, **RESULTS[report.nodeid],
                                    "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        save_results()
