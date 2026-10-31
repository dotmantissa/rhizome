"""Actual public changing-byte retrieval, with authenticated synthetic metadata."""
import hashlib
import json
from pathlib import Path
import requests
from tests.evidence import canonical, source_packet
from tests.integration.test_studio import live, open_request, assess
from scripts.studio import VERIFICATION
import pytest

pytestmark = pytest.mark.integration


def test_changed_public_bytes_cannot_certify_origins(live):
    studio, source, resolver, _, catalog = live
    saved = VERIFICATION / "changed-source-record.json"
    principal = studio.accounts["deployer"].address
    control, control_raw, metadata, _ = source_packet("changed", principal)
    url = "https://httpbingo.org/uuid?rhizome=source-change-verification"
    if saved.exists():
        capture = json.loads(saved.read_text())
        metadata = capture["metadata"]
    else:
        first = requests.get(url, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"}, timeout=30)
        assert first.status_code == 200
        raw = first.content
        metadata.update(url=url, sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
                        spans=[{"span_id": "all", "start": 0, "end": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}])
        capture = {"classification": "SYNTHETIC SIGNED TEST METADATA; REAL CHANGING PUBLIC UUID ENDPOINT",
                   "metadata": metadata, "initial_raw_hex": raw.hex()}
        saved.write_text(json.dumps(capture, indent=2) + "\n")
    authority = {"authority_id": metadata["authority_id"], "principal": principal,
                 "channel": metadata["channel"], "url_prefix": "https://httpbingo.org/", "control_record": control}
    registered = studio.submit("authority-changing-bytes", source, "register_authority",
                  [metadata["authority_id"], principal, metadata["channel"], authority["url_prefix"], canonical(control)])
    studio.drain(registered, "authority-changing-bytes")
    attested = studio.submit("attest-changing-bytes", source, "attest_source", [canonical(metadata)])
    studio.drain(attested, "attest-changing-bytes")
    catalog["changed"] = {"source": metadata, "authority": authority, "role": "deployer"}
    open_request(live, "changed-public-bytes", ["changed", "delta"], "event-independence", resolver)
    second = requests.get(url, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"}, timeout=30)
    assert second.status_code == 200 and hashlib.sha256(second.content).hexdigest() != metadata["sha256"], "endpoint did not change; cannot claim the probe ran"
    capture["independent_later_raw_hex"] = second.content.hex()
    saved.write_text(json.dumps(capture, indent=2) + "\n")
    decision, _ = assess(live, "changed-public-bytes", "changed", "delta")
    assert decision["relation"] == "UNKNOWN" and not decision["available"]
    assert decision["unresolved_reason"] == "SOURCE_CHANGED" and decision["witnesses"] == []
    studio.submit("seal-changing-bytes", source, "seal_batch", ["changed-public-bytes"])
    certificate = studio.read(source, "get_certificate", ["changed-public-bytes"])["sealed_result"]
    assert certificate["unresolved"] and certificate["certified_origin_count"] == 0 and not certificate["threshold_met"]
