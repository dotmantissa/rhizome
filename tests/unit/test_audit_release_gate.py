"""Old successful receipts must not qualify changed security-critical source."""
from pathlib import Path
import pytest
from scripts import verification_report


def test_historical_eleven_scenarios_do_not_qualify_corrected_release(monkeypatch):
    evidence = Path(__file__).resolve().parents[2] / 'verification' / 'treasury-v3'
    monkeypatch.setattr(verification_report, 'VERIFICATION', evidence)
    with pytest.raises(AssertionError, match='hosted suite is incomplete'):
        verification_report.report()
