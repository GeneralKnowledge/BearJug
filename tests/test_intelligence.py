import pytest
from pydantic import ValidationError

from bearjug.schema import CampaignLink, parse_intelligence

BASE = {
    "record_id": "intel-1",
    "created_at": "2026-11-18T04:00:00Z",
    "engine": {"name": "aito-behaviour", "version": "0.1"},
}
SUPPORT = {"confidence": 0.7, "supporting_events": ["evt-8", "evt-30"]}


def test_campaign_link():
    rec = parse_intelligence({**BASE, "kind": "campaign.link", "campaign_id": "camp-1",
                              "session_id": "sess-1", "basis": ["decoy_secret_reuse"], "support": SUPPORT})
    assert isinstance(rec, CampaignLink)


def test_claims_need_supporting_events():
    with pytest.raises(ValidationError):
        parse_intelligence({**BASE, "kind": "campaign.link", "campaign_id": "camp-1", "session_id": "sess-1",
                            "basis": ["decoy_secret_reuse"], "support": {"confidence": 0.7, "supporting_events": []}})


@pytest.mark.parametrize("value,confidence", [(1.5, 0.5), (0.5, -0.1)])
def test_scores_are_probabilities(value, confidence):
    with pytest.raises(ValidationError):
        parse_intelligence({**BASE, "kind": "session.assessment", "session_id": "sess-1",
                            "credential_discovered": True,
                            "automation_likelihood": {"value": value, "support": {**SUPPORT, "confidence": confidence}}})


def test_session_link_is_scored_and_evidenced():
    rec = parse_intelligence({**BASE, "kind": "session.link", "session_id": "sess-2",
                              "prior_session_id": "sess-1", "basis": ["password_reuse"], "support": SUPPORT})
    assert rec.support.confidence == 0.7
    with pytest.raises(ValidationError):
        parse_intelligence({**BASE, "kind": "session.link", "session_id": "sess-2",
                            "prior_session_id": "sess-1", "basis": ["password_reuse"]})
