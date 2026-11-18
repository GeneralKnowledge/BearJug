import pytest
from pydantic import ValidationError

from bearjug.schema import AuthAttempt, OutboundSimulated, SessionStart, parse_event


def auth(base, pw, **kw):
    return {
        **base,
        "event_type": "auth.attempt",
        "src": {"ip": "203.0.113.7", "port": 4242},
        "username": "root",
        "password": pw,
        "decision": "accept",
        "rule": "exact_synthetic_match",
        "policy": {"kind": "production"},
        **kw,
    }


def test_exact_match_accept(base, pw):
    assert isinstance(parse_event(auth(base, pw)), AuthAttempt)


def test_no_match_reject(base, pw):
    parse_event(auth(base, pw, decision="reject", rule="no_synthetic_match"))


@pytest.mark.parametrize(
    "decision,rule",
    [
        ("accept", "no_synthetic_match"),
        ("reject", "exact_synthetic_match"),
        ("accept", "accept_after_n"),  # not allowed outside an experiment
    ],
)
def test_production_policy_only_accepts_exact_matches(base, pw, decision, rule):
    with pytest.raises(ValidationError):
        parse_event(auth(base, pw, decision=decision, rule=rule))


def test_experimental_policy_must_be_labelled(base, pw):
    exp = {"kind": "experimental", "experiment_id": "exp-accept-after-3"}
    e = parse_event(auth(base, pw, rule="accept_after_n", policy=exp))
    assert e.policy.experiment_id == "exp-accept-after-3"
    with pytest.raises(ValidationError):
        parse_event(auth(base, pw, rule="accept_after_n", policy={"kind": "experimental"}))
    with pytest.raises(ValidationError):
        parse_event(auth(base, pw, policy={"kind": "production", "experiment_id": "x"}))


def test_session_start_carries_policy(base):
    e = parse_event(
        {
            **base,
            "event_type": "session.start",
            "src": {"ip": "2001:db8::1", "port": 22},
            "account": "root",
            "policy": {"kind": "experimental", "experiment_id": "exp-1"},
        }
    )
    assert isinstance(e, SessionStart) and e.policy.kind.value == "experimental"


def test_plaintext_password_rejected(base, pw):
    with pytest.raises(ValidationError):
        parse_event(auth(base, {**pw, "plaintext": "hunter2"}))
    with pytest.raises(ValidationError):
        parse_event({**auth(base, pw), "password": "hunter2"})


def test_unknown_fields_rejected(base, pw):
    with pytest.raises(ValidationError):
        parse_event({**auth(base, pw), "password_plain": "hunter2"})


def test_event_requires_evidence(base, pw):
    with pytest.raises(ValidationError):
        parse_event({**auth(base, pw), "evidence": []})


def test_naive_timestamp_rejected(base, pw):
    with pytest.raises(ValidationError):
        parse_event({**auth(base, pw), "occurred_at": "2026-11-18T03:00:00"})


def outbound(base, **kw):
    return {**base, "event_type": "outbound.simulated", "tool": "curl",
            "url": "http://198.51.100.1/a", "simulated_response": "http 404", **kw}


def test_outbound_is_never_a_real_connection(base):
    assert parse_event(outbound(base)).connection_made is False
    with pytest.raises(ValidationError):
        parse_event(outbound(base, connection_made=True))


def test_outbound_needs_destination(base):
    with pytest.raises(ValidationError):
        parse_event(outbound(base, url=None))
    assert isinstance(parse_event(outbound(base, url=None, host="10.20.0.15", port=5432)), OutboundSimulated)


def test_unknown_event_type_rejected(base):
    with pytest.raises(ValidationError):
        parse_event({**base, "event_type": "shell.exec"})


def test_events_are_immutable(base, pw):
    e = parse_event(auth(base, pw))
    with pytest.raises(ValidationError):
        e.username = "admin"


def test_session_start_records_ip_recurrence_not_identity(base):
    e = parse_event({**base, "event_type": "session.start", "src": {"ip": "203.0.113.7", "port": 22},
                     "account": "root", "policy": {"kind": "production"}, "source_ip_seen_before": True})
    assert e.source_ip_seen_before is True
    with pytest.raises(ValidationError):
        parse_event({**base, "event_type": "session.start", "src": {"ip": "203.0.113.7", "port": 22},
                     "account": "root", "policy": {"kind": "production"}, "returning_visitor": True})
