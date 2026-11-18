import hashlib
from datetime import datetime, timezone

import pytest

TEST_KEY = b"aito-decoy-test-key-not-secret-00000000"


@pytest.fixture
def base():
    return {
        "event_id": "evt-1",
        "occurred_at": datetime(2026, 11, 18, 3, 0, tzinfo=timezone.utc).isoformat(),
        "sensor_id": "sensor-test",
        "profile_id": "prod-db-01",
        "session_id": "sess-1",
        "parser": "test/0",
        "evidence": [{"evidence_id": "ev-1", "sha256": hashlib.sha256(b"x").hexdigest()}],
    }


@pytest.fixture
def pw():
    from bearjug.schema import password_ref

    return password_ref("hunter2", key=TEST_KEY, key_id="test-key").model_dump()
