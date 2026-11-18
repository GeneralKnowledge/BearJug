import pytest

from bearjug.schema import password_ref
from conftest import TEST_KEY


def test_same_password_same_key_links():
    a = password_ref("123456", key=TEST_KEY, key_id="k")
    b = password_ref("123456", key=TEST_KEY, key_id="k")
    assert a.hmac_sha256 == b.hmac_sha256


def test_different_key_does_not_link():
    a = password_ref("123456", key=TEST_KEY, key_id="k1")
    b = password_ref("123456", key=TEST_KEY[::-1], key_id="k2")
    assert a.hmac_sha256 != b.hmac_sha256


def test_plaintext_never_in_serialised_ref():
    ref = password_ref("Sup3r-Secret!", key=TEST_KEY, key_id="k")
    assert "Sup3r-Secret!" not in ref.model_dump_json()


def test_features():
    f = password_ref("Ab1!", key=TEST_KEY, key_id="k", wordlist={"Ab1!"}).features
    assert (f.length, f.has_lower, f.has_upper, f.has_digit, f.has_symbol, f.in_wordlist) == (
        4, True, True, True, True, True,
    )
    assert password_ref("x", key=TEST_KEY, key_id="k").features.in_wordlist is None


def test_short_key_rejected():
    with pytest.raises(ValueError):
        password_ref("x", key=b"short", key_id="k")
