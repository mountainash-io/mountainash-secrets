from __future__ import annotations

import pytest
from mountainash_secrets import to_key_segment
from mountainash_secrets.core.keys import is_valid_segment, validate_segment
from mountainash_secrets.stores.filesystem import FilesystemSecretStore


def test_clean_id_passes_through():
    assert to_key_segment("margot") == "margot"
    assert to_key_segment("oura_user_1") == "oura_user_1"


def test_email_is_encoded_to_valid_segment():
    seg = to_key_segment("margot@example.com")
    assert seg.startswith("h_")
    assert is_valid_segment(seg)


@pytest.mark.parametrize("raw", ["AbC", "uuid-1234-5678", "Margot", "a.b", "a/b"])
def test_non_segment_ids_are_encoded(raw):
    seg = to_key_segment(raw)
    assert seg.startswith("h_")
    assert is_valid_segment(seg)


def test_deterministic():
    assert to_key_segment("a@b.com") == to_key_segment("a@b.com")


def test_distinct_inputs_distinct_outputs():
    assert to_key_segment("a@b.com") != to_key_segment("c@d.com")


def test_reserved_prefix_input_is_hashed_not_passed_through():
    # "h_foo" is a valid segment but reserved-prefixed → it must be encoded so it
    # can never collide with a genuinely-encoded value.
    out = to_key_segment("h_foo")
    assert out != "h_foo"
    assert out.startswith("h_")
    assert is_valid_segment(out)


def test_empty_is_deterministic_valid_segment():
    out = to_key_segment("")
    assert is_valid_segment(out)
    assert out == to_key_segment("")


def test_encoded_segment_roundtrips_through_filesystem_store(tmp_path):
    store = FilesystemSecretStore(base_dir=tmp_path)
    key = f"oura.{to_key_segment('margot@example.com')}"
    store.set(key, {"access_token": "t"})
    assert store.get(key) == {"access_token": "t"}


def test_validate_segment_raises_on_bad():
    with pytest.raises(ValueError):
        validate_segment("a@b")
