from mountainash_secrets.core.protocols import SecretReader, SecretWriter
from mountainash_secrets.stores.env import EnvReader


def test_reads_value_from_environment(monkeypatch):
    monkeypatch.setenv("MASECRET_DB_PASSWORD", "hunter2")
    r = EnvReader(prefix="MASECRET_")
    assert r.get("db.password") == {"value": "hunter2"}


def test_missing_env_var_returns_none(monkeypatch):
    monkeypatch.delenv("MASECRET_NOPE", raising=False)
    assert EnvReader(prefix="MASECRET_").get("nope") is None


def test_default_prefix_is_empty(monkeypatch):
    monkeypatch.setenv("API_KEY", "k")
    assert EnvReader().get("api.key") == {"value": "k"}


def test_is_reader_not_writer():
    r = EnvReader()
    assert isinstance(r, SecretReader)
    assert not isinstance(r, SecretWriter)
