from mountainash_secrets.core.errors import (
    CapabilityError,
    ResolverError,
    SecretNotFoundError,
    SecretStoreError,
    StoreUnavailableError,
)


def test_all_errors_subclass_base():
    for exc in (ResolverError, CapabilityError, StoreUnavailableError, SecretNotFoundError):
        assert issubclass(exc, SecretStoreError)


def test_base_is_exception():
    assert issubclass(SecretStoreError, Exception)


def test_errors_are_distinct():
    assert ResolverError is not CapabilityError
    assert StoreUnavailableError is not SecretNotFoundError
