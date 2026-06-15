from mountainash_secrets.core.errors import (
    SecretCapabilityError,
    SecretResolverError,
    SecretNotFoundError,
    SecretStoreError,
    SecretStoreUnavailableError,
)


def test_all_errors_subclass_base():
    for exc in (SecretResolverError, SecretCapabilityError, SecretStoreUnavailableError, SecretNotFoundError):
        assert issubclass(exc, SecretStoreError)


def test_base_is_exception():
    assert issubclass(SecretStoreError, Exception)


def test_errors_are_distinct():
    assert SecretResolverError is not SecretCapabilityError
    assert SecretStoreUnavailableError is not SecretNotFoundError
