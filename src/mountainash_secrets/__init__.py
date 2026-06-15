"""mountainash-secrets — capability-graded secret-store port."""
from .__version__ import __version__
from .core.access import require
from .core.errors import (
    SecretCapabilityError,
    SecretNotFoundError,
    SecretResolverError,
    SecretStoreError,
    SecretStoreUnavailableError,
)
from .core.keys import to_key_segment
from .core.protocols import (
    ClearableSecretStore,
    JSONValue,
    SecretReader,
    SecretRecord,
    SecretWriter,
    VersionedSecretReader,
)
from .core.resolver import SecretRegistryResolver, SecretStoreResolver
from .stores.env import EnvReader
from .stores.filesystem import FilesystemSecretStore
from .stores.memory import InMemorySecretStore
from .stores.namespaced import NamespacedSecretStore

__all__ = [
    "__version__",
    "SecretReader",
    "SecretWriter",
    "ClearableSecretStore",
    "VersionedSecretReader",
    "SecretRecord",
    "JSONValue",
    "SecretStoreResolver",
    "SecretRegistryResolver",
    "SecretStoreError",
    "SecretResolverError",
    "SecretCapabilityError",
    "SecretStoreUnavailableError",
    "SecretNotFoundError",
    "InMemorySecretStore",
    "FilesystemSecretStore",
    "EnvReader",
    "NamespacedSecretStore",
    "require",
    "to_key_segment",
]
