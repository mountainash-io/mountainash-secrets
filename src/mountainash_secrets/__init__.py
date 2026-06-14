"""mountainash-secrets — capability-graded secret-store port."""
from .__version__ import __version__
from .core.access import require
from .core.errors import (
    CapabilityError,
    ResolverError,
    SecretNotFoundError,
    SecretStoreError,
    StoreUnavailableError,
)
from .core.protocols import (
    ClearableStore,
    JSONValue,
    SecretReader,
    SecretRecord,
    SecretWriter,
    VersionedReader,
)
from .core.resolver import RegistryResolver, SecretStoreResolver
from .stores.env import EnvReader
from .stores.filesystem import FilesystemStore
from .stores.memory import InMemoryStore
from .stores.namespaced import NamespacedStore

__all__ = [
    "__version__",
    "SecretReader",
    "SecretWriter",
    "ClearableStore",
    "VersionedReader",
    "SecretRecord",
    "JSONValue",
    "SecretStoreResolver",
    "RegistryResolver",
    "SecretStoreError",
    "ResolverError",
    "CapabilityError",
    "StoreUnavailableError",
    "SecretNotFoundError",
    "InMemoryStore",
    "FilesystemStore",
    "EnvReader",
    "NamespacedStore",
    "require",
]
