"""Injected, capability-aware store resolution.

There is no process-global resolver. An application composition root builds one
RegistryResolver of pre-constructed stores and injects it into consumers.
"""
from __future__ import annotations

import threading
import typing as t

from .errors import SecretCapabilityError, SecretResolverError
from .protocols import SecretReader

__all__ = ["SecretStoreResolver", "SecretRegistryResolver"]

C = t.TypeVar("C", bound=SecretReader)


@t.runtime_checkable
class SecretStoreResolver(t.Protocol):
    def resolve(self, name: str) -> SecretReader: ...

    def resolve_as(self, name: str, capability: type[C]) -> C: ...


class SecretRegistryResolver:
    """Resolves a name to a PRE-BUILT store. Never constructs or authenticates.

    register()/replace are composition-time operations; resolve()/resolve_as()
    are read-only lookups. A lock guards the dict for defensiveness, but mutation
    after startup is not a supported concurrency pattern.
    """

    def __init__(self, stores: dict[str, SecretReader] | None = None) -> None:
        self._stores: dict[str, SecretReader] = dict(stores) if stores else {}
        self._lock = threading.Lock()

    def register(self, name: str, store: SecretReader, *, replace: bool = False) -> None:
        with self._lock:
            if name in self._stores and not replace:
                raise SecretResolverError(f"Store already registered: {name!r}")
            self._stores[name] = store

    def resolve(self, name: str) -> SecretReader:
        with self._lock:
            try:
                return self._stores[name]
            except KeyError:
                raise SecretResolverError(f"No store registered under name: {name!r}") from None

    def resolve_as(self, name: str, capability: type[C]) -> C:
        store = self.resolve(name)
        if not isinstance(store, capability):
            raise SecretCapabilityError(
                f"Store {name!r} does not satisfy {capability.__name__}"
            )
        return t.cast(C, store)
