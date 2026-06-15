import mountainash_secrets as ms


def test_public_symbols_are_exported():
    expected = {
        "__version__",
        # protocols
        "SecretReader",
        "SecretWriter",
        "ClearableStore",
        "VersionedReader",
        "SecretRecord",
        "JSONValue",
        # resolver
        "SecretStoreResolver",
        "RegistryResolver",
        # errors
        "SecretStoreError",
        "ResolverError",
        "CapabilityError",
        "StoreUnavailableError",
        "SecretNotFoundError",
        # stores
        "InMemoryStore",
        "FilesystemStore",
        "EnvReader",
        "NamespacedStore",
        # access
        "require",
    }
    assert expected.issubset(set(ms.__all__))
    for name in expected:
        assert hasattr(ms, name), name


def test_end_to_end_resolve_and_namespace():
    resolver = ms.SecretRegistryResolver({"local": ms.InMemorySecretStore()})
    store = resolver.resolve_as("local", ms.ClearableSecretStore)
    tokens = ms.NamespacedSecretStore(store, "oauth")
    tokens.set("garmin", {"access_token": "T", "expires_at": 123})
    assert tokens.get("garmin") == {"access_token": "T", "expires_at": 123}
