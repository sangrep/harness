# Compatibility

Python 3.11 or newer is the declared interpreter floor. The distribution name is
`sangrep-harness`; the import namespace is `sangrep_harness`.

## Contracts artifact

The only contracts dependency is `sangrep-contracts==0.1.0.dev0`. The accepted source
commit is `28f6d9ada5b2da9fb432aead11462104207750c0`. The immutable source archive has
SHA-256 `30a284d0d978cd036f7ccd789f1b6223fc409df257838115dd1b668e570e2e6e`.
The accepted wheel is `sangrep_contracts-0.1.0.dev0-py3-none-any.whl`, 95,679 bytes,
SHA-256 `8b6e52f4fb6db1ee021c7111cd17021577d9deb20ba7167622456a1bd329423c`.

The bootstrap verifies both identities before installing the wheel. It does not
install a mutable branch, an editable package or a sibling source directory. No
package-registry release is claimed. Updating the pin requires explicit review of
the contract behavior and the new immutable artifact's provenance.

## Compatibility policy

Development versions can change before a stable release. Versioned wire objects
reject malformed input; callers should preserve schema versions and handle explicit
failures. Adapter integrations must pass provider and evidence contract tests for
the version they consume. Passing these tests does not qualify a live provider or
claim arbitrary format support.
