# Historical ASCII npm instance identities

The npm lock readers accept safe ASCII mixed-case package and scope segments
without lowercasing them. This is read compatibility for existing historical
records. It does not broaden user exact-target or fresh registry-candidate name
grammars, authorize an upgrade, or claim support for every historical npm name.

The Core before/after obligation compiler and MCP lock-scope owner require every
mixed-case install/canonical identity in the candidate to retain its exact
original instance record. New or changed mixed-case instances are unsupported.
Version, integrity, metadata and alias changes cannot use this compatibility path.
Existing scope guards still decide whether removal of an instance is authorized.

Lock v2's packages and compatible legacy views must describe the same paths,
records and incoming requirements. Casefold-colliding physical namespaces fail
closed. Case is preserved across path, package identity and edge resolution;
it is not guessed from a tarball URL. SRI, alias, host/platform and ordinary
path/reparse safeguards remain unchanged. Unsafe separators, traversal, NUL,
colon and encoded separators are not package-name compatibility exceptions.
