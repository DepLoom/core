# Platform archive evidence resource budget

Optional-instance absence still requires exact archive SRI, package identity,
platform selectors, host identity, compatible lock views and eligible incoming
optional edges. The expected dependency denominator is unchanged.

Rules may explicitly declare `resourceLimits: {maxTotalArchiveBytes: N}`.
The value must be an integer from 134217728 through 268435456 bytes. Without
this field the original 128 MiB aggregate compressed-archive limit remains.
An explicit null, boolean, unknown key or excessive value fails closed. This
resource setting is retained in `optionalAbsenceRules` and therefore bound into
the dependency obligation plan identity. It is not permission to omit packages.

The 32 MiB per-archive input limit, 128 MiB per-archive expanded-size limit,
archive entry count, path/reparse checks and all SRI/metadata checks are unchanged.
A resource cap failure is unavailable evidence, never dependency incompatibility
or solver UNSAT. Reusing an already fetched exact archive still requires its SRI
and selectors to be verified; a download receipt is not an omission proof.
