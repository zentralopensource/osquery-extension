# Attribution

The Go source files under this directory are vendored from the Fleet
project, with package import paths rewritten to live under this
module's path. They are reused under the MIT Expat license; see
`LICENSE` in this directory.

## Source

- Upstream repository: https://github.com/fleetdm/fleet
- Upstream commit: `4462067be2fe73a9278222acff74d4b3b0f493f7`
- Upstream commit date: `2026-05-29`
- Copyright: © 2020-present Fleet Device Management Inc, © 2017 Kolide

## Modifications

The only change applied to the copied files is a mechanical import
rewrite from `github.com/fleetdm/fleet/v4/...` to
`github.com/zentralopensource/osquery-extension/tables/fleetdm/...`,
so the vendored packages resolve to their new location in this module.
No logic, comments, or copyright notices were altered.

## Scope

Only the source needed to build the osquery tables registered by this
extension was copied. Specifically:

### Table packages (under `orbit/pkg/table/`)

- `adobe_plugins`
- `app_sso_platform`
- `bitlocker_key_protectors`
- `cis_audit`
- `crowdstrike/falcon_kernel_check`
- `crowdstrike/falconctl`
- `mcp_listening_servers`
- `windowsupdatetable`

### Helper packages (transitive dependencies of the above)

- `orbit/pkg/table/tablehelpers`
- `orbit/pkg/table/dataflattentable`
- `orbit/pkg/dataflatten`
- `orbit/pkg/user`
- `orbit/pkg/build`
- `orbit/pkg/windows/windowsupdate`
- `orbit/pkg/windows/oleconv`
- `pkg/fleethttp`

### Excluded

- `_test.go` files and `testdata/` directories — tests are not run from
  this module. Pull them in from upstream at the pinned commit above if
  you need to run the original test suite.
- Anything under Fleet's `ee/` directory — that tree is licensed
  separately under `ee/LICENSE` upstream, and none of the code copied
  here imports from it (verified at the pinned commit).
