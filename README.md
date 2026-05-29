# Zentral Osquery Extension

A collection of extra tables for [osquery](https://osquery.io/).

The extension is a single Go binary that registers a set of osquery virtual
tables. Some tables are implemented in this repo, some come from upstream
projects ([macadmins/osquery-extension](https://github.com/macadmins/osquery-extension)
imported as a Go module, [fleetdm/fleet](https://github.com/fleetdm/fleet/tree/main/orbit/pkg/table)
vendored under [`tables/fleetdm/`](tables/fleetdm/)).

## Tables

| Name | Description | Platforms | Source |
|---|---|---|---|
| [`adobe_plugins`](tables/fleetdm/orbit/pkg/table/adobe_plugins/) | Adobe CEP / UXP / native plug-ins discovered by scanning well-known directories | macOS, Windows | fleet |
| [`app_sso_platform`](tables/fleetdm/orbit/pkg/table/app_sso_platform/) | Apple Platform SSO registration state for the logged-in user | macOS | fleet |
| [`bitlocker_key_protectors`](tables/fleetdm/orbit/pkg/table/bitlocker_key_protectors/) | BitLocker key protector types per drive | Windows | fleet |
| [`cis_audit`](tables/fleetdm/orbit/pkg/table/cis_audit/) | Security configuration data (auditpol, secedit) for CIS benchmark checks | Windows | fleet |
| `falcon_kernel_check` | Whether the running kernel is supported by the CrowdStrike Falcon sensor | Linux | fleet |
| `falconctl` | Status of the CrowdStrike Falcon agent (`falconctl -g …` parser) | macOS | local |
| `falconctl_option` | CrowdStrike Falcon agent options exposed via `falconctl -g` | Linux | fleet |
| [`google_chrome_profiles`](https://github.com/macadmins/osquery-extension/tree/main/tables/chromeuserprofiles) | Google Chrome profiles found on disk | macOS | macadmins |
| [`local_network_permissions`](https://github.com/macadmins/osquery-extension/tree/main/tables/localnetworkpermissions) | macOS local network permission grants per app | macOS | macadmins |
| [`macadmins_unified_log`](https://github.com/macadmins/osquery-extension/tree/main/tables/unifiedlog) | `log show` query results from the macOS unified log | macOS | macadmins |
| [`macos_profiles`](https://github.com/macadmins/osquery-extension/tree/main/tables/macos_profiles) | High-level information on installed configuration profiles | macOS | macadmins |
| [`mcp_listening_servers`](tables/fleetdm/orbit/pkg/table/mcp_listening_servers/) | Local processes that serve an MCP (Model Context Protocol) endpoint on a listening port | macOS, Linux, Windows | fleet |
| [`mdm`](https://github.com/macadmins/osquery-extension/tree/main/tables/mdm) | MDM enrollment status and DEP information | macOS | macadmins — see upstream notes about rate limits |
| [`sofa_security_release_info`](https://github.com/macadmins/osquery-extension/tree/main/tables/sofa) | macOS security release info for a given OS version (from [SOFA](https://sofa.macadmins.io/)) | macOS | macadmins |
| [`sofa_unpatched_cves`](https://github.com/macadmins/osquery-extension/tree/main/tables/sofa) | CVEs not yet patched on the running macOS version (from SOFA) | macOS | macadmins |
| [`wifi_network`](https://github.com/macadmins/osquery-extension/tree/main/tables/wifi_network) | Current Wi-Fi network name and security level | macOS | macadmins |
| [`windows_updates`](tables/fleetdm/orbit/pkg/table/windowsupdatetable/) | Pending Windows updates returned by the Windows Update Agent COM API | Windows | fleet |

## Building

The build is pure Go (no cgo) and uses standard `GOOS`/`GOARCH` cross-compilation.
Per-platform registration lives in `main_<goos>.go` files; build constraints
ensure each target only pulls in the table packages that compile for it.

```sh
GOOS=darwin  GOARCH=arm64 go build .
GOOS=linux   GOARCH=amd64 go build .
GOOS=windows GOARCH=amd64 go build .
```

The output binary should be renamed to match osquery's extension convention
(`*.ext` on Unix, `*.ext.exe` on Windows) before loading. The release pipeline
produces correctly-named archives automatically.

## Releases

Pushing a tag matching `v*` triggers
[.github/workflows/release.yml](.github/workflows/release.yml), which runs
[GoReleaser](https://goreleaser.com/) per [.goreleaser.yml](.goreleaser.yml).
Artifacts produced for each release:

- `osquery-extension_<version>_darwin_amd64.tar.gz`
- `osquery-extension_<version>_darwin_arm64.tar.gz`
- `osquery-extension_<version>_linux_amd64.tar.gz`
- `osquery-extension_<version>_linux_arm64.tar.gz`
- `osquery-extension_<version>_windows_amd64.zip`
- `osquery-extension_<version>_windows_arm64.zip`
- `checksums.txt`

Each archive ships the binary, project `LICENSE.txt`, `README.md`, and (in
`licenses/`) the vendored fleet `LICENSE` and `ATTRIBUTION.md`.

## Third-party code

- Code under [`tables/fleetdm/`](tables/fleetdm/) is vendored from
  [fleetdm/fleet](https://github.com/fleetdm/fleet) under the MIT Expat
  license. See [`tables/fleetdm/LICENSE`](tables/fleetdm/LICENSE) and
  [`tables/fleetdm/ATTRIBUTION.md`](tables/fleetdm/ATTRIBUTION.md) for the
  pinned commit and the list of vendored packages.
- The macadmins tables are pulled in as a Go module dependency
  ([`github.com/macadmins/osquery-extension`](https://github.com/macadmins/osquery-extension))
  rather than vendored — their license travels with the module.

## License

This project is licensed under the MIT License — see [LICENSE.txt](LICENSE.txt).
