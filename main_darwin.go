//go:build darwin

package main

import (
	"context"

	"github.com/macadmins/osquery-extension/tables/chromeuserprofiles"
	"github.com/macadmins/osquery-extension/tables/localnetworkpermissions"
	"github.com/macadmins/osquery-extension/tables/macos_profiles"
	"github.com/macadmins/osquery-extension/tables/mdm"
	"github.com/macadmins/osquery-extension/tables/sofa"
	"github.com/macadmins/osquery-extension/tables/unifiedlog"
	"github.com/macadmins/osquery-extension/tables/wifi_network"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	zlog "github.com/rs/zerolog/log"
	"github.com/zentralopensource/osquery-extension/tables/falconctl"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/adobe_plugins"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/app_sso_platform"
)

func platformPlugins(socket string) []osquery.OsqueryPlugin {
	return []osquery.OsqueryPlugin{
		table.NewPlugin("falconctl", falconctl.FalconctlColumns(), falconctl.FalconctlGenerate),
		table.NewPlugin("google_chrome_profiles", chromeuserprofiles.GoogleChromeProfilesColumns(), chromeuserprofiles.GoogleChromeProfilesGenerate),
		table.NewPlugin("local_network_permissions", localnetworkpermissions.LocalNetworkPermissionsColumns(), localnetworkpermissions.LocalNetworkPermissionsGenerate),
		table.NewPlugin("macos_profiles", macos_profiles.MacOSProfilesColumns(), macos_profiles.MacOSProfilesGenerate),
		table.NewPlugin("mdm", mdm.MDMInfoColumns(), mdm.MDMInfoGenerate),
		table.NewPlugin("sofa_security_release_info", sofa.SofaSecurityReleaseInfoColumns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
			return sofa.SofaSecurityReleaseInfoGenerate(ctx, queryContext, socket)
		}),
		table.NewPlugin("sofa_unpatched_cves", sofa.SofaUnpatchedCVEsColumns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
			return sofa.SofaUnpatchedCVEsGenerate(ctx, queryContext, socket)
		}),
		table.NewPlugin("macadmins_unified_log", unifiedlog.UnifiedLogColumns(), unifiedlog.UnifiedLogGenerate),
		table.NewPlugin("wifi_network", wifi_network.WifiNetworkColumns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
			return wifi_network.WifiNetworkGenerate(ctx, queryContext, socket)
		}),
		adobe_plugins.TablePlugin(zlog.Logger),
		table.NewPlugin("app_sso_platform", app_sso_platform.Columns(), app_sso_platform.Generate),
	}
}
