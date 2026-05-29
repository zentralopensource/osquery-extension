//go:build linux

package main

import (
	"github.com/osquery/osquery-go"
	zlog "github.com/rs/zerolog/log"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/crowdstrike/falcon_kernel_check"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/crowdstrike/falconctl"
)

func platformPlugins(_ string) []osquery.OsqueryPlugin {
	return []osquery.OsqueryPlugin{
		falconctl.NewFalconctlOptionTable(zlog.Logger),
		falcon_kernel_check.TablePlugin(zlog.Logger),
	}
}
