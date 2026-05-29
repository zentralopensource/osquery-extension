//go:build windows

package main

import (
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	zlog "github.com/rs/zerolog/log"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/adobe_plugins"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/bitlocker_key_protectors"
	cisaudit "github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/cis_audit"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/windowsupdatetable"
)

func platformPlugins(_ string) []osquery.OsqueryPlugin {
	return []osquery.OsqueryPlugin{
		adobe_plugins.TablePlugin(zlog.Logger),
		bitlocker_key_protectors.TablePlugin(zlog.Logger),
		table.NewPlugin("cis_audit", cisaudit.Columns(), cisaudit.Generate),
		windowsupdatetable.TablePlugin(windowsupdatetable.UpdatesTable, zlog.Logger),
	}
}
