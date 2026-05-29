package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/zentralopensource/osquery-extension/tables/fleetdm/orbit/pkg/table/mcp_listening_servers"
)

var (
	name = "zentral_extension"
	// version is overridden at build time via `-X main.version=...` ldflag
	// (see .goreleaser.yml). Defaults to "dev" for local builds.
	version = "dev"
)

func main() {
	var (
		socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
		timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
		interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
	)
	flag.Parse()

	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		name,
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// platform agnostic plugins
	plugins := []osquery.OsqueryPlugin{
		table.NewPlugin("mcp_listening_servers", mcp_listening_servers.Columns(), func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
			return mcp_listening_servers.Generate(ctx, queryContext, *socket)
		}),
	}

	plugins = append(plugins, platformPlugins(*socket)...)

	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
