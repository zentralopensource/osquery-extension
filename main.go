package main

import (
	"flag"
	"log"
	"runtime"
	"time"

	"github.com/macadmins/osquery-extension/tables/macos_profiles"
	"github.com/macadmins/osquery-extension/tables/mdm"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/zentralopensource/osquery-extension/tables/falconctl"
)

var name = "zentral_extension"

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
	plugins := []osquery.OsqueryPlugin{}

	// darwin plugins
	if runtime.GOOS == "darwin" {
		darwinPlugins := []osquery.OsqueryPlugin{
			table.NewPlugin("falconctl", falconctl.FalconctlColumns(), falconctl.FalconctlGenerate),
			table.NewPlugin("macos_profiles", macos_profiles.MacOSProfilesColumns(), macos_profiles.MacOSProfilesGenerate),
			table.NewPlugin("mdm", mdm.MDMInfoColumns(), mdm.MDMInfoGenerate),
		}
		plugins = append(plugins, darwinPlugins...)
	}

	// this loop will register all the plugins
	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	// start the server
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
