//go:build !darwin && !linux && !windows

package main

import "github.com/osquery/osquery-go"

func platformPlugins(_ string) []osquery.OsqueryPlugin { return nil }
