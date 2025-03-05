package falconctl

import (
	"context"
	"os/exec"
	"strconv"

	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type cloudInfo struct {
	Host  string
	Port  int
	State string
}

type agentInfo struct {
	AgentId           string `plist:"agentID"`
	CustomerId        string `plist:"customerID"`
	SensorOperational string `plist:"sensor_operational"`
	SensorStatus      string `plist:"sensor_status"`
	Version           string `plist:"version"`
}

type statsOutput struct {
	CloudInfo cloudInfo
	AgentInfo agentInfo `plist:"agent_info"`
}

func FalconctlColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("cloud_host"),
		table.IntegerColumn("cloud_port"),
		table.TextColumn("cloud_state"),
		table.TextColumn("agent_id"),
		table.TextColumn("customer_id"),
		table.TextColumn("sensor_operational"),
		table.TextColumn("sensor_status"),
		table.TextColumn("version"),
	}
}

func FalconctlGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	output, err := runFalconctlCmd()
	if err != nil {
		return nil, errors.Wrap(err, "run falconctl command")
	}

	stats, err := unmarshalFalconctlOutput(output)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalFalconctlOutput")
	}

	return generateResults(stats), nil
}

func generateResults(stats statsOutput) []map[string]string {
	var results []map[string]string
	result := map[string]string{
		"cloud_host":         stats.CloudInfo.Host,
		"cloud_port":         strconv.Itoa(stats.CloudInfo.Port),
		"cloud_state":        stats.CloudInfo.State,
		"agent_id":           stats.AgentInfo.AgentId,
		"customer_id":        stats.AgentInfo.CustomerId,
		"sensor_operational": stats.AgentInfo.SensorOperational,
		"sensor_status":      stats.AgentInfo.SensorStatus,
		"version":            stats.AgentInfo.Version,
	}
	results = append(results, result)
	return results
}

func runFalconctlCmd() ([]byte, error) {
	cmd := exec.Command("/Applications/Falcon.app/Contents/Resources/falconctl", "stats", "--plist")
	out, err := cmd.Output()
	if err != nil {
		return out, errors.Wrap(err, "calling falconctl")
	}
	return out, nil
}

func unmarshalFalconctlOutput(output []byte) (statsOutput, error) {
	var stats statsOutput
	if err := plist.Unmarshal(output, &stats); err != nil {
		return stats, errors.Wrap(err, "unmarshal stats output")
	}
	return stats, nil
}
