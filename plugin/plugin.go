package plugin

import (
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad-autoscaler/plugins/base"
	"github.com/hashicorp/nomad-autoscaler/plugins/target"
	"github.com/hashicorp/nomad-autoscaler/sdk"

	multipass "github.com/michaelmosher/nomad-plugin-multipass-target/pkg/multipass/client"
)

const (
	pluginName = "multipass-target"
)

var (
	pluginInfo = &base.PluginInfo{
		Name:       pluginName,
		PluginType: sdk.PluginTypeTarget,
	}
)

// Assert that TargetPlugin meets the target.Target interface.
var _ target.Target = (*TargetPlugin)(nil)

// TargetPlugin is the multipass implementation of the target.Target interface.
type TargetPlugin struct {
	logger hclog.Logger
	client *multipass.RpcClient
}

func NewTargetPlugin(log hclog.Logger) *TargetPlugin {
	return &TargetPlugin{
		logger: log,
	}
}

func (t *TargetPlugin) PluginInfo() (*base.PluginInfo, error) {
	t.logger.Debug("plugin info")
	return pluginInfo, nil
}

// The SetConfig function is called when starting an instance of the plugin.
// It contains the configuration for a named instance of the plugin as provided
// in the autoscaler agent config.
//
// References:
// - https://developer.hashicorp.com/nomad/tools/autoscaling/concepts/plugins/base
// - https://developer.hashicorp.com/nomad/tools/autoscaling/agent
func (t *TargetPlugin) SetConfig(config map[string]string) error {
	t.logger.Debug("set config", "config", config)
	return nil
}

// The Scale method is called by the agent during policy evaluation. The action
// argument specifies the details about the scaling action that should be made
// against the target. config includes the details about the scaling target
// that were provided in the scaling policy.
//
// References:
// - https://developer.hashicorp.com/nomad/tools/autoscaling/internals/plugins/target
// - https://github.com/hashicorp/nomad-autoscaler/blob/v0.3.0/sdk/strategy.go#L25
// - https://developer.hashicorp.com/nomad/tools/autoscaling/policy#target
func (t *TargetPlugin) Scale(action sdk.ScalingAction, config map[string]string) error {
	t.logger.Debug("received scale action", "count", action.Count, "reason", action.Reason)
	return nil
}

// The Status method is called by the agent in order to determine the current
// status of a scaling target. This is performed as part of policy evaluation,
// and the information returned may be used by the scaling strategy to inform
// the next scaling action. Information returned includes current scaling
// level, readiness, and arbitrary metadata.
//
// References:
// - https://developer.hashicorp.com/nomad/tools/autoscaling/internals/plugins/target
// - https://github.com/hashicorp/nomad-autoscaler/blob/v0.3.0/sdk/target.go#L6
func (t *TargetPlugin) Status(config map[string]string) (*sdk.TargetStatus, error) {
	var count int64
	countStr := config["count"]
	if countStr != "" {
		count, _ = strconv.ParseInt(countStr, 10, 64)
	}

	ready := !(config["ready"] == "false")

	t.logger.Debug("received status request", "count", count, "ready", ready)

	return &sdk.TargetStatus{
		Count: count,
		Ready: ready,
	}, nil
}
