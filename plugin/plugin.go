package plugin

import (
	"fmt"

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
	client multipass.RpcClient
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

	if err := validateConfig(config); err != nil {
		return fmt.Errorf("validateConfig: %w", err)
	}

	if err := t.setupClient(config); err != nil {
		return fmt.Errorf("setupClient: %w", err)
	}

	passphrase := config[configKeyPassphrase]
	if err := t.authenticate(passphrase); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}

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

	namePrefix, ok := config[configKeyNamePrefix]
	if !ok {
		return fmt.Errorf("required config param %s not found", configKeyNamePrefix)
	}

	instances, err := t.getInstanceList(namePrefix)
	if err != nil {
		return fmt.Errorf("getInstanceList: %w", err)
	}

	if action.Direction == sdk.ScaleDirectionUp {
		imageName, ok := config[configKeyImageName]
		if !ok {
			return fmt.Errorf("%s config param is required to scale up", configKeyImageName)
		}

		scaleOutCount := action.Count - int64(len(instances))
		for scaleOutCount > 0 {
			// Don't prematurely optimize: add instances one at a time
			err := t.scaleOut(namePrefix, imageName)
			if err != nil {
				return fmt.Errorf("scaleUp(%s, %s): %w", namePrefix, imageName, err)
			}

			instances, err = t.getInstanceList(namePrefix)
			if err != nil {
				return fmt.Errorf("getInstanceList: %w", err)
			}

			scaleOutCount = action.Count - int64(len(instances))
		}
	}

	if action.Direction == sdk.ScaleDirectionDown {
		t.logger.Debug("scaleDown action not yet implemented")
	}

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
	// Note: config here is the options passed to the `target` block within a
	// scaling policy – not the plugin config.
	t.logger.Debug("Status", "config", config)

	namePrefix, ok := config[configKeyNamePrefix]
	if !ok {
		return nil, fmt.Errorf("required config param %s not found", configKeyNamePrefix)
	}

	instances, err := t.getInstanceList(namePrefix)
	if err != nil {
		return nil, fmt.Errorf("getInstanceList: %w", err)
	}

	count := len(instances)
	// How do we account for instances that aren't running? For now,
	// let's just WARN about them.
	for _, instance := range instances {
		if instance.InstanceStatus.GetStatus() != multipass.InstanceStatus_RUNNING {
			t.logger.Warn("Instance is counted, but not running", "instance", instance.GetName())
		}
	}

	t.logger.Debug("received status request", "count", count)

	return &sdk.TargetStatus{
		Count: int64(count),
		Ready: true,
	}, nil
}
