package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad-autoscaler/plugins"
	multipass "github.com/michaelmosher/nomad-plugin-multipass-target/plugin"
)

func main() {
	plugins.Serve(factory)
}

func factory(l hclog.Logger) interface{} {
	return multipass.NewTargetPlugin(l)
}
