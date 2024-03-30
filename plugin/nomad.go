package plugin

import (
	"fmt"

	"github.com/hashicorp/nomad/api"
)

// multipassNodeIDMap is used to identify the Multipass instance of a Nomad
// node. An Nomad attribute is used to store the name of the Multipass instance
// (unique.hostname by default).
func (t *TargetPlugin) multipassNodeIDMap(n *api.Node) (string, error) {
	val, ok := n.Attributes[t.nodeIDAttribute]
	if !ok || val == "" {
		return "", fmt.Errorf("attribute %q not found", t.nodeIDAttribute)
	}
	return val, nil
}
