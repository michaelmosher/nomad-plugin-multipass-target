# Multipass Target Plugin (for Nomad Autoscaler)

This repo contains a plugin for the
[Nomad Autoscaler](https://github.com/hashicorp/nomad-autoscaler/tree/v0.3.0),
which enables
[cluster scaling policies](https://developer.hashicorp.com/nomad/tools/autoscaling/policy#target)
to target [Multipass VMs](https://multipass.run/).

## Prerequisites

The intended use-case for this plugin is you:

- having installed Multipass on your local workstation and
- having deployed a set of Multipass VMs to host a Nomad cluster,
- need the capability to auto-scale the Nomad client VMs in your cluster.

This document will not cover Multipass installation, as it is better handled in
the [official docs](https://multipass.run/install).

If the Nomad Autoscaler is run within a Multipass VM (as opposed to running on
the Multipass host), the Multipass daemon must be
[configured to accept remote communication](https://multipass.run/docs/how-to-use-multipass-remotely-a-preview),
which requires that the
[local.passphrase](https://multipass.run/docs/passphrase) configuration key has
been set.

An example of deploying a Nomad cluster on Multipass VMs can be found
[here](https://github.com/michaelmosher/nomad-in-multipass).

## Installation

Presuming that the Autoscaler will be run as a Nomad job, this plugin can be
installed using an `artifact` block in the job spec:

```hcl
locals {
  # eg. https://github.com/michaelmosher/nomad-plugin-multipass-target/releases/download/v1/nomad-plugin-multipass-target-linux-amd64
  plugin_repo     = "https://github.com/michaelmosher/nomad-plugin-multipass-target"
  plugin_version  = "v13"
  plugin_artifact = "multipass-target-${attr.kernel.name}-${attr.cpu.arch}.zip"
  plugin_artifact_url = format("%s/releases/download/%s/%s",
    local.plugin_repo, local.plugin_version, local.plugin_artifact,
  )
}

job "nomad-auto-scaler" {
  ...
  group "agent" {
    ...
    task "main" {
      ...
      artifact {
        source      = local.plugin_artifact_url
        destination = "local/plugins"
      }
    }
  }
}

```

## Plugin Configuration

When configuring the plugin itself (ie. in the `target` block of the auto-scaler
config file), the following attributes must be provided:

| Name | Description |
|---|---|
| multipass_address | The network address for the Multipass daemon. If the Autoscaler is run on the Multipass host, this can instead be the path to a Unix socket (eg. `unix:///var/run/multipass_socket`). |
| client_cert_path | The path to the PEM-encoded public certificate of an X.509 certificate which the plugin can use when opening a TLS connection to the Multipass daemon. |
|client_key_path| The path to the PEM-encoded private key of an X.509 certificate which the plugin can use when opening a TLS connection to the Multipass daemon. |
| passphrase | The value of `local.passphrase` for the Multipass daemon, as configured above. |

## Scaling Target Configuration

When configuring a Multipass scaling target (ie. in the `target` block of a
cluster scaling policy), the following attributes must be provided:

| Name | Description |
|---|---|
| cloud_init_user_data_path | The path to a [Cloud-init](https://cloudinit.readthedocs.io/en/latest/) user-data file to use when launching new Multipass VMs. |
| instance_image_name | The name of the image to use when launching new Multipass VMs (ie. as shown by `multipass find`). |
| node_class | The [node_class](https://developer.hashicorp.com/nomad/docs/configuration/client#node_class) of the auto-scaled Nomad clients. This is also used as a name prefix when launching new Multipass VMs. |

**Note**: for auto-scaling to work properly, it is essential that the user-data
provided configures the Nomad client as a member of the node_class provided.
