package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	multipass "github.com/michaelmosher/nomad-plugin-multipass-target/pkg/multipass/client"
)

// configKeys represents the known configuration parameters.
const (
	// plugin config keys
	configKeyAddress        = "multipass_addr"
	configKeyClientCertPath = "multipass_client_cert_path"
	configKeyClientKeyPath  = "multipass_client_key_path"
	configKeyPassphrase     = "multipass_passphrase"

	// target scaling config keys
	configKeyNamePrefix = "multipass_instance_name_prefix"
)

func validateConfig(config map[string]string) error {
	requiredKeys := []string{
		configKeyAddress,
		configKeyClientCertPath,
		configKeyClientKeyPath,
		configKeyPassphrase,
	}
	missingKeys := make([]string, len(requiredKeys))

	for _, key := range requiredKeys {
		if _, ok := config[key]; !ok {
			missingKeys = append(missingKeys, key)
		}
	}

	if len(missingKeys) > 0 {
		return fmt.Errorf(
			"required keys missing from config: %s",
			strings.Join(missingKeys, ", "),
		)
	}

	return nil
}

func (t *TargetPlugin) setupClient(config map[string]string) error {
	t.logger.Debug("set up client")

	clientCertFilePath := config[configKeyClientCertPath]
	cert, err := parseClientCertificate(clientCertFilePath)
	if err != nil {
		return fmt.Errorf("parseClientCertificate: %w", err)
	}

	clientKeyFilePath := config[configKeyClientKeyPath]
	key, err := parseClientKey(clientKeyFilePath)
	if err != nil {
		return fmt.Errorf("parseClientKey: %w", err)
	}

	addr := config[configKeyAddress]
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{cert.Raw},
					Leaf:        cert,
					PrivateKey:  key,
				}},
				// We aren't verifying the server identity, which makes us
				// vulnerable to MitM attacks – be aware and proceed with
				// caution.
				InsecureSkipVerify: true,
			}),
		),
	)
	if err != nil {
		return fmt.Errorf("grpc.Dial: %w", err)
	}

	t.client = multipass.NewRpcClient(conn)

	return nil
}

func (t *TargetPlugin) authenticate(passphrase string) error {
	t.logger.Debug("authenticate")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	authStream, err := t.client.Authenticate(ctx)
	if err != nil {
		return fmt.Errorf("client.Authenticate: %v", err)
	}

	authStream.Send(&multipass.AuthenticateRequest{
		Passphrase: passphrase,
	})

	authReply := multipass.AuthenticateReply{}
	err = authStream.RecvMsg(&authReply)
	if err != nil && err != io.EOF {
		return fmt.Errorf("authStream.RecvMsg: %w", err)
	}

	// TODO: remove if this is never non-empty
	if authReply.LogLine != "" {
		t.logger.Info("authReply.LogLine", authReply.LogLine)
	}

	return nil
}

func (t *TargetPlugin) getInstanceList(namePrefix string) ([]*multipass.ListVMInstance, error) {
	t.logger.Debug("getInstanceList")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	listStream, err := t.client.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("client.List: %w", err)
	}

	listStream.Send(&multipass.ListRequest{
		Snapshots: false,
	})

	listReply := multipass.ListReply{}
	err = listStream.RecvMsg(&listReply)
	if err != nil {
		return nil, fmt.Errorf("listStream.RecvMsg: %w", err)
	}

	result := make([]*multipass.ListVMInstance, 0)
	for _, instance := range listReply.GetInstanceList().GetInstances() {
		name := instance.GetName()
		if strings.HasPrefix(name, namePrefix) {
			result = append(result, instance)
		}
	}
	return result, nil
}

