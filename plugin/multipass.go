package plugin

import (
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	multipass "github.com/michaelmosher/nomad-plugin-multipass-target/pkg/multipass/client"
)

const (
	// configKeys represents the known configuration parameters required at
	// varying points throughout the plugins lifecycle.
	configKeyAddress        = "multipass_addr"
	configKeyClientCertPath = "multipass_client_cert_path"
	configKeyClientKeyPath  = "multipass_client_key_path"
)

func validateConfig(config map[string]string) error {
	requiredKeys := []string{
		configKeyAddress,
		configKeyClientCertPath,
		configKeyClientKeyPath,
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
