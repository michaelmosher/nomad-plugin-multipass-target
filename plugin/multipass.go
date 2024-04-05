package plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	multipass "github.com/michaelmosher/nomad-plugin-multipass-target/pkg/multipass/client"
)

// configKeys represents the known configuration parameters.
const (
	// plugin config keys
	configKeyAddress        = "multipass_address"
	configKeyClientCertPath = "client_cert_path"
	configKeyClientKeyPath  = "client_key_path"
	configKeyPassphrase     = "passphrase"

	// target scaling config keys
	configKeyNamePrefix            = "instance_name_prefix"
	configKeyImageName             = "instance_image_name"
	configKeyCloudInitUserDataPath = "cloud_init_user_data_path"
	// TODO: support non-default CPU/RAM/Disk configs
)

func validateConfig(config map[string]string) error {
	requiredKeys := []string{
		configKeyAddress,
		configKeyClientCertPath,
		configKeyClientKeyPath,
		configKeyPassphrase,
	}
	missingKeys := make([]string, 0)

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

func (t *TargetPlugin) scaleOut(
	delta int64,
	config map[string]string,
) error {
	t.logger.Debug("scaleOut", "delta", delta)

	namePrefix := config[configKeyNamePrefix]
	imageName, ok := config[configKeyImageName]
	if !ok {
		return fmt.Errorf("%s config param is required to scale up", configKeyImageName)
	}

	var userData string
	if userDataPath, ok := config[configKeyCloudInitUserDataPath]; ok {
		bytes, err := os.ReadFile(userDataPath)
		if err != nil {
			return fmt.Errorf("os.ReadFile(%s): %w", userDataPath, err)
		}
		// Additional safetys might be nice here – is this valid user-data?
		userData = string(bytes)
	}

	for i := 0; i < int(delta); i++ {
		launchStream, err := t.client.Launch(context.Background())
		if err != nil {
			return fmt.Errorf("client.Launch: %w", err)
		}

		now := time.Now()
		// This will result in names that lexicographically sort oldest to newest.
		nameSuffix := now.Format(fmt.Sprintf("%sT%s", time.DateOnly, "150405"))

		launchStream.Send(&multipass.LaunchRequest{
			InstanceName:      namePrefix + "-" + nameSuffix,
			Image:             imageName,
			CloudInitUserData: userData,
		})
		launchReply := multipass.LaunchReply{}

		for {
			err = launchStream.RecvMsg(&launchReply)
			if err != nil && err != io.EOF {
				return fmt.Errorf("launchStream.RecvMsg: %w", err)
			}

			if msg := launchReply.GetReplyMessage(); msg != "" {
				t.logger.Debug(msg)
			}

			if err == io.EOF {
				break
			}
		}

		t.logger.Debug("scaleUp successful", "name", launchReply.GetVmInstanceName())
	}

	return nil
}

func (t *TargetPlugin) scaleIn(
	instances []*multipass.ListVMInstance,
	delta int64,
	config map[string]string,
) error {
	t.logger.Debug("scaleIn", "delta", delta)

	multipassInstanceNames := make([]string, len(instances))
	for i, instance := range instances {
		multipassInstanceNames[i] = instance.GetName()
	}

	slices.Sort(multipassInstanceNames)
	targeted := multipassInstanceNames[0:delta]

	nodes, err := t.clusterUtils.RunPreScaleInTasksWithRemoteCheck(
		context.Background(),
		config,
		targeted,
		int(delta),
	)
	if err != nil {
		return fmt.Errorf("clusterUtils.RunPreScaleInTasksWithRemoteCheck: %w", err)
	}

	for _, node := range nodes {
		deleteStream, err := t.client.Delet(context.Background())
		if err != nil {
			return fmt.Errorf("client.Delet: %w", err)
		}

		target := &multipass.InstanceSnapshotPair{
			InstanceName: node.RemoteResourceID,
		}
		deleteStream.Send(&multipass.DeleteRequest{
			InstanceSnapshotPairs: []*multipass.InstanceSnapshotPair{target},
			Purge:                 true,
		})

		// TODO: validate if this ever returns more than one message
		deleteReply := multipass.DeleteReply{}
		for {
			err = deleteStream.RecvMsg(&deleteReply)
			if err != nil && err != io.EOF {
				return fmt.Errorf("deleteStream.RecvMsg: %w", err)
			}

			if msg := deleteReply.GetLogLine(); msg != "" {
				t.logger.Debug(msg)
			}

			if err == io.EOF {
				break
			}
		}
		t.logger.Debug("delete successful",
			"nomadId", node.NomadNodeID,
			"multipassID", node.RemoteResourceID)
	}

	return nil
}
