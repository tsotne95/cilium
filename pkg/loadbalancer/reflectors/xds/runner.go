// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	xdsclient "github.com/cilium/cilium/pkg/xds/experimental/client"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var Cell = cell.Module(
	"xds-l4lb-reflector",
	"Synchronizes load-balancing services via the xDS control plane",
	cell.Config(DefaultConfig),
	cell.Invoke(registerXDSReflector),
)

type reflectorParams struct {
	cell.In

	Log      *slog.Logger
	Config   Config
	LBConfig loadbalancer.Config
	Writer   *writer.Writer
	Jobs     job.Group
}

func registerXDSReflector(p reflectorParams) error {
	if !p.Config.Enabled {
		return nil
	}
	if p.Config.ServerAddress == "" {
		return fmt.Errorf("xds-lb-server-address must be configured when xds-lb-enabled is true")
	}

	ctrl := newController(p.Log.With(logfields.LogSubsys, "xds-l4lb"), p.Config, newWriterAdapter(p.Writer))

	connOpts := xdsclient.Defaults
	connOpts.RetryBackoff.Min = p.LBConfig.RetryBackoffMin
	connOpts.RetryBackoff.Max = p.LBConfig.RetryBackoffMax
	connOpts.RetryConnection = true

	backoff := job.ExponentialBackoff{
		Min: p.LBConfig.RetryBackoffMin,
		Max: p.LBConfig.RetryBackoffMax,
	}

	p.Jobs.Add(job.OneShot("xds-lb-client", func(ctx context.Context, health cell.Health) error {
		return ctrl.run(ctx, health, connOpts)
	}, job.WithRetry(-1, &backoff)))

	return nil
}

func (c *controller) run(ctx context.Context, health cell.Health, connOpts xdsclient.ConnectionOptions) error {
	creds, err := buildTransportCredentials(c.cfg)
	if err != nil {
		return err
	}

	dialTimeout := c.cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultConfig.DialTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(dctx, c.cfg.ServerAddress, grpc.WithBlock(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial xDS server: %w", err)
	}
	defer conn.Close()

	client := xdsclient.NewClient(c.log, c.cfg.UseSOTW, &connOpts)
	stopClusters := client.AddResourceWatcher(envoy.ClusterTypeURL, c.HandleClusters)
	defer stopClusters()
	stopEndpoints := client.AddResourceWatcher(envoy.EndpointTypeURL, c.HandleEndpoints)
	defer stopEndpoints()

	if err := client.Observe(ctx, envoy.ClusterTypeURL, nil); err != nil {
		return fmt.Errorf("observe clusters: %w", err)
	}
	if err := client.Observe(ctx, envoy.EndpointTypeURL, nil); err != nil {
		return fmt.Errorf("observe endpoints: %w", err)
	}

	nodeID := c.cfg.NodeID
	if nodeID == "" {
		nodeID = nodetypes.GetName()
	}

	node := &corepb.Node{
		Id:            nodeID,
		Cluster:       c.cfg.ClusterName,
		UserAgentName: "cilium-agent",
	}

	health.OK("connected to xDS control plane")
	err = client.Run(ctx, node, conn)
	if err != nil {
		health.Degraded("xDS client stopped", err)
		return err
	}
	health.Stopped("xDS client stopped")
	return nil
}

func buildTransportCredentials(cfg Config) (credentials.TransportCredentials, error) {
	hasTLS := cfg.CACertPath != "" || cfg.ClientCertPath != "" || cfg.ClientKeyPath != ""
	if !hasTLS {
		return insecure.NewCredentials(), nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertPath != "" {
		caPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.ClientCertPath != "" || cfg.ClientKeyPath != "" {
		if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
			return nil, fmt.Errorf("both xds-lb-client-cert-path and xds-lb-client-key-path are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsConfig), nil
}
