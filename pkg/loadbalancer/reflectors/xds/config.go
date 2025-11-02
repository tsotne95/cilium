// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"time"

	"github.com/spf13/pflag"
)

// Config configures the standalone xDS load-balancer reflector.
type Config struct {
	Enabled        bool          `mapstructure:"xds-lb-enabled"`
	ServerAddress  string        `mapstructure:"xds-lb-server-address"`
	ClientCertPath string        `mapstructure:"xds-lb-client-cert-path"`
	ClientKeyPath  string        `mapstructure:"xds-lb-client-key-path"`
	CACertPath     string        `mapstructure:"xds-lb-ca-cert-path"`
	MetadataKey    string        `mapstructure:"xds-lb-metadata-key"`
	Namespace      string        `mapstructure:"xds-lb-namespace"`
	ClusterName    string        `mapstructure:"xds-lb-cluster"`
	NodeID         string        `mapstructure:"xds-lb-node-id"`
	UseSOTW        bool          `mapstructure:"xds-lb-use-sotw"`
	DialTimeout    time.Duration `mapstructure:"xds-lb-dial-timeout"`
}

// DefaultConfig contains the defaults for the reflector configuration.
var DefaultConfig = Config{
	Enabled:     false,
	MetadataKey: "io.cilium.l4lb",
	Namespace:   "xds",
	ClusterName: "",
	UseSOTW:     true,
	DialTimeout: 10 * time.Second,
}

// Flags implements the hive flagger interface.
func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("xds-lb-enabled", c.Enabled, "Enable the standalone xDS load-balancer client")
	flags.String("xds-lb-server-address", c.ServerAddress, "Address of the external xDS management server")
	flags.String("xds-lb-client-cert-path", c.ClientCertPath, "Path to the client certificate for authenticating to the xDS server")
	flags.String("xds-lb-client-key-path", c.ClientKeyPath, "Path to the client certificate key for authenticating to the xDS server")
	flags.String("xds-lb-ca-cert-path", c.CACertPath, "Path to the CA certificate used to validate the xDS server")
	flags.String("xds-lb-metadata-key", c.MetadataKey, "Metadata key on xDS clusters identifying L4 load-balancer definitions")
	flags.String("xds-lb-namespace", c.Namespace, "Namespace used when creating standalone xDS managed services")
	flags.String("xds-lb-cluster", c.ClusterName, "Cluster name prefix used when creating standalone xDS managed services")
	flags.String("xds-lb-node-id", c.NodeID, "Node ID used when connecting to the xDS management server")
	flags.Bool("xds-lb-use-sotw", c.UseSOTW, "Use the state-of-the-world variant of the xDS protocol")
	flags.Duration("xds-lb-dial-timeout", c.DialTimeout, "Timeout for establishing the gRPC connection to the xDS management server")
}
