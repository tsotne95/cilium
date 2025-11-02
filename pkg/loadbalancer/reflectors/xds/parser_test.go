// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParseClusterConfigReturnsNilWhenMetadataMissing(t *testing.T) {
	cfg := DefaultConfig
	cluster := &clusterpb.Cluster{Name: "no-meta"}

	cc, err := parseClusterConfig(cfg, cluster)
	require.NoError(t, err)
	require.Nil(t, cc)
}

func TestParseClusterConfigBuildsServiceAndFrontend(t *testing.T) {
	cfg := DefaultConfig
	cfg.Namespace = "database"
	cfg.ClusterName = "prod"

	meta := mustStruct(t, map[string]any{
		"vip":      "10.0.0.5",
		"port":     5432,
		"protocol": "tcp",
		"service":  "postgres",
		"portName": "sql",
	})
	cluster := &clusterpb.Cluster{
		Name:     "db-cluster",
		Metadata: &corepb.Metadata{FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: meta}},
	}

	cc, err := parseClusterConfig(cfg, cluster)
	require.NoError(t, err)
	require.NotNil(t, cc)

	svc := cc.service
	require.Equal(t, source.XDS, svc.Source)
	require.Equal(t, "prod", svc.Name.Cluster())
	require.Equal(t, "database", svc.Name.Namespace())
	require.Equal(t, "postgres", svc.Name.Name())
	require.Equal(t, loadbalancer.SVCNatPolicyNone, svc.NatPolicy)
	require.Equal(t, map[string]uint16{"sql": 5432}, svc.PortNames)

	require.Len(t, cc.frontends, 1)
	fe := cc.frontends[0]
	require.Equal(t, loadbalancer.SVCTypeLoadBalancer, fe.Type)
	require.Equal(t, loadbalancer.FEPortName("sql"), fe.PortName)
	require.Equal(t, uint16(5432), fe.ServicePort)
	require.Equal(t, "10.0.0.5", fe.Address.Addr().String())
	require.Equal(t, uint16(5432), fe.Address.Port())
	require.Equal(t, loadbalancer.TCP, fe.Address.Protocol())
}

func TestParseClusterConfigAppliesOverrides(t *testing.T) {
	cfg := DefaultConfig
	cfg.Namespace = "default"
	meta := mustStruct(t, map[string]any{
		"vip":       "10.0.0.6",
		"port":      80,
		"protocol":  "UDP",
		"namespace": "override",
		"cluster":   "edge",
		"service":   "frontend",
	})

	cluster := &clusterpb.Cluster{
		Name:     "ignored",
		Metadata: &corepb.Metadata{FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: meta}},
	}

	cc, err := parseClusterConfig(cfg, cluster)
	require.NoError(t, err)
	require.Equal(t, loadbalancer.UDP, cc.protocol)
	require.Equal(t, "edge", cc.service.Name.Cluster())
	require.Equal(t, "override", cc.service.Name.Namespace())
	require.Equal(t, "frontend", cc.service.Name.Name())
}

func TestParseClusterConfigValidatesVIPAndPort(t *testing.T) {
	cfg := DefaultConfig
	cases := []map[string]any{
		{"port": 80},
		{"vip": "bad", "port": 80},
		{"vip": "10.0.0.5"},
		{"vip": "10.0.0.5", "port": 70000},
	}
	for _, tc := range cases {
		cluster := &clusterpb.Cluster{
			Name:     "svc",
			Metadata: &corepb.Metadata{FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, tc)}},
		}
		cc, err := parseClusterConfig(cfg, cluster)
		require.Error(t, err)
		require.Nil(t, cc)
	}
}

func TestParseEndpointsParsesBackends(t *testing.T) {
	cfg := DefaultConfig
	cfg.MetadataKey = "custom"

	cla := &endpointpb.ClusterLoadAssignment{
		ClusterName: "db-cluster",
		Endpoints: []*endpointpb.LocalityLbEndpoints{{
			Locality: &corepb.Locality{Zone: "zone-a"},
			LbEndpoints: []*endpointpb.LbEndpoint{
				{
					HostIdentifier:      &endpointpb.LbEndpoint_Endpoint{Endpoint: makeEndpoint("192.168.1.10", 5432)},
					LoadBalancingWeight: wrapperspb.UInt32(10),
					HealthStatus:        corepb.HealthStatus_DRAINING,
					Metadata: &corepb.Metadata{FilterMetadata: map[string]*structpb.Struct{
						cfg.MetadataKey: mustStruct(t, map[string]any{"zone": "zone-b", "nodeName": "node-a"}),
					}},
				},
				{
					HostIdentifier: &endpointpb.LbEndpoint_Endpoint{Endpoint: makeEndpoint("192.168.1.11", 5433)},
					HealthStatus:   corepb.HealthStatus_UNHEALTHY,
				},
			},
		}},
	}

	records, err := parseEndpoints(cfg, cla)
	require.NoError(t, err)
	require.Len(t, records, 2)

	require.Equal(t, cmtypes.MustParseAddrCluster("192.168.1.10"), records[0].addr)
	require.Equal(t, uint16(5432), records[0].port)
	require.Equal(t, uint16(10), records[0].weight)
	require.Equal(t, loadbalancer.BackendStateTerminating, records[0].state)
	require.False(t, records[0].unhealthy)
	require.NotNil(t, records[0].zone)
	require.Equal(t, "zone-b", records[0].zone.Zone)
	require.Equal(t, "node-a", records[0].nodeName)

	require.Equal(t, cmtypes.MustParseAddrCluster("192.168.1.11"), records[1].addr)
	require.Equal(t, uint16(5433), records[1].port)
	require.Equal(t, uint16(1), records[1].weight)
	require.Equal(t, loadbalancer.BackendStateActive, records[1].state)
	require.True(t, records[1].unhealthy)
	require.NotNil(t, records[1].zone)
	require.Equal(t, "zone-a", records[1].zone.Zone)
}

func TestParseEndpointsValidation(t *testing.T) {
	cfg := DefaultConfig

	cases := []struct {
		name string
		cla  *endpointpb.ClusterLoadAssignment
	}{
		{
			name: "invalid-address",
			cla: &endpointpb.ClusterLoadAssignment{
				ClusterName: "demo",
				Endpoints: []*endpointpb.LocalityLbEndpoints{{
					LbEndpoints: []*endpointpb.LbEndpoint{{
						HostIdentifier: &endpointpb.LbEndpoint_Endpoint{Endpoint: makeEndpoint("bad address", 80)},
					}},
				}},
			},
		},
		{
			name: "missing-port",
			cla: &endpointpb.ClusterLoadAssignment{
				ClusterName: "demo",
				Endpoints: []*endpointpb.LocalityLbEndpoints{{
					LbEndpoints: []*endpointpb.LbEndpoint{{
						HostIdentifier: &endpointpb.LbEndpoint_Endpoint{
							Endpoint: &endpointpb.Endpoint{Address: &corepb.Address{Address: &corepb.Address_SocketAddress{SocketAddress: &corepb.SocketAddress{Address: "10.0.0.1"}}}},
						},
					}},
				}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records, err := parseEndpoints(cfg, tc.cla)
			require.Error(t, err)
			require.Nil(t, records)
		})
	}
}

func TestReadNumberParsesNumericStrings(t *testing.T) {
	s := mustStruct(t, map[string]any{"port": "8080"})
	val, err := readNumber(s, "port")
	require.NoError(t, err)
	require.Equal(t, float64(8080), val)
}

func makeEndpoint(address string, port uint32) *endpointpb.Endpoint {
	return &endpointpb.Endpoint{
		Address: &corepb.Address{
			Address: &corepb.Address_SocketAddress{
				SocketAddress: &corepb.SocketAddress{
					Address:       address,
					PortSpecifier: &corepb.SocketAddress_PortValue{PortValue: port},
				},
			},
		},
	}
}
