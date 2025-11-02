// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"

	envoyxds "github.com/cilium/cilium/pkg/envoy/xds"
	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeWriter struct {
	services       map[loadbalancer.ServiceName]*loadbalancer.Service
	frontends      map[loadbalancer.ServiceName][]loadbalancer.FrontendParams
	backends       map[loadbalancer.ServiceName][]loadbalancer.BackendParams
	backendSources map[loadbalancer.ServiceName]source.Source
	deletes        []loadbalancer.ServiceName
}

type fakeTxn struct{}

func newFakeWriter() *fakeWriter {
	return &fakeWriter{
		services:       make(map[loadbalancer.ServiceName]*loadbalancer.Service),
		frontends:      make(map[loadbalancer.ServiceName][]loadbalancer.FrontendParams),
		backends:       make(map[loadbalancer.ServiceName][]loadbalancer.BackendParams),
		backendSources: make(map[loadbalancer.ServiceName]source.Source),
	}
}

func (f *fakeWriter) WriteTxn(...statedb.TableMeta) writeTxn { return &fakeTxn{} }

func (f *fakeWriter) UpsertServiceAndFrontends(_ writeTxn, svc *loadbalancer.Service, fes ...loadbalancer.FrontendParams) error {
	f.services[svc.Name] = svc.Clone()
	f.frontends[svc.Name] = append([]loadbalancer.FrontendParams(nil), fes...)
	return nil
}

func (f *fakeWriter) DeleteServiceAndFrontends(_ writeTxn, name loadbalancer.ServiceName) (*loadbalancer.Service, error) {
	svc := f.services[name]
	delete(f.services, name)
	delete(f.frontends, name)
	delete(f.backends, name)
	f.deletes = append(f.deletes, name)
	return svc, nil
}

func (f *fakeWriter) SetBackends(_ writeTxn, name loadbalancer.ServiceName, _ source.Source, bes ...loadbalancer.BackendParams) error {
	f.backends[name] = append([]loadbalancer.BackendParams(nil), bes...)
	f.backendSources[name] = source.XDS
	return nil
}

func (f *fakeTxn) Abort()  {}
func (f *fakeTxn) Commit() {}

func mustStruct(t *testing.T, data map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(data)
	require.NoError(t, err)
	return s
}

func TestControllerAppliesResources(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "database"
	ctrl := newController(newTestLogger(), cfg, fw)

	clusterMeta, err := structpb.NewStruct(map[string]any{
		"vip":      "10.1.2.3",
		"port":     3306,
		"protocol": "tcp",
		"service":  "mysql",
	})
	require.NoError(t, err)

	cluster := &clusterpb.Cluster{
		Name: "db-cluster",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				cfg.MetadataKey: clusterMeta,
			},
		},
	}

	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cluster},
	})

	cla := &endpointpb.ClusterLoadAssignment{
		ClusterName: cluster.GetName(),
		Endpoints: []*endpointpb.LocalityLbEndpoints{
			{
				Locality: &corepb.Locality{Zone: "zone-a"},
				LbEndpoints: []*endpointpb.LbEndpoint{
					{
						HostIdentifier: &endpointpb.LbEndpoint_Endpoint{
							Endpoint: &endpointpb.Endpoint{
								Address: &corepb.Address{
									Address: &corepb.Address_SocketAddress{
										SocketAddress: &corepb.SocketAddress{
											Address:       "192.168.1.10",
											PortSpecifier: &corepb.SocketAddress_PortValue{PortValue: 3306},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	ctrl.HandleEndpoints(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cla},
	})

	serviceName := loadbalancer.NewServiceName("database", "mysql")
	svc, ok := fw.services[serviceName]
	require.True(t, ok)
	require.Equal(t, source.XDS, svc.Source)

	require.Equal(t, loadbalancer.SVCNatPolicyNone, svc.NatPolicy)
	require.Equal(t, loadbalancer.SVCTrafficPolicyCluster, svc.ExtTrafficPolicy)
	require.Equal(t, loadbalancer.SVCTrafficPolicyCluster, svc.IntTrafficPolicy)

	frontends := fw.frontends[serviceName]
	require.Len(t, frontends, 1)
	require.Equal(t, "10.1.2.3", frontends[0].Address.Addr().String())
	require.Equal(t, uint16(3306), frontends[0].Address.Port())
	require.Equal(t, loadbalancer.SVCTypeLoadBalancer, frontends[0].Type)

	backends := fw.backends[serviceName]
	require.Len(t, backends, 1)
	require.Equal(t, "192.168.1.10", backends[0].Address.Addr().String())
	require.Equal(t, uint16(3306), backends[0].Address.Port())
	require.Equal(t, source.XDS, fw.backendSources[serviceName])
}

func TestControllerRemovesResources(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "default"
	ctrl := newController(newTestLogger(), cfg, fw)

	cluster := &clusterpb.Cluster{
		Name: "demo",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.1.2.3", "port": 8080})},
		},
	}
	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cluster},
	})
	ctrl.HandleEndpoints(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{&endpointpb.ClusterLoadAssignment{ClusterName: cluster.GetName()}},
	})

	ctrl.HandleEndpoints(&envoyxds.VersionedResources{})
	ctrl.HandleClusters(&envoyxds.VersionedResources{})

	_, ok := fw.services[loadbalancer.NewServiceName("default", "demo")]
	require.False(t, ok)
	require.Empty(t, fw.backends)
	require.ElementsMatch(t, []loadbalancer.ServiceName{loadbalancer.NewServiceName("default", "demo")}, fw.deletes)
}

func TestControllerRemovesWhenMetadataMissing(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "default"
	ctrl := newController(newTestLogger(), cfg, fw)

	cluster := &clusterpb.Cluster{
		Name: "demo",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.1.2.3", "port": 8080})},
		},
	}
	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cluster},
	})

	serviceName := loadbalancer.NewServiceName("default", "demo")
	require.Contains(t, fw.services, serviceName)

	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{&clusterpb.Cluster{Name: cluster.GetName()}},
	})

	require.NotContains(t, fw.services, serviceName)
	require.ElementsMatch(t, []loadbalancer.ServiceName{serviceName}, fw.deletes)
}

func TestControllerRespectsClusterResourceNames(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "default"
	ctrl := newController(newTestLogger(), cfg, fw)

	clusterA := &clusterpb.Cluster{
		Name: "alpha",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.0.0.1", "port": 80})},
		},
	}
	clusterB := &clusterpb.Cluster{
		Name: "bravo",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.0.0.2", "port": 81})},
		},
	}

	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{clusterA.GetName(), clusterB.GetName()},
		Resources:     []proto.Message{clusterA, clusterB},
	})

	require.Contains(t, fw.services, loadbalancer.NewServiceName("default", "alpha"))
	require.Contains(t, fw.services, loadbalancer.NewServiceName("default", "bravo"))

	ctrl.HandleClusters(&envoyxds.VersionedResources{ResourceNames: []string{clusterA.GetName()}})

	require.Contains(t, fw.services, loadbalancer.NewServiceName("default", "alpha"))
	require.NotContains(t, fw.services, loadbalancer.NewServiceName("default", "bravo"))
	require.ElementsMatch(t, []loadbalancer.ServiceName{loadbalancer.NewServiceName("default", "bravo")}, fw.deletes)
}

func TestControllerClearsEndpointsWhenMissing(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "default"
	ctrl := newController(newTestLogger(), cfg, fw)

	cluster := &clusterpb.Cluster{
		Name: "demo",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.1.2.3", "port": 8080})},
		},
	}
	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cluster},
	})

	cla := &endpointpb.ClusterLoadAssignment{
		ClusterName: cluster.GetName(),
		Endpoints: []*endpointpb.LocalityLbEndpoints{{
			Locality: &corepb.Locality{Zone: "zone-a"},
			LbEndpoints: []*endpointpb.LbEndpoint{{
				HostIdentifier: &endpointpb.LbEndpoint_Endpoint{
					Endpoint: &endpointpb.Endpoint{
						Address: &corepb.Address{
							Address: &corepb.Address_SocketAddress{
								SocketAddress: &corepb.SocketAddress{
									Address:       "192.168.1.10",
									PortSpecifier: &corepb.SocketAddress_PortValue{PortValue: 8080},
								},
							},
						},
					},
				},
			}},
		}},
	}

	ctrl.HandleEndpoints(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cla},
	})

	serviceName := loadbalancer.NewServiceName("default", "demo")
	backends := fw.backends[serviceName]
	require.Len(t, backends, 1)

	ctrl.HandleEndpoints(&envoyxds.VersionedResources{ResourceNames: []string{"other"}})

	backends = fw.backends[serviceName]
	require.Len(t, backends, 0)
	require.Contains(t, fw.backendSources, serviceName)
	require.Equal(t, source.XDS, fw.backendSources[serviceName])
}

func TestControllerEndpointMetadataOverrides(t *testing.T) {
	fw := newFakeWriter()
	cfg := DefaultConfig
	cfg.Enabled = true
	cfg.Namespace = "default"
	ctrl := newController(newTestLogger(), cfg, fw)

	cluster := &clusterpb.Cluster{
		Name: "demo",
		Metadata: &corepb.Metadata{
			FilterMetadata: map[string]*structpb.Struct{cfg.MetadataKey: mustStruct(t, map[string]any{"vip": "10.1.2.3", "port": 8080, "protocol": "udp"})},
		},
	}
	ctrl.HandleClusters(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cluster},
	})

	endpointMeta := &corepb.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			cfg.MetadataKey: mustStruct(t, map[string]any{"zone": "zone-override", "nodeName": "node-a"}),
		},
	}

	cla := &endpointpb.ClusterLoadAssignment{
		ClusterName: cluster.GetName(),
		Endpoints: []*endpointpb.LocalityLbEndpoints{{
			Locality: &corepb.Locality{Zone: "zone-a"},
			LbEndpoints: []*endpointpb.LbEndpoint{
				{
					LoadBalancingWeight: wrapperspb.UInt32(10),
					HealthStatus:        corepb.HealthStatus_DRAINING,
					Metadata:            endpointMeta,
					HostIdentifier: &endpointpb.LbEndpoint_Endpoint{
						Endpoint: &endpointpb.Endpoint{
							Address: &corepb.Address{
								Address: &corepb.Address_SocketAddress{
									SocketAddress: &corepb.SocketAddress{
										Address:       "192.168.1.10",
										PortSpecifier: &corepb.SocketAddress_PortValue{PortValue: 8081},
									},
								},
							},
						},
					},
				},
				{
					LoadBalancingWeight: wrapperspb.UInt32(0),
					HealthStatus:        corepb.HealthStatus_UNHEALTHY,
					HostIdentifier: &endpointpb.LbEndpoint_Endpoint{
						Endpoint: &endpointpb.Endpoint{
							Address: &corepb.Address{
								Address: &corepb.Address_SocketAddress{
									SocketAddress: &corepb.SocketAddress{
										Address:       "192.168.1.11",
										PortSpecifier: &corepb.SocketAddress_PortValue{PortValue: 8082},
									},
								},
							},
						},
					},
				},
			},
		}},
	}

	ctrl.HandleEndpoints(&envoyxds.VersionedResources{
		ResourceNames: []string{cluster.GetName()},
		Resources:     []proto.Message{cla},
	})

	serviceName := loadbalancer.NewServiceName("default", "demo")
	backends := fw.backends[serviceName]
	require.Len(t, backends, 2)

	require.Equal(t, "192.168.1.10", backends[0].Address.Addr().String())
	require.Equal(t, loadbalancer.UDP, backends[0].Address.Protocol())
	require.Equal(t, uint16(8081), backends[0].Address.Port())
	require.Equal(t, uint16(10), backends[0].Weight)
	require.Equal(t, loadbalancer.BackendStateTerminating, backends[0].State)
	require.False(t, backends[0].Unhealthy)
	require.NotNil(t, backends[0].Zone)
	require.Equal(t, "zone-override", backends[0].Zone.Zone)
	require.Equal(t, "node-a", backends[0].NodeName)

	require.Equal(t, "192.168.1.11", backends[1].Address.Addr().String())
	require.Equal(t, uint16(8082), backends[1].Address.Port())
	require.Equal(t, uint16(1), backends[1].Weight)
	require.Equal(t, loadbalancer.BackendStateActive, backends[1].State)
	require.True(t, backends[1].Unhealthy)
	require.NotNil(t, backends[1].Zone)
	require.Equal(t, "zone-a", backends[1].Zone.Zone)
	require.Empty(t, backends[1].NodeName)
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}
