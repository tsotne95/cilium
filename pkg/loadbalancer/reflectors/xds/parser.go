// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"errors"
	"fmt"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

var (
	errMissingVIP  = errors.New("missing vip metadata")
	errMissingPort = errors.New("missing port metadata")
)

func parseClusterConfig(cfg Config, cluster *clusterpb.Cluster) (*clusterConfig, error) {
	metadata := cluster.GetMetadata().GetFilterMetadata()
	entry := metadata[cfg.MetadataKey]
	if entry == nil {
		return nil, nil
	}

	vip, ok := readString(entry, "vip")
	if !ok || vip == "" {
		return nil, errMissingVIP
	}
	addr, err := cmtypes.ParseAddrCluster(strings.TrimSpace(vip))
	if err != nil {
		return nil, fmt.Errorf("parse vip %q: %w", vip, err)
	}

	portFloat, err := readNumber(entry, "port")
	if err != nil {
		return nil, errMissingPort
	}
	if portFloat < 1 || portFloat > 65535 {
		return nil, fmt.Errorf("invalid port %.0f", portFloat)
	}
	port := uint16(portFloat)

	protoName, _ := readString(entry, "protocol")
	if protoName == "" {
		protoName = "tcp"
	}
	proto, err := loadbalancer.NewL4Type(protoName)
	if err != nil {
		return nil, fmt.Errorf("unsupported protocol %q", protoName)
	}

	namespace := cfg.Namespace
	if ns, ok := readString(entry, "namespace"); ok && ns != "" {
		namespace = ns
	}
	if namespace == "" {
		namespace = DefaultConfig.Namespace
	}

	serviceName := cluster.GetName()
	if svc, ok := readString(entry, "service"); ok && svc != "" {
		serviceName = svc
	}

	clusterName := cfg.ClusterName
	if clusterOverride, ok := readString(entry, "cluster"); ok && clusterOverride != "" {
		clusterName = clusterOverride
	}

	portName, _ := readString(entry, "portName")

	lbServiceName := loadbalancer.NewServiceNameInCluster(clusterName, namespace, serviceName)
	service := &loadbalancer.Service{
		Name:             lbServiceName,
		Source:           source.XDS,
		NatPolicy:        loadbalancer.SVCNatPolicyNone,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	if portName != "" {
		service.PortNames = map[string]uint16{portName: port}
	}

	frontend := loadbalancer.FrontendParams{
		Address:     loadbalancer.NewL3n4Addr(proto, addr, port, loadbalancer.ScopeExternal),
		Type:        loadbalancer.SVCTypeLoadBalancer,
		ServiceName: lbServiceName,
		ServicePort: port,
	}
	if portName != "" {
		frontend.PortName = loadbalancer.FEPortName(portName)
	}

	return &clusterConfig{
		service:   service,
		frontends: []loadbalancer.FrontendParams{frontend},
		protocol:  proto,
	}, nil
}

func parseEndpoints(cfg Config, cla *endpointpb.ClusterLoadAssignment) ([]endpointRecord, error) {
	var records []endpointRecord
	for _, locality := range cla.GetEndpoints() {
		localityZone := locality.GetLocality().GetZone()
		for _, lbEndpoint := range locality.GetLbEndpoints() {
			ep := lbEndpoint.GetEndpoint()
			if ep == nil {
				continue
			}
			socketAddr := ep.GetAddress().GetSocketAddress()
			if socketAddr == nil {
				continue
			}
			address := strings.TrimSpace(socketAddr.GetAddress())
			addr, err := cmtypes.ParseAddrCluster(address)
			if err != nil {
				return nil, fmt.Errorf("parse backend address %q: %w", address, err)
			}
			port := socketAddr.GetPortValue()
			if port == 0 {
				return nil, fmt.Errorf("backend %q missing port", address)
			}

			weight := uint16(1)
			if lbEndpoint.GetLoadBalancingWeight() != nil {
				weight = uint16(lbEndpoint.GetLoadBalancingWeight().GetValue())
				if weight == 0 {
					weight = 1
				}
			}

			endpointZone := localityZone
			nodeName := ""
			metadata := lbEndpoint.GetMetadata().GetFilterMetadata()[cfg.MetadataKey]
			if metadata != nil {
				if metaZone, ok := readString(metadata, "zone"); ok && metaZone != "" {
					endpointZone = metaZone
				}
				if n, ok := readString(metadata, "nodeName"); ok {
					nodeName = n
				}
			}

			var backendZone *loadbalancer.BackendZone
			if endpointZone != "" {
				backendZone = &loadbalancer.BackendZone{Zone: endpointZone}
			}

			state := loadbalancer.BackendStateActive
			unhealthy := false
			switch lbEndpoint.GetHealthStatus() {
			case corepb.HealthStatus_DRAINING:
				state = loadbalancer.BackendStateTerminating
			case corepb.HealthStatus_UNHEALTHY:
				unhealthy = true
			case corepb.HealthStatus_DEGRADED:
				state = loadbalancer.BackendStateMaintenance
			}

			records = append(records, endpointRecord{
				addr:      addr,
				port:      uint16(port),
				weight:    weight,
				nodeName:  nodeName,
				zone:      backendZone,
				state:     state,
				unhealthy: unhealthy,
			})
		}
	}
	return records, nil
}

func readString(structVal *structpb.Struct, field string) (string, bool) {
	if structVal == nil {
		return "", false
	}
	value, ok := structVal.GetFields()[field]
	if !ok {
		return "", false
	}
	str := strings.TrimSpace(value.GetStringValue())
	return str, true
}

func readNumber(structVal *structpb.Struct, field string) (float64, error) {
	if structVal == nil {
		return 0, fmt.Errorf("missing metadata struct")
	}
	value, ok := structVal.GetFields()[field]
	if !ok {
		return 0, fmt.Errorf("missing field %s", field)
	}
	switch v := value.Kind.(type) {
	case *structpb.Value_NumberValue:
		return v.NumberValue, nil
	case *structpb.Value_StringValue:
		num, err := parseFloat(v.StringValue)
		if err != nil {
			return 0, err
		}
		return num, nil
	default:
		return 0, fmt.Errorf("field %s is not numeric", field)
	}
}

func parseFloat(value string) (float64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("invalid number %q", value)
	}
	var num float64
	_, err := fmt.Sscanf(value, "%f", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", value)
	}
	return num, nil
}
