// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	envoyxds "github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
)

type controller struct {
	log    *slog.Logger
	cfg    Config
	writer writerAPI

	mu             sync.Mutex
	services       map[string]*serviceState
	pendingDeletes map[string]loadbalancer.ServiceName
}

type writeTxn interface {
	Abort()
	Commit()
}

type writerAPI interface {
	WriteTxn(extraTables ...statedb.TableMeta) writeTxn
	UpsertServiceAndFrontends(txn writeTxn, svc *loadbalancer.Service, fes ...loadbalancer.FrontendParams) error
	DeleteServiceAndFrontends(txn writeTxn, name loadbalancer.ServiceName) (*loadbalancer.Service, error)
	SetBackends(txn writeTxn, name loadbalancer.ServiceName, src source.Source, bes ...loadbalancer.BackendParams) error
}

type serviceState struct {
	serviceName loadbalancer.ServiceName
	cluster     *clusterConfig
	endpoints   []endpointRecord
}

type clusterConfig struct {
	service   *loadbalancer.Service
	frontends []loadbalancer.FrontendParams
	protocol  loadbalancer.L4Type
}

type endpointRecord struct {
	addr      cmtypes.AddrCluster
	port      uint16
	weight    uint16
	nodeName  string
	zone      *loadbalancer.BackendZone
	state     loadbalancer.BackendState
	unhealthy bool
}

func newController(log *slog.Logger, cfg Config, w writerAPI) *controller {
	return &controller{
		log:            log,
		cfg:            cfg,
		writer:         w,
		services:       make(map[string]*serviceState),
		pendingDeletes: make(map[string]loadbalancer.ServiceName),
	}
}

// HandleClusters processes a snapshot of Cluster resources.
func (c *controller) HandleClusters(res *envoyxds.VersionedResources) {
	if res == nil {
		return
	}

	c.mu.Lock()
	changed := false
	seen := make(map[string]struct{}, len(res.Resources))
	for _, msg := range res.Resources {
		cluster, ok := msg.(*clusterpb.Cluster)
		if !ok {
			c.log.Warn("Ignoring unexpected xDS cluster type", logfields.XDSResource, fmt.Sprintf("%T", msg))
			continue
		}
		name := cluster.GetName()
		seen[name] = struct{}{}

		cfg, err := parseClusterConfig(c.cfg, cluster)
		if err != nil {
			c.log.Error("Failed to parse xDS cluster", logfields.XDSResourceName, name, logfields.Error, err)
			if c.removeServiceLocked(name) {
				changed = true
			}
			continue
		}
		if cfg == nil {
			if c.removeServiceLocked(name) {
				changed = true
			}
			continue
		}

		st := c.ensureStateLocked(name)
		st.cluster = cfg
		st.serviceName = cfg.service.Name
		delete(c.pendingDeletes, name)
		changed = true
	}

	if len(res.ResourceNames) > 0 {
		current := make(map[string]struct{}, len(res.ResourceNames))
		for _, name := range res.ResourceNames {
			current[name] = struct{}{}
		}
		for name := range c.services {
			if _, ok := current[name]; ok {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			if c.removeServiceLocked(name) {
				changed = true
			}
		}
	}

	if len(res.ResourceNames) == 0 && len(res.Resources) == 0 {
		for name := range c.services {
			if c.removeServiceLocked(name) {
				changed = true
			}
		}
	}

	snapshotStates := c.snapshotStatesLocked()
	deletes := maps.Clone(c.pendingDeletes)
	c.mu.Unlock()

	if !changed && len(deletes) == 0 {
		return
	}

	if err := c.sync(snapshotStates, deletes); err != nil {
		c.log.Error("Failed to reconcile xDS cluster updates", logfields.Error, err)
		return
	}

	if len(deletes) > 0 {
		c.mu.Lock()
		for name := range deletes {
			delete(c.pendingDeletes, name)
		}
		c.mu.Unlock()
	}
}

// HandleEndpoints processes a snapshot of ClusterLoadAssignment resources.
func (c *controller) HandleEndpoints(res *envoyxds.VersionedResources) {
	if res == nil {
		return
	}

	c.mu.Lock()
	changed := false
	seen := make(map[string]struct{}, len(res.Resources))
	for _, msg := range res.Resources {
		cla, ok := msg.(*endpointpb.ClusterLoadAssignment)
		if !ok {
			c.log.Warn("Ignoring unexpected xDS load assignment type", logfields.XDSResource, fmt.Sprintf("%T", msg))
			continue
		}
		clusterName := cla.GetClusterName()
		seen[clusterName] = struct{}{}

		endpoints, err := parseEndpoints(c.cfg, cla)
		if err != nil {
			c.log.Error("Failed to parse xDS load assignment", logfields.XDSResourceName, clusterName, logfields.Error, err)
			continue
		}
		st := c.ensureStateLocked(clusterName)
		st.endpoints = endpoints
		changed = true
	}

	if len(res.ResourceNames) > 0 {
		current := make(map[string]struct{}, len(res.ResourceNames))
		for _, name := range res.ResourceNames {
			current[name] = struct{}{}
		}
		for name, st := range c.services {
			if _, ok := current[name]; ok {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			if st != nil && len(st.endpoints) > 0 {
				st.endpoints = nil
				changed = true
			}
		}
	}

	if len(res.ResourceNames) == 0 && len(res.Resources) == 0 {
		for _, st := range c.services {
			if st != nil && len(st.endpoints) > 0 {
				st.endpoints = nil
				changed = true
			}
		}
	}

	snapshotStates := c.snapshotStatesLocked()
	deletes := maps.Clone(c.pendingDeletes)
	c.mu.Unlock()

	if !changed && len(deletes) == 0 {
		return
	}

	if err := c.sync(snapshotStates, deletes); err != nil {
		c.log.Error("Failed to reconcile xDS endpoint updates", logfields.Error, err)
		return
	}

	if len(deletes) > 0 {
		c.mu.Lock()
		for name := range deletes {
			delete(c.pendingDeletes, name)
		}
		c.mu.Unlock()
	}
}

func (c *controller) ensureStateLocked(name string) *serviceState {
	if st, ok := c.services[name]; ok {
		return st
	}
	st := &serviceState{}
	c.services[name] = st
	return st
}

func (c *controller) removeServiceLocked(name string) bool {
	st, ok := c.services[name]
	if ok {
		delete(c.services, name)
		if st != nil {
			c.pendingDeletes[name] = st.serviceName
		} else {
			c.pendingDeletes[name] = loadbalancer.ServiceName{}
		}
		return true
	}
	if _, ok := c.pendingDeletes[name]; ok {
		return false
	}
	c.pendingDeletes[name] = loadbalancer.ServiceName{}
	return true
}

func (c *controller) snapshotStatesLocked() map[string]serviceSnapshot {
	snapshot := make(map[string]serviceSnapshot, len(c.services))
	for name, st := range c.services {
		if st == nil {
			continue
		}
		var cfgCopy *clusterConfig
		if st.cluster != nil {
			cfgCopy = &clusterConfig{
				service:   st.cluster.service.Clone(),
				frontends: slices.Clone(st.cluster.frontends),
				protocol:  st.cluster.protocol,
			}
		}
		eps := make([]endpointRecord, len(st.endpoints))
		copy(eps, st.endpoints)
		snapshot[name] = serviceSnapshot{
			serviceName: st.serviceName,
			cluster:     cfgCopy,
			endpoints:   eps,
		}
	}
	return snapshot
}

type serviceSnapshot struct {
	serviceName loadbalancer.ServiceName
	cluster     *clusterConfig
	endpoints   []endpointRecord
}

func (c *controller) sync(states map[string]serviceSnapshot, deletes map[string]loadbalancer.ServiceName) error {
	txn := c.writer.WriteTxn()
	defer txn.Abort()

	for clusterName, svcName := range deletes {
		if svcName.String() == "" {
			continue
		}
		if _, err := c.writer.DeleteServiceAndFrontends(txn, svcName); err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
			return fmt.Errorf("delete service %s: %w", clusterName, err)
		}
	}

	for clusterName, st := range states {
		if st.cluster == nil {
			continue
		}
		svc := st.cluster.service.Clone()
		svc.Source = source.XDS

		frontends := make([]loadbalancer.FrontendParams, len(st.cluster.frontends))
		for i, fe := range st.cluster.frontends {
			fe.ServiceName = svc.Name
			if fe.ServicePort == 0 {
				fe.ServicePort = fe.Address.Port()
			}
			frontends[i] = fe
		}
		if err := c.writer.UpsertServiceAndFrontends(txn, svc, frontends...); err != nil {
			return fmt.Errorf("upsert service %s: %w", clusterName, err)
		}

		backends := make([]loadbalancer.BackendParams, len(st.endpoints))
		for i, ep := range st.endpoints {
			addr := loadbalancer.NewL3n4Addr(st.cluster.protocol, ep.addr, ep.port, loadbalancer.ScopeExternal)
			backends[i] = loadbalancer.BackendParams{
				Address:   addr,
				Weight:    ep.weight,
				NodeName:  ep.nodeName,
				Zone:      ep.zone,
				State:     ep.state,
				Unhealthy: ep.unhealthy,
			}
		}
		if err := c.writer.SetBackends(txn, svc.Name, source.XDS, backends...); err != nil {
			return fmt.Errorf("set backends for %s: %w", clusterName, err)
		}
	}

	txn.Commit()
	return nil
}
