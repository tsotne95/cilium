=====================================
Standalone xDS-driven L4 Load Balancer
=====================================

Cilium can synchronise standalone Layer 4 load-balancers from any xDS control
plane. The agent embeds a specialised xDS client that watches ``Cluster`` and
``ClusterLoadAssignment`` resources and translates them into entries in the
``statedb`` service and backend tables. This enables platform teams to expose
TCP or UDP virtual IPs (VIPs) that are completely decoupled from Kubernetes
Services while still using Cilium's datapath for NAT and health tracking.

Getting started
===============

Enable the reflector by setting the xDS load-balancer configuration block:

.. code-block:: yaml

   xds-control-plane:
     enabled: true
     server-address: "xds.example.net:9000"
     client-cert-path: "/var/lib/cilium/tls/xds-client.crt"
     client-key-path: "/var/lib/cilium/tls/xds-client.key"
     ca-cert-path: "/var/lib/cilium/tls/xds-ca.crt"
     metadata-key: "io.cilium.l4lb"
     namespace: "platform"
     cluster: "prod"

When enabled, the controller subscribes to clusters that embed the Cilium
metadata block. A minimal example is shown below:

.. code-block:: yaml

   resource:
     '@type': type.googleapis.com/envoy.config.cluster.v3.Cluster
     name: inventory-write
     metadata:
       filter_metadata:
         io.cilium.l4lb:
           vip: "10.0.20.15"
           port: 9042
           protocol: tcp
           service: cassandra
   ---
   resource:
     '@type': type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
     cluster_name: inventory-write
     endpoints:
     - lb_endpoints:
       - endpoint:
           address:
             socket_address: { address: 192.168.100.10, port_value: 9042 }
       - endpoint:
           address:
             socket_address: { address: 192.168.101.10, port_value: 9042 }

The controller stores an internal snapshot of the received resources and drives
the ``writer.Writer`` service API to create services, frontends, and backends
with the ``source.XDS`` provenance. Endpoints inherit locality zone
information, honour backend metadata (``zone`` and ``nodeName`` keys), and map
xDS health states onto Cilium backend states.

Comparison with existing options
================================

The xDS-based workflow complements the existing Kubernetes and file-based
reflectors. The table below highlights the major differences:

.. list-table::
   :header-rows: 1

   * - Capability
     - xDS reflector
     - Kubernetes Service
     - File-based reflector
   * - Control-plane integration
     - Connects to any gRPC/xDS management server, supports dynamic discovery
     - Driven by Kubernetes API objects only
     - Local JSON file pushed to each node
   * - Update semantics
     - Incremental and state-of-the-world snapshots, supports endpoint removal
       via resource name tracking
     - Event driven through Kubernetes informers
     - Node-local polling or file watch
   * - Service identity
     - Namespace, service name, cluster ID and port name taken from xDS
       metadata, stored as ``source.XDS``
     - Kubernetes namespaces and services, stored as ``source.Kubernetes``
     - Configured as ``source.Directory``
   * - Security
     - Optional mTLS with per-node certificates
     - Kubernetes API authentication
     - Depends on host file permissions

Testing and validation
======================

Unit tests validate the controller's handling of cluster deletion, endpoint
removal, metadata parsing, backend state mapping, writer integration, and TLS
transport credential creation. ``go test ./pkg/loadbalancer/reflectors/xds``
covers the controller, parser, and transport helpers, while
``go test ./pkg/source`` verifies that ``source.XDS`` is prioritised between
custom-resource and Kubernetes derived state.
