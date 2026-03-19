# APEX-KV Operational Runbooks

This document provides operational procedures for running APEX-KV in production.

## Table of Contents

1. [Deployment](#deployment)
2. [Monitoring & Alerting](#monitoring--alerting)
3. [Backup & Recovery](#backup--recovery)
4. [Scaling Operations](#scaling-operations)
5. [Incident Response](#incident-response)
6. [Maintenance Procedures](#maintenance-procedures)

---

## Deployment

### Prerequisites

- Linux kernel 4.19+ (for epoll, eventfd)
- OpenSSL 1.1.1+ (for mTLS)
- CMake 3.16+
- At least 2GB RAM per node
- SSD storage recommended for WAL durability

### Building from Source

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Configuration

Each node requires:
- Unique node ID (1-65535)
- Hostname/IP and port
- WAL directory path
- TLS certificates (for mTLS)

Example configuration file (`config.yaml`):
```yaml
node_id: 1
host: "192.168.1.10"
port: 9000
wal_dir: "/var/lib/apex-kv/wal"
data_dir: "/var/lib/apex-kv/data"
tls:
  enabled: true
  cert_path: "/etc/apex-kv/certs/node.crt"
  key_path: "/etc/apex-kv/certs/node.key"
  ca_path: "/etc/apex-kv/certs/ca.crt"
  verify_peers: true
auth:
  enabled: true
  token_ttl_hours: 24
peers:
  - node_id: 2
    host: "192.168.1.11"
    port: 9000
  - node_id: 3
    host: "192.168.1.12"
    port: 9000
```

### Starting a Node

```bash
./apex-kv --config config.yaml
```

Or with command-line flags:
```bash
./apex-kv \
  --id 1 \
  --host 0.0.0.0 \
  --port 9000 \
  --wal-dir /var/lib/apex-kv/wal \
  --peer 192.168.1.11:9000:2 \
  --peer 192.168.1.12:9000:3
```

### Docker Deployment

```bash
docker run -d \
  --name apex-kv-node1 \
  -p 9000:9000 \
  -v /var/lib/apex-kv:/var/lib/apex-kv \
  -v /etc/apex-kv:/etc/apex-kv \
  apex-kv:latest \
  --id 1 --host 0.0.0.0 --port 9000 \
  --wal-dir /var/lib/apex-kv/wal
```

### Verifying Cluster Health

```bash
# Check node status
curl http://localhost:9000/health

# Get metrics
curl http://localhost:9000/metrics

# Test connectivity
./apex-client ping --host localhost --port 9000
```

---

## Monitoring & Alerting

### Key Metrics

APEX-KV exposes Prometheus-compatible metrics at `/metrics`:

#### Performance Metrics
- `apex_ops_total{op="get|put|del"}` - Operation counts
- `apex_latency_us{op="get|put",quantile="0.5|0.99"}` - Latency percentiles
- `apex_connections_accepted` / `apex_connections_closed` - Connection stats

#### Raft Consensus
- `apex_raft_commits_total` - Committed log entries
- `apex_raft_elections_total` - Leader elections
- `apex_raft_term` - Current Raft term

#### Gossip Protocol
- `apex_gossip_members{state="alive|suspect|dead"}` - Cluster membership

#### System Resources
- `apex_wal_size_bytes` - WAL file size
- `apex_active_tokens` - Active authentication tokens

### Recommended Alerts

```yaml
# Prometheus alerting rules
groups:
  - name: apex-kv
    rules:
      - alert: ApexKVNodeDown
        expr: up{job="apex-kv"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "APEX-KV node {{ $labels.instance }} is down"

      - alert: ApexKVHighLatency
        expr: histogram_quantile(0.99, rate(apex_latency_us_bucket[5m])) > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High p99 latency on {{ $labels.instance }}"

      - alert: ApexKVFrequentElections
        expr: increase(apex_raft_elections_total[1h]) > 3
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Frequent leader elections detected"

      - alert: ApexKVWALGrowing
        expr: rate(apex_wal_size_bytes[1h]) > 1048576
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "WAL size growing rapidly"

      - alert: ApexKVQuorumLost
        expr: sum(apex_gossip_members{state="alive"}) < (count(apex_gossip_members) / 2 + 1)
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Cluster has lost quorum"
```

### Dashboard Panels

Recommended Grafana dashboard panels:
1. Operations per second (GET/PUT/DEL)
2. Latency heatmap (p50, p95, p99)
3. Raft leader changes over time
4. Cluster membership status
5. WAL size trend
6. Error rates by type

---

## Backup & Recovery

### WAL Snapshotting

APEX-KV supports automatic WAL compaction via snapshots:

```cpp
// Create snapshot through index N
wal.create_snapshot("/path/to/snapshot", through_index);

// Compact WAL (removes entries before snapshot)
wal.compact_before(compaction_index);
```

### Manual Backup Procedure

1. **Stop writes** (optional but recommended for consistency):
   ```bash
   # Pause the node or redirect traffic
   apex-cli pause --node node1
   ```

2. **Copy WAL files**:
   ```bash
   rsync -av /var/lib/apex-kv/wal/ backup-server:/backups/apex-kv/wal-$(date +%Y%m%d-%H%M%S)/
   ```

3. **Copy snapshots**:
   ```bash
   rsync -av /var/lib/apex-kv/snapshots/ backup-server:/backups/apex-kv/snapshots/
   ```

4. **Verify backup integrity**:
   ```bash
   # Check file checksums
   sha256sum /backups/apex-kv/wal-*/*.wal > checksums.txt
   ```

### Recovery from Backup

1. **Stop the node**:
   ```bash
   systemctl stop apex-kv
   ```

2. **Restore WAL and snapshots**:
   ```bash
   rsync -av backup-server:/backups/apex-kv/wal-latest/ /var/lib/apex-kv/wal/
   rsync -av backup-server:/backups/apex-kv/snapshots/ /var/lib/apex-kv/snapshots/
   ```

3. **Start the node**:
   ```bash
   systemctl start apex-kv
   ```

4. **Verify data integrity**:
   ```bash
   apex-cli check-integrity --node node1
   ```

### Disaster Recovery

**Scenario: Complete cluster loss**

1. Restore the node with the most recent data first
2. Start it as a single-node cluster
3. Add other nodes one by one using peer addition
4. Verify replication and data consistency

```bash
# Start first node (no peers initially)
apex-kv --id 1 --host 192.168.1.10 --port 9000 --single-node

# After first node is stable, add peers
apex-cli add-peer --from node1 --to 192.168.1.11:9000 --peer-id 2
apex-cli add-peer --from node1 --to 192.168.1.12:9000 --peer-id 3
```

---

## Scaling Operations

### Adding a New Node

1. **Prepare the new node**:
   ```bash
   # Install and configure
   apex-kv --id 4 --host 192.168.1.13 --port 9000 \
     --peer 192.168.1.10:9000:1 \
     --peer 192.168.1.11:9000:2 \
     --peer 192.168.1.12:9000:3
   ```

2. **Add to cluster** (from existing leader):
   ```bash
   apex-cli add-peer --leader node1 --new-node 192.168.1.13:9000 --id 4
   ```

3. **Wait for synchronization**:
   ```bash
   # Monitor replication progress
   watch 'apex-cli status --node 4 | grep -i sync'
   ```

4. **Update client configurations** to include the new node

### Removing a Node

1. **Drain connections**:
   ```bash
   apex-cli drain --node node4
   ```

2. **Transfer leadership** (if removing leader):
   ```bash
   apex-cli transfer-leadership --from node4 --to node1
   ```

3. **Remove from cluster**:
   ```bash
   apex-cli remove-peer --from node1 --target node4
   ```

4. **Stop the node**:
   ```bash
   systemctl stop apex-kv-node4
   ```

### Rebalancing Data

APEX-KV uses consistent hashing for automatic data distribution. After adding/removing nodes:

```bash
# Trigger rebalance
apex-cli rebalance --cluster

# Monitor progress
apex-cli rebalance-status
```

---

## Incident Response

### Node Unreachable

**Symptoms**: Clients report timeouts, metrics show connection failures

**Diagnosis**:
```bash
# Check node status
apex-cli status --node <node_id>

# Check network connectivity
ping <node_ip>
telnet <node_ip> 9000

# Check logs
journalctl -u apex-kv -n 100 --no-pager
```

**Resolution**:
1. If network issue: fix networking
2. If process crashed: restart node
3. If data corruption: restore from backup

### Leader Election Storm

**Symptoms**: High `apex_raft_elections_total`, frequent write failures

**Diagnosis**:
```bash
# Check election frequency
promtool query 'rate(apex_raft_elections_total[5m])'

# Check network latency between nodes
ping -c 10 <peer_ips>

# Check disk I/O latency
iostat -x 1 5
```

**Resolution**:
1. Identify and fix network partitions
2. Reduce election timeout if network is stable
3. Check disk performance (slow fsync causes elections)
4. Consider increasing heartbeat frequency

### Split Brain

**Symptoms**: Multiple leaders, inconsistent reads

**Diagnosis**:
```bash
# Check leader on each node
for node in 1 2 3; do
  apex-cli get-leader --node $node
done
```

**Resolution**:
1. Identify minority partition
2. Stop nodes in minority partition
3. Restore quorum in majority partition
4. Restart minority nodes after network healed
5. Verify data consistency

### High Latency

**Symptoms**: p99 latency > 10ms, client timeouts

**Diagnosis**:
```bash
# Check system resources
top -bn1 | head -20
free -h
iostat -x 1 3

# Check WAL performance
apex-cli wal-stats --node <node_id>

# Profile slow operations
apex-cli profile --node <node_id> --duration 60
```

**Resolution**:
1. If CPU bound: scale horizontally
2. If I/O bound: upgrade to faster storage
3. If memory pressure: increase RAM or reduce working set
4. Check for GC pauses or context switching

---

## Maintenance Procedures

### Rolling Upgrades

1. **Prepare**:
   - Test new version in staging
   - Create full backup
   - Schedule maintenance window

2. **Upgrade nodes one by one**:
   ```bash
   for node in node1 node2 node3; do
     # Drain connections
     apex-cli drain --node $node
     
     # Wait for leadership transfer if needed
     apex-cli wait-no-leader --node $node
     
     # Stop old version
     systemctl stop apex-kv
     
     # Deploy new version
     deploy-apex-kv-new-version.sh
     
     # Start new version
     systemctl start apex-kv
     
     # Verify health
     apex-cli health-check --node $node
     
     # Wait before next node
     sleep 300
   done
   ```

3. **Post-upgrade verification**:
   ```bash
   # Check cluster health
   apex-cli cluster-status
   
   # Run smoke tests
   apex-cli smoke-test --cluster
   
   # Compare metrics before/after
   ```

### WAL Compaction

Schedule regular WAL compaction to prevent unbounded growth:

```bash
#!/bin/bash
# cron: 0 3 * * * /usr/local/bin/apex-compact.sh

NODE_ID=1
THRESHOLD_BYTES=$((1024 * 1024 * 1024))  # 1GB

CURRENT_SIZE=$(apex-cli wal-size --node $NODE_ID)

if [ "$CURRENT_SIZE" -gt "$THRESHOLD_BYTES" ]; then
  LAST_INDEX=$(apex-cli last-index --node $NODE_ID)
  COMPACT_INDEX=$((LAST_INDEX - 10000))  # Keep last 10k entries
  
  apex-cli compact --node $NODE_ID --through $COMPACT_INDEX
  
  # Verify compaction
  NEW_SIZE=$(apex-cli wal-size --node $NODE_ID)
  if [ "$NEW_SIZE" -lt "$CURRENT_SIZE" ]; then
    echo "Compaction successful: $CURRENT_SIZE -> $NEW_SIZE bytes"
  else
    echo "Compaction failed!" >&2
    exit 1
  fi
fi
```

### Certificate Rotation

For mTLS certificate renewal:

1. **Generate new certificates** (before expiry):
   ```bash
   openssl req -new -key node.key -out node.csr
   # Submit CSR to CA
   # Receive new node.crt
   ```

2. **Deploy new certificate** (rolling):
   ```bash
   for node in node1 node2 node3; do
     # Copy new cert
     scp node.crt node.key $node:/etc/apex-kv/certs/
     
     # Reload (no restart needed)
     ssh $node 'systemctl reload apex-kv'
     
     # Verify
     apex-cli tls-check --node $node
   done
   ```

3. **Revoke old certificates** after all nodes updated

### Token Cleanup

Periodically clean up expired authentication tokens:

```bash
# Daily cleanup cron job
apex-cli auth-cleanup --node all
```

---

## Troubleshooting Guide

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| Port already in use | "Cannot bind port" error | Check `lsof -i :9000`, kill conflicting process |
| WAL corruption | CRC errors on startup | Restore from snapshot or backup |
| Peer connection refused | Connection errors in logs | Check firewall, verify peer addresses |
| Slow fsync | High PUT latency | Upgrade storage, adjust durability mode |
| Certificate expired | TLS handshake failures | Rotate certificates immediately |

### Debug Commands

```bash
# Enable debug logging
apex-cli set-log-level --node all --level debug

# Dump internal state
apex-cli dump-state --node <node_id> --output state.json

# Trace a request
apex-cli trace-request --node <node_id> --request-id <id>

# Check Raft log
apex-cli raft-log --node <node_id> --from <index> --limit 100
```

### Getting Help

- Documentation: `/docs` directory
- GitHub Issues: https://github.com/apex-kv/apex-kv/issues
- Community Slack: #apex-kv-users

---

*Last updated: 2024*
*Version: 1.0.0*
