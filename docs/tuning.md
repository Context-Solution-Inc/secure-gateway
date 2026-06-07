# Kernel & ulimit tuning (PRD §9.2)

The relay holds tens of thousands of mostly-idle TCP connections per instance
(target ≥ 50k / 4 GB·2 vCPU — see [capacity.md](capacity.md)). The Linux
defaults exhaust file descriptors, the accept backlog, and ephemeral ports long
before that. Apply the settings below on any host running the relay at scale.

There are two layers:

1. **Per-container, network-namespaced sysctls** — already set on the relay
   service in `docker-compose.yml` and in the Kubernetes pod spec
   (`deploy/k8s/relay-deployment.yaml`). Safe to set without host privileges.
2. **Host-level knobs** — not namespaced; must be set on the host (or the node),
   not per-container.

## File descriptors (nofile)

Each connection is one fd. Raise the soft/hard limit above the per-instance
connection target plus headroom.

- Container: `ulimits.nofile` is set to 1048576 in compose; the Kubernetes spec
  documents the same via the container runtime / node config.
- Host (systemd unit): `LimitNOFILE=1048576` (set in
  `deploy/systemd/*.service` if you deploy via systemd).
- Host-wide cap: `fs.file-max` must be ≥ the sum across all processes:

  ```
  # /etc/sysctl.d/90-relay.conf
  fs.file-max = 2097152
  ```

## Network-namespaced sysctls (per-container — already applied)

Set on the relay container in compose / k8s:

```
net.core.somaxconn          = 65535     # accept() backlog (listen queue)
net.ipv4.tcp_max_syn_backlog = 65535    # half-open (SYN) queue
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse        = 1        # reuse TIME_WAIT sockets for outbound
```

`somaxconn` / `tcp_max_syn_backlog` matter most during a **reconnect storm**
(a whole instance's clients reconnecting at once); too small and SYNs are
dropped, lengthening recovery past the §10.1 ≤ 60s budget.

## Host-level sysctls (set on the host/node)

These are **not** network-namespaced and cannot be set per-container; put them in
`/etc/sysctl.d/90-relay.conf` on the host (or via a node DaemonSet / privileged
init container in Kubernetes — see the note in `deploy/k8s/relay-deployment.yaml`):

```
# /etc/sysctl.d/90-relay.conf
fs.file-max = 2097152

# Socket buffer ceilings (bytes). Idle WS connections need little, but raising
# the max lets the autotuner grow buffers under load without manual per-socket sizing.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Connection tracking table (only if a stateful firewall/conntrack is in path).
net.netfilter.nf_conntrack_max = 1048576

# Redis prints a startup WARNING without this; it lets a background save /
# replication fork succeed under memory pressure. It is a global (non-namespaced)
# kernel param, so it CANNOT be set per-container — it must live here on the host.
# (Our co-located Redis runs with persistence disabled, so this is best-practice
# rather than strictly required, but it silences the warning and is safe.)
vm.overcommit_memory = 1
```

Apply with:

```
sudo sysctl --system        # reload /etc/sysctl.d/*
ulimit -n                    # verify the process limit in the relay's shell/unit
```

## Verifying

During a load/soak run, watch the relay's `/metrics`:

- `relay_fd_used` / `relay_fd_limit` — fd headroom (alerts fire at >80%).
- `rate(relay_connects_total[1m])` — reconnect-storm rate; if SYN/accept queues
  are too small you'll see connect failures (client-side dial errors) here.

See [capacity.md](capacity.md) for the full-scale run procedure.
