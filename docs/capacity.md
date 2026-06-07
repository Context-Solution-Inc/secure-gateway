# Capacity & performance (PRD §10.1)

This document records the v1 capacity targets, what is asserted automatically vs.
only measured, and the procedure for the full-scale load test that this developer
box cannot host.

## Targets (PRD §10.1)

| Metric | Target | Where validated |
|---|---|---|
| Concurrent connections / 4 GB·2 vCPU instance | ≥ 50,000 | **Documented full run** (below) + 10k idle soak (`make soak`) |
| Added relay latency (frame in→out), p99 | ≤ 50 ms intra-region | CI-asserted: `TestForwardLatencyP99` |
| Token validation overhead, p99 | ≤ 1 ms (local verify) | CI-asserted: `TestTokenVerifyP99` + `BenchmarkTokenVerify` |
| Revocation propagation | ≤ 2 s webhook→socket close | CI-asserted: `TestRevocationPropagation` |
| Reconnect storm | full instance absorbed ≤ 60 s | CI-asserted (scaled): `TestReconnectStorm` |

## What CI asserts (scaled)

`make bench` runs `test/bench/` (build tag `bench`) at a small, CI-friendly
scale and **asserts** the timing targets above with headroom:

```
make bench
```

These are regression guards, not SLA measurements — on a localhost relay the
latency numbers are dominated by loopback + goroutine scheduling, so the
assertions carry generous margin against the §10.1 ceilings. Representative local
results (Intel Core Ultra 9, in-process relay):

- forward latency p99 ≈ 0.2 ms (budget 50 ms)
- token verify p99 ≈ 0.05 ms (budget 1 ms)
- revocation propagation ≈ 0.2 ms (budget 2 s)
- reconnect storm, 2,000 conns ≈ 45 ms (budget 60 s)

Scale up on a larger host via env overrides:

```
make bench LAT_FRAMES=20000 STORM_CONNS=20000
```

## What is only documented (full-scale, not run in CI)

The **≥ 50,000 concurrent connections / instance** target is not run on this
2-vCPU developer box. It is validated the same way the soak harness already works
(`test/soak`, `make soak`): a scaled CI default plus a documented full run.

### Full 50k-connection run

1. Provision a host matching the target: **2 vCPU / 4 GB**, Linux.
2. Apply the kernel/ulimit tuning in [docs/tuning.md](tuning.md) (somaxconn, TCP
   buffers, `nofile`). Without it the box will exhaust ephemeral ports / fds long
   before 50k.
3. Run the soak at full scale (each pair is two connections):

   ```
   make soak SOAK_CONNS=50000 SOAK_DURATION=24h
   ```

   or directly:

   ```
   SOAK_CONNS=50000 SOAK_DURATION=24h \
     go test -tags soak -run TestSoak -timeout 25h -v ./test/soak/
   ```

4. The soak holds the connections idle and asserts no goroutine/heap/fd leak
   (M1 exit criterion). Watch the relay's `/metrics` during the run:
   `relay_connections_active`, `relay_fd_used` / `relay_fd_limit`,
   `relay_forward_latency_seconds`, and `relay_connects_total` (reconnect-storm
   rate via `rate()`).

### Driving load from a separate client host

For a realistic multi-instance run, stand up Redis + ≥2 relay instances via
`docker compose` (see the repo root compose file) and point the soak client at
the load balancer. Each client host is itself limited by ~64k ephemeral ports per
destination IP:port, so use multiple client hosts or multiple relay
listener addresses to exceed ~60k from one client.

## Notes

- Each active user consumes **two** connections (mobile + desktop); capacity
  planning uses connections, not users.
- Go's per-connection cost is two goroutines + buffers; the soak proves this is
  flat over 24h. The 50k target is memory-bound (≈4 GB) more than CPU-bound.
- The latency/verify/revocation assertions are deterministic and run on every
  `make bench`; the 50k figure is the one number that requires real hardware.
