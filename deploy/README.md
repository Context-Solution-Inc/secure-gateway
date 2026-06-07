# Deployment artifacts

Production deployment, observability, and hardening assets for the Secure Device
Relay (PRD §9.2, §9.3, §10.2).

## Layout

- `k8s/` — Kubernetes manifests for the relay + auth services.
- `prometheus/alerts.yml` — alerting rules (§9.3 signals).
- `grafana/relay-dashboard.json` — dashboard; import and pick a Prometheus source.

Container hardening (distroless/nonroot, digest-pinned base images, read-only
rootfs, dropped caps) lives in the repo-root `Dockerfile` / `Dockerfile.auth`;
local multi-instance + kernel sysctls in `docker-compose.yml`. Host kernel/ulimit
tuning is documented in [../docs/tuning.md](../docs/tuning.md); capacity targets
and the full-scale load procedure in [../docs/capacity.md](../docs/capacity.md).

## Kubernetes

```
# 1. Secrets (template only — fill in real values out-of-band, do not commit).
cp k8s/secrets.example.yaml k8s/secrets.yaml   # edit
go run ../cmd/devtoken -gen-keys -out-dir ./keys -alg ES256
kubectl create secret generic auth-signing-key \
  --from-file=signing.key.json=keys/relay.key.json

# 2. Config + workloads.
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/auth-deployment.yaml -f k8s/relay-deployment.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/pdb-hpa.yaml

# Validate without applying:
kubectl apply --dry-run=client -f k8s/
```

The manifests assume Redis and Postgres are reachable at `redis:6379` /
`postgres:5432` (run your own or a managed instance; they are not included here).

### Hardening applied (mirrors compose)

- `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem`, `allowPrivilegeEscalation:
  false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- Relay requests/limits 2 vCPU / 4 GB (the §10.1 instance); HPA scales on
  memory + CPU; a PDB keeps ≥1 pod during disruptions.
- Signing key mounted read-only from a Secret; no secrets in images/ConfigMaps.
- Namespaced TCP sysctls set in-pod; **unsafe** sysctls (`net.core.somaxconn`,
  `net.ipv4.tcp_max_syn_backlog`) and host-level knobs require node config — see
  [../docs/tuning.md](../docs/tuning.md).

## Prometheus / Grafana

```
promtool check rules prometheus/alerts.yml   # validate the rules
```

Load `prometheus/alerts.yml` into your Prometheus rule_files, and import
`grafana/relay-dashboard.json`. Both services expose `/metrics`; the k8s pods
carry `prometheus.io/scrape` annotations.
