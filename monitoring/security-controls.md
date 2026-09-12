# CPS Range Security Controls — Version 2

## Safety model

Version 2 is a **local research simulator**, not a guarantee of complete isolation. Keep it on a dedicated lab host, do not connect it to production networks or devices, and review the active Compose profile before starting it.

- Published ports bind to `127.0.0.1` by default.
- The standard, closed, enhanced, laptop, and monitoring defaults use bridge networks.
- Default services do not use host networking, privileged mode, `NET_ADMIN`, or `NET_RAW`.
- The normal `suricata-ids` service performs configuration validation only (`suricata -T`); it does not capture packets.
- Live packet capture is excluded unless the operator explicitly enables the `dangerous-packet-capture` profile.
- Non-loopback Modbus access requires `--allow-external-modbus` and may read from and write to the target device.

## Access and credentials

All published service ports are loopback-only. Set a unique Grafana password before sharing a host or captured output:

```bash
export GRAFANA_ADMIN_PASSWORD='replace-with-a-strong-password'
```

The simulated SSH account is intentionally weak training data. Never reuse its credentials elsewhere.

## Safe profiles

### Standard four-service range

```bash
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml down
```

### Closed four-service range

```bash
docker compose -f monitoring/docker-compose-closed.yml up -d
docker compose -f monitoring/docker-compose-closed.yml down
```

### Enhanced range with monitoring and offline IDS validation

```bash
docker compose -f monitoring/docker-compose-enhanced.yml up -d
docker compose -f monitoring/docker-compose-enhanced.yml ps
docker compose -f monitoring/docker-compose-enhanced.yml down
```

### Laptop profile

```bash
docker compose -f monitoring/laptop-optimization.yml up -d
docker stats --no-stream
docker compose -f monitoring/laptop-optimization.yml down
```

## Verification

Confirm published ports are loopback-bound:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml ps
docker port gw_dmz_01
docker port hist_data_01
docker port cps_grafana
docker port cps_prometheus
```

Inspect service logs:

```bash
docker logs gw_dmz_01
docker logs hist_data_01
docker logs hmi_ops_01
docker logs plc_industrial_01
docker logs cps_suricata_ids
```

The one-shot IDS validator should exit successfully after checking the shipped configuration:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml run --rm suricata-ids
```

## Explicit live-capture mode

Only on a dedicated, isolated lab host, review the Compose file and then opt in explicitly:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture up -d suricata-live
```

This mode adds packet-capture capabilities and is not part of the safe default. Stop it with:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture down
```

## Emergency stop and cleanup

Stop only this project's profiles first:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture down
docker compose -f monitoring/laptop-optimization.yml down
docker compose -f monitoring/docker-compose-closed.yml down
docker compose -f docker-compose.yml down
```

Do not use system-wide prune or process-kill commands unless you understand their effect on unrelated Docker workloads.

## Operating rules

1. Use synthetic data only.
2. Never target production systems.
3. Keep external Modbus mode disabled unless the endpoint is an authorized lab device.
4. Keep live capture disabled unless the host and network are deliberately isolated.
5. Review container images and configuration changes before each run.
6. Remove old logs, packet captures, and exported datasets according to your research data policy.
