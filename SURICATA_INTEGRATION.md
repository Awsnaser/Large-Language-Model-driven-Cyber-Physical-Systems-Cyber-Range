# Suricata integration — Version 2.0.0

Version 2 separates safe Suricata configuration validation from live packet capture.

## Safe default: configuration validation

The `suricata-ids` service in `monitoring/docker-compose-enhanced.yml` and `monitoring/laptop-optimization.yml` uses the pinned image `jasonish/suricata:7.0.11` and runs:

```bash
suricata -T -c /etc/suricata/suricata.yaml
```

It mounts these read-only project files:

```text
configs/suricata/suricata.yaml
configs/suricata/custom-cps.rules
```

The service needs no capture capabilities and exits after checking the configuration. It does **not** monitor traffic, create a live alert stream, or automatically capture packets.

Run and check the safe enhanced stack:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml config -q
docker compose -f monitoring/docker-compose-enhanced.yml up -d
docker compose -f monitoring/docker-compose-enhanced.yml ps suricata-ids
```

A zero exit status from `suricata-ids` means the shipped configuration passed its Suricata validation. It is not evidence that an interface is being observed or that a rule will detect a scenario. Treat nonzero status as a configuration/runtime validation failure and inspect the job logs:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml logs suricata-ids
```

The laptop file offers the same offline validation behavior with resource limits. `monitoring/docker-compose-closed.yml` is a four-service closed range and does not add a Suricata service.

## Explicit live capture: isolated lab only

Live capture exists only as `suricata-live` in the enhanced Compose file. It is behind the named `dangerous-packet-capture` profile and is not selected by a normal `docker compose up` or any normal `cyberrange.py` command.

```bash
# Perform this only on an isolated lab host after reviewing Docker access,
# interfaces, traffic scope, storage, and applicable policy.
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture up -d
```

`suricata-live` runs on its Compose bridge network, not host networking, and explicitly requests `NET_ADMIN` and `NET_RAW`. Those capabilities are why it is opt-in. Stop it with:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture down -v
```

Do not treat this profile as a production IDS deployment, a complete isolation boundary, or host-wide capture.

## Related monitoring

Prometheus and Grafana are separate Compose services. Their published Compose ports bind to `127.0.0.1`. Configure Grafana before startup:

```bash
export GRAFANA_ADMIN_PASSWORD='use-a-unique-local-password'
```

The configured Grafana user is `admin`; `admin/admin` is not a supported default. The Python runner's optional `--metrics` endpoint is host-side and should be reviewed separately for exposure.

## Troubleshooting checklist

1. Confirm Docker Engine and Compose v2: `docker info` and `docker compose version`.
2. Validate the rendered file: `docker compose -f monitoring/docker-compose-enhanced.yml config -q`.
3. Check the one-shot validation job logs and exit state, not an assumed long-running IDS container.
4. Verify the mounted rule/config paths are the Version 2 paths above.
5. Enable `dangerous-packet-capture` only when live bridge-interface capture is deliberately required and authorized.
