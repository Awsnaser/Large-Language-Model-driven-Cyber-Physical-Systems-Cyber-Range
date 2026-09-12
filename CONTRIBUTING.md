# Contributing — Version 2.0.0

Contributions are welcome. Keep changes focused, testable, and consistent with the Version 2 safety model.

## Development setup

```bash
git clone <repository-url>
cd llm-cps-cyber-range
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Install optional neural dependencies only when working on that subsystem:

```bash
python -m pip install -r requirements-neural.txt
```

Use the canonical CLI in examples and tests:

```bash
python cyberrange.py --no-docker-up --scripted-agents --rounds 10
python cyberrange.py --version
pytest -q
```

The historical `python cyberrange_all_in_one.py` command is a supported compatibility wrapper, not the target for new documentation or entry-point work.

## Change guidelines

1. Create a focused branch and explain the user-facing effect in the pull request.
2. Add or update tests for behavior changes. Run `pytest -q` before submission.
3. Keep the core simulator usable with only `requirements.txt`. Guard Torch-dependent work as optional.
4. Keep CLI documentation accurate: Version 2 accepts only `deep_feedforward` and `deep` for `--neural-arch`; do not present unsupported architectures or `--neuroevolution` as working runner options.
5. Update root documentation when commands, profiles, requirements, or safety behavior changes.
6. Do not silently turn symbolic/simulated behavior into real-world activity.

## Safety-sensitive changes

The normal Compose service set is safe by default: no host networking, privileged containers, or packet-capture capabilities, and Compose-published management ports bind to loopback. Preserve these defaults.

- The regular `suricata-ids` service is a one-shot `-T` configuration-validation job, not a live IDS service.
- Live capture belongs only in the explicit `dangerous-packet-capture` profile in `monitoring/docker-compose-enhanced.yml`. Changes to it require clear documentation of traffic scope, requested capabilities, and isolated-lab use.
- `--real-modbus` can read/write an endpoint. Preserve the non-loopback acknowledgement guard and test it when touching that path.
- Do not claim complete isolation, automatic packet capture, host-wide monitoring, or unsupported credentials.

When changing a Compose file, validate it and check the relevant services:

```bash
docker compose -f <compose-file> config -q
docker compose -f monitoring/docker-compose-enhanced.yml up -d
docker compose -f monitoring/docker-compose-enhanced.yml ps
```

A successfully exited `suricata-ids` job validates configuration syntax only. It does not demonstrate capture or detection.

## Tests and quality checks

```bash
pytest -q

# Optional topology viewer checks
cd topology-viewer
npm install
npm run typecheck
npm test
npm run build
```

For Docker-dependent validation, also confirm a running engine with `docker info`. Avoid committing generated exports, logs, local environments, node modules, or credentials.

## Pull request checklist

- [ ] Change is scoped and documented.
- [ ] `pytest -q` passes (or skipped optional-neural tests are explained).
- [ ] Relevant Compose file passes `docker compose -f <file> config -q`.
- [ ] Normal profiles remain safe by default.
- [ ] Any live-capture or Modbus behavior has explicit opt-in, reviewable documentation.
- [ ] CLI examples use `python cyberrange.py`.
