# Changelog

All notable changes are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- Clarified the Version 2 entry point, safe Compose profiles, Suricata validation versus opt-in live capture, optional neural behavior, and runtime validation requirements.

## [2.0.0]

### Added
- `cyberrange.py` as the canonical Version 2 entry point and `cps-cyberrange` console script.
- A safe-by-default four-asset CPS range with standard, closed, laptop, and enhanced Compose definitions.
- A safe Suricata `-T` configuration-validation service using the shipped CPS rules.
- An explicit `dangerous-packet-capture` profile for the separate `suricata-live` service.
- Optional Torch-based multi-agent support, multi-output GP risk modeling, safe active probes, monitoring integration, and topology JSON export/viewing.

### Changed
- The historical `python cyberrange_all_in_one.py` filename now delegates to the Version 2 implementation.
- Normal Compose service definitions avoid host networking, privileged mode, and packet-capture capabilities; published Compose management ports bind to loopback.
- The integrated neural CLI limits decision architecture selection to `deep_feedforward` and `deep`.

### Safety notes
- Live packet capture is never started by normal profiles.
- `--real-modbus` refuses non-loopback targets unless `--allow-external-modbus` is explicitly supplied.
- A successful Suricata validation job confirms configuration validation only; it is not live detection.

## [1.5.0]

### Added
- Large-scale topology generation, animation, benchmark output, and the topology viewer workflow.

## [1.4.0]

### Added
- Docker-based CPS simulation, LLM red/blue gameplay, and monitoring-oriented simulation features.

## [1.3.0]

### Added
- Scripted red/blue agents and safer process-simulation behavior.

## [1.2.0]

### Added
- Interactive terminal status output and visualization options.

## [1.1.0]

### Added
- Multi-output GP modeling, safe probing, and data export.

## [1.0.0]

### Added
- Initial CPS range simulation.
