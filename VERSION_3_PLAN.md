# Version 3 Plan — Multi-Architecture Autonomous CPS Range

## Purpose

Version 3 will turn the current four-asset cyber range into a scenario-driven research platform. It will support five distinct deployment architectures, each with its own storyline, system topology, attacker objectives, defender objectives, and measurable outcomes. Drone activity will be represented only through software-in-the-loop simulation inside an isolated lab; the project will not provide real-world targeting, weaponization, radio jamming, or uncontrolled flight capabilities.

## Design principles

1. **Safe by default:** all scenarios start in deterministic simulation mode with loopback-only services and no physical interfaces.
2. **Architecture as data:** topology, roles, events, objectives, and scoring live in versioned scenario manifests rather than hard-coded branches.
3. **Reproducible storylines:** seeded runs produce comparable results and export an event timeline, topology snapshot, metrics, and evidence bundle.
4. **Defender-first evaluation:** every attack event must map to preventive, detective, responsive, and recovery controls.
5. **Composable agents:** scripted baselines and LLM/neural agents share the same observation/action contracts.
6. **No silent escalation:** physical devices, external endpoints, live capture, and drone hardware adapters require separate opt-in gates and explicit operator confirmation.

## Shared Version 3 platform

All five architectures will use a common scenario engine:

- `ScenarioManifest` schema for topology, storyline phases, assets, trust zones, agents, safety policy, and scoring.
- Architecture plug-in interface with lifecycle hooks for build, validate, start, observe, stop, and export.
- Event bus for simulated telemetry, alerts, attacker actions, defender actions, mission events, and ground truth.
- Policy engine that rejects actions outside the scenario allowlist.
- Digital-twin adapters for the existing tank process plus software-in-the-loop drones.
- Deterministic scripted red/blue baselines for regression testing before optional LLM or neural control.
- Unified evidence export: JSON timeline, CSV metrics, topology JSON, optional synthetic PCAP, and after-action report.
- Scenario scoring across safety impact, mission continuity, detection time, containment time, recovery time, false positives, and agent cost.

## Architecture 1 — Centralized Mission-Control Range

**Pattern:** hub-and-spoke command center with a central mission API, drone simulator, CPS process, identity service, SIEM, and segmented IT/DMZ/OT/drone networks.

**Storyline: “Compromised Inspection Dispatch.”** A simulated maintenance account is phished. The attacker attempts to alter a virtual inspection-drone route, pivot through the mission API, and suppress process alarms while a tank-level anomaly develops.

**Defender mission:** detect abnormal identity use, prevent unauthorized route changes, isolate the mission service, preserve the tank safety envelope, and restore a trusted mission plan.

**Research focus:** centralized policy enforcement, identity-aware segmentation, command authorization, correlated cyber/physical alerts, and rapid rollback.

**Acceptance measures:** no unsafe tank state; unauthorized route command blocked or contained; complete cross-domain timeline; mean detection and recovery times reported.

## Architecture 2 — Decentralized Drone-Swarm Range

**Pattern:** peer-to-peer virtual drone swarm with local consensus, distributed task assignment, mesh telemetry, an edge observer, and no continuously available central controller.

**Storyline: “Rogue Swarm Member.”** One simulated drone identity is cloned and sends conflicting position and task messages. The adversary tries to split consensus, create a false inspection result, and overload peer communications.

**Defender mission:** identify the Byzantine participant, preserve quorum, quarantine untrusted messages, maintain minimum mission coverage, and reconstruct trustworthy observations.

**Research focus:** distributed trust, resilient consensus, peer reputation, signed telemetry, graceful degradation, and swarm-level anomaly detection.

**Acceptance measures:** quorum remains available; malicious peer is attributed; mission coverage stays above a configured threshold; no control action crosses the simulation boundary.

## Architecture 3 — Hierarchical Edge–Cloud Range

**Pattern:** local drone/CPS edge gateway, regional operations tier, cloud analytics tier, zero-trust service identities, and intermittent wide-area connectivity.

**Storyline: “Edge Gateway Under Pressure.”** During a simulated storm inspection, the edge gateway receives crafted telemetry and loses its cloud link. The attacker attempts command injection and data exfiltration while defenders must continue safe local operations.

**Defender mission:** validate command provenance, switch to an offline-safe policy, protect sensitive imagery metadata, retain evidence locally, and reconcile state after connectivity returns.

**Research focus:** edge autonomy, disconnected operation, policy synchronization, service identity, data minimization, and cloud/edge recovery.

**Acceptance measures:** local safety controls remain available during disconnection; injected commands are rejected; buffered evidence reconciles without duplicate actions; recovery is deterministic.

## Architecture 4 — Federated Multi-Site Range

**Pattern:** two independently administered cyber ranges sharing selected indicators and model updates through a federation gateway. Each site has its own CPS process, simulated drone mission, policies, and audit trail.

**Storyline: “Poisoned Coalition Update.”** A partner site distributes a compromised anomaly-model update just before coordinated virtual drone inspections. The update attempts to hide a process anomaly and spread through federation trust.

**Defender mission:** verify model provenance, detect behavioral drift, stop unsafe propagation, preserve site autonomy, share a minimal incident indicator, and roll back affected models.

**Research focus:** federated learning security, software/model supply chain, cross-site trust, privacy-preserving coordination, and blast-radius control.

**Acceptance measures:** untrusted update is quarantined; unaffected site remains operational; rollback is auditable; shared indicators reveal no disallowed site data.

## Architecture 5 — Event-Driven Autonomous-Resilience Range

**Pattern:** loosely coupled services and agents coordinated through a durable event bus, with policy-as-code, workflow orchestration, digital twins, and independent recovery controllers.

**Storyline: “Coordinated Air-and-Ground Disruption.”** Simulated drone telemetry deception coincides with a network intrusion against the tank-control environment. Attack events are staged and non-destructive, but they force defenders to distinguish distraction from the safety-critical path.

**Defender mission:** correlate events across domains, prioritize physical safety, contain compromised identities, re-plan the virtual drone mission, recover services, and explain every autonomous response.

**Research focus:** event correlation, autonomous response guardrails, multi-agent coordination, causal timelines, explainability, and recovery orchestration.

**Acceptance measures:** safety policy always overrides mission optimization; response actions are explainable and reversible; event replay reproduces the decision sequence; recovery objectives are met.

## Scenario lifecycle

Each storyline will use six phases:

1. **Baseline:** establish healthy telemetry, identities, topology, and mission state.
2. **Foothold:** introduce a controlled simulated compromise signal.
3. **Escalation:** expose architecture-specific attack events within the allowlist.
4. **Safety challenge:** combine cyber observations with a bounded digital-twin disturbance.
5. **Containment and recovery:** let defenders isolate, restore, and verify services.
6. **After-action review:** export evidence, score outcomes, and compare scripted, LLM, and neural policies.

## Delivery milestones

### Milestone 1 — V3 foundations

- Define and validate the scenario-manifest schema.
- Add architecture and adapter plug-in contracts.
- Implement seeded event replay and evidence bundles.
- Create safety-policy tests that prove external interfaces remain disabled by default.

### Milestone 2 — Centralized and swarm prototypes

- Deliver Architectures 1 and 2 with scripted red/blue baselines.
- Add software-in-the-loop drone state, mission, and telemetry models.
- Extend the topology viewer for moving assets, trust relationships, and storyline phases.

### Milestone 3 — Edge–cloud and federation

- Deliver Architectures 3 and 4.
- Add disconnected-operation tests, model-signing fixtures, rollback, and federation audit trails.
- Add privacy and provenance metrics.

### Milestone 4 — Autonomous resilience

- Deliver Architecture 5 and cross-domain event correlation.
- Add response guardrails, reversible workflows, causal replay, and explanation export.
- Run comparative scripted/LLM/neural evaluations.

### Milestone 5 — V3 release candidate

- Threat-model review for every architecture.
- Full compatibility, performance, deterministic-replay, and safety regression suite.
- Operator guides, migration notes, example evidence bundles, and release checklist.

## Testing and release gates

Version 3 is releasable only when:

- every scenario passes schema and topology validation;
- identical seeds reproduce equivalent timelines and scores;
- scripted baseline agents complete all five storylines without external network or hardware access;
- denied actions are recorded with policy reasons;
- drone simulations cannot address real flight controllers in the default build;
- Compose, Suricata, Python, viewer, and dependency checks pass;
- each architecture has at least one prevention, detection, response, and recovery assertion;
- after-action reports identify architecture, seed, agent policy, safety decisions, and final state;
- documentation clearly separates simulation adapters from any future reviewed hardware-in-the-loop extension.

## Proposed repository layout

```text
architectures/
  centralized-mission-control/
  decentralized-swarm/
  edge-cloud/
  federated-multi-site/
  event-driven-resilience/
scenarios/
  compromised-inspection-dispatch/
  rogue-swarm-member/
  edge-gateway-under-pressure/
  poisoned-coalition-update/
  coordinated-air-ground-disruption/
schemas/
  scenario-manifest.schema.json
src/
  scenario_engine/
  architecture_plugins/
  safety_policy/
  evidence/
tests/
  architectures/
  scenarios/
  safety/
```

## Out of scope for Version 3

- real-world drone targeting or weapon payloads;
- radio-frequency jamming or interference instructions;
- autonomous connection to public or third-party systems;
- default support for physical flight controllers;
- destructive actions against real infrastructure;
- claims that simulation results alone prove production safety.
