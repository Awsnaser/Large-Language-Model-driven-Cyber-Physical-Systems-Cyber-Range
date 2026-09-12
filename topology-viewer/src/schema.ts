import { AssetInfo, Criticality, RoundData, SimulationData, SubnetInfo } from './types';

const ZONE_COLORS: Record<string, string> = {
  IT: '#4c78a8',
  DMZ: '#f58518',
  OT: '#54a24b',
  SCADA: '#e45756',
  CLOUD: '#72b7b2',
};

export const DEFAULT_SUBNET = 'Unassigned';
export const DEFAULT_CRITICALITY: Criticality = 'MEDIUM';

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value.trim() || fallback;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function bool(value: unknown, fallback = false): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function normalizeCriticality(value: unknown): Criticality {
  const normalized = text(value).toUpperCase();
  return normalized === 'HIGH' || normalized === 'MEDIUM' || normalized === 'LOW'
    ? normalized
    : DEFAULT_CRITICALITY;
}

function colorForZone(zone: string): string {
  return ZONE_COLORS[zone.toUpperCase()] ?? '#64748b';
}

function normalizeAsset(value: unknown, index: number, usedIds: Set<string>): AssetInfo | null {
  if (!isRecord(value)) return null;
  const proposedId = text(value.asset_id, `asset-${index + 1}`);
  let assetId = proposedId;
  let suffix = 2;
  while (usedIds.has(assetId)) assetId = `${proposedId}-${suffix++}`;
  usedIds.add(assetId);

  const zone = text(value.zone, 'Unknown');
  const subnet = text(value.subnet, text(value.network, zone || DEFAULT_SUBNET));
  const services = asArray(value.services).map((service) => text(service)).filter(Boolean);

  return {
    asset_id: assetId,
    zone,
    kind: text(value.kind, 'unknown'),
    ip: text(value.ip),
    subnet: subnet || DEFAULT_SUBNET,
    criticality: normalizeCriticality(value.criticality),
    compromised: bool(value.compromised),
    privilege: text(value.privilege, 'NONE'),
    services,
  };
}

function normalizeSubnet(value: unknown): SubnetInfo | null {
  if (!isRecord(value)) return null;
  const name = text(value.name);
  if (!name) return null;
  const zone = text(value.zone, 'Unknown');
  return {
    name,
    zone,
    cidr: text(value.cidr),
    color: text(value.color, colorForZone(zone)),
    asset_count: Math.max(0, Math.floor(numberValue(value.asset_count, numberValue(value.count, 0)))),
  };
}

function normalizeRound(value: unknown, index: number): RoundData | null {
  if (!isRecord(value)) return null;
  return {
    round: Math.max(0, Math.floor(numberValue(value.round, index + 1))),
    red_action: text(value.red_action, 'NONE'),
    red_target: text(value.red_target, 'NONE'),
    red_result: text(value.red_result),
    blue_action: text(value.blue_action, 'NONE'),
    blue_target: text(value.blue_target, 'NONE'),
    blue_result: text(value.blue_result),
    tank_level: numberValue(value.tank_level, 50),
    alerts_total: Math.max(0, Math.floor(numberValue(value.alerts_total))),
    compromised_count: Math.max(0, Math.floor(numberValue(value.compromised_count))),
    attacker_zone: text(value.attacker_zone, 'Unknown'),
    alarm_flag: numberValue(value.alarm_flag),
    damage_flag: numberValue(value.damage_flag),
    gp_p_alarm: numberValue(value.gp_p_alarm),
    gp_p_damage: numberValue(value.gp_p_damage),
    policy_choice: text(value.policy_choice),
  };
}

function assetSource(input: unknown): JsonRecord | null {
  return isRecord(input) ? input : null;
}

/**
 * Converts both the full simulation export and lightweight asset exports into
 * the viewer's complete, safe model. A bare asset array is also accepted.
 */
export function normalizeSimulationData(input: unknown): SimulationData {
  const source = assetSource(input);
  const rawAssets = Array.isArray(input)
    ? input
    : source && 'asset_id' in source
      ? [source]
      : asArray(source?.assets ?? source?.topology_assets);
  const usedIds = new Set<string>();
  const assets = rawAssets
    .map((asset, index) => normalizeAsset(asset, index, usedIds))
    .filter((asset): asset is AssetInfo => asset !== null);

  const subnetByName = new Map<string, SubnetInfo>();
  for (const rawSubnet of asArray(source?.subnets)) {
    const subnet = normalizeSubnet(rawSubnet);
    if (subnet) subnetByName.set(subnet.name, subnet);
  }
  for (const asset of assets) {
    if (!subnetByName.has(asset.subnet)) {
      subnetByName.set(asset.subnet, {
        name: asset.subnet,
        zone: asset.zone,
        cidr: '',
        color: colorForZone(asset.zone),
        asset_count: 0,
      });
    }
  }
  for (const subnet of subnetByName.values()) {
    const actualCount = assets.filter((asset) => asset.subnet === subnet.name).length;
    // Exported count can describe an empty subnet, but never let it understate loaded assets.
    subnet.asset_count = Math.max(subnet.asset_count, actualCount);
  }

  const links: [string, string][] = [];
  for (const candidate of asArray(source?.subnet_links)) {
    if (!Array.isArray(candidate) || candidate.length < 2) continue;
    const from = text(candidate[0]);
    const to = text(candidate[1]);
    if (from && to) links.push([from, to]);
  }

  const rounds = asArray(source?.rounds)
    .map((round, index) => normalizeRound(round, index))
    .filter((round): round is RoundData => round !== null);

  return {
    assets,
    subnets: [...subnetByName.values()],
    subnet_links: links,
    rounds,
    total_ips: Math.max(assets.length, Math.floor(numberValue(source?.total_ips, assets.length))),
  };
}
