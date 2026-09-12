import { useMemo } from 'react';
import { AssetInfo, RoundData, SubnetInfo } from '../types';
import { computeSubnetLayout, getSubnetBounds } from '../layout';
import { PublicationIcon, resolveAssetIcon } from './PublicationIcons';

interface Props {
  assets: AssetInfo[];
  subnets: SubnetInfo[];
  currentRound: RoundData | null;
  compromisedSet: Set<string>;
  width: number;
  height: number;
  showIPs?: boolean;
  showLabels?: boolean;
  compact?: boolean;
}

export function PublicationTopology({ assets, subnets, currentRound, compromisedSet, width, height, showIPs = true, showLabels = true, compact = false }: Props) {
  const positions = useMemo(() => computeSubnetLayout(assets, subnets, width, height), [assets, subnets, width, height]);
  const subnetByName = useMemo(() => new Map(subnets.map((subnet) => [subnet.name, subnet])), [subnets]);
  const allSubnetNames = useMemo(() => {
    const names = subnets.map((subnet) => subnet.name);
    for (const asset of assets) if (!names.includes(asset.subnet)) names.push(asset.subnet);
    return names;
  }, [assets, subnets]);
  const size = compact ? 10 : 15;

  return (
    <svg aria-label="Publication network topology" width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: 'block', maxWidth: '100%', height: 'auto', background: '#fff', borderRadius: 8, border: '1px solid #334155' }}>
      <defs>
        <pattern id="topology-grid" width="25" height="25" patternUnits="userSpaceOnUse"><path d="M 25 0 L 0 0 0 25" fill="none" stroke="#e5e7eb" strokeWidth="0.5" /></pattern>
        <marker id="attack-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto"><path d="M0,0 L0,7 L7,3.5 z" fill="#dc2626" /></marker>
      </defs>
      <rect width={width} height={height} fill="white" />
      <rect width={width} height={height} fill="url(#topology-grid)" />
      {allSubnetNames.map((name) => {
        const bounds = getSubnetBounds(assets, positions, name);
        if (!bounds) return null;
        const subnet = subnetByName.get(name);
        const color = subnet?.color ?? '#64748b';
        return <g key={name}><rect x={bounds.x} y={bounds.y} width={bounds.w} height={bounds.h} fill={color} opacity="0.09" stroke={color} strokeDasharray="5 3" /><text x={bounds.x + 4} y={bounds.y - 5} fill={color} fontSize="11" fontWeight="600">{name}</text></g>;
      })}
      {assets.map((asset) => {
        const point = positions.get(asset.asset_id);
        if (!point) return null;
        const compromised = compromisedSet.has(asset.asset_id);
        const color = subnetByName.get(asset.subnet)?.color ?? '#64748b';
        return <g key={asset.asset_id} transform={`translate(${point.x} ${point.y})`}><PublicationIcon type={resolveAssetIcon(asset.kind)} size={size} color={compromised ? '#dc2626' : color} compromised={compromised} />{showLabels && <text y={size + (compact ? 9 : 13)} textAnchor="middle" fontSize={compact ? 7 : 8} fill="#172033">{asset.asset_id}</text>}{showIPs && asset.ip && <text y={size + (compact ? 17 : 24)} textAnchor="middle" fontSize={compact ? 6 : 7} fill="#64748b">{asset.ip}</text>}</g>;
      })}
      {currentRound && (() => {
        const target = positions.get(currentRound.red_target);
        const sourceAsset = assets.find((asset) => asset.zone === currentRound.attacker_zone);
        const source = sourceAsset ? positions.get(sourceAsset.asset_id) : undefined;
        return source && target ? <line x1={source.x} y1={source.y - 25} x2={target.x} y2={target.y} stroke="#dc2626" strokeWidth="2" markerEnd="url(#attack-arrow)" /> : null;
      })()}
      <text x={width / 2} y="24" textAnchor="middle" fontSize="15" fontWeight="700" fill="#172033">Network Topology Visualization</text>
      {currentRound && <text x="16" y={height - 12} fontSize="10" fill="#64748b">Round {currentRound.round} · {compromisedSet.size} compromised</text>}
    </svg>
  );
}
