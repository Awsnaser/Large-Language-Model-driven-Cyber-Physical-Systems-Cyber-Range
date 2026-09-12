import { useCallback, useEffect, useRef } from 'react';
import { AssetInfo, RoundData, SubnetInfo } from './types';
import { computeSubnetLayout, getSubnetBounds, Point } from './layout';

interface Props {
  assets: AssetInfo[];
  subnets: SubnetInfo[];
  subnetLinks: [string, string][];
  currentRound: RoundData | null;
  compromisedSet: Set<string>;
  width: number;
  height: number;
}

const CRITICALITY_SIZE = { HIGH: 12, MEDIUM: 9, LOW: 6 } as const;

function drawAsset(ctx: CanvasRenderingContext2D, asset: AssetInfo, point: Point, compromised: boolean, color: string) {
  const size = CRITICALITY_SIZE[asset.criticality];
  const fill = compromised ? '#dc2626' : color;
  ctx.save();
  ctx.fillStyle = fill;
  ctx.strokeStyle = compromised ? '#fecaca' : '#172033';
  ctx.lineWidth = compromised ? 2 : 1.25;
  if (compromised) {
    ctx.shadowColor = '#ef4444';
    ctx.shadowBlur = 9;
  }

  // Known kinds get recognizable geometry; all other kinds intentionally use a safe circle.
  if (asset.kind === 'gateway' || asset.kind === 'firewall' || asset.kind === 'router') {
    ctx.beginPath();
    ctx.moveTo(point.x, point.y - size * 1.25);
    ctx.lineTo(point.x + size, point.y);
    ctx.lineTo(point.x, point.y + size * 1.25);
    ctx.lineTo(point.x - size, point.y);
    ctx.closePath();
  } else if (asset.kind === 'plc' || asset.kind === 'rtu' || asset.kind === 'ied') {
    ctx.beginPath();
    for (let index = 0; index < 6; index += 1) {
      const angle = (Math.PI * index) / 3;
      const x = point.x + Math.cos(angle) * size * 1.15;
      const y = point.y + Math.sin(angle) * size * 1.15;
      if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
  } else if (asset.kind === 'server' || asset.kind === 'database' || asset.kind === 'historian') {
    ctx.beginPath();
    ctx.rect(point.x - size * 0.75, point.y - size, size * 1.5, size * 2);
  } else if (asset.kind === 'hmi' || asset.kind === 'workstation' || asset.kind === 'laptop') {
    ctx.beginPath();
    ctx.rect(point.x - size, point.y - size * 0.65, size * 2, size * 1.3);
  } else {
    ctx.beginPath();
    ctx.arc(point.x, point.y, size, 0, Math.PI * 2);
  }
  ctx.fill();
  ctx.stroke();
  ctx.shadowBlur = 0;

  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.font = '600 9px system-ui, sans-serif';
  const label = asset.asset_id;
  const textWidth = ctx.measureText(label).width;
  ctx.fillStyle = 'rgba(255,255,255,0.92)';
  ctx.fillRect(point.x - textWidth / 2 - 3, point.y + size + 6, textWidth + 6, 12);
  ctx.fillStyle = '#172033';
  ctx.fillText(label, point.x, point.y + size + 7);
  if (asset.ip) {
    ctx.font = '8px ui-monospace, monospace';
    ctx.fillStyle = '#64748b';
    ctx.fillText(asset.ip, point.x, point.y + size + 20);
  }
  ctx.restore();
}

function drawArrow(ctx: CanvasRenderingContext2D, from: Point, to: Point, color: string) {
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  ctx.save();
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(from.x, from.y);
  ctx.lineTo(to.x, to.y);
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(to.x, to.y);
  ctx.lineTo(to.x - 10 * Math.cos(angle - Math.PI / 6), to.y - 10 * Math.sin(angle - Math.PI / 6));
  ctx.lineTo(to.x - 10 * Math.cos(angle + Math.PI / 6), to.y - 10 * Math.sin(angle + Math.PI / 6));
  ctx.closePath();
  ctx.fill();
  ctx.restore();
}

export default function TopologyCanvas({ assets, subnets, subnetLinks, currentRound, compromisedSet, width, height }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!ctx) return;
    const positions = computeSubnetLayout(assets, subnets, width, height);
    const subnetByName = new Map(subnets.map((subnet) => [subnet.name, subnet]));

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = '#eef2f7';
    ctx.lineWidth = 0.5;
    for (let x = 0; x <= width; x += 25) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke(); }
    for (let y = 0; y <= height; y += 25) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke(); }

    const allSubnetNames = [...subnets.map((subnet) => subnet.name)];
    for (const asset of assets) if (!allSubnetNames.includes(asset.subnet)) allSubnetNames.push(asset.subnet);
    const subnetBoxes = new Map<string, ReturnType<typeof getSubnetBounds>>();
    for (const name of allSubnetNames) {
      const bounds = getSubnetBounds(assets, positions, name);
      if (!bounds) continue;
      subnetBoxes.set(name, bounds);
      const subnet = subnetByName.get(name);
      const color = subnet?.color ?? '#64748b';
      ctx.save();
      ctx.setLineDash([6, 3]);
      ctx.strokeStyle = `${color}99`;
      ctx.lineWidth = 1.25;
      ctx.strokeRect(bounds.x, bounds.y, bounds.w, bounds.h);
      ctx.setLineDash([]);
      ctx.fillStyle = `${color}16`;
      ctx.fillRect(bounds.x, bounds.y, bounds.w, bounds.h);
      ctx.fillStyle = color;
      ctx.font = '600 11px system-ui, sans-serif';
      ctx.textBaseline = 'bottom';
      ctx.textAlign = 'left';
      ctx.fillText(name, bounds.x + 5, bounds.y - 4);
      ctx.restore();
    }

    ctx.save();
    ctx.strokeStyle = '#64748b';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    for (const [from, to] of subnetLinks) {
      const start = subnetBoxes.get(from);
      const end = subnetBoxes.get(to);
      if (!start || !end) continue;
      ctx.beginPath();
      ctx.moveTo(start.x + start.w / 2, start.y + start.h / 2);
      ctx.lineTo(end.x + end.w / 2, end.y + end.h / 2);
      ctx.stroke();
    }
    ctx.restore();

    for (const asset of assets) {
      const point = positions.get(asset.asset_id);
      if (!point) continue;
      const color = subnetByName.get(asset.subnet)?.color ?? '#64748b';
      drawAsset(ctx, asset, point, compromisedSet.has(asset.asset_id), color);
    }

    if (currentRound) {
      const target = positions.get(currentRound.red_target);
      const zoneAssets = assets.filter((asset) => asset.zone === currentRound.attacker_zone);
      const source = zoneAssets.map((asset) => positions.get(asset.asset_id)).find((point): point is Point => point !== undefined);
      if (source && target) drawArrow(ctx, { x: source.x, y: Math.max(24, source.y - 38) }, target, '#dc2626');
      const defenseTarget = positions.get(currentRound.blue_target);
      if (defenseTarget) drawArrow(ctx, { x: width - 24, y: 28 }, defenseTarget, '#2563eb');
    }
  }, [assets, subnets, subnetLinks, currentRound, compromisedSet, width, height]);

  useEffect(() => { draw(); }, [draw]);
  return <canvas aria-label="Network topology" ref={canvasRef} width={width} height={height} style={{ display: 'block', maxWidth: '100%', height: 'auto', borderRadius: 8, border: '1px solid #334155' }} />;
}
