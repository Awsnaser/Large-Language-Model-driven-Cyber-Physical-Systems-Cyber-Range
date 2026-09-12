import { AssetInfo, SubnetInfo } from './types';

export interface Point {
  x: number;
  y: number;
}

export interface Bounds extends Point {
  w: number;
  h: number;
}

function groupName(asset: AssetInfo): string {
  return asset.subnet || asset.zone || 'Unassigned';
}

/** Produces a stable position for every asset, including unregistered subnets. */
export function computeSubnetLayout(
  assets: AssetInfo[],
  subnets: SubnetInfo[],
  width: number,
  height: number,
): Map<string, Point> {
  const bySubnet = new Map<string, AssetInfo[]>();
  for (const asset of assets) {
    const name = groupName(asset);
    const group = bySubnet.get(name) ?? [];
    group.push(asset);
    bySubnet.set(name, group);
  }

  const subnetOrder = [...subnets.map((subnet) => subnet.name)];
  for (const name of bySubnet.keys()) {
    if (!subnetOrder.includes(name)) subnetOrder.push(name);
  }
  const columns = Math.max(subnetOrder.length, 1);
  const colWidth = Math.max((width - 80) / columns, 45);
  const positions = new Map<string, Point>();

  subnetOrder.forEach((name, column) => {
    const items = bySubnet.get(name) ?? [];
    const centerX = 40 + column * colWidth + colWidth / 2;
    const maxRows = 16;
    items.forEach((asset, index) => {
      const innerColumn = Math.floor(index / maxRows);
      const row = index % maxRows;
      const columnSize = Math.min(maxRows, items.length - innerColumn * maxRows);
      const ySpacing = Math.max((height - 130) / Math.max(columnSize, 1), 20);
      positions.set(asset.asset_id, {
        x: centerX + (innerColumn - Math.floor((items.length - 1) / maxRows) / 2) * 28,
        y: 70 + row * ySpacing,
      });
    });
  });

  return positions;
}

export function getSubnetBounds(
  assets: AssetInfo[],
  positions: Map<string, Point>,
  subnetName: string,
): Bounds | null {
  const points = assets
    .filter((asset) => groupName(asset) === subnetName)
    .map((asset) => positions.get(asset.asset_id))
    .filter((point): point is Point => point !== undefined);
  if (points.length === 0) return null;

  const pad = 22;
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  return { x: minX - pad, y: minY - pad, w: Math.max(maxX - minX + pad * 2, 50), h: Math.max(maxY - minY + pad * 2, 50) };
}
