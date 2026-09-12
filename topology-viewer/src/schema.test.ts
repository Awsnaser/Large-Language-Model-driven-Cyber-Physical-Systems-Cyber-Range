import { describe, expect, it } from 'vitest';
import { computeSubnetLayout } from './layout';
import { normalizeSimulationData } from './schema';

describe('normalizeSimulationData', () => {
  it('accepts the minimal exporter asset shape and derives subnet metadata', () => {
    const data = normalizeSimulationData({
      assets: [{ asset_id: 'pump-1', zone: 'OT', kind: 'pump-controller', ip: '10.2.0.8', network: 'field-net' }],
    });
    expect(data.assets[0]).toMatchObject({ subnet: 'field-net', criticality: 'MEDIUM', kind: 'pump-controller' });
    expect(data.subnets).toEqual([expect.objectContaining({ name: 'field-net', zone: 'OT', asset_count: 1 })]);
    expect(data.rounds).toEqual([]);
  });

  it('uses safe defaults for incomplete input and keeps duplicate identifiers distinct', () => {
    const data = normalizeSimulationData([{ asset_id: 'same' }, { asset_id: 'same', zone: 'IT' }, {}]);
    expect(data.assets.map((asset) => asset.asset_id)).toEqual(['same', 'same-2', 'asset-3']);
    expect(data.assets.every((asset) => asset.subnet.length > 0)).toBe(true);
  });
});

describe('computeSubnetLayout', () => {
  it('places every asset even when no subnet metadata was supplied', () => {
    const data = normalizeSimulationData({ assets: [{ asset_id: 'a', zone: 'IT' }, { asset_id: 'b', zone: 'OT', network: 'field' }] });
    const layout = computeSubnetLayout(data.assets, [], 600, 400);
    expect(layout.size).toBe(2);
    expect(layout.get('a')).toBeDefined();
    expect(layout.get('b')).toBeDefined();
  });
});
