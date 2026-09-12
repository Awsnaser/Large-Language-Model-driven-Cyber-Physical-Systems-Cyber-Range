# CPS Topology Viewer (Version 2)

A static React/Vite viewer for cyber-range topology exports. It opens entirely in the browser; no backend is required.

## Run

```bash
npm install
npm run dev
```

Then open the local URL printed by Vite. Create an optimized static bundle with:

```bash
npm run typecheck
npm test
npm run build
```

`npm run build` writes deployable files to `dist/`.

## Loading data

Use **Load JSON** to select an exporter output. The viewer accepts the complete simulation shape:

```json
{
  "subnets": [{"name":"OT field","zone":"OT","cidr":"192.168.1.0/24","color":"#54a24b","asset_count":1}],
  "assets": [{"asset_id":"plc-1","zone":"OT","kind":"plc","ip":"192.168.1.10","subnet":"OT field","criticality":"HIGH"}],
  "subnet_links": [["IT", "OT field"]],
  "rounds": [],
  "total_ips": 1
}
```

It also accepts a bare asset array, a single asset, or an object with `assets`/`topology_assets` containing the minimal exporter shape:

```json
{"assets":[{"asset_id":"plc-1","zone":"OT","kind":"plc","ip":"192.168.1.10","network":"field-bus"}]}
```

`network` is normalized to `subnet`. Missing subnet information falls back to the asset's zone (then `Unassigned`), missing criticality defaults to `MEDIUM`, missing round fields receive safe display defaults, and unknown asset kinds render as generic nodes. Inferred subnet records guarantee every asset receives a layout position.

## Notes for exporter maintainers

The present exporter-compatible fields are sufficient for the viewer. For richer and more deterministic diagrams, it is still recommended to emit:

- a stable `subnet` for each asset (rather than relying on legacy `network`);
- complete `subnets` entries, including `name`, `zone`, CIDR, color, and accurate `asset_count`;
- `criticality` as `LOW`, `MEDIUM`, or `HIGH` and a stable non-empty `kind`;
- `subnet_links` that reference the exported subnet names; and
- complete, ordered `rounds` when playback and compromise animation are wanted.

The viewer deliberately does not require these recommendations to load an export.
