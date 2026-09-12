import { ReactElement } from 'react';

export type AssetIconKind = 'server' | 'firewall' | 'plc' | 'sensor' | 'database' | 'gateway' | 'hmi' | 'generic';

interface IconProps {
  type: AssetIconKind;
  size: number;
  color: string;
  strokeColor?: string;
  compromised?: boolean;
}

/** SVG-only icon so publication mode works without browser-specific foreignObject support. */
export function PublicationIcon({ type, size, color, strokeColor = '#172033', compromised = false }: IconProps): ReactElement {
  const common = { fill: color, stroke: strokeColor, strokeWidth: compromised ? 2 : 1.25 };
  let shape: ReactElement;
  if (type === 'firewall' || type === 'gateway') {
    shape = <path d={`M0,${-size} L${size},${-size / 2} L${size},${size / 3} Q${size},${size * 0.75} 0,${size} Q${-size},${size * 0.75} ${-size},${size / 3} L${-size},${-size / 2} Z`} {...common} />;
  } else if (type === 'plc') {
    const points = Array.from({ length: 6 }, (_, index) => {
      const angle = (Math.PI * index) / 3;
      return `${Math.cos(angle) * size},${Math.sin(angle) * size}`;
    }).join(' ');
    shape = <polygon points={points} {...common} />;
  } else if (type === 'server' || type === 'database') {
    shape = <rect x={-size * 0.7} y={-size} width={size * 1.4} height={size * 2} rx={type === 'database' ? size / 4 : 1} {...common} />;
  } else if (type === 'hmi') {
    shape = <rect x={-size} y={-size * 0.65} width={size * 2} height={size * 1.3} rx={2} {...common} />;
  } else {
    shape = <circle r={size} {...common} />;
  }
  return <g>{shape}{compromised && <text x={size * 0.75} y={-size * 0.65} fill="#dc2626" fontSize={size} fontWeight="bold">!</text>}</g>;
}

export function resolveAssetIcon(kind: string): AssetIconKind {
  if (kind === 'gateway' || kind === 'router') return 'gateway';
  if (kind === 'firewall') return 'firewall';
  if (kind === 'plc' || kind === 'rtu' || kind === 'ied') return 'plc';
  if (kind === 'sensor' || kind === 'actuator') return 'sensor';
  if (kind === 'database' || kind === 'db' || kind === 'historian') return 'database';
  if (kind === 'hmi' || kind === 'workstation' || kind === 'laptop') return 'hmi';
  if (kind === 'server' || kind === 'webserver' || kind === 'dns' || kind === 'mailserver') return 'server';
  return 'generic';
}
