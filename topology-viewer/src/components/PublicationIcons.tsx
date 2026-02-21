import React from 'react';

// Publication-quality SVG icons for academic papers
export const PublicationIcon: React.FC<{
  type: 'server' | 'firewall' | 'plc' | 'sensor' | 'database' | 'gateway' | 'hmi';
  size: number;
  color: string;
  strokeColor?: string;
  compromised?: boolean;
}> = ({ type, size, color, strokeColor = '#1e293b', compromised = false }) => {
  const strokeWidth = compromised ? 2 : 1.5;
  const opacity = compromised ? 0.8 : 1;
  
  // Add glow effect for compromised assets
  const filter = compromised ? 
    `url(#compromisedGlow)` : 
    'none';

  const icons = {
    server: (
      <g opacity={opacity}>
        {/* Server rack */}
        <rect
          x={-size * 0.6}
          y={-size * 0.9}
          width={size * 1.2}
          height={size * 1.8}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Rack lines */}
        {[-2, -1, 0, 1, 2].map(i => (
          <line
            key={i}
            x1={-size * 0.4}
            y1={i * size * 0.3}
            x2={size * 0.4}
            y2={i * size * 0.3}
            stroke={strokeColor}
            strokeWidth={0.5}
            opacity={0.6}
          />
        ))}
        {/* Server indicators */}
        <circle cx={-size * 0.2} cy={-size * 0.6} r={size * 0.08} fill="#4ade80" />
        <circle cx={0} cy={-size * 0.6} r={size * 0.08} fill="#4ade80" />
        <circle cx={size * 0.2} cy={-size * 0.6} r={size * 0.08} fill="#4ade80" />
      </g>
    ),
    
    firewall: (
      <g opacity={opacity}>
        {/* Shield shape */}
        <path
          d={`M 0,${-size} 
              C ${size * 0.8},${-size * 0.7} ${size * 0.8},${-size * 0.3} ${size * 0.8},0
              C ${size * 0.8},${size * 0.3} ${size * 0.8},${size * 0.7} 0,${size}
              C ${-size * 0.8},${size * 0.7} ${-size * 0.8},${size * 0.3} ${-size * 0.8},0
              C ${-size * 0.8},${-size * 0.3} ${-size * 0.8},${-size * 0.7} 0,${-size}`}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Lock symbol */}
        <rect
          x={-size * 0.2}
          y={-size * 0.1}
          width={size * 0.4}
          height={size * 0.3}
          fill="none"
          stroke={strokeColor}
          strokeWidth={1}
          rx={size * 0.05}
        />
        <path
          d={`M ${-size * 0.15},${-size * 0.1} 
              C ${-size * 0.15},${-size * 0.2} ${-size * 0.05},${-size * 0.25} 0,${-size * 0.25}
              C ${size * 0.05},${-size * 0.25} ${size * 0.15},${-size * 0.2} ${size * 0.15},${-size * 0.1}`}
          fill="none"
          stroke={strokeColor}
          strokeWidth={1}
        />
      </g>
    ),
    
    plc: (
      <g opacity={opacity}>
        {/* Hexagon for PLC */}
        <path
          d={Array.from({length: 6}, (_, i) => {
            const angle = (Math.PI / 3) * i;
            const px = size * 1.1 * Math.cos(angle);
            const py = size * 1.1 * Math.sin(angle);
            return `${i === 0 ? 'M' : 'L'} ${px},${py}`;
          }).join(' ') + ' Z'}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Circuit pattern */}
        <circle cx={0} cy={0} r={size * 0.5} fill="none" stroke={strokeColor} strokeWidth={0.8} opacity={0.5} />
        <circle cx={0} cy={0} r={size * 0.3} fill="none" stroke={strokeColor} strokeWidth={0.8} opacity={0.5} />
        {/* PLC indicator */}
        <text x={0} y={size * 0.15} textAnchor="middle" fontSize={size * 0.4} fill="#1e293b" fontWeight="bold">PLC</text>
      </g>
    ),
    
    sensor: (
      <g opacity={opacity}>
        {/* Outer circle */}
        <circle
          cx={0}
          cy={0}
          r={size}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Crosshair */}
        <line x1={-size * 0.7} y1={0} x2={size * 0.7} y2={0} stroke={strokeColor} strokeWidth={0.8} opacity={0.6} />
        <line x1={0} y1={-size * 0.7} x2={0} y2={size * 0.7} stroke={strokeColor} strokeWidth={0.8} opacity={0.6} />
        {/* Center dot */}
        <circle cx={0} cy={0} r={size * 0.15} fill={strokeColor} />
        {/* Wave pattern */}
        <path
          d={`M ${-size * 0.5},${-size * 0.5} Q ${-size * 0.25},${-size * 0.7} 0,${-size * 0.5} Q ${size * 0.25},${-size * 0.3} ${size * 0.5},${-size * 0.5}`}
          fill="none"
          stroke={strokeColor}
          strokeWidth={1}
          opacity={0.7}
        />
      </g>
    ),
    
    database: (
      <g opacity={opacity}>
        {/* Cylinder shape */}
        <ellipse
          cx={0}
          cy={-size * 0.6}
          rx={size * 0.8}
          ry={size * 0.2}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        <rect
          x={-size * 0.8}
          y={-size * 0.6}
          width={size * 1.6}
          height={size * 1.2}
          fill={color}
          stroke="none"
        />
        <ellipse
          cx={0}
          cy={size * 0.6}
          rx={size * 0.8}
          ry={size * 0.2}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Database lines */}
        <line x1={-size * 0.6} y1={-size * 0.2} x2={size * 0.6} y2={-size * 0.2} stroke={strokeColor} strokeWidth={0.5} />
        <line x1={-size * 0.6} y1={0} x2={size * 0.6} y2={0} stroke={strokeColor} strokeWidth={0.5} />
        <line x1={-size * 0.6} y1={size * 0.2} x2={size * 0.6} y2={size * 0.2} stroke={strokeColor} strokeWidth={0.5} />
      </g>
    ),
    
    gateway: (
      <g opacity={opacity}>
        {/* Diamond shape for gateway */}
        <path
          d={`M 0,${-size} L ${size},0 L 0,${size} L ${-size},0 Z`}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Arrow indicators */}
        <path
          d={`M ${-size * 0.3},${-size * 0.3} L ${size * 0.3},${-size * 0.3} L ${size * 0.3},${-size * 0.1} L ${size * 0.1},${-size * 0.1} L ${size * 0.1},${size * 0.1} L ${size * 0.3},${size * 0.1} L ${size * 0.3},${size * 0.3} L ${-size * 0.3},${size * 0.3} L ${-size * 0.3},${size * 0.1} L ${-size * 0.1},${size * 0.1} L ${-size * 0.1},${-size * 0.1} L ${-size * 0.3},${-size * 0.1} Z`}
          fill={strokeColor}
          opacity={0.6}
        />
      </g>
    ),
    
    hmi: (
      <g opacity={opacity}>
        {/* Monitor shape */}
        <rect
          x={-size * 0.8}
          y={-size * 0.6}
          width={size * 1.6}
          height={size * 1.0}
          fill={color}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          rx={size * 0.1}
        />
        {/* Screen */}
        <rect
          x={-size * 0.6}
          y={-size * 0.4}
          width={size * 1.2}
          height={size * 0.6}
          fill="#1e293b"
          opacity={0.8}
        />
        {/* HMI interface elements */}
        <rect x={-size * 0.4} y={-size * 0.2} width={size * 0.3} height={size * 0.15} fill="#4ade80" opacity={0.7} />
        <rect x={size * 0.1} y={-size * 0.2} width={size * 0.3} height={size * 0.15} fill="#f59e0b" opacity={0.7} />
        <rect x={-size * 0.4} y={size * 0.05} width={size * 0.8} height={size * 0.1} fill="#3b82f6" opacity={0.7} />
        {/* Stand */}
        <rect x={-size * 0.1} y={size * 0.4} width={size * 0.2} height={size * 0.3} fill={strokeColor} />
      </g>
    )
  };

  return (
    <svg width={size * 2.5} height={size * 2.5} viewBox={`${-size * 1.25} ${-size * 1.25} ${size * 2.5} ${size * 2.5}`}>
      <defs>
        <filter id="compromisedGlow">
          <feGaussianBlur stdDeviation={3} result="coloredBlur"/>
          <feMerge> 
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/> 
          </feMerge>
        </filter>
      </defs>
      {icons[type]}
      {compromised && (
        <g>
          {/* Warning indicator */}
          <circle cx={size * 0.7} cy={-size * 0.7} r={size * 0.2} fill="#ef4444" />
          <text x={size * 0.7} y={-size * 0.65} textAnchor="middle" fontSize={size * 0.25} fill="white" fontWeight="bold">!</text>
        </g>
      )}
    </svg>
  );
};

// Publication-quality connection line
export const PublicationConnection: React.FC<{
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  type: 'network' | 'compromised' | 'attack' | 'defense';
  animated?: boolean;
}> = ({ x1, y1, x2, y2, type, animated = false }) => {
  const colors = {
    network: '#64748b',
    compromised: '#ef4444',
    attack: '#dc2626',
    defense: '#16a34a'
  };

  const strokeWidths = {
    network: 1.5,
    compromised: 2.5,
    attack: 2,
    defense: 2
  };

  return (
    <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
      <defs>
        {animated && (
          <marker
            id={`arrowhead-${type}`}
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon
              points="0 0, 10 3.5, 0 7"
              fill={colors[type]}
            />
          </marker>
        )}
      </defs>
      <line
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke={colors[type]}
        strokeWidth={strokeWidths[type]}
        strokeDasharray={type === 'network' ? '5,5' : 'none'}
        markerEnd={animated ? `url(#arrowhead-${type})` : 'none'}
        opacity={type === 'compromised' ? 0.8 : 1}
      />
    </svg>
  );
};
