import React, { useMemo } from 'react';
import { AssetInfo, SubnetInfo, RoundData } from '../types';
import { PublicationIcon, PublicationConnection } from './PublicationIcons';

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

const ZONE_COLORS: Record<string, string> = {
  IT: '#3b82f6',
  DMZ: '#f59e0b',
  OT: '#10b981',
  SCADA: '#ef4444',
  CLOUD: '#06b6d4',
};

const PUBLICATION_LAYOUT = {
  padding: 60,
  zoneSpacing: 40,
  assetSpacing: 80,
  labelSpacing: 25,
};

export const PublicationTopology: React.FC<Props> = ({
  assets,
  subnets,
  currentRound,
  compromisedSet,
  width,
  height,
  showIPs = true,
  showLabels = true,
  compact = false
}) => {
  // Calculate publication-quality layout
  const layout = useMemo(() => {
    const zones = Array.from(new Set(assets.map(a => a.zone)));
    const zonePositions: Record<string, { x: number; y: number; width: number; height: number }> = {};
    
    // Calculate zone grid layout
    const cols = Math.ceil(Math.sqrt(zones.length));
    const zoneWidth = (width - PUBLICATION_LAYOUT.padding * 2 - PUBLICATION_LAYOUT.zoneSpacing * (cols - 1)) / cols;
    const zoneHeight = (height - PUBLICATION_LAYOUT.padding * 2 - PUBLICATION_LAYOUT.zoneSpacing * (Math.ceil(zones.length / cols) - 1)) / Math.ceil(zones.length / cols);
    
    zones.forEach((zone, index) => {
      const row = Math.floor(index / cols);
      const col = index % cols;
      zonePositions[zone] = {
        x: PUBLICATION_LAYOUT.padding + col * (zoneWidth + PUBLICATION_LAYOUT.zoneSpacing),
        y: PUBLICATION_LAYOUT.padding + row * (zoneHeight + PUBLICATION_LAYOUT.zoneSpacing),
        width: zoneWidth,
        height: zoneHeight
      };
    });
    
    // Position assets within zones
    const assetPositions: Record<string, { x: number; y: number }> = {};
    assets.forEach(asset => {
      const zone = zonePositions[asset.zone];
      if (!zone) return;
      
      const zoneAssets = assets.filter(a => a.zone === asset.zone);
      const assetIndex = zoneAssets.findIndex(a => a.asset_id === asset.asset_id);
      
      const colsInZone = Math.ceil(Math.sqrt(zoneAssets.length));
      const assetIndexRow = Math.floor(assetIndex / colsInZone);
      const assetIndexCol = assetIndex % colsInZone;
      
      const cellWidth = zone.width / colsInZone;
      const cellHeight = zone.height / Math.ceil(zoneAssets.length / colsInZone);
      
      assetPositions[asset.asset_id] = {
        x: zone.x + assetIndexCol * cellWidth + cellWidth / 2,
        y: zone.y + assetIndexRow * cellHeight + cellHeight / 2
      };
    });
    
    return { zonePositions, assetPositions };
  }, [assets, width, height]);

  // Publication-quality text rendering
  const renderText = (text: string, x: number, y: number, style: 'zone' | 'asset' | 'ip') => {
    const styles = {
      zone: {
        fontSize: compact ? 11 : 13,
        fontWeight: 'bold',
        fill: '#1e293b',
        textAnchor: 'middle' as const
      },
      asset: {
        fontSize: compact ? 8 : 9,
        fontWeight: 'normal',
        fill: '#374151',
        textAnchor: 'middle' as const
      },
      ip: {
        fontSize: compact ? 7 : 8,
        fontWeight: 'normal',
        fill: '#6b7280',
        textAnchor: 'middle' as const
      }
    };
    
    const s = styles[style];
    return (
      <text x={x} y={y} fontSize={s.fontSize} fontWeight={s.fontWeight} fill={s.fill} textAnchor={s.textAnchor}>
        {text}
      </text>
    );
  };

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ background: '#ffffff' }}>
      {/* White background for publication */}
      <rect width={width} height={height} fill="#ffffff" />
      
      {/* Grid pattern for publication quality */}
      <defs>
        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
          <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#e5e7eb" strokeWidth="0.5"/>
        </pattern>
      </defs>
      <rect width={width} height={height} fill="url(#grid)" opacity={0.3} />
      
      {/* Zone backgrounds */}
      {Object.entries(layout.zonePositions).map(([zone, pos]) => (
        <g key={zone}>
          <rect
            x={pos.x}
            y={pos.y}
            width={pos.width}
            height={pos.height}
            fill={ZONE_COLORS[zone]}
            opacity={0.08}
            stroke={ZONE_COLORS[zone]}
            strokeWidth={1}
            strokeDasharray="5,3"
          />
          {showLabels && renderText(zone, pos.x + pos.width / 2, pos.y - 10, 'zone')}
        </g>
      ))}
      
      {/* Zone connections */}
      {subnets.map((subnet, i) => {
        const subnetAssets = assets.filter(a => a.subnet === subnet.name);
        if (subnetAssets.length < 2) return null;
        
        const positions = subnetAssets.map(a => layout.assetPositions[a.asset_id]).filter(Boolean);
        if (positions.length < 2) return null;
        
        return (
          <g key={`subnet-${subnet.name}`}>
            {positions.slice(0, -1).map((start, j) => {
              const end = positions[j + 1];
              return (
                <line
                  key={`${subnet.name}-${j}`}
                  x1={start.x}
                  y1={start.y}
                  x2={end.x}
                  y2={end.y}
                  stroke="#9ca3af"
                  strokeWidth={1}
                  strokeDasharray="3,3"
                  opacity={0.6}
                />
              );
            })}
          </g>
        );
      })}
      
      {/* Assets */}
      {assets.map(asset => {
        const pos = layout.assetPositions[asset.asset_id];
        if (!pos) return null;
        
        const isCompromised = compromisedSet.has(asset.asset_id);
        const iconSize = compact ? 12 : 18;
        const zoneColor = ZONE_COLORS[asset.zone] || '#64748b';
        
        return (
          <g key={asset.asset_id}>
            {/* Asset icon */}
            <foreignObject
              x={pos.x - iconSize}
              y={pos.y - iconSize}
              width={iconSize * 2}
              height={iconSize * 2}
            >
              <PublicationIcon
                type={asset.kind as any}
                size={iconSize}
                color={isCompromised ? '#ef4444' : zoneColor}
                strokeColor={isCompromised ? '#fca5a5' : '#1e293b'}
                compromised={isCompromised}
              />
            </foreignObject>
            
            {/* Asset labels */}
            {showLabels && (
              <text
                x={pos.x}
                y={pos.y + iconSize + (compact ? 8 : 12)}
                fontSize={compact ? 7 : 8}
                fontWeight="normal"
                fill="#374151"
                textAnchor="middle"
              >
                {asset.asset_id}
              </text>
            )}
            
            {/* IP addresses */}
            {showIPs && asset.ip && (
              <text
                x={pos.x}
                y={pos.y + iconSize + (compact ? 16 : 22)}
                fontSize={compact ? 6 : 7}
                fontWeight="normal"
                fill="#6b7280"
                textAnchor="middle"
              >
                {asset.ip}
              </text>
            )}
          </g>
        );
      })}
      
      {/* Attack/Defense indicators */}
      {currentRound && (
        <g>
          {/* Attacker position */}
          {currentRound.attacker_zone && layout.zonePositions[currentRound.attacker_zone] && (
            <g>
              <foreignObject
                x={layout.zonePositions[currentRound.attacker_zone].x + layout.zonePositions[currentRound.attacker_zone].width / 2 - 15}
                y={layout.zonePositions[currentRound.attacker_zone].y - 35}
                width={30}
                height={30}
              >
                <PublicationIcon
                  type="firewall"
                  size={12}
                  color="#dc2626"
                  compromised={true}
                />
              </foreignObject>
              <text
                x={layout.zonePositions[currentRound.attacker_zone].x + layout.zonePositions[currentRound.attacker_zone].width / 2}
                y={layout.zonePositions[currentRound.attacker_zone].y - 40}
                fontSize={9}
                fontWeight="bold"
                fill="#dc2626"
                textAnchor="middle"
              >
                ATT
              </text>
            </g>
          )}
          
          {/* Attack arrow */}
          {currentRound.red_target && layout.assetPositions[currentRound.red_target] && currentRound.attacker_zone && (
            <line
              x1={layout.zonePositions[currentRound.attacker_zone].x + layout.zonePositions[currentRound.attacker_zone].width / 2}
              y1={layout.zonePositions[currentRound.attacker_zone].y - 20}
              x2={layout.assetPositions[currentRound.red_target].x}
              y2={layout.assetPositions[currentRound.red_target].y - 25}
              stroke="#dc2626"
              strokeWidth={2}
              markerEnd="url(#attackArrow)"
              opacity={0.8}
            />
          )}
          
          {/* Defense arrow */}
          {currentRound.blue_target && layout.assetPositions[currentRound.blue_target] && (
            <line
              x1={layout.assetPositions[currentRound.blue_target].x + 20}
              y1={layout.assetPositions[currentRound.blue_target].y}
              x2={layout.assetPositions[currentRound.blue_target].x + 40}
              y2={layout.assetPositions[currentRound.blue_target].y - 20}
              stroke="#16a34a"
              strokeWidth={2}
              markerEnd="url(#defenseArrow)"
              opacity={0.8}
            />
          )}
        </g>
      )}
      
      {/* Arrow markers */}
      <defs>
        <marker
          id="attackArrow"
          markerWidth="10"
          markerHeight="10"
          refX="9"
          refY="3"
          orient="auto"
          markerUnits="strokeWidth"
        >
          <path d="M0,0 L0,6 L9,3 z" fill="#dc2626" />
        </marker>
        <marker
          id="defenseArrow"
          markerWidth="10"
          markerHeight="10"
          refX="9"
          refY="3"
          orient="auto"
          markerUnits="strokeWidth"
        >
          <path d="M0,0 L0,6 L9,3 z" fill="#16a34a" />
        </marker>
      </defs>
      
      {/* Legend */}
      <g transform={`translate(${width - 150}, 20)`}>
        <rect x={0} y={0} width={140} height={compact ? 80 : 120} fill="white" stroke="#e5e7eb" strokeWidth={1} rx={4} />
        <text x={70} y={15} fontSize={10} fontWeight="bold" fill="#1e293b" textAnchor="middle">Legend</text>
        
        <foreignObject x={10} y={25} width={15} height={15}>
          <PublicationIcon type="server" size={7} color="#3b82f6" />
        </foreignObject>
        <text x={30} y={35} fontSize={8} fill="#374151">Normal Asset</text>
        
        <foreignObject x={10} y={45} width={15} height={15}>
          <PublicationIcon type="server" size={7} color="#ef4444" compromised={true} />
        </foreignObject>
        <text x={30} y={55} fontSize={8} fill="#374151">Compromised</text>
        
        {!compact && (
          <>
            <line x1={10} x2={25} y1={70} y2={70} stroke="#dc2626" strokeWidth={2} markerEnd="url(#attackArrow)" />
            <text x={30} y={73} fontSize={8} fill="#374151">Attack</text>
            
            <line x1={10} x2={25} y1={85} y2={85} stroke="#16a34a" strokeWidth={2} markerEnd="url(#defenseArrow)" />
            <text x={30} y={88} fontSize={8} fill="#374151">Defense</text>
          </>
        )}
      </g>
      
      {/* Title */}
      <text x={width / 2} y={25} fontSize={16} fontWeight="bold" fill="#1e293b" textAnchor="middle">
        Network Topology Visualization
      </text>
      
      {/* Round indicator */}
      {currentRound && (
        <text x={20} y={height - 10} fontSize={10} fill="#6b7280">
          Round {currentRound.round} | {compromisedSet.size} Compromised
        </text>
      )}
    </svg>
  );
};
