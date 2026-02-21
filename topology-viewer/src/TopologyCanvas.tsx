import React, { useRef, useEffect, useCallback } from 'react';
import { AssetInfo, SubnetInfo, RoundData } from './types';

// Font Awesome icons (most comprehensive)
import { 
  FaShieldAlt, FaNetworkWired, FaServer, FaCloud, FaExclamationTriangle, 
  FaLock, FaEye, FaSkull, FaGlobe, FaDatabase, FaWifi, FaRoute,
  FaIndustry, FaMicrochip, FaDesktop, FaLaptop, FaHdd, FaMemory,
  FaSitemap, FaProjectDiagram, FaRadiation, FaBug, FaUserSecret,
  FaSatelliteDish, FaBroadcastTower, FaThermometerHalf, FaCog, FaUsers
} from 'react-icons/fa';

// Material Design icons
import { 
  MdSecurity, MdNetworkCheck, MdSettingsEthernet, MdStorage, 
  MdCloudQueue, MdWarning, MdVisibility, MdGppBad, MdDns,
  MdRouter, MdDeviceHub, MdSensors, MdPrecisionManufacturing
} from 'react-icons/md';

// Heroicons
import { 
  HiShieldCheck, HiServer, HiCloud, HiExclamationCircle, HiEye,
  HiLockClosed, HiChip, HiDesktopComputer, HiDatabase
} from 'react-icons/hi';

// Lucide icons (modern, clean)
import { 
  Shield, ShieldAlert, Network, Server, Cloud, AlertTriangle,
  Lock, Eye, Skull, Globe, Database, Wifi, Router, RadioTower,
  Cpu, HardDrive, Monitor, Laptop, Zap, Activity, Binary,
  Bug, User, Users, Camera, CameraOff
} from 'lucide-react';

interface Props {
  assets: AssetInfo[];
  subnets: SubnetInfo[];
  subnetLinks: [string, string][];
  currentRound: RoundData | null;
  compromisedSet: Set<string>;
  width: number;
  height: number;
}

const ZONE_COLORS: Record<string, string> = {
  IT: '#4c78a8',
  DMZ: '#f58518',
  OT: '#54a24b',
  SCADA: '#e45756',
  CLOUD: '#72b7b2',
};

// Cyber-specific icon mappings for asset types
const ASSET_ICONS: Record<string, any> = {
  // IT Zone assets
  workstation: FaDesktop,
  laptop: FaLaptop,
  server: FaServer,
  database: FaDatabase,
  dns: MdDns,
  mailserver: FaServer,
  printer: FaDesktop,
  voip: FaDesktop,
  
  // DMZ/Network assets
  gateway: FaShieldAlt,
  firewall: FaShieldAlt,
  proxy: FaUserSecret,
  jumpbox: FaBug,
  vpn_conc: FaLock,
  router: MdRouter,
  webserver: FaCloud,
  
  // OT/Industrial assets
  plc: MdPrecisionManufacturing,
  hmi: FaDesktop,
  historian: FaDatabase,
  sensor: MdSensors,
  actuator: FaCog,
  rtu: FaBroadcastTower,
  ied: FaSatelliteDish,
  scada_srv: FaIndustry,
  alarm_srv: FaExclamationTriangle,
  
  // Cloud assets
  cloud_gw: FaCloud,
  
  // Monitoring assets
  siem: FaEye,
  nms: FaNetworkWired,
  backup: FaHdd,
  
  // Default fallback
  default: FaServer,
};

// Zone-specific security icons
const ZONE_SECURITY_ICONS: Record<string, any> = {
  IT: FaShieldAlt,
  DMZ: FaLock,
  OT: FaIndustry,
  SCADA: FaExclamationTriangle,
  CLOUD: FaCloud,
};

// Attacker/Defender icons
const ATTACKER_ICONS = {
  normal: FaUserSecret,
  active: FaSkull,
  stealth: FaEye,
};

const DEFENDER_ICONS = {
  monitor: FaEye,
  active: FaShieldAlt,
  blocking: FaLock,
};

// Compromise status icons
const COMPROMISE_ICONS = {
  safe: Shield,
  warning: ShieldAlert,
  compromised: FaSkull,
  isolated: FaLock,
};

const KIND_SHAPES: Record<string, string> = {
  workstation: 'rect',
  server: 'diamond',
  gateway: 'diamond',
  plc: 'triangle',
  hmi: 'rect',
  historian: 'hexagon',
  sensor: 'circle',
  actuator: 'circle',
  rtu: 'triangle',
  dc: 'diamond',
  db: 'hexagon',
  webserver: 'circle',
  dns: 'circle',
  mailserver: 'circle',
  jumpbox: 'diamond',
  proxy: 'rect',
  eng_ws: 'diamond',
  ied: 'triangle',
  scada_srv: 'diamond',
  alarm_srv: 'circle',
  cloud_gw: 'diamond',
  siem: 'circle',
  nms: 'rect',
  vpn_conc: 'diamond',
  printer: 'rect',
  voip: 'circle',
  backup: 'rect',
};

const CRIT_SIZE: Record<string, number> = { HIGH: 12, MEDIUM: 8, LOW: 5 };

function computeLayout(
  assets: AssetInfo[],
  subnets: SubnetInfo[],
  width: number,
  height: number
): Map<string, { x: number; y: number }> {
  const bySubnet = new Map<string, AssetInfo[]>();
  for (const a of assets) {
    const sn = a.subnet || 'unknown';
    if (!bySubnet.has(sn)) bySubnet.set(sn, []);
    bySubnet.get(sn)!.push(a);
  }

  const subnetOrder = subnets.map((s) => s.name);
  const nCols = Math.max(subnetOrder.length, 1);
  const colWidth = (width - 80) / nCols;
  const pos = new Map<string, { x: number; y: number }>();

  for (let ci = 0; ci < subnetOrder.length; ci++) {
    const sn = subnetOrder[ci];
    const items = bySubnet.get(sn) || [];
    const xCenter = 50 + ci * colWidth + colWidth / 2;
    const n = items.length;
    const maxPerCol = 30;

    for (let j = 0; j < n; j++) {
      const innerCol = Math.floor(j / maxPerCol);
      const innerRow = j % maxPerCol;
      const rowCount = Math.min(n - innerCol * maxPerCol, maxPerCol);
      const ySpacing = (height - 120) / Math.max(rowCount, 1);
      const x = xCenter + (innerCol - Math.floor(n / maxPerCol) / 2) * 25;
      const y = 70 + innerRow * ySpacing;
      pos.set(items[j].asset_id, { x, y });
    }
  }

  return pos;
}

function getSubnetBounds(
  assets: AssetInfo[],
  pos: Map<string, { x: number; y: number }>,
  subnetName: string
): { x: number; y: number; w: number; h: number } | null {
  const filtered = assets.filter((a) => a.subnet === subnetName);
  if (filtered.length === 0) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const a of filtered) {
    const p = pos.get(a.asset_id);
    if (!p) continue;
    minX = Math.min(minX, p.x);
    maxX = Math.max(maxX, p.x);
    minY = Math.min(minY, p.y);
    maxY = Math.max(maxY, p.y);
  }
  const pad = 20;
  return { x: minX - pad, y: minY - pad, w: maxX - minX + 2 * pad, h: maxY - minY + 2 * pad };
}

function drawShape(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  size: number,
  shape: string,
  fill: string,
  stroke: string
) {
  ctx.fillStyle = fill;
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 1.5;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';

  switch (shape) {
    case 'server':
    case 'database':
      // Publication-quality server rack
      ctx.fillRect(x - size * 0.7, y - size * 1.0, size * 1.4, size * 2.0);
      ctx.strokeRect(x - size * 0.7, y - size * 1.0, size * 1.4, size * 2.0);
      // Server indicators
      ctx.fillStyle = '#4ade80';
      ctx.fillRect(x - size * 0.4, y - size * 0.8, size * 0.2, size * 0.1);
      ctx.fillRect(x - size * 0.1, y - size * 0.8, size * 0.2, size * 0.1);
      ctx.fillRect(x + size * 0.2, y - size * 0.8, size * 0.2, size * 0.1);
      ctx.fillStyle = fill;
      // Rack lines
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 0.8;
      for (let i = -2; i <= 2; i++) {
        ctx.beginPath();
        ctx.moveTo(x - size * 0.5, y + i * size * 0.35);
        ctx.lineTo(x + size * 0.5, y + i * size * 0.35);
        ctx.stroke();
      }
      break;
      
    case 'gateway':
    case 'firewall':
      // Publication-quality shield
      ctx.beginPath();
      ctx.moveTo(x, y - size * 1.2);
      ctx.quadraticCurveTo(x + size * 1.1, y - size * 0.8, x + size * 1.1, y);
      ctx.quadraticCurveTo(x + size * 1.1, y + size * 0.8, x, y + size * 1.2);
      ctx.quadraticCurveTo(x - size * 1.1, y + size * 0.8, x - size * 1.1, y);
      ctx.quadraticCurveTo(x - size * 1.1, y - size * 0.8, x, y - size * 1.2);
      ctx.fill();
      ctx.stroke();
      // Lock symbol
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(x, y - size * 0.2, size * 0.3, 0, Math.PI * 2);
      ctx.stroke();
      ctx.fillRect(x - size * 0.15, y - size * 0.2, size * 0.3, size * 0.15);
      break;
      
    case 'plc':
    case 'rtu':
      // Publication-quality hexagon with details
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        const px = x + size * 1.2 * Math.cos(angle);
        const py = y + size * 1.2 * Math.sin(angle);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      // Inner circuit pattern
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.arc(x, y, size * 0.6, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(x, y, size * 0.3, 0, Math.PI * 2);
      ctx.stroke();
      // PLC label
      ctx.fillStyle = '#1e293b';
      ctx.font = `bold ${size * 0.6}px Arial`;
      ctx.fillText('PLC', x, y);
      break;
      
    case 'hmi':
      // Publication-quality monitor
      ctx.fillRect(x - size * 0.8, y - size * 0.6, size * 1.6, size * 1.0);
      ctx.strokeRect(x - size * 0.8, y - size * 0.6, size * 1.6, size * 1.0);
      // Screen
      ctx.fillStyle = '#1e293b';
      ctx.fillRect(x - size * 0.6, y - size * 0.4, size * 1.2, size * 0.5);
      // Interface elements
      ctx.fillStyle = '#4ade80';
      ctx.fillRect(x - size * 0.4, y - size * 0.2, size * 0.25, size * 0.1);
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(x + size * 0.15, y - size * 0.2, size * 0.25, size * 0.1);
      ctx.fillStyle = '#3b82f6';
      ctx.fillRect(x - size * 0.4, y + size * 0.05, size * 0.8, size * 0.08);
      // Stand
      ctx.fillStyle = stroke;
      ctx.fillRect(x - size * 0.1, y + size * 0.4, size * 0.2, size * 0.3);
      break;
      
    case 'sensor':
    case 'actuator':
      // Publication-quality sensor with crosshair
      ctx.beginPath();
      ctx.arc(x, y, size, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      // Crosshair
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(x - size * 0.7, y);
      ctx.lineTo(x + size * 0.7, y);
      ctx.moveTo(x, y - size * 0.7);
      ctx.lineTo(x, y + size * 0.7);
      ctx.stroke();
      // Center dot
      ctx.beginPath();
      ctx.arc(x, y, size * 0.2, 0, Math.PI * 2);
      ctx.fill();
      // Wave pattern
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.moveTo(x - size * 0.5, y - size * 0.5);
      ctx.quadraticCurveTo(x - size * 0.25, y - size * 0.7, x, y - size * 0.5);
      ctx.quadraticCurveTo(x + size * 0.25, y - size * 0.3, x + size * 0.5, y - size * 0.5);
      ctx.stroke();
      break;
      
    case 'diamond':
      ctx.beginPath();
      ctx.moveTo(x, y - size * 1.3);
      ctx.lineTo(x + size, y);
      ctx.lineTo(x, y + size * 1.3);
      ctx.lineTo(x - size, y);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      break;
      
    case 'triangle':
      ctx.beginPath();
      ctx.moveTo(x, y - size * 1.3);
      ctx.lineTo(x + size * 1.1, y + size);
      ctx.lineTo(x - size * 1.1, y + size);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      break;
      
    case 'hexagon':
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        const px = x + size * 1.3 * Math.cos(angle);
        const py = y + size * 1.3 * Math.sin(angle);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      break;
      
    case 'circle':
    default:
      // Default circle for unknown types
      ctx.beginPath();
      ctx.arc(x, y, size, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      break;
  }
}

// New function to draw cyber icons with enhanced styling
function drawCyberIcon(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  size: number,
  iconType: string,
  isCompromised: boolean,
  fill: string,
  stroke: string
) {
  // Draw enhanced shape based on asset type
  ctx.fillStyle = fill;
  ctx.strokeStyle = stroke;
  ctx.lineWidth = isCompromised ? 2.0 : 1.2;
  
  // Add glow effect for compromised assets
  if (isCompromised) {
    ctx.shadowColor = '#ef4444';
    ctx.shadowBlur = 8;
  }
  
  // Draw different styles for different cyber asset types
  switch (iconType) {
    case 'gateway':
    case 'firewall':
      // Shield shape for security devices
      ctx.beginPath();
      ctx.moveTo(x, y - size * 1.2);
      ctx.quadraticCurveTo(x + size * 1.2, y - size * 0.8, x + size * 1.2, y);
      ctx.quadraticCurveTo(x + size * 1.2, y + size * 0.8, x, y + size * 1.2);
      ctx.quadraticCurveTo(x - size * 1.2, y + size * 0.8, x - size * 1.2, y);
      ctx.quadraticCurveTo(x - size * 1.2, y - size * 0.8, x, y - size * 1.2);
      ctx.fill();
      ctx.stroke();
      break;
      
    case 'plc':
    case 'rtu':
      // Industrial control shape (hexagon with tech styling)
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        const px = x + size * 1.3 * Math.cos(angle);
        const py = y + size * 1.3 * Math.sin(angle);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      // Add inner circuit pattern
      ctx.strokeStyle = isCompromised ? '#fca5a5' : '#64748b';
      ctx.lineWidth = 0.8;
      ctx.beginPath();
      ctx.arc(x, y, size * 0.6, 0, Math.PI * 2);
      ctx.stroke();
      break;
      
    case 'server':
    case 'database':
      // Server rack shape
      ctx.fillRect(x - size * 0.8, y - size * 1.2, size * 1.6, size * 2.4);
      ctx.strokeRect(x - size * 0.8, y - size * 1.2, size * 1.6, size * 2.4);
      // Add rack lines
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 0.6;
      for (let i = -2; i <= 2; i++) {
        ctx.beginPath();
        ctx.moveTo(x - size * 0.6, y + i * size * 0.4);
        ctx.lineTo(x + size * 0.6, y + i * size * 0.4);
        ctx.stroke();
      }
      break;
      
    case 'sensor':
    case 'actuator':
      // Circular sensor with inner detail
      ctx.beginPath();
      ctx.arc(x, y, size, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      // Add sensor crosshair
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1.0;
      ctx.beginPath();
      ctx.moveTo(x - size * 0.6, y);
      ctx.lineTo(x + size * 0.6, y);
      ctx.moveTo(x, y - size * 0.6);
      ctx.lineTo(x, y + size * 0.6);
      ctx.stroke();
      break;
      
    default:
      // Default circle for unknown types
      ctx.beginPath();
      ctx.arc(x, y, size, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      break;
  }
  
  // Reset shadow
  ctx.shadowColor = 'transparent';
  ctx.shadowBlur = 0;
}

// Function to draw attacker/defender indicators
function drawActorIndicator(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  actorType: 'attacker' | 'defender',
  status: string,
  size: number = 8
) {
  if (actorType === 'attacker') {
    // Draw skull icon for attacker
    ctx.fillStyle = status === 'active' ? '#dc2626' : '#f59e0b';
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1.0;
    
    // Simple skull representation
    ctx.beginPath();
    ctx.arc(x, y - size * 0.3, size * 0.6, 0, Math.PI * 2); // Head
    ctx.fill();
    ctx.stroke();
    
    ctx.fillRect(x - size * 0.8, y - size * 0.1, size * 1.6, size * 0.8); // Jaw
    ctx.strokeRect(x - size * 0.8, y - size * 0.1, size * 1.6, size * 0.8);
    
    // Eye sockets
    ctx.fillStyle = '#1e293b';
    ctx.beginPath();
    ctx.arc(x - size * 0.3, y - size * 0.3, size * 0.15, 0, Math.PI * 2);
    ctx.arc(x + size * 0.3, y - size * 0.3, size * 0.15, 0, Math.PI * 2);
    ctx.fill();
  } else {
    // Draw shield icon for defender
    ctx.fillStyle = status === 'active' ? '#16a34a' : '#3b82f6';
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1.0;
    
    // Shield shape
    ctx.beginPath();
    ctx.moveTo(x, y - size);
    ctx.quadraticCurveTo(x + size * 0.8, y - size * 0.6, x + size * 0.8, y);
    ctx.quadraticCurveTo(x + size * 0.8, y + size * 0.6, x, y + size);
    ctx.quadraticCurveTo(x - size * 0.8, y + size * 0.6, x - size * 0.8, y);
    ctx.quadraticCurveTo(x - size * 0.8, y - size * 0.6, x, y - size);
    ctx.fill();
    ctx.stroke();
    
    // Shield emblem
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 6px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('D', x, y + 2);
  }
}

function drawArrow(
  ctx: CanvasRenderingContext2D,
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  color: string,
  lineWidth: number = 2,
  headSize: number = 10
) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const angle = Math.atan2(dy, dx);

  ctx.strokeStyle = color;
  ctx.lineWidth = lineWidth;
  ctx.beginPath();
  ctx.moveTo(x1, y1);
  ctx.lineTo(x2, y2);
  ctx.stroke();

  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.moveTo(x2, y2);
  ctx.lineTo(
    x2 - headSize * Math.cos(angle - Math.PI / 6),
    y2 - headSize * Math.sin(angle - Math.PI / 6)
  );
  ctx.lineTo(
    x2 - headSize * Math.cos(angle + Math.PI / 6),
    y2 - headSize * Math.sin(angle + Math.PI / 6)
  );
  ctx.closePath();
  ctx.fill();
}

const TopologyCanvas: React.FC<Props> = ({
  assets,
  subnets,
  subnetLinks,
  currentRound,
  compromisedSet,
  width,
  height,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const posRef = useRef<Map<string, { x: number; y: number }>>(new Map());

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const pos = computeLayout(assets, subnets, width, height);
    posRef.current = pos;

    // Publication-quality white background
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    
    // Add subtle grid for publication quality
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 0.5;
    ctx.setLineDash([2, 2]);
    for (let i = 0; i < width; i += 20) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, height);
      ctx.stroke();
    }
    for (let i = 0; i < height; i += 20) {
      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(width, i);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    // Draw subnet bounding boxes
    const subnetLookup = new Map(subnets.map((s) => [s.name, s]));
    const subnetBoxes = new Map<string, { x: number; y: number; w: number; h: number }>();

    for (const sn of subnets) {
      const bounds = getSubnetBounds(assets, pos, sn.name);
      if (!bounds) continue;
      subnetBoxes.set(sn.name, bounds);

      ctx.strokeStyle = sn.color + '66';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([6, 3]);
      ctx.strokeRect(bounds.x, bounds.y, bounds.w, bounds.h);
      ctx.setLineDash([]);

      ctx.fillStyle = sn.color + '18';
      ctx.fillRect(bounds.x, bounds.y, bounds.w, bounds.h);

      // Publication-quality subnet label
      ctx.fillStyle = sn.color;
      ctx.font = 'bold 12px Arial, sans-serif';
      ctx.fillText(`${sn.name}`, bounds.x + 8, bounds.y - 8);
      ctx.font = '10px Arial, sans-serif';
      ctx.fillStyle = '#6b7280';
      ctx.fillText(`${sn.cidr} (${sn.asset_count} assets)`, bounds.x + 8, bounds.y + bounds.h + 16);
    }

    // Draw subnet links
    for (const [sn1, sn2] of subnetLinks) {
      const b1 = subnetBoxes.get(sn1);
      const b2 = subnetBoxes.get(sn2);
      if (!b1 || !b2) continue;
      const cx1 = b1.x + b1.w / 2;
      const cy1 = b1.y + b1.h / 2;
      const cx2 = b2.x + b2.w / 2;
      const cy2 = b2.y + b2.h / 2;

      ctx.strokeStyle = '#475569';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(cx1, cy1);
      ctx.lineTo(cx2, cy2);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Draw assets
    for (const a of assets) {
      const p = pos.get(a.asset_id);
      if (!p) continue;

      const isComp = compromisedSet.has(a.asset_id);
      const sn = subnetLookup.get(a.subnet);
      const baseColor = sn?.color || '#64748b';
      const fill = isComp ? '#ef4444' : baseColor;
      const stroke = isComp ? '#fca5a5' : '#1e293b';
      const size = CRIT_SIZE[a.criticality] || 5;
      const shape = KIND_SHAPES[a.kind] || 'circle';

      // Use cyber icon drawing for enhanced visualization
      drawCyberIcon(ctx, p.x, p.y, size, a.kind, isComp, fill, stroke);

      // Publication-quality asset label
      ctx.fillStyle = '#1e293b';
      ctx.font = 'bold 9px Arial, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      
      // Add background for better readability
      const textWidth = ctx.measureText(a.asset_id).width;
      ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.fillRect(p.x - textWidth/2 - 2, p.y + size + 10, textWidth + 4, 12);
      ctx.fillStyle = '#1e293b';
      ctx.fillText(a.asset_id, p.x, p.y + size + 12);

      // Publication-quality IP label
      if (a.ip) {
        ctx.fillStyle = '#6b7280';
        ctx.font = '8px monospace';
        ctx.textBaseline = 'top';
        const ipWidth = ctx.measureText(a.ip).width;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.95)';
        ctx.fillRect(p.x - ipWidth/2 - 2, p.y + size + 24, ipWidth + 4, 10);
        ctx.fillStyle = '#6b7280';
        ctx.fillText(a.ip, p.x, p.y + size + 24);
      }

      // Glow effect for compromised
      if (isComp) {
        ctx.shadowColor = '#ef4444';
        ctx.shadowBlur = 8;
        drawShape(ctx, p.x, p.y, size, shape, fill + '44', 'transparent');
        ctx.shadowBlur = 0;
        
        // Publication-quality compromise indicator
        ctx.fillStyle = '#dc2626';
        ctx.font = 'bold 10px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('⚠', p.x + size - 8, p.y - size - 8);
      }
    }

    // Draw attacker position
    if (currentRound) {
      const attackerZone = currentRound.attacker_zone;
      // Find average position of assets in attacker zone
      let ax = 40, ay = 40;
      const zoneAssets = assets.filter((a) => a.zone === attackerZone);
      if (zoneAssets.length > 0) {
        let sx = 0, sy = 0, cnt = 0;
        for (const a of zoneAssets) {
          const p = pos.get(a.asset_id);
          if (p) { sx += p.x; sy += p.y; cnt++; }
        }
        if (cnt > 0) { ax = sx / cnt - 30; ay = 30; }
      }

      // Attacker star
      ctx.fillStyle = '#fbbf24';
      ctx.strokeStyle = '#000';
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let i = 0; i < 10; i++) {
        const r = i % 2 === 0 ? 14 : 7;
        const angle = (Math.PI / 5) * i - Math.PI / 2;
        const px = ax + r * Math.cos(angle);
        const py = ay + r * Math.sin(angle);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#fbbf24';
      ctx.font = 'bold 10px sans-serif';
      ctx.fillText(`Attacker@${attackerZone}`, ax + 18, ay + 4);

      // Red attack arrow
      if (currentRound.red_target && currentRound.red_target !== 'NONE') {
        const targetPos = pos.get(currentRound.red_target);
        if (targetPos) {
          drawArrow(ctx, ax, ay + 14, targetPos.x, targetPos.y, '#ef4444', 2.5, 12);
        }
      }

      // Blue defense arrow
      if (currentRound.blue_target && currentRound.blue_target !== 'NONE') {
        const targetPos = pos.get(currentRound.blue_target);
        if (targetPos) {
          const bx = width - 60;
          const by = 30;
          drawArrow(ctx, bx, by, targetPos.x, targetPos.y, '#3b82f6', 2, 10);
        }
      }
    }

    // Legend
    const legendX = width - 180;
    const legendY = height - 130;
    ctx.fillStyle = '#1e293b';
    ctx.fillRect(legendX - 10, legendY - 15, 175, 120);
    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 1;
    ctx.strokeRect(legendX - 10, legendY - 15, 175, 120);

    ctx.font = 'bold 10px sans-serif';
    ctx.fillStyle = '#e2e8f0';
    ctx.fillText('Legend', legendX, legendY);

    let ly = legendY + 16;
    for (const [zone, color] of Object.entries(ZONE_COLORS)) {
      ctx.fillStyle = color;
      ctx.fillRect(legendX, ly - 6, 10, 10);
      ctx.fillStyle = '#cbd5e1';
      ctx.font = '9px sans-serif';
      ctx.fillText(zone, legendX + 15, ly + 2);
      ly += 14;
    }
    // Compromised indicator
    ctx.fillStyle = '#ef4444';
    ctx.fillRect(legendX, ly - 6, 10, 10);
    ctx.fillStyle = '#cbd5e1';
    ctx.fillText('Compromised', legendX + 15, ly + 2);
  }, [assets, subnets, subnetLinks, currentRound, compromisedSet, width, height]);

  useEffect(() => {
    draw();
  }, [draw]);

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      style={{ borderRadius: 8, border: '1px solid #334155' }}
    />
  );
};

export default TopologyCanvas;
