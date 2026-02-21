import { SimulationData, SubnetInfo, AssetInfo, RoundData } from './types';

const SUBNETS: SubnetInfo[] = [
  { name: 'Corporate LAN', zone: 'IT', cidr: '10.1.0.0/24', color: '#4c78a8', asset_count: 12 },
  { name: 'IT Server Farm', zone: 'IT', cidr: '10.1.1.0/24', color: '#6a89cc', asset_count: 8 },
  { name: 'DMZ Public', zone: 'DMZ', cidr: '172.16.0.0/24', color: '#f58518', asset_count: 6 },
  { name: 'DMZ Services', zone: 'DMZ', cidr: '172.16.1.0/24', color: '#e8a838', asset_count: 4 },
  { name: 'OT Control', zone: 'OT', cidr: '192.168.10.0/24', color: '#54a24b', asset_count: 8 },
  { name: 'OT Field Bus', zone: 'OT', cidr: '192.168.11.0/24', color: '#88d27a', asset_count: 10 },
  { name: 'SCADA', zone: 'OT', cidr: '192.168.20.0/24', color: '#e45756', asset_count: 4 },
  { name: 'Cloud/Mgmt', zone: 'IT', cidr: '10.200.0.0/24', color: '#72b7b2', asset_count: 4 },
];

const SUBNET_LINKS: [string, string][] = [
  ['Corporate LAN', 'IT Server Farm'],
  ['IT Server Farm', 'DMZ Public'],
  ['DMZ Public', 'DMZ Services'],
  ['DMZ Services', 'OT Control'],
  ['OT Control', 'OT Field Bus'],
  ['OT Control', 'SCADA'],
  ['IT Server Farm', 'Cloud/Mgmt'],
  ['Corporate LAN', 'Cloud/Mgmt'],
];

function makeAssets(): AssetInfo[] {
  const assets: AssetInfo[] = [];
  let ipCounter: Record<string, number> = {};

  function nextIp(subnet: SubnetInfo): string {
    const base = subnet.cidr.split('/')[0];
    const parts = base.split('.').map(Number);
    const count = (ipCounter[subnet.name] || 0) + 1;
    ipCounter[subnet.name] = count;
    parts[3] = count + 10;
    return parts.join('.');
  }

  // Corporate LAN
  const corpLan = SUBNETS[0];
  for (let i = 0; i < 8; i++) {
    assets.push({ asset_id: `ws_${i + 1}`, zone: 'IT', kind: 'workstation', ip: nextIp(corpLan), subnet: corpLan.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['smb'] });
  }
  for (let i = 0; i < 2; i++) {
    assets.push({ asset_id: `printer_${i + 1}`, zone: 'IT', kind: 'printer', ip: nextIp(corpLan), subnet: corpLan.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['ipp'] });
  }
  for (let i = 0; i < 2; i++) {
    assets.push({ asset_id: `voip_${i + 1}`, zone: 'IT', kind: 'voip', ip: nextIp(corpLan), subnet: corpLan.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['sip'] });
  }

  // IT Server Farm
  const itSrv = SUBNETS[1];
  for (let i = 0; i < 4; i++) {
    assets.push({ asset_id: `srv_${i + 1}`, zone: 'IT', kind: 'server', ip: nextIp(itSrv), subnet: itSrv.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['ssh', 'http'] });
  }
  assets.push({ asset_id: 'dc_01', zone: 'IT', kind: 'dc', ip: nextIp(itSrv), subnet: itSrv.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['ldap', 'kerberos'] });
  assets.push({ asset_id: 'db_01', zone: 'IT', kind: 'db', ip: nextIp(itSrv), subnet: itSrv.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['mysql'] });
  assets.push({ asset_id: 'backup_01', zone: 'IT', kind: 'backup', ip: nextIp(itSrv), subnet: itSrv.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['rsync'] });
  assets.push({ asset_id: 'srv_mail', zone: 'IT', kind: 'server', ip: nextIp(itSrv), subnet: itSrv.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['smtp'] });

  // DMZ Public
  const dmzPub = SUBNETS[2];
  assets.push({ asset_id: 'gw_dmz_01', zone: 'DMZ', kind: 'gateway', ip: nextIp(dmzPub), subnet: dmzPub.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['ssh', 'vpn'] });
  for (let i = 0; i < 3; i++) {
    assets.push({ asset_id: `web_${i + 1}`, zone: 'DMZ', kind: 'webserver', ip: nextIp(dmzPub), subnet: dmzPub.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['http', 'https'] });
  }
  assets.push({ asset_id: 'dns_01', zone: 'DMZ', kind: 'dns', ip: nextIp(dmzPub), subnet: dmzPub.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['dns'] });
  assets.push({ asset_id: 'mail_01', zone: 'DMZ', kind: 'mailserver', ip: nextIp(dmzPub), subnet: dmzPub.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['smtp', 'imap'] });

  // DMZ Services
  const dmzSvc = SUBNETS[3];
  assets.push({ asset_id: 'hist_data_01', zone: 'DMZ', kind: 'historian', ip: nextIp(dmzSvc), subnet: dmzSvc.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['http'] });
  assets.push({ asset_id: 'jumpbox_01', zone: 'DMZ', kind: 'jumpbox', ip: nextIp(dmzSvc), subnet: dmzSvc.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['ssh', 'rdp'] });
  assets.push({ asset_id: 'proxy_01', zone: 'DMZ', kind: 'proxy', ip: nextIp(dmzSvc), subnet: dmzSvc.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['http'] });
  assets.push({ asset_id: 'proxy_02', zone: 'DMZ', kind: 'proxy', ip: nextIp(dmzSvc), subnet: dmzSvc.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['socks'] });

  // OT Control
  const otCtrl = SUBNETS[4];
  assets.push({ asset_id: 'hmi_ops_01', zone: 'OT', kind: 'hmi', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['rdp'] });
  assets.push({ asset_id: 'hmi_ops_02', zone: 'OT', kind: 'hmi', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['rdp'] });
  assets.push({ asset_id: 'eng_ws_01', zone: 'OT', kind: 'eng_ws', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['ssh'] });
  assets.push({ asset_id: 'plc_industrial_01', zone: 'OT', kind: 'plc', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['modbus', 'prog'] });
  assets.push({ asset_id: 'plc_02', zone: 'OT', kind: 'plc', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['modbus'] });
  for (let i = 0; i < 3; i++) {
    assets.push({ asset_id: `rtu_${i + 1}`, zone: 'OT', kind: 'rtu', ip: nextIp(otCtrl), subnet: otCtrl.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['dnp3'] });
  }

  // OT Field Bus
  const otField = SUBNETS[5];
  for (let i = 0; i < 5; i++) {
    assets.push({ asset_id: `sensor_${i + 1}`, zone: 'OT', kind: 'sensor', ip: nextIp(otField), subnet: otField.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['modbus'] });
  }
  for (let i = 0; i < 3; i++) {
    assets.push({ asset_id: `actuator_${i + 1}`, zone: 'OT', kind: 'actuator', ip: nextIp(otField), subnet: otField.name, criticality: 'LOW', compromised: false, privilege: 'NONE', services: ['modbus'] });
  }
  for (let i = 0; i < 2; i++) {
    assets.push({ asset_id: `ied_${i + 1}`, zone: 'OT', kind: 'ied', ip: nextIp(otField), subnet: otField.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['goose'] });
  }

  // SCADA
  const scada = SUBNETS[6];
  assets.push({ asset_id: 'scada_srv_01', zone: 'OT', kind: 'scada_srv', ip: nextIp(scada), subnet: scada.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['opc-ua'] });
  assets.push({ asset_id: 'scada_hist_01', zone: 'OT', kind: 'historian', ip: nextIp(scada), subnet: scada.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['http'] });
  assets.push({ asset_id: 'alarm_srv_01', zone: 'OT', kind: 'alarm_srv', ip: nextIp(scada), subnet: scada.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['snmp'] });
  assets.push({ asset_id: 'scada_srv_02', zone: 'OT', kind: 'scada_srv', ip: nextIp(scada), subnet: scada.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['opc-ua'] });

  // Cloud/Mgmt
  const cloud = SUBNETS[7];
  assets.push({ asset_id: 'cloud_gw_01', zone: 'IT', kind: 'cloud_gw', ip: nextIp(cloud), subnet: cloud.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['https'] });
  assets.push({ asset_id: 'siem_01', zone: 'IT', kind: 'siem', ip: nextIp(cloud), subnet: cloud.name, criticality: 'HIGH', compromised: false, privilege: 'NONE', services: ['https', 'syslog'] });
  assets.push({ asset_id: 'nms_01', zone: 'IT', kind: 'nms', ip: nextIp(cloud), subnet: cloud.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['snmp'] });
  assets.push({ asset_id: 'vpn_conc_01', zone: 'IT', kind: 'vpn_conc', ip: nextIp(cloud), subnet: cloud.name, criticality: 'MEDIUM', compromised: false, privilege: 'NONE', services: ['ipsec'] });

  return assets;
}

function generateRounds(numRounds: number = 100): RoundData[] {
  const rounds: RoundData[] = [];
  let tankLevel = 50.0;
  let alertsTotal = 0;
  let compromisedCount = 0;
  let attackerZone = 'IT';
  let gpAlarm = 0.5;
  let gpDamage = 0.0;

  const killChain = [
    // Phase 1: RECON (rounds 1-3)
    ...Array(3).fill(null).map((_, i) => ({
      red_action: 'RECON', red_target: 'NONE', red_result: 'RECON_OK: scanning network',
      blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK',
    })),
    // Phase 2: EXPLOIT DMZ (rounds 4-8)
    { red_action: 'EXPLOIT', red_target: 'gw_dmz_01', red_result: 'SUCCESS: USER access via T0887', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'COVER', red_target: 'NONE', red_result: 'COVER_OK', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'EXPLOIT', red_target: 'hist_data_01', red_result: 'SUCCESS: USER access via T0819', blue_action: 'PATCH', blue_target: 'gw_dmz_01', blue_result: 'DEFENSE: patched ssh' },
    { red_action: 'EXECUTE', red_target: 'gw_dmz_01', red_result: 'SUCCESS: privilege escalated to ADMIN', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'EXECUTE', red_target: 'hist_data_01', red_result: 'SUCCESS: privilege escalated to ADMIN', blue_action: 'TUNE', blue_target: 'NONE', blue_result: 'TUNE_OK: sensitivity=0.65' },
    // Phase 3: PIVOT to DMZ (rounds 9-12)
    { red_action: 'PIVOT', red_target: 'gw_dmz_01', red_result: 'PIVOT_OK: attacker now in DMZ', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'COVER', red_target: 'NONE', red_result: 'COVER_OK', blue_action: 'HARDEN', blue_target: 'plc_industrial_01', blue_result: 'DEFENSE: hardening applied' },
    { red_action: 'RECON', red_target: 'NONE', red_result: 'RECON_OK: OT assets visible', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'BRUTE', red_target: 'hmi_ops_01', red_result: 'FAIL: creds resisted', blue_action: 'PATCH', blue_target: 'hmi_ops_01', blue_result: 'DEFENSE: patched rdp' },
    // Phase 4: Compromise OT (rounds 13-20)
    { red_action: 'EXPLOIT', red_target: 'hmi_ops_01', red_result: 'SUCCESS: USER access via T0823', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'EXECUTE', red_target: 'hmi_ops_01', red_result: 'SUCCESS: privilege escalated to ADMIN', blue_action: 'RESTORE', blue_target: 'gw_dmz_01', blue_result: 'DEFENSE: host restored' },
    { red_action: 'COVER', red_target: 'NONE', red_result: 'COVER_OK', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'PIVOT', red_target: 'hmi_ops_01', red_result: 'PIVOT_OK: attacker now in OT', blue_action: 'ISOLATE', blue_target: 'gw_dmz_01', blue_result: 'DEFENSE: asset isolated' },
    { red_action: 'EXPLOIT', red_target: 'plc_industrial_01', red_result: 'FAIL: exploit did not land', blue_action: 'RESTORE', blue_target: 'hmi_ops_01', blue_result: 'DEFENSE: host restored' },
    { red_action: 'EXPLOIT', red_target: 'plc_industrial_01', red_result: 'SUCCESS: USER access via T0866', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
    { red_action: 'EXECUTE', red_target: 'plc_industrial_01', red_result: 'FAIL: privesc failed', blue_action: 'RESTORE', blue_target: 'plc_industrial_01', blue_result: 'DEFENSE: PLC restored to SAFE logic' },
    { red_action: 'EXPLOIT', red_target: 'plc_industrial_01', red_result: 'SUCCESS: USER access via T0866', blue_action: 'MONITOR', blue_target: 'NONE', blue_result: 'MONITOR_OK' },
  ];

  for (let i = 0; i < numRounds; i++) {
    const kc = i < killChain.length ? killChain[i] : null;

    // Simulate zone progression
    if (i >= 9 && i < 16) attackerZone = 'DMZ';
    if (i >= 16) attackerZone = 'OT';

    // Simulate compromised count
    if (i < 4) compromisedCount = 0;
    else if (i < 9) compromisedCount = 2;
    else if (i < 13) compromisedCount = 2;
    else if (i < 18) compromisedCount = Math.min(3, compromisedCount + (Math.random() < 0.3 ? 1 : 0));
    else compromisedCount = Math.min(4, 2 + Math.floor(Math.random() * 3));

    // Tank level dynamics
    if (i < 15) {
      tankLevel += (Math.random() - 0.5) * 3;
    } else if (i < 25) {
      tankLevel += (Math.random() - 0.3) * 4; // slight upward drift
    } else if (i < 40) {
      tankLevel += (Math.random() - 0.2) * 5; // stronger drift from OT compromise
    } else {
      // IMPACT phase: wild oscillations
      const phase = Math.sin(i * 0.3) * 8;
      tankLevel += phase + (Math.random() - 0.5) * 6;
    }
    tankLevel = Math.max(5, Math.min(95, tankLevel));

    // Alerts accumulation
    if (i > 3) alertsTotal += Math.random() < 0.4 ? 1 : 0;
    if (i > 15) alertsTotal += Math.random() < 0.3 ? 1 : 0;

    // GP predictions
    if (i < 10) {
      gpAlarm = 0.5 + Math.random() * 0.1;
      gpDamage = Math.random() * 0.05;
    } else if (i < 25) {
      gpAlarm = 0.5 + (i - 10) * 0.015 + Math.random() * 0.08;
      gpDamage = (i - 10) * 0.01 + Math.random() * 0.05;
    } else {
      gpAlarm = Math.min(0.95, 0.6 + (i - 25) * 0.005 + Math.random() * 0.1);
      gpDamage = Math.min(0.8, 0.15 + (i - 25) * 0.008 + Math.random() * 0.08);
    }

    const alarmFlag = tankLevel > 85 || tankLevel < 15 ? 1 : 0;
    const damageFlag = tankLevel > 92 || tankLevel < 8 ? 1 : 0;

    let redAction = kc?.red_action || (i > 20 ? 'IMPACT' : 'EXPLOIT');
    let redTarget = kc?.red_target || (i > 20 ? 'plc_industrial_01' : 'hmi_ops_01');
    let redResult = kc?.red_result || (i > 20 ? 'CRITICAL: PLC logic modified' : 'FAIL: exploit did not land');
    let blueAction = kc?.blue_action || (compromisedCount > 2 ? 'RESTORE' : 'MONITOR');
    let blueTarget = kc?.blue_target || (compromisedCount > 2 ? 'plc_industrial_01' : 'NONE');
    let blueResult = kc?.blue_result || 'MONITOR_OK';

    rounds.push({
      round: i + 1,
      red_action: redAction,
      red_target: redTarget,
      red_result: redResult,
      blue_action: blueAction,
      blue_target: blueTarget,
      blue_result: blueResult,
      tank_level: Math.round(tankLevel * 10) / 10,
      alerts_total: alertsTotal,
      compromised_count: compromisedCount,
      attacker_zone: attackerZone,
      alarm_flag: alarmFlag,
      damage_flag: damageFlag,
      gp_p_alarm: Math.round(gpAlarm * 1000) / 1000,
      gp_p_damage: Math.round(gpDamage * 1000) / 1000,
      policy_choice: i % 3 === 0 ? 'PROBE:FORCE_OFF/AUTO' : '',
    });
  }

  return rounds;
}

export function generateDemoData(): SimulationData {
  const assets = makeAssets();
  return {
    subnets: SUBNETS,
    assets,
    subnet_links: SUBNET_LINKS,
    rounds: generateRounds(100),
    total_ips: assets.length,
  };
}
