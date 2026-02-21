export interface SubnetInfo {
  name: string;
  zone: string;
  cidr: string;
  color: string;
  asset_count: number;
}

export interface AssetInfo {
  asset_id: string;
  zone: string;
  kind: string;
  ip: string;
  subnet: string;
  criticality: string;
  compromised: boolean;
  privilege: string;
  services: string[];
}

export interface RoundData {
  round: number;
  red_action: string;
  red_target: string;
  red_result: string;
  blue_action: string;
  blue_target: string;
  blue_result: string;
  tank_level: number;
  alerts_total: number;
  compromised_count: number;
  attacker_zone: string;
  alarm_flag: number;
  damage_flag: number;
  gp_p_alarm: number;
  gp_p_damage: number;
  policy_choice: string;
}

export interface SimulationData {
  subnets: SubnetInfo[];
  assets: AssetInfo[];
  subnet_links: [string, string][];
  rounds: RoundData[];
  total_ips: number;
}

export type PlaybackState = 'stopped' | 'playing' | 'paused';
