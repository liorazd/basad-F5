export interface PoolMember {
  id: string;
  ipAddress: string;
  port: string;
}

export interface VIPRequest {
  id: string;
  requestType?: 'new_vip' | 'add_port';
  vipName: string;
  vipIP?: string;
  target?: string;
  targetName?: string;
  email: string;
  ports: string[];
  ssl: boolean;
  requireSni?: boolean;
  pfxFile?: File;
  pfxFileBase64?: string;
  pfxFileName?: string;
  pfxFileType?: string;
  pfxFileSize?: number;
  pfxPassword?: string;
  poolMembers: PoolMember[];
  monitorUri?: string;
  monitorRecv?: string;
  status: 'pending' | 'approved' | 'declined';
  createdAt: string;
  declineReason?: string;
  assignedIP?: string;
}

export interface SnatMapping {
  vip_cidr: string;
  // Exactly one of these is set per mapping:
  snat_ip?: string;        // fixed SNAT address shared by the whole range
  snat_network?: string;   // host-preserving remap target (172.20.63.157 -> 172.20.7.157)
}

export interface F5Config {
  dmzUrl: string;
  dcUrl: string;
  username: string;
  password: string;
}

export interface F5Environment {
  id: string;
  name: string;
  url: string;
  configured_url?: string;
  authenticated?: boolean;
  nodes?: string[];
  member_networks?: string[];
  snat_mappings?: SnatMapping[];
}

export interface EmailNotification {
  to: string;
  subject: string;
  body: string;
  type: 'success' | 'declined';
}

export interface F5VIPPort {
  port: string;
  vsName: string;
  pool?: string;
  profiles?: string[];
  rules?: string[];
  mode?: 'vs' | 'irule';
}

export interface F5VIP {
  name: string;
  ip: string;
  target: string;
  target_name?: string;
  ports: F5VIPPort[];
  // 'irule' when this VIP is a single all-ports / port-list VS that dispatches
  // ports via a switch [TCP::local_port] iRule; 'vs' for the classic one-VS-per-port.
  mode?: 'vs' | 'irule';
  rules?: string[];
}

export interface IRuleVersion {
  version: number;
  name: string;
  path: string;
}

export interface CertInfo {
  commonName?: string;
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  sans?: string[];
  name?: string;
  fullPath?: string;
  serialNumber?: string;
  profile?: string;
  certRef?: string;
  keyRef?: string;
}

export interface AuditEntry {
  id: string;
  ts: string;
  user: string;
  user_type: 'admin' | 'api' | 'requester';
  action: string;
  target: string;
  result: string;
  client_ip?: string;
  revertible: boolean;
  reverted: boolean;
  reverted_at?: string | null;
  reverted_by?: string | null;
  details?: Record<string, unknown>;
}

export interface F5StatusMember {
  name: string;
  ip?: string;
  port?: string;
  availability: string;
  enabled: string;
  state: 'up' | 'down' | 'unknown';
  reason?: string;
  key?: string;
  since?: string;
}

export interface F5StatusVip {
  vsName: string;
  ip: string;
  port: string;
  pool: string;
  monitor: string;
  target: string;
  target_name?: string;
  members: F5StatusMember[];
  summary: 'up' | 'down' | 'unknown' | 'no-members';
  // 'irule' when this row is one dispatch case of a switch [TCP::local_port]
  // iRule (port -> pool); 'vs' for a classic one-VS-per-port row.
  mode?: 'vs' | 'irule';
  condition?: string | null;
  // Persistence profile name attached to the VS (empty when stateless).
  persist?: string;
}

export interface PoolMemberStat {
  name: string;
  ip: string;
  port: string;
  state: 'up' | 'down' | 'unknown';
  curConns: number;
  totConns: number;
  maxConns: number;
  pktsIn: number;
  pktsOut: number;
  bitsIn: number;
  bitsOut: number;
}

export interface PoolStats {
  pool: string;
  ts: string;
  members: PoolMemberStat[];
  totals: {
    curConns: number;
    totConns: number;
    pktsIn: number;
    pktsOut: number;
    bitsIn: number;
    bitsOut: number;
  };
}

export interface NodeHistoryEntry {
  event: string;
  ts: string;
  key: string;
  from: string;
  to: string;
  details?: Record<string, unknown>;
}
