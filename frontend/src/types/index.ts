export type UserRole = 'admin' | 'analyst' | 'viewer';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export type ScanStatus = 'idle' | 'running' | 'completed' | 'failed';

export interface User {
  id: string;
  email: string;
  role: UserRole;
}

export interface Asset {
  id: string;
  hostname: string;
  ip: string;
  tlsVersion: string;
  riskScore: number;
  riskLevel: RiskLevel;
  pqcStatus: 'compliant' | 'non-compliant' | 'unknown';
  lastScanned: string;
}

export interface ScanJob {
  id: string;
  target: string;
  status: ScanStatus;
  progress: number;
  createdAt: string;
}

export interface RiskDistribution {
  category: RiskLevel;
  count: number;
}