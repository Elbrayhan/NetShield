export interface Device {
  id: string;
  name: string;
  ip: string;
  mac: string;
  department: string;
  status: 'allowed' | 'restricted' | 'blocked';
  os: string;
  lastActive: string;
  threatLevel: 'low' | 'medium' | 'high';
  trafficBytes: number;
}

export interface NetworkLog {
  id: string;
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS';
  bytes: number;
  status: 'allowed' | 'blocked';
  deviceName?: string;
  flagged: boolean;
  threatDescription?: string;
  country?: string;
  category?: string;
}

export interface BlockedRule {
  id: string;
  ip: string;
  reason: string;
  createdAt: string;
  type: 'auto' | 'manual';
  severity: 'medium' | 'high' | 'critical';
}

export interface MFAConfig {
  enabled: boolean;
  method: 'authenticator' | 'sms' | 'email';
  phoneNumber?: string;
  email?: string;
  mfaVerified: boolean;
  recoveryCodes: string[];
}

export interface BackupConfig {
  frequency: 'hourly' | 'daily' | 'weekly';
  provider: 'Google Cloud Storage' | 'Amazon S3' | 'Azure Blob';
  encrypted: boolean;
  lastBackupTime: string;
  status: 'success' | 'backing_up' | 'failed';
}

export interface EmailNotificationSettings {
  enabled: boolean;
  recipients: string[];
  minimumSeverity: 'low' | 'medium' | 'high' | 'critical';
}

export interface NetworkStats {
  blockedCount: number;
  allowedCount: number;
  criticalAlerts: number;
  activeIpBlockCount: number;
  cpuLoad: number;
  ramUsage: number;
  networkThroughput: number; // in Mbps
}

export interface SecurityIncident {
  id: string;
  title: string;
  ip: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'active' | 'resolved';
  timestamp: string;
  description: string;
}

export interface EmailAlert {
  id: string;
  ip: string;
  timestamp: string;
  recipient: string;
  subject: string;
  body: string;
  status: 'sent' | 'delivered' | 'failed';
}

export interface UserSession {
  id: string;
  name: string;
  email: string;
  assignedIp: string;
}

export interface FinalTestState {
  status: 'not_started' | 'running' | 'completed' | 'failed';
  progress: number;
  logs: string[];
  score: number;
  certified: boolean;
  completedAt: string | null;
}

