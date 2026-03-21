export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AlertStatus = 'open' | 'resolved' | 'dismissed';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean';
export type RoleName = 'owner' | 'admin' | 'responder' | 'analyst' | 'viewer' | 'msp_operator';

export interface WorkflowComment {
  id: string;
  actor: string;
  message: string;
  mentions?: string[];
  createdAt: string;
}

export interface ApprovalStep {
  step: number;
  role: RoleName | string;
  status: 'pending' | 'approved' | 'rejected';
  actor?: string;
  decidedAt?: string;
  note?: string;
}

export interface WorkflowAction {
  type: string;
  key: string;
  createdAt?: string;
  sentAt?: string;
  detail?: string;
  severity?: string;
  channel?: string;
  target?: string;
}

export interface AlertWorkflow {
  owner?: string;
  note?: string;
  suppressReason?: string;
  confidence?: 'high' | 'medium' | 'low';
  caseStatus?: 'open' | 'triage' | 'ready_to_execute' | 'closed';
  approvalStatus?: 'pending' | 'approved' | 'rejected';
  requestedAction?: 'monitor' | 'revoke' | 'disable';
  dueAt?: string;
  escalationLevel?: number;
  slaBreachedAt?: string;
  isOverdue?: boolean;
  comments?: WorkflowComment[];
  mentions?: string[];
  approvalSteps?: ApprovalStep[];
  approvalHistory?: Array<{ step: number; role: string; decision: string; actor: string; note?: string; timestamp: string }>;
  notifications?: WorkflowAction[];
  automationActions?: WorkflowAction[];
  runbookSteps?: string[];
  updatedAt?: string;
}

export interface Alert {
  id: string;
  userId: string;
  userDisplayName: string;
  userPrincipalName: string;
  roles: string[];
  signInId: string;
  signInTime: string;
  ipAddress?: string;
  country?: string;
  city?: string;
  deviceName?: string;
  deviceOs?: string;
  appName?: string;
  riskScore?: number;
  appTier?: string;
  riskFactors?: Array<{ type: string; score: number; detail: string }>;
  anomalyType: string;
  anomalyLabel: string;
  severity: Severity;
  detail: string;
  status: AlertStatus;
  detectedAt: string;
  actionsTriggered: { action: string; timestamp: string }[];
  resolvedBy?: string;
  resolvedAt?: string;
  workflow?: AlertWorkflow;
}

export interface PrivilegedUser {
  id: string;
  displayName: string;
  userPrincipalName: string;
  mail?: string;
  accountEnabled: boolean;
  roles: string[];
  alertCount: number;
  riskLevel: RiskLevel;
  lastAlert?: Alert;
}

export interface SignIn {
  id: string;
  createdDateTime: string;
  userDisplayName: string;
  userPrincipalName: string;
  userId: string;
  ipAddress?: string;
  location?: {
    city?: string;
    countryOrRegion?: string;
    geoCoordinates?: { latitude: number; longitude: number };
  };
  deviceDetail?: {
    deviceId?: string;
    displayName?: string;
    operatingSystem?: string;
    browser?: string;
  };
  status?: { errorCode: number; failureReason?: string };
  appDisplayName?: string;
  riskLevelAggregated?: string;
}

export interface AlertStats {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolvedToday: number;
  workflow?: {
    total: number;
    overdue: number;
    pendingApproval: number;
    approved: number;
    commented: number;
    assigned: number;
    mentioned?: number;
  };
}

export interface AccessProfile {
  role: RoleName;
  permissions: string[];
}


export interface InvestigationView {
  summary: {
    alertId: string; severity: string; anomalyLabel: string; status: string;
    userDisplayName: string; userPrincipalName: string; roles: string[]; appName: string; recommendedAction: string;
  };
  anomalyFactors: Array<{ type: string; score?: number; detail: string }>;
  signInTimeline: Array<{ type: string; title: string; subtitle: string; detail: string; time: string }>;
  relatedSignIns: Array<{ id: string; time: string; ip?: string; appName?: string; city?: string; country?: string; riskLevel?: string; deviceName?: string; status?: string }>;
  geoContext: { current: { city?: string | null; country?: string | null; ipAddress?: string | null }; knownCountries: string[]; geoVariance: number };
  deviceContext: { current: { name?: string | null; os?: string | null }; knownDevices: string[]; novelty: string };
  entraRiskContext: { score?: number | null; appTier?: string | null; riskEventsSeen: number; recentAnomalies: Array<{ time: string; type: string; severity: string; detail: string }> };
  recommendedAction: { primary: string; rationale: string };
  analystNotes: WorkflowComment[];
  resolutionState: { status: string; approvalStatus: string; resolvedBy?: string | null; resolvedAt?: string | null; suppressReason?: string };
  baselineProfile: { knownIPs: string[]; knownCountries: string[]; knownDevices: string[]; totalSignIns: number; offHoursCount: number; priorAnomalyHistory: Array<{ time: string; type: string; severity: string; detail: string }>; resolutionHistory: Array<{ timestamp: string; action: string; actor: string; note?: string }> };
  evidence: Record<string, unknown>;
  executionCheck?: { canExecute: boolean; state: string; reason: string };
  caseLinks?: Array<{ alertId: string; severity: string; caseStatus: string; approvalStatus: string; detectedAt: string; title: string }>;
}


export interface PolicyDecision {
  suppressed: boolean;
  suppressionRule?: { id?: string; name?: string; reason?: string };
  requiresApproval: boolean;
  notifyRoles: string[];
  allowedActions: string[];
  blockedActions?: Record<string, string[]>;
  autoContain: boolean;
  slaMinutes: number;
  recommendedAction: string;
  rationale: string;
}

export interface RiskPosture {
  summary: {
    monitoredPrivilegedAccounts: number;
    alertsBySeverity: Record<string, number>;
    autoContainedIncidents: number;
    falsePositiveTrend: number;
    mttaHours: number | null;
    mttrHours: number | null;
    averageRiskScore: number;
    retention: { incidentDays?: number; auditDays?: number; reportDays?: number; includeDismissedInTrend?: boolean };
  };
  mostRiskyAdmins: Array<{
    userId: string;
    displayName: string;
    userPrincipalName: string;
    roles: string[];
    score: number;
    level: string;
    openAlerts: number;
    criticalOpen: number;
    recentAnomalies: Array<{ time: string; type: string; severity: string; detail: string }>;
    baseline: { knownCountries: string[]; knownDevices: string[]; knownIPs: string[] };
  }>;
  trend: Array<{ day: string; alerts: number; autoContained: number; dismissed: number; resolved: number }>;
  topAnomalyCategories: Array<{ name: string; count: number }>;
}
