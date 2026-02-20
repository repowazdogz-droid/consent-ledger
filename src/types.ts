/**
 * Consent Ledger Protocol (CNL-1.0) — type definitions
 */

export const schema = 'CNL-1.0' as const;

export type ConsentScope =
  | 'specific'
  | 'categorical'
  | 'standing'
  | 'emergency'
  | 'delegated';

export type ConsentStatus =
  | 'authorised'
  | 'exceeded'
  | 'within_bounds'
  | 'revoked'
  | 'expired'
  | 'pending_ratification';

export type ConstraintType =
  | 'monetary_limit'
  | 'domain_restriction'
  | 'time_window'
  | 'approval_required'
  | 'recipient_restriction'
  | 'frequency_limit'
  | 'custom';

export type ViolationSeverity = 'minor' | 'major' | 'critical';

export interface ConsentConstraint {
  type: ConstraintType;
  description: string;
  parameter: string;
}

export interface AuthorisationEntry {
  id: string;
  timestamp: string;
  principal_id: string;
  agent_id: string;
  scope: ConsentScope;
  description: string;
  constraints: ConsentConstraint[];
  expires_at: string | null;
  revoked: boolean;
  revoked_at: string | null;
  hash: string;
  previous_hash: string;
}

export interface ActionRecord {
  id: string;
  timestamp: string;
  agent_id: string;
  authorisation_id: string;
  action_type: string;
  description: string;
  parameters: Record<string, unknown>;
  clearpath_trace_id?: string;
  hash: string;
  previous_hash: string;
}

export interface ConsentViolation {
  constraint_type: string;
  expected: string;
  actual: string;
  severity: ViolationSeverity;
  description: string;
}

export interface ConsentMatch {
  authorisation_id: string;
  action_id: string;
  status: ConsentStatus;
  violations: ConsentViolation[];
  matched_at: string;
}

export type ScopeCreepPatternType =
  | 'gradual_expansion'
  | 'constraint_erosion'
  | 'frequency_escalation'
  | 'domain_drift'
  | 'authority_inflation';

export interface ScopeCreepPattern {
  id: string;
  pattern_type: ScopeCreepPatternType;
  description: string;
  evidence_ids: string[];
  severity: number;
  first_detected: string;
  occurrences: number;
}

export interface LedgerSnapshot {
  schema: typeof schema;
  principal_id: string;
  authorisations: AuthorisationEntry[];
  actions: ActionRecord[];
}

export interface VerifyResult {
  valid: boolean;
  authorisations_checked: number;
  actions_checked: number;
}

export interface ActionFilters {
  agent_id?: string;
  authorisation_id?: string;
  status?: ConsentStatus;
}
