/**
 * Consent Ledger Protocol (CNL-1.0)
 * Tamper-evident records of what a human authorised an AI agent to do,
 * what the agent actually did, and whether those two things match.
 *
 * Zero external dependencies (Node.js crypto only).
 */

export { schema } from './types';
export type {
  ConsentScope,
  ConsentStatus,
  ConstraintType,
  ViolationSeverity,
  ConsentConstraint,
  AuthorisationEntry,
  ActionRecord,
  ConsentViolation,
  ConsentMatch,
  ScopeCreepPatternType,
  ScopeCreepPattern,
  LedgerSnapshot,
  VerifyResult,
  ActionFilters,
} from './types';

export { ConsentLedger } from './consent-ledger';
export { matchConsent, type MatcherContext } from './matcher';
export { detectScopeCreep, type DriftDetectorInput } from './drift-detector';
export {
  buildComplianceReport,
  buildAuditReport,
  reportToMarkdown,
  type ComplianceReport,
  type AuditReport,
} from './reporter';
export { sha256, chainHash, generateId } from './hash';
