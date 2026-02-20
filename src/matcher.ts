/**
 * Consent Ledger Protocol (CNL-1.0) — consent vs action matching
 */

import type {
  AuthorisationEntry,
  ActionRecord,
  ConsentMatch,
  ConsentViolation,
  ConsentStatus,
  ConsentConstraint,
} from './types';
import { schema } from './types';

const GENESIS = '0';

function isoNow(): string {
  return new Date().toISOString();
}

function parseNumber(value: unknown): number | null {
  if (typeof value === 'number' && !Number.isNaN(value)) return value;
  if (typeof value === 'string') {
    const n = parseFloat(value);
    return Number.isNaN(n) ? null : n;
  }
  return null;
}

function checkMonetaryLimit(
  constraint: ConsentConstraint,
  parameters: Record<string, unknown>
): ConsentViolation | null {
  const limit = parseNumber(constraint.parameter);
  if (limit === null) return null;
  const amount = parseNumber(parameters.amount ?? parameters.value ?? parameters.cost);
  if (amount === null) return null;
  if (amount > limit) {
    return {
      constraint_type: 'monetary_limit',
      expected: `≤ ${constraint.parameter}`,
      actual: String(amount),
      severity: amount > limit * 1.5 ? 'critical' : 'major',
      description: constraint.description,
    };
  }
  return null;
}

function checkDomainRestriction(
  constraint: ConsentConstraint,
  parameters: Record<string, unknown>
): ConsentViolation | null {
  const allowed = constraint.parameter.toLowerCase().split(',').map((s) => s.trim());
  const domain = String(parameters.domain ?? parameters.category ?? parameters.type ?? '').toLowerCase();
  if (!domain) return null;
  const inDomain = allowed.some((d) => domain.includes(d) || d.includes(domain));
  if (!inDomain) {
    return {
      constraint_type: 'domain_restriction',
      expected: allowed.join(', '),
      actual: domain,
      severity: 'major',
      description: constraint.description,
    };
  }
  return null;
}

function checkTimeWindow(
  constraint: ConsentConstraint,
  actionTimestamp: string
): ConsentViolation | null {
  // parameter e.g. "2024-01-01/2024-12-31" or "09:00/17:00"
  const [start, end] = constraint.parameter.split('/').map((s) => s.trim());
  if (!start || !end) return null;
  const t = new Date(actionTimestamp).getTime();
  const startDate = new Date(start).getTime();
  const endDate = new Date(end).getTime();
  if (!Number.isNaN(startDate) && !Number.isNaN(endDate)) {
    if (t < startDate || t > endDate) {
      return {
        constraint_type: 'time_window',
        expected: `${start} – ${end}`,
        actual: actionTimestamp,
        severity: 'major',
        description: constraint.description,
      };
    }
  }
  return null;
}

function checkApprovalRequired(
  constraint: ConsentConstraint,
  parameters: Record<string, unknown>
): ConsentViolation | null {
  const approved = parameters.approval_obtained ?? parameters.approved;
  if (approved !== true && approved !== 'true') {
    return {
      constraint_type: 'approval_required',
      expected: 'approval obtained',
      actual: String(approved ?? 'none'),
      severity: 'major',
      description: constraint.description,
    };
  }
  return null;
}

function checkRecipientRestriction(
  constraint: ConsentConstraint,
  parameters: Record<string, unknown>
): ConsentViolation | null {
  const allowed = constraint.parameter.split(',').map((s) => s.trim().toLowerCase());
  const recipient = String(parameters.recipient ?? parameters.to ?? parameters.payee ?? '').toLowerCase();
  if (!recipient) return null;
  const allowedMatch = allowed.some((r) => recipient.includes(r) || r.includes(recipient));
  if (!allowedMatch) {
    return {
      constraint_type: 'recipient_restriction',
      expected: allowed.join(', '),
      actual: recipient,
      severity: 'critical',
      description: constraint.description,
    };
  }
  return null;
}

function checkFrequencyLimit(
  _constraint: ConsentConstraint,
  _parameters: Record<string, unknown>,
  context: { actionCountForAuthInPeriod?: number; limit?: number }
): ConsentViolation | null {
  const limit = context.limit ?? parseNumber(_constraint.parameter);
  const count = context.actionCountForAuthInPeriod ?? 0;
  if (limit === null || limit === undefined) return null;
  if (count > limit) {
    return {
      constraint_type: 'frequency_limit',
      expected: `≤ ${limit} in period`,
      actual: String(count),
      severity: count > limit * 2 ? 'critical' : 'major',
      description: _constraint.description,
    };
  }
  return null;
}

function checkCustom(
  constraint: ConsentConstraint,
  action: ActionRecord
): ConsentViolation | null {
  const descMatch = action.description.toLowerCase().includes(constraint.description.toLowerCase());
  if (!descMatch) {
    return {
      constraint_type: 'custom',
      expected: constraint.description,
      actual: action.description,
      severity: 'minor',
      description: constraint.description,
    };
  }
  return null;
}

export interface MatcherContext {
  actionCountByAuthorisationInPeriod?: Map<string, number>;
  frequencyLimitByConstraint?: Map<string, number>;
}

/**
 * Compare a single action against its authorisation and return a ConsentMatch.
 */
export function matchConsent(
  authorisation: AuthorisationEntry | null,
  action: ActionRecord,
  context?: MatcherContext
): ConsentMatch {
  const matched_at = isoNow();

  if (!authorisation) {
    return {
      authorisation_id: action.authorisation_id,
      action_id: action.id,
      status: 'exceeded',
      violations: [
        {
          constraint_type: 'authorisation',
          expected: 'valid authorisation',
          actual: 'none',
          severity: 'critical',
          description: 'Action has no matching authorisation',
        },
      ],
      matched_at,
    };
  }

  if (authorisation.revoked) {
    return {
      authorisation_id: authorisation.id,
      action_id: action.id,
      status: 'revoked',
      violations: [
        {
          constraint_type: 'revocation',
          expected: 'active authorisation',
          actual: `revoked at ${authorisation.revoked_at}`,
          severity: 'critical',
          description: 'Action performed after authorisation was revoked',
        },
      ],
      matched_at,
    };
  }

  if (authorisation.expires_at && new Date(authorisation.expires_at) < new Date(action.timestamp)) {
    return {
      authorisation_id: authorisation.id,
      action_id: action.id,
      status: 'expired',
      violations: [
        {
          constraint_type: 'expiry',
          expected: `valid before ${authorisation.expires_at}`,
          actual: action.timestamp,
          severity: 'critical',
          description: 'Action performed after authorisation expired',
        },
      ],
      matched_at,
    };
  }

  if (authorisation.scope === 'emergency') {
    return {
      authorisation_id: authorisation.id,
      action_id: action.id,
      status: 'pending_ratification',
      violations: [],
      matched_at,
    };
  }

  const violations: ConsentViolation[] = [];

  for (const constraint of authorisation.constraints) {
    let v: ConsentViolation | null = null;
    switch (constraint.type) {
      case 'monetary_limit':
        v = checkMonetaryLimit(constraint, action.parameters);
        break;
      case 'domain_restriction':
        v = checkDomainRestriction(constraint, action.parameters);
        break;
      case 'time_window':
        v = checkTimeWindow(constraint, action.timestamp);
        break;
      case 'approval_required':
        v = checkApprovalRequired(constraint, action.parameters);
        break;
      case 'recipient_restriction':
        v = checkRecipientRestriction(constraint, action.parameters);
        break;
      case 'frequency_limit': {
        const count = context?.actionCountByAuthorisationInPeriod?.get(authorisation.id);
        const limit = context?.frequencyLimitByConstraint?.get(constraint.parameter) ?? parseNumber(constraint.parameter);
        v = checkFrequencyLimit(constraint, action.parameters, {
          actionCountForAuthInPeriod: count,
          limit: limit ?? undefined,
        });
        break;
      }
      case 'custom':
        v = checkCustom(constraint, action);
        break;
      default:
        break;
    }
    if (v) violations.push(v);
  }

  const status: ConsentStatus =
    violations.length > 0 ? 'exceeded' : 'within_bounds';

  return {
    authorisation_id: authorisation.id,
    action_id: action.id,
    status,
    violations,
    matched_at,
  };
}

// Ensure schema is referenced for export
void schema;
