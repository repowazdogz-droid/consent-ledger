/**
 * Consent Ledger Protocol (CNL-1.0) — scope creep / drift detection
 * Requires 3+ data points to detect a trend.
 */

import type { AuthorisationEntry, ActionRecord, ScopeCreepPattern } from './types';
import { generateId } from './hash';

const MIN_DATA_POINTS = 3;

function parseNumber(value: unknown): number | null {
  if (typeof value === 'number' && !Number.isNaN(value)) return value;
  if (typeof value === 'string') {
    const n = parseFloat(value);
    return Number.isNaN(n) ? null : n;
  }
  return null;
}

function getMonetaryValue(parameters: Record<string, unknown>): number | null {
  return parseNumber(parameters.amount ?? parameters.value ?? parameters.cost);
}

function getLimitForAuth(auth: AuthorisationEntry, type: string): number | null {
  const c = auth.constraints.find((x) => x.type === type);
  return c ? parseNumber(c.parameter) : null;
}

/**
 * Detect gradual_expansion: spending (or similar) creeping toward limit over time.
 */
function detectGradualExpansion(
  authorisations: AuthorisationEntry[],
  actions: ActionRecord[]
): ScopeCreepPattern[] {
  const patterns: ScopeCreepPattern[] = [];
  const byAuth = new Map<string, ActionRecord[]>();
  for (const a of actions) {
    const list = byAuth.get(a.authorisation_id) ?? [];
    list.push(a);
    byAuth.set(a.authorisation_id, list);
  }

  for (const auth of authorisations) {
    const limit = getLimitForAuth(auth, 'monetary_limit');
    if (limit === null) continue;
    const list = (byAuth.get(auth.id) ?? []).slice().sort(
      (x, y) => new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime()
    );
    const values = list.map((a) => ({ id: a.id, ts: a.timestamp, v: getMonetaryValue(a.parameters) }))
      .filter((x): x is typeof x & { v: number } => x.v !== null);
    if (values.length < MIN_DATA_POINTS) continue;
    const ratios = values.map((x) => x.v / limit);
    let increasing = true;
    for (let i = 1; i < ratios.length; i++) {
      if (ratios[i] <= ratios[i - 1]) {
        increasing = false;
        break;
      }
    }
    if (increasing && ratios[ratios.length - 1] >= 0.7) {
      patterns.push({
        id: generateId(),
        pattern_type: 'gradual_expansion',
        description: `Spending or value creeping toward limit (${limit}) over ${values.length} actions`,
        evidence_ids: values.map((x) => x.id),
        severity: Math.min(0.9, 0.3 + ratios[ratios.length - 1] * 0.5),
        first_detected: values[0].ts,
        occurrences: values.length,
      });
    }
  }
  return patterns;
}

/**
 * Detect frequency_escalation: action count per period increasing.
 */
function detectFrequencyEscalation(
  authorisations: AuthorisationEntry[],
  actions: ActionRecord[]
): ScopeCreepPattern[] {
  const patterns: ScopeCreepPattern[] = [];
  const byAuth = new Map<string, ActionRecord[]>();
  for (const a of actions) {
    const list = byAuth.get(a.authorisation_id) ?? [];
    list.push(a);
    byAuth.set(a.authorisation_id, list);
  }

  const periodMs = 24 * 60 * 60 * 1000; // 1 day
  for (const auth of authorisations) {
    const list = (byAuth.get(auth.id) ?? []).slice().sort(
      (x, y) => new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime()
    );
    if (list.length < MIN_DATA_POINTS) continue;
    const buckets = new Map<number, number>();
    for (const a of list) {
      const t = new Date(a.timestamp).getTime();
      const bucket = Math.floor(t / periodMs) * periodMs;
      buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1);
    }
    const counts = Array.from(buckets.entries()).sort((a, b) => a[0] - b[0]).map(([, c]) => c);
    if (counts.length < MIN_DATA_POINTS) continue;
    let escalating = true;
    for (let i = 1; i < counts.length; i++) {
      if (counts[i] <= counts[i - 1]) {
        escalating = false;
        break;
      }
    }
    if (escalating) {
      patterns.push({
        id: generateId(),
        pattern_type: 'frequency_escalation',
        description: `Action frequency increasing over time (${counts.join(' → ')} per period)`,
        evidence_ids: list.slice(-MIN_DATA_POINTS).map((a) => a.id),
        severity: Math.min(0.9, 0.2 + (counts[counts.length - 1] / 10)),
        first_detected: list[0].timestamp,
        occurrences: counts.length,
      });
    }
  }
  return patterns;
}

/**
 * Detect domain_drift: actions increasingly outside original authorised domain.
 * We use constraint parameter as allowed domains and check action parameters.
 */
function detectDomainDrift(
  authorisations: AuthorisationEntry[],
  actions: ActionRecord[]
): ScopeCreepPattern[] {
  const patterns: ScopeCreepPattern[] = [];
  const byAuth = new Map<string, ActionRecord[]>();
  for (const a of actions) {
    const list = byAuth.get(a.authorisation_id) ?? [];
    list.push(a);
    byAuth.set(a.authorisation_id, list);
  }

  for (const auth of authorisations) {
    const domainConstraint = auth.constraints.find((c) => c.type === 'domain_restriction');
    if (!domainConstraint) continue;
    const allowed = domainConstraint.parameter.toLowerCase().split(',').map((s) => s.trim());
    const list = (byAuth.get(auth.id) ?? []).slice().sort(
      (x, y) => new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime()
    );
    if (list.length < MIN_DATA_POINTS) continue;
    const outside: { id: string; ts: string }[] = [];
    for (const a of list) {
      const domain = String(a.parameters.domain ?? a.parameters.category ?? a.parameters.type ?? '').toLowerCase();
      if (!domain) continue;
      const inDomain = allowed.some((d) => domain.includes(d) || d.includes(domain));
      if (!inDomain) outside.push({ id: a.id, ts: a.timestamp });
    }
    if (outside.length >= MIN_DATA_POINTS) {
      patterns.push({
        id: generateId(),
        pattern_type: 'domain_drift',
        description: `Actions increasingly outside authorised domain (${allowed.join(', ')})`,
        evidence_ids: outside.map((x) => x.id),
        severity: Math.min(0.9, 0.3 + outside.length * 0.1),
        first_detected: outside[0].ts,
        occurrences: outside.length,
      });
    }
  }
  return patterns;
}

/**
 * constraint_erosion: same constraint violated repeatedly with increasing severity.
 * We need match results; drift detector can accept pre-computed violations.
 */
function detectConstraintErosion(
  _authorisations: AuthorisationEntry[],
  actions: ActionRecord[],
  violationsByAction: Map<string, { constraint_type: string; severity: string }[]>
): ScopeCreepPattern[] {
  const byType = new Map<string, { actionId: string; severity: string }[]>();
  for (const [actionId, violations] of violationsByAction) {
    for (const v of violations) {
      const list = byType.get(v.constraint_type) ?? [];
      list.push({ actionId, severity: v.severity });
      byType.set(v.constraint_type, list);
    }
  }
  const patterns: ScopeCreepPattern[] = [];
  const severityOrder = { minor: 1, major: 2, critical: 3 };
  for (const [constraintType, list] of byType) {
    if (list.length < MIN_DATA_POINTS) continue;
    const ordered = list.map((x) => severityOrder[x.severity as keyof typeof severityOrder] ?? 0);
    let increasing = true;
    for (let i = 1; i < ordered.length; i++) {
      if (ordered[i] <= ordered[i - 1]) {
        increasing = false;
        break;
      }
    }
    if (increasing) {
      patterns.push({
        id: generateId(),
        pattern_type: 'constraint_erosion',
        description: `Repeated violations of ${constraintType} with increasing severity`,
        evidence_ids: list.map((x) => x.actionId),
        severity: 0.7,
        first_detected: new Date().toISOString(),
        occurrences: list.length,
      });
    }
  }
  return patterns;
}

/**
 * authority_inflation: agent taking actions that would require higher authorisation.
 * Simplified: actions referencing revoked or expired auth, or no auth.
 */
function detectAuthorityInflation(
  authorisations: AuthorisationEntry[],
  actions: ActionRecord[],
  matchStatusByAction: Map<string, string>
): ScopeCreepPattern[] {
  const inflated = actions.filter(
    (a) => ['exceeded', 'revoked', 'expired'].includes(matchStatusByAction.get(a.id) ?? '')
  );
  if (inflated.length < MIN_DATA_POINTS) return [];
  const authIds = new Set(authorisations.map((x) => x.id));
  const noAuth = inflated.filter((a) => !authIds.has(a.authorisation_id));
  if (noAuth.length >= MIN_DATA_POINTS) {
    return [
      {
        id: generateId(),
        pattern_type: 'authority_inflation',
        description: 'Actions without valid authorisation (no auth or exceeded/revoked/expired)',
        evidence_ids: noAuth.map((a) => a.id),
        severity: 0.8,
        first_detected: noAuth[0].timestamp,
        occurrences: noAuth.length,
      },
    ];
  }
  return [];
}

export interface DriftDetectorInput {
  authorisations: AuthorisationEntry[];
  actions: ActionRecord[];
  /** Optional: pre-computed violations per action (for constraint_erosion) */
  violationsByAction?: Map<string, { constraint_type: string; severity: string }[]>;
  /** Optional: pre-computed match status per action (for authority_inflation) */
  matchStatusByAction?: Map<string, string>;
}

/**
 * Run all scope-creep detectors. Returns patterns that have 3+ evidence points.
 */
export function detectScopeCreep(input: DriftDetectorInput): ScopeCreepPattern[] {
  const {
    authorisations,
    actions,
    violationsByAction = new Map(),
    matchStatusByAction = new Map(),
  } = input;

  const all: ScopeCreepPattern[] = [];
  all.push(...detectGradualExpansion(authorisations, actions));
  all.push(...detectFrequencyEscalation(authorisations, actions));
  all.push(...detectDomainDrift(authorisations, actions));
  all.push(...detectConstraintErosion(authorisations, actions, violationsByAction));
  all.push(...detectAuthorityInflation(authorisations, actions, matchStatusByAction));

  return all.filter((p) => p.evidence_ids.length >= MIN_DATA_POINTS);
}
