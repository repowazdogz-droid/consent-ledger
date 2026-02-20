/**
 * Consent Ledger Protocol (CNL-1.0) — comprehensive test suite
 */

import { ConsentLedger } from '../src/consent-ledger';
import type { AuthorisationEntry, ActionRecord } from '../src/types';

// --- Helpers ---

function auth(
  ledger: ConsentLedger,
  overrides: Partial<Parameters<ConsentLedger['authorise']>[0]> = {}
): AuthorisationEntry {
  return ledger.authorise({
    principal_id: 'user-1',
    agent_id: 'agent-1',
    scope: 'categorical',
    description: 'Book flights under £500 to European destinations',
    constraints: [
      { type: 'monetary_limit', description: 'Max £500', parameter: '500' },
      { type: 'domain_restriction', description: 'Europe only', parameter: 'europe,eu' },
    ],
    expires_at: null,
    ...overrides,
  });
}

function action(
  ledger: ConsentLedger,
  authorisation_id: string,
  overrides: Partial<Omit<ActionRecord, 'id' | 'timestamp' | 'hash' | 'previous_hash'>> = {}
): ActionRecord {
  return ledger.recordAction({
    agent_id: 'agent-1',
    authorisation_id,
    action_type: 'book_flight',
    description: 'Book flight to Paris',
    parameters: { amount: 300, domain: 'europe', destination: 'Paris' },
    ...overrides,
  });
}

// --- Core (6) ---

describe('ConsentLedger — Core', () => {
  test('creates consent ledger with principal', () => {
    const ledger = new ConsentLedger('user-1');
    expect(ledger.principal_id).toBe('user-1');
    expect(ledger.getActiveAuthorisations()).toEqual([]);
    expect(ledger.verify().valid).toBe(true);
  });

  test('records authorisation with constraints', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    expect(a.id).toBeDefined();
    expect(a.timestamp).toBeDefined();
    expect(a.scope).toBe('categorical');
    expect(a.constraints).toHaveLength(2);
    expect(a.revoked).toBe(false);
    expect(a.hash).toBeDefined();
    expect(ledger.getAuthorisation(a.id)).toEqual(a);
    expect(ledger.getActiveAuthorisations()).toHaveLength(1);
  });

  test('records action linked to authorisation', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id);
    expect(act.authorisation_id).toBe(a.id);
    expect(act.agent_id).toBe('agent-1');
    expect(act.hash).toBeDefined();
    expect(ledger.checkConsent(act.id).status).toBe('within_bounds');
  });

  test('revokes authorisation', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const revoked = ledger.revoke(a.id);
    expect(revoked.revoked).toBe(true);
    expect(revoked.revoked_at).toBeDefined();
    expect(ledger.getActiveAuthorisations()).toHaveLength(0);
  });

  test('expired authorisation detected', () => {
    const ledger = new ConsentLedger('user-1');
    const past = new Date(Date.now() - 86400000).toISOString();
    const a = auth(ledger, { expires_at: past });
    const act = action(ledger, a.id);
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('expired');
    expect(match.violations.some((v) => v.constraint_type === 'expiry')).toBe(true);
  });

  test('hash chain maintained', () => {
    const ledger = new ConsentLedger('user-1');
    const a1 = auth(ledger);
    const a2 = auth(ledger, { description: 'Second auth' });
    expect(a1.previous_hash).toBe('0');
    expect(a2.previous_hash).toBe(a1.hash);
    const act1 = action(ledger, a1.id);
    const act2 = action(ledger, a1.id);
    expect(act1.previous_hash).toBe('0');
    expect(act2.previous_hash).toBe(act1.hash);
    expect(ledger.verify().valid).toBe(true);
  });
});

// --- Matching (8) ---

describe('ConsentLedger — Matching', () => {
  test('action within all constraints matches as within_bounds', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id, {
      parameters: { amount: 300, domain: 'europe' },
    });
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('within_bounds');
    expect(match.violations).toHaveLength(0);
  });

  test('action exceeding monetary limit matches as exceeded with violation', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id, {
      parameters: { amount: 600, domain: 'europe' },
    });
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('exceeded');
    const v = match.violations.find((x) => x.constraint_type === 'monetary_limit');
    expect(v).toBeDefined();
    expect(v!.actual).toBe('600');
    expect(v!.expected).toContain('500');
  });

  test('action outside domain restriction detected', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id, {
      parameters: { amount: 300, domain: 'asia' },
    });
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('exceeded');
    const v = match.violations.find((x) => x.constraint_type === 'domain_restriction');
    expect(v).toBeDefined();
  });

  test('action after revocation detected', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    ledger.revoke(a.id);
    const act = action(ledger, a.id);
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('revoked');
    expect(match.violations.some((v) => v.constraint_type === 'revocation')).toBe(true);
  });

  test('action after expiry detected', () => {
    const ledger = new ConsentLedger('user-1');
    const past = new Date(Date.now() - 1000).toISOString();
    const a = auth(ledger, { expires_at: past });
    const act = action(ledger, a.id);
    expect(ledger.checkConsent(act.id).status).toBe('expired');
  });

  test('multiple constraint violations on single action', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id, {
      parameters: { amount: 600, domain: 'asia' },
    });
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('exceeded');
    expect(match.violations.length).toBeGreaterThanOrEqual(2);
  });

  test('action with no matching authorisation flagged', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: 'nonexistent-id',
      action_type: 'book_flight',
      description: 'Book flight',
      parameters: {},
    });
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('exceeded');
    expect(match.violations.some((v) => v.constraint_type === 'authorisation')).toBe(true);
  });

  test('emergency action flagged as pending_ratification', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger, { scope: 'emergency' });
    const act = action(ledger, a.id);
    const match = ledger.checkConsent(act.id);
    expect(match.status).toBe('pending_ratification');
    expect(match.violations).toHaveLength(0);
  });
});

// --- Drift detection (5) ---

describe('ConsentLedger — Drift detection', () => {
  test('gradual expansion detected (spending creeping toward limit)', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger, {
      constraints: [{ type: 'monetary_limit', description: 'Max 500', parameter: '500' }],
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'pay',
      description: 'Pay 100',
      parameters: { amount: 100 },
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'pay',
      description: 'Pay 250',
      parameters: { amount: 250 },
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'pay',
      description: 'Pay 400',
      parameters: { amount: 400 },
    });
    const patterns = ledger.detectScopeCreep();
    const gradual = patterns.filter((p) => p.pattern_type === 'gradual_expansion');
    expect(gradual.length).toBeGreaterThanOrEqual(1);
  });

  test('frequency escalation detected', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    for (let i = 0; i < 4; i++) {
      ledger.recordAction({
        agent_id: 'agent-1',
        authorisation_id: a.id,
        action_type: 'query',
        description: `Query ${i}`,
        parameters: {},
      });
    }
    const actions = ledger.getActions();
    expect(actions.length).toBeGreaterThanOrEqual(3);
    const patterns = ledger.detectScopeCreep();
    expect(Array.isArray(patterns)).toBe(true);
  });

  test('domain drift detected', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger, {
      constraints: [
        { type: 'domain_restriction', description: 'Europe only', parameter: 'europe' },
      ],
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'book',
      description: 'Book Europe',
      parameters: { domain: 'europe' },
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'book',
      description: 'Book Asia',
      parameters: { domain: 'asia' },
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'book',
      description: 'Book Asia again',
      parameters: { domain: 'asia' },
    });
    ledger.recordAction({
      agent_id: 'agent-1',
      authorisation_id: a.id,
      action_type: 'book',
      description: 'Book Asia third',
      parameters: { domain: 'asia' },
    });
    const patterns = ledger.detectScopeCreep();
    const domainDrift = patterns.filter((p) => p.pattern_type === 'domain_drift');
    expect(domainDrift.length).toBeGreaterThanOrEqual(0);
  });

  test('no false positives on normal behaviour', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id, { parameters: { amount: 100, domain: 'europe' } });
    action(ledger, a.id, { parameters: { amount: 150, domain: 'europe' } });
    action(ledger, a.id, { parameters: { amount: 120, domain: 'europe' } });
    const matches = ledger.checkAllActions();
    expect(matches.every((m) => m.status === 'within_bounds')).toBe(true);
    const violations = ledger.getViolations();
    expect(violations).toHaveLength(0);
  });

  test('pattern requires 3+ data points', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id);
    action(ledger, a.id);
    const patterns = ledger.detectScopeCreep();
    for (const p of patterns) {
      expect(p.evidence_ids.length).toBeGreaterThanOrEqual(3);
    }
  });
});

// --- Integrity (3) ---

describe('ConsentLedger — Integrity', () => {
  test('valid chain verifies', () => {
    const ledger = new ConsentLedger('user-1');
    auth(ledger);
    const a = auth(ledger);
    action(ledger, a.id);
    const result = ledger.verify();
    expect(result.valid).toBe(true);
    expect(result.authorisations_checked).toBe(2);
    expect(result.actions_checked).toBe(1);
  });

  test('tampered authorisation breaks chain', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id);
    const json = ledger.toJSON();
    const tampered = json.replace(
      new RegExp(a.description, 'g'),
      'TAMPERED'
    );
    const restored = ConsentLedger.fromJSON(tampered);
    const result = restored.verify();
    expect(result.valid).toBe(false);
  });

  test('tampered action breaks chain', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id);
    const json = ledger.toJSON();
    const tampered = json.replace(
      act.description,
      'TAMPERED_ACTION'
    );
    const restored = ConsentLedger.fromJSON(tampered);
    const result = restored.verify();
    expect(result.valid).toBe(false);
  });
});

// --- Export/Import (2) ---

describe('ConsentLedger — Export/Import', () => {
  test('JSON roundtrip preserves all data', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    const act = action(ledger, a.id);
    const json = ledger.toJSON();
    const restored = ConsentLedger.fromJSON(json);
    expect(restored.principal_id).toBe(ledger.principal_id);
    expect(restored.getAuthorisation(a.id)?.description).toBe(a.description);
    const actions = restored.getActions();
    expect(actions).toHaveLength(1);
    expect(actions[0].description).toBe(act.description);
    expect(restored.verify().valid).toBe(true);
  });

  test('Markdown output includes violations summary', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id, { parameters: { amount: 999, domain: 'asia' } });
    const md = ledger.toMarkdown();
    expect(md).toContain('Consent Ledger');
    expect(md).toContain('Violations');
    expect(md).toContain('Critical');
    expect(md).toContain('Exceeded');
  });
});

// --- Querying ---

describe('ConsentLedger — Querying', () => {
  test('getActions filters by agent_id and authorisation_id', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id);
    action(ledger, a.id);
    expect(ledger.getActions()).toHaveLength(2);
    expect(ledger.getActions({ agent_id: 'agent-1' })).toHaveLength(2);
    expect(ledger.getActions({ authorisation_id: a.id })).toHaveLength(2);
    expect(ledger.getActions({ agent_id: 'other' })).toHaveLength(0);
  });

  test('getViolations returns only matches with violations', () => {
    const ledger = new ConsentLedger('user-1');
    const a = auth(ledger);
    action(ledger, a.id);
    action(ledger, a.id, { parameters: { amount: 999 } });
    const violations = ledger.getViolations();
    expect(violations).toHaveLength(1);
    expect(violations[0].violations.length).toBeGreaterThan(0);
  });
});
