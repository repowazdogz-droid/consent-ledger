/**
 * Consent Ledger Protocol (CNL-1.0) — main ConsentLedger class
 */

import type {
  AuthorisationEntry,
  ActionRecord,
  ConsentMatch,
  ConsentStatus,
  ScopeCreepPattern,
  LedgerSnapshot,
  VerifyResult,
  ActionFilters,
} from './types';
import { schema } from './types';
import { generateId, chainHash, authorisationPayload, actionPayload } from './hash';
import { matchConsent, type MatcherContext } from './matcher';
import { detectScopeCreep, type DriftDetectorInput } from './drift-detector';
import { buildComplianceReport, reportToMarkdown } from './reporter';

const GENESIS = '0';

export class ConsentLedger {
  readonly principal_id: string;
  private authorisations: AuthorisationEntry[] = [];
  private actions: ActionRecord[] = [];
  private authById: Map<string, AuthorisationEntry> = new Map();
  private actionById: Map<string, ActionRecord> = new Map();

  constructor(principal_id: string) {
    this.principal_id = principal_id;
  }

  authorise(
    entry: Omit<
      AuthorisationEntry,
      'id' | 'timestamp' | 'hash' | 'previous_hash' | 'revoked' | 'revoked_at'
    >
  ): AuthorisationEntry {
    const id = generateId();
    const timestamp = new Date().toISOString();
    const previous_hash = this.authorisations.length === 0
      ? GENESIS
      : this.authorisations[this.authorisations.length - 1].hash;
    const full: AuthorisationEntry = {
      ...entry,
      id,
      timestamp,
      revoked: false,
      revoked_at: null,
      previous_hash,
      hash: '',
    };
    full.hash = chainHash(previous_hash, authorisationPayload(full));
    this.authorisations.push(full);
    this.authById.set(id, full);
    return full;
  }

  revoke(authorisation_id: string): AuthorisationEntry {
    const auth = this.authById.get(authorisation_id);
    if (!auth) throw new Error(`Authorisation not found: ${authorisation_id}`);
    if (auth.revoked) return auth;
    const revoked_at = new Date().toISOString();
    const updated: AuthorisationEntry = {
      ...auth,
      revoked: true,
      revoked_at,
      hash: '',
    };
    updated.hash = chainHash(auth.previous_hash, authorisationPayload(updated));
    const idx = this.authorisations.findIndex((a) => a.id === authorisation_id);
    this.authorisations[idx] = updated;
    this.authById.set(authorisation_id, updated);
    return updated;
  }

  getAuthorisation(id: string): AuthorisationEntry | null {
    return this.authById.get(id) ?? null;
  }

  getActiveAuthorisations(): AuthorisationEntry[] {
    const now = new Date();
    return this.authorisations.filter(
      (a) =>
        !a.revoked &&
        (!a.expires_at || new Date(a.expires_at) > now)
    );
  }

  recordAction(
    action: Omit<ActionRecord, 'id' | 'timestamp' | 'hash' | 'previous_hash'>
  ): ActionRecord {
    const id = generateId();
    const timestamp = new Date().toISOString();
    const previous_hash = this.actions.length === 0
      ? GENESIS
      : this.actions[this.actions.length - 1].hash;
    const full: ActionRecord = {
      ...action,
      id,
      timestamp,
      previous_hash,
      hash: '',
    };
    full.hash = chainHash(previous_hash, actionPayload(full));
    this.actions.push(full);
    this.actionById.set(id, full);
    return full;
  }

  private buildMatcherContext(): MatcherContext {
    const periodMs = 24 * 60 * 60 * 1000;
    const actionCountByAuthorisationInPeriod = new Map<string, number>();
    for (const a of this.actions) {
      const bucket = Math.floor(new Date(a.timestamp).getTime() / periodMs) * periodMs;
      const key = `${a.authorisation_id}:${bucket}`;
      actionCountByAuthorisationInPeriod.set(
        a.authorisation_id,
        (actionCountByAuthorisationInPeriod.get(a.authorisation_id) ?? 0) + 1
      );
    }
    return { actionCountByAuthorisationInPeriod };
  }

  checkConsent(action_id: string): ConsentMatch {
    const action = this.actionById.get(action_id);
    if (!action) throw new Error(`Action not found: ${action_id}`);
    const auth = this.getAuthorisation(action.authorisation_id);
    const context = this.buildMatcherContext();
    return matchConsent(auth ?? null, action, context);
  }

  checkAllActions(): ConsentMatch[] {
    const context = this.buildMatcherContext();
    return this.actions.map((action) => {
      const auth = this.getAuthorisation(action.authorisation_id);
      return matchConsent(auth ?? null, action, context);
    });
  }

  detectScopeCreep(): ScopeCreepPattern[] {
    const matches = this.checkAllActions();
    const violationsByAction = new Map<string, { constraint_type: string; severity: string }[]>();
    const matchStatusByAction = new Map<string, string>();
    for (const m of matches) {
      matchStatusByAction.set(m.action_id, m.status);
      if (m.violations.length > 0) {
        violationsByAction.set(
          m.action_id,
          m.violations.map((v) => ({ constraint_type: v.constraint_type, severity: v.severity }))
        );
      }
    }
    const input: DriftDetectorInput = {
      authorisations: this.authorisations,
      actions: this.actions,
      violationsByAction,
      matchStatusByAction,
    };
    return detectScopeCreep(input);
  }

  verify(): VerifyResult {
    let authOk = true;
    let prev = GENESIS;
    for (const a of this.authorisations) {
      if (a.previous_hash !== prev) authOk = false;
      const expected = chainHash(a.previous_hash, authorisationPayload(a));
      if (a.hash !== expected) authOk = false;
      prev = a.hash;
    }
    let actionOk = true;
    let prevAction = GENESIS;
    for (const a of this.actions) {
      if (a.previous_hash !== prevAction) actionOk = false;
      const expected = chainHash(a.previous_hash, actionPayload(a));
      if (a.hash !== expected) actionOk = false;
      prevAction = a.hash;
    }
    return {
      valid: authOk && actionOk,
      authorisations_checked: this.authorisations.length,
      actions_checked: this.actions.length,
    };
  }

  toJSON(): string {
    const snapshot: LedgerSnapshot = {
      schema,
      principal_id: this.principal_id,
      authorisations: this.authorisations,
      actions: this.actions,
    };
    return JSON.stringify(snapshot, null, 2);
  }

  toMarkdown(): string {
    const matches = this.checkAllActions();
    const scopeCreep = this.detectScopeCreep();
    const integrity = this.verify();
    const snapshot: LedgerSnapshot = {
      schema,
      principal_id: this.principal_id,
      authorisations: this.authorisations,
      actions: this.actions,
    };
    const compliance = buildComplianceReport(snapshot, matches, scopeCreep, integrity);
    return reportToMarkdown(compliance, {
      includeScopeCreep: true,
      scopeCreepPatterns: scopeCreep,
    });
  }

  static fromJSON(json: string): ConsentLedger {
    const snapshot: LedgerSnapshot = JSON.parse(json);
    if (snapshot.schema !== schema) throw new Error(`Invalid schema: expected ${schema}`);
    const ledger = new ConsentLedger(snapshot.principal_id);
    const L = ledger as unknown as {
      authorisations: AuthorisationEntry[];
      actions: ActionRecord[];
      authById: Map<string, AuthorisationEntry>;
      actionById: Map<string, ActionRecord>;
    };
    L.authorisations = snapshot.authorisations;
    L.actions = snapshot.actions;
    L.authById = new Map(snapshot.authorisations.map((a) => [a.id, a]));
    L.actionById = new Map(snapshot.actions.map((a) => [a.id, a]));
    return ledger;
  }

  getActions(filters?: ActionFilters): ActionRecord[] {
    let list = this.actions.slice();
    if (filters?.agent_id) list = list.filter((a) => a.agent_id === filters.agent_id);
    if (filters?.authorisation_id) list = list.filter((a) => a.authorisation_id === filters.authorisation_id);
    if (filters?.status) {
      const matches = this.checkAllActions();
      const matchByAction = new Map(matches.map((m) => [m.action_id, m]));
      list = list.filter((a) => matchByAction.get(a.id)?.status === filters.status);
    }
    return list;
  }

  getViolations(): ConsentMatch[] {
    return this.checkAllActions().filter((m) => m.violations.length > 0);
  }
}
