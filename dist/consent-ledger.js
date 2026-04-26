"use strict";
/**
 * Consent Ledger Protocol (CNL-1.0) — main ConsentLedger class
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConsentLedger = void 0;
const types_1 = require("./types");
const hash_1 = require("./hash");
const matcher_1 = require("./matcher");
const drift_detector_1 = require("./drift-detector");
const reporter_1 = require("./reporter");
const GENESIS = '0';
class ConsentLedger {
    constructor(principal_id) {
        this.authorisations = [];
        this.actions = [];
        this.authById = new Map();
        this.actionById = new Map();
        this.principal_id = principal_id;
    }
    authorise(entry) {
        const id = (0, hash_1.generateId)();
        const timestamp = new Date().toISOString();
        const previous_hash = this.authorisations.length === 0
            ? GENESIS
            : this.authorisations[this.authorisations.length - 1].hash;
        const full = {
            ...entry,
            id,
            timestamp,
            revoked: false,
            revoked_at: null,
            previous_hash,
            hash: '',
        };
        full.hash = (0, hash_1.chainHash)(previous_hash, (0, hash_1.authorisationPayload)(full));
        this.authorisations.push(full);
        this.authById.set(id, full);
        return full;
    }
    revoke(authorisation_id) {
        const auth = this.authById.get(authorisation_id);
        if (!auth)
            throw new Error(`Authorisation not found: ${authorisation_id}`);
        if (auth.revoked)
            return auth;
        const revoked_at = new Date().toISOString();
        const updated = {
            ...auth,
            revoked: true,
            revoked_at,
            hash: '',
        };
        updated.hash = (0, hash_1.chainHash)(auth.previous_hash, (0, hash_1.authorisationPayload)(updated));
        const idx = this.authorisations.findIndex((a) => a.id === authorisation_id);
        this.authorisations[idx] = updated;
        this.authById.set(authorisation_id, updated);
        return updated;
    }
    getAuthorisation(id) {
        return this.authById.get(id) ?? null;
    }
    getActiveAuthorisations() {
        const now = new Date();
        return this.authorisations.filter((a) => !a.revoked &&
            (!a.expires_at || new Date(a.expires_at) > now));
    }
    recordAction(action) {
        const id = (0, hash_1.generateId)();
        const timestamp = new Date().toISOString();
        const previous_hash = this.actions.length === 0
            ? GENESIS
            : this.actions[this.actions.length - 1].hash;
        const full = {
            ...action,
            id,
            timestamp,
            previous_hash,
            hash: '',
        };
        full.hash = (0, hash_1.chainHash)(previous_hash, (0, hash_1.actionPayload)(full));
        this.actions.push(full);
        this.actionById.set(id, full);
        return full;
    }
    buildMatcherContext() {
        const periodMs = 24 * 60 * 60 * 1000;
        const actionCountByAuthorisationInPeriod = new Map();
        for (const a of this.actions) {
            const bucket = Math.floor(new Date(a.timestamp).getTime() / periodMs) * periodMs;
            const key = `${a.authorisation_id}:${bucket}`;
            actionCountByAuthorisationInPeriod.set(a.authorisation_id, (actionCountByAuthorisationInPeriod.get(a.authorisation_id) ?? 0) + 1);
        }
        return { actionCountByAuthorisationInPeriod };
    }
    checkConsent(action_id) {
        const action = this.actionById.get(action_id);
        if (!action)
            throw new Error(`Action not found: ${action_id}`);
        const auth = this.getAuthorisation(action.authorisation_id);
        const context = this.buildMatcherContext();
        return (0, matcher_1.matchConsent)(auth ?? null, action, context);
    }
    checkAllActions() {
        const context = this.buildMatcherContext();
        return this.actions.map((action) => {
            const auth = this.getAuthorisation(action.authorisation_id);
            return (0, matcher_1.matchConsent)(auth ?? null, action, context);
        });
    }
    detectScopeCreep() {
        const matches = this.checkAllActions();
        const violationsByAction = new Map();
        const matchStatusByAction = new Map();
        for (const m of matches) {
            matchStatusByAction.set(m.action_id, m.status);
            if (m.violations.length > 0) {
                violationsByAction.set(m.action_id, m.violations.map((v) => ({ constraint_type: v.constraint_type, severity: v.severity })));
            }
        }
        const input = {
            authorisations: this.authorisations,
            actions: this.actions,
            violationsByAction,
            matchStatusByAction,
        };
        return (0, drift_detector_1.detectScopeCreep)(input);
    }
    verify() {
        let authOk = true;
        let prev = GENESIS;
        for (const a of this.authorisations) {
            if (a.previous_hash !== prev)
                authOk = false;
            const expected = (0, hash_1.chainHash)(a.previous_hash, (0, hash_1.authorisationPayload)(a));
            if (a.hash !== expected)
                authOk = false;
            prev = a.hash;
        }
        let actionOk = true;
        let prevAction = GENESIS;
        for (const a of this.actions) {
            if (a.previous_hash !== prevAction)
                actionOk = false;
            const expected = (0, hash_1.chainHash)(a.previous_hash, (0, hash_1.actionPayload)(a));
            if (a.hash !== expected)
                actionOk = false;
            prevAction = a.hash;
        }
        return {
            valid: authOk && actionOk,
            authorisations_checked: this.authorisations.length,
            actions_checked: this.actions.length,
        };
    }
    toJSON() {
        const snapshot = {
            schema: types_1.schema,
            principal_id: this.principal_id,
            authorisations: this.authorisations,
            actions: this.actions,
        };
        return JSON.stringify(snapshot, null, 2);
    }
    toMarkdown() {
        const matches = this.checkAllActions();
        const scopeCreep = this.detectScopeCreep();
        const integrity = this.verify();
        const snapshot = {
            schema: types_1.schema,
            principal_id: this.principal_id,
            authorisations: this.authorisations,
            actions: this.actions,
        };
        const compliance = (0, reporter_1.buildComplianceReport)(snapshot, matches, scopeCreep, integrity);
        return (0, reporter_1.reportToMarkdown)(compliance, {
            includeScopeCreep: true,
            scopeCreepPatterns: scopeCreep,
        });
    }
    static fromJSON(json) {
        const snapshot = JSON.parse(json);
        if (snapshot.schema !== types_1.schema)
            throw new Error(`Invalid schema: expected ${types_1.schema}`);
        const ledger = new ConsentLedger(snapshot.principal_id);
        const L = ledger;
        L.authorisations = snapshot.authorisations;
        L.actions = snapshot.actions;
        L.authById = new Map(snapshot.authorisations.map((a) => [a.id, a]));
        L.actionById = new Map(snapshot.actions.map((a) => [a.id, a]));
        return ledger;
    }
    getActions(filters) {
        let list = this.actions.slice();
        if (filters?.agent_id)
            list = list.filter((a) => a.agent_id === filters.agent_id);
        if (filters?.authorisation_id)
            list = list.filter((a) => a.authorisation_id === filters.authorisation_id);
        if (filters?.status) {
            const matches = this.checkAllActions();
            const matchByAction = new Map(matches.map((m) => [m.action_id, m]));
            list = list.filter((a) => matchByAction.get(a.id)?.status === filters.status);
        }
        return list;
    }
    getViolations() {
        return this.checkAllActions().filter((m) => m.violations.length > 0);
    }
}
exports.ConsentLedger = ConsentLedger;
