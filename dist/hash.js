"use strict";
/**
 * Consent Ledger Protocol (CNL-1.0) — hashing and ID generation
 * Uses Node.js crypto only (zero external dependencies).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256 = sha256;
exports.chainHash = chainHash;
exports.generateId = generateId;
exports.authorisationPayload = authorisationPayload;
exports.actionPayload = actionPayload;
const crypto_1 = require("crypto");
const HASH_ALGORITHM = 'sha256';
const ID_BYTES = 16;
/**
 * SHA-256 hash of UTF-8 encoded string. Returns hex digest.
 */
function sha256(data) {
    return (0, crypto_1.createHash)(HASH_ALGORITHM).update(data, 'utf8').digest('hex');
}
/**
 * Chain hash: hash(previous_hash + payload). Used for authorisation and action chains.
 */
function chainHash(previousHash, payload) {
    return sha256(previousHash + payload);
}
/**
 * Generate a unique ID (hex string) for entries.
 */
function generateId() {
    return (0, crypto_1.randomBytes)(ID_BYTES).toString('hex');
}
/**
 * Build deterministic payload string for an authorisation entry (excluding hash fields).
 */
function authorisationPayload(entry) {
    const constraintsStr = entry.constraints
        .map((c) => `${c.type}:${c.description}:${c.parameter}`)
        .join('|');
    return [
        entry.id,
        entry.timestamp,
        entry.principal_id,
        entry.agent_id,
        entry.scope,
        entry.description,
        constraintsStr,
        entry.expires_at ?? '',
        String(entry.revoked),
        entry.revoked_at ?? '',
    ].join('\n');
}
/**
 * Build deterministic payload string for an action record (excluding hash fields).
 */
function actionPayload(record) {
    const paramsStr = JSON.stringify(record.parameters, Object.keys(record.parameters).sort());
    return [
        record.id,
        record.timestamp,
        record.agent_id,
        record.authorisation_id,
        record.action_type,
        record.description,
        paramsStr,
        record.clearpath_trace_id ?? '',
    ].join('\n');
}
