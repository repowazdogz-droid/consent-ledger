/**
 * Consent Ledger Protocol (CNL-1.0) — hashing and ID generation
 * Uses Node.js crypto only (zero external dependencies).
 */

import { createHash, randomBytes } from 'crypto';

const HASH_ALGORITHM = 'sha256';
const ID_BYTES = 16;

/**
 * SHA-256 hash of UTF-8 encoded string. Returns hex digest.
 */
export function sha256(data: string): string {
  return createHash(HASH_ALGORITHM).update(data, 'utf8').digest('hex');
}

/**
 * Chain hash: hash(previous_hash + payload). Used for authorisation and action chains.
 */
export function chainHash(previousHash: string, payload: string): string {
  return sha256(previousHash + payload);
}

/**
 * Generate a unique ID (hex string) for entries.
 */
export function generateId(): string {
  return randomBytes(ID_BYTES).toString('hex');
}

/**
 * Build deterministic payload string for an authorisation entry (excluding hash fields).
 */
export function authorisationPayload(entry: {
  id: string;
  timestamp: string;
  principal_id: string;
  agent_id: string;
  scope: string;
  description: string;
  constraints: Array<{ type: string; description: string; parameter: string }>;
  expires_at: string | null;
  revoked: boolean;
  revoked_at: string | null;
}): string {
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
export function actionPayload(record: {
  id: string;
  timestamp: string;
  agent_id: string;
  authorisation_id: string;
  action_type: string;
  description: string;
  parameters: Record<string, unknown>;
  clearpath_trace_id?: string;
}): string {
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
