/**
 * Consent Ledger Protocol (CNL-1.0) — hashing and ID generation
 * Uses Node.js crypto only (zero external dependencies).
 */
/**
 * SHA-256 hash of UTF-8 encoded string. Returns hex digest.
 */
export declare function sha256(data: string): string;
/**
 * Chain hash: hash(previous_hash + payload). Used for authorisation and action chains.
 */
export declare function chainHash(previousHash: string, payload: string): string;
/**
 * Generate a unique ID (hex string) for entries.
 */
export declare function generateId(): string;
/**
 * Build deterministic payload string for an authorisation entry (excluding hash fields).
 */
export declare function authorisationPayload(entry: {
    id: string;
    timestamp: string;
    principal_id: string;
    agent_id: string;
    scope: string;
    description: string;
    constraints: Array<{
        type: string;
        description: string;
        parameter: string;
    }>;
    expires_at: string | null;
    revoked: boolean;
    revoked_at: string | null;
}): string;
/**
 * Build deterministic payload string for an action record (excluding hash fields).
 */
export declare function actionPayload(record: {
    id: string;
    timestamp: string;
    agent_id: string;
    authorisation_id: string;
    action_type: string;
    description: string;
    parameters: Record<string, unknown>;
    clearpath_trace_id?: string;
}): string;
//# sourceMappingURL=hash.d.ts.map