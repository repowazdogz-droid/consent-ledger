/**
 * Consent Ledger Protocol (CNL-1.0) — main ConsentLedger class
 */
import type { AuthorisationEntry, ActionRecord, ConsentMatch, ScopeCreepPattern, VerifyResult, ActionFilters } from './types';
export declare class ConsentLedger {
    readonly principal_id: string;
    private authorisations;
    private actions;
    private authById;
    private actionById;
    constructor(principal_id: string);
    authorise(entry: Omit<AuthorisationEntry, 'id' | 'timestamp' | 'hash' | 'previous_hash' | 'revoked' | 'revoked_at'>): AuthorisationEntry;
    revoke(authorisation_id: string): AuthorisationEntry;
    getAuthorisation(id: string): AuthorisationEntry | null;
    getActiveAuthorisations(): AuthorisationEntry[];
    recordAction(action: Omit<ActionRecord, 'id' | 'timestamp' | 'hash' | 'previous_hash'>): ActionRecord;
    private buildMatcherContext;
    checkConsent(action_id: string): ConsentMatch;
    checkAllActions(): ConsentMatch[];
    detectScopeCreep(): ScopeCreepPattern[];
    verify(): VerifyResult;
    toJSON(): string;
    toMarkdown(): string;
    static fromJSON(json: string): ConsentLedger;
    getActions(filters?: ActionFilters): ActionRecord[];
    getViolations(): ConsentMatch[];
}
//# sourceMappingURL=consent-ledger.d.ts.map