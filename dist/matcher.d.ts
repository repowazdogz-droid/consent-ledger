/**
 * Consent Ledger Protocol (CNL-1.0) — consent vs action matching
 */
import type { AuthorisationEntry, ActionRecord, ConsentMatch } from './types';
export interface MatcherContext {
    actionCountByAuthorisationInPeriod?: Map<string, number>;
    frequencyLimitByConstraint?: Map<string, number>;
}
/**
 * Compare a single action against its authorisation and return a ConsentMatch.
 */
export declare function matchConsent(authorisation: AuthorisationEntry | null, action: ActionRecord, context?: MatcherContext): ConsentMatch;
//# sourceMappingURL=matcher.d.ts.map