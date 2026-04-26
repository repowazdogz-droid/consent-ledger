/**
 * Consent Ledger Protocol (CNL-1.0) — scope creep / drift detection
 * Requires 3+ data points to detect a trend.
 */
import type { AuthorisationEntry, ActionRecord, ScopeCreepPattern } from './types';
export interface DriftDetectorInput {
    authorisations: AuthorisationEntry[];
    actions: ActionRecord[];
    /** Optional: pre-computed violations per action (for constraint_erosion) */
    violationsByAction?: Map<string, {
        constraint_type: string;
        severity: string;
    }[]>;
    /** Optional: pre-computed match status per action (for authority_inflation) */
    matchStatusByAction?: Map<string, string>;
}
/**
 * Run all scope-creep detectors. Returns patterns that have 3+ evidence points.
 */
export declare function detectScopeCreep(input: DriftDetectorInput): ScopeCreepPattern[];
//# sourceMappingURL=drift-detector.d.ts.map