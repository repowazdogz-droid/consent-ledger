/**
 * Consent Ledger Protocol (CNL-1.0) — compliance and audit reports
 */
import type { AuthorisationEntry, ActionRecord, ConsentMatch, ScopeCreepPattern, LedgerSnapshot, VerifyResult } from './types';
import { schema } from './types';
export interface ComplianceReport {
    schema: typeof schema;
    generated_at: string;
    principal_id: string;
    summary: {
        total_authorisations: number;
        active_authorisations: number;
        total_actions: number;
        within_bounds: number;
        exceeded: number;
        revoked: number;
        expired: number;
        pending_ratification: number;
        no_authorisation: number;
    };
    violations_summary: {
        critical: number;
        major: number;
        minor: number;
    };
    scope_creep_patterns: number;
    integrity: VerifyResult | null;
}
export interface AuditReport {
    schema: typeof schema;
    generated_at: string;
    principal_id: string;
    authorisations: AuthorisationEntry[];
    actions: ActionRecord[];
    matches: ConsentMatch[];
    violations: ConsentMatch[];
    scope_creep: ScopeCreepPattern[];
    integrity: VerifyResult | null;
}
/**
 * Build a compliance summary from ledger snapshot, matches, and optional integrity result.
 */
export declare function buildComplianceReport(snapshot: LedgerSnapshot, matches: ConsentMatch[], scopeCreep: ScopeCreepPattern[], integrity: VerifyResult | null): ComplianceReport;
/**
 * Build a full audit report (detailed) including all matches and violations.
 */
export declare function buildAuditReport(snapshot: LedgerSnapshot, matches: ConsentMatch[], scopeCreep: ScopeCreepPattern[], integrity: VerifyResult | null): AuditReport;
/**
 * Generate Markdown summary suitable for human reading, including violations summary.
 */
export declare function reportToMarkdown(compliance: ComplianceReport, options?: {
    includeScopeCreep?: boolean;
    scopeCreepPatterns?: ScopeCreepPattern[];
}): string;
//# sourceMappingURL=reporter.d.ts.map