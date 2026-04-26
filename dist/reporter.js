"use strict";
/**
 * Consent Ledger Protocol (CNL-1.0) — compliance and audit reports
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildComplianceReport = buildComplianceReport;
exports.buildAuditReport = buildAuditReport;
exports.reportToMarkdown = reportToMarkdown;
const types_1 = require("./types");
/**
 * Build a compliance summary from ledger snapshot, matches, and optional integrity result.
 */
function buildComplianceReport(snapshot, matches, scopeCreep, integrity) {
    const active = snapshot.authorisations.filter((a) => !a.revoked && (!a.expires_at || new Date(a.expires_at) > new Date()));
    const byStatus = new Map();
    const violationsSummary = { critical: 0, major: 0, minor: 0 };
    for (const m of matches) {
        byStatus.set(m.status, (byStatus.get(m.status) ?? 0) + 1);
        for (const v of m.violations) {
            if (v.severity === 'critical')
                violationsSummary.critical++;
            else if (v.severity === 'major')
                violationsSummary.major++;
            else
                violationsSummary.minor++;
        }
    }
    const noAuth = matches.filter((m) => m.status === 'exceeded' && m.violations.some((v) => v.constraint_type === 'authorisation')).length;
    return {
        schema: types_1.schema,
        generated_at: new Date().toISOString(),
        principal_id: snapshot.principal_id,
        summary: {
            total_authorisations: snapshot.authorisations.length,
            active_authorisations: active.length,
            total_actions: snapshot.actions.length,
            within_bounds: byStatus.get('within_bounds') ?? 0,
            exceeded: byStatus.get('exceeded') ?? 0,
            revoked: byStatus.get('revoked') ?? 0,
            expired: byStatus.get('expired') ?? 0,
            pending_ratification: byStatus.get('pending_ratification') ?? 0,
            no_authorisation: noAuth,
        },
        violations_summary: violationsSummary,
        scope_creep_patterns: scopeCreep.length,
        integrity,
    };
}
/**
 * Build a full audit report (detailed) including all matches and violations.
 */
function buildAuditReport(snapshot, matches, scopeCreep, integrity) {
    const violations = matches.filter((m) => m.violations.length > 0);
    return {
        schema: types_1.schema,
        generated_at: new Date().toISOString(),
        principal_id: snapshot.principal_id,
        authorisations: snapshot.authorisations,
        actions: snapshot.actions,
        matches,
        violations,
        scope_creep: scopeCreep,
        integrity,
    };
}
/**
 * Generate Markdown summary suitable for human reading, including violations summary.
 */
function reportToMarkdown(compliance, options) {
    const lines = [
        '# Consent Ledger Compliance Report',
        '',
        `**Schema:** ${compliance.schema}  `,
        `**Generated:** ${compliance.generated_at}  `,
        `**Principal:** ${compliance.principal_id}`,
        '',
        '## Summary',
        '',
        `| Metric | Count |`,
        `|--------|-------|`,
        `| Total authorisations | ${compliance.summary.total_authorisations} |`,
        `| Active authorisations | ${compliance.summary.active_authorisations} |`,
        `| Total actions | ${compliance.summary.total_actions} |`,
        `| Within bounds | ${compliance.summary.within_bounds} |`,
        `| Exceeded | ${compliance.summary.exceeded} |`,
        `| Revoked | ${compliance.summary.revoked} |`,
        `| Expired | ${compliance.summary.expired} |`,
        `| Pending ratification | ${compliance.summary.pending_ratification} |`,
        `| No authorisation | ${compliance.summary.no_authorisation} |`,
        '',
        '## Violations',
        '',
        `| Severity | Count |`,
        `|----------|-------|`,
        `| Critical | ${compliance.violations_summary.critical} |`,
        `| Major | ${compliance.violations_summary.major} |`,
        `| Minor | ${compliance.violations_summary.minor} |`,
        '',
    ];
    if (compliance.integrity) {
        lines.push('## Integrity', '');
        lines.push(`Chain valid: **${compliance.integrity.valid ? 'Yes' : 'No'}**  `);
        lines.push(`Authorisations checked: ${compliance.integrity.authorisations_checked}  `);
        lines.push(`Actions checked: ${compliance.integrity.actions_checked}`);
        lines.push('');
    }
    if (options?.includeScopeCreep && options?.scopeCreepPatterns && options.scopeCreepPatterns.length > 0) {
        lines.push('## Scope creep patterns', '');
        for (const p of options.scopeCreepPatterns) {
            lines.push(`- **${p.pattern_type}**: ${p.description} (severity: ${p.severity}, evidence: ${p.evidence_ids.length})`);
        }
        lines.push('');
    }
    return lines.join('\n');
}
