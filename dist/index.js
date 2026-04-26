"use strict";
/**
 * Consent Ledger Protocol (CNL-1.0)
 * Tamper-evident records of what a human authorised an AI agent to do,
 * what the agent actually did, and whether those two things match.
 *
 * Zero external dependencies (Node.js crypto only).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateId = exports.chainHash = exports.sha256 = exports.reportToMarkdown = exports.buildAuditReport = exports.buildComplianceReport = exports.detectScopeCreep = exports.matchConsent = exports.ConsentLedger = exports.schema = void 0;
var types_1 = require("./types");
Object.defineProperty(exports, "schema", { enumerable: true, get: function () { return types_1.schema; } });
var consent_ledger_1 = require("./consent-ledger");
Object.defineProperty(exports, "ConsentLedger", { enumerable: true, get: function () { return consent_ledger_1.ConsentLedger; } });
var matcher_1 = require("./matcher");
Object.defineProperty(exports, "matchConsent", { enumerable: true, get: function () { return matcher_1.matchConsent; } });
var drift_detector_1 = require("./drift-detector");
Object.defineProperty(exports, "detectScopeCreep", { enumerable: true, get: function () { return drift_detector_1.detectScopeCreep; } });
var reporter_1 = require("./reporter");
Object.defineProperty(exports, "buildComplianceReport", { enumerable: true, get: function () { return reporter_1.buildComplianceReport; } });
Object.defineProperty(exports, "buildAuditReport", { enumerable: true, get: function () { return reporter_1.buildAuditReport; } });
Object.defineProperty(exports, "reportToMarkdown", { enumerable: true, get: function () { return reporter_1.reportToMarkdown; } });
var hash_1 = require("./hash");
Object.defineProperty(exports, "sha256", { enumerable: true, get: function () { return hash_1.sha256; } });
Object.defineProperty(exports, "chainHash", { enumerable: true, get: function () { return hash_1.chainHash; } });
Object.defineProperty(exports, "generateId", { enumerable: true, get: function () { return hash_1.generateId; } });
