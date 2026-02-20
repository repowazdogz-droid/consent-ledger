# Consent Ledger Protocol (CNL-1.0)

Tamper-evident authorisation records for AI agents.

The Consent Ledger creates hash-chained records of what a human authorised an AI agent to do, what the agent actually did, and whether those two things match. Every authorisation and every action is timestamped, constrained, and cryptographically linked. Any modification breaks the chain.

Clearpath traces what was decided. The Cognitive Ledger traces the decision-maker. The Consent Ledger traces whether the decision was authorised.

## Why this exists

AI agents are acting on behalf of humans with no record of what they were authorised to do. When an agent books a flight you didn't ask for, when an agent spends beyond your limit, when an agent shares data you never consented to share — there is no record of the boundary between what was permitted and what was done.

The Consent Ledger is the protocol layer. It doesn't care what the agent did. It makes the gap between authorisation and action inspectable, verifiable, and reconstructable.

## What it does

Every authorisation records who gave consent, which agent received it, what scope it covers, what constraints apply, and when it expires. Every action records what the agent did and links it to the authorisation it claims to be acting under. The matcher compares the two and flags any violation.

Three capabilities:

**Consent matching** compares each action against its linked authorisation in real time. Did the agent exceed a monetary limit? Act outside its domain? Continue after revocation? Act after expiry? Every violation is classified by severity (minor, major, critical) with a plain-language description of what went wrong.

**Scope creep detection** analyses action history to find gradual patterns of overreach. Spending creeping toward limits. Frequency escalating beyond original patterns. Actions drifting outside authorised domains. Authority inflating over time. The most dangerous consent violations are gradual, not sudden. Detection requires three or more data points showing a trend.

**Dual hash chains** maintain integrity independently for authorisations and actions. Tampering with any authorisation breaks the authorisation chain. Tampering with any action breaks the action chain. Both are independently verifiable.

## Consent scopes

- **specific** — one-time authorisation for a single action
- **categorical** — authorisation for a category of actions (e.g., "book flights under £500")
- **standing** — ongoing authorisation until revoked
- **emergency** — agent acted without consent due to urgency, must be ratified
- **delegated** — consent passed from one agent to another

## Install

```bash
npm install
npm run build
```

## Quick start

```javascript
const { ConsentLedger } = require('./dist/index');

const ledger = new ConsentLedger('user-1');

// Authorise an agent to book flights
const auth = ledger.authorise({
  principal_id: 'user-1',
  agent_id: 'travel-agent',
  scope: 'categorical',
  description: 'Book flights under £500 to European destinations',
  constraints: [
    { type: 'monetary_limit', description: 'Maximum £500 per booking', parameter: '500' },
    { type: 'domain_restriction', description: 'European destinations only', parameter: 'europe' }
  ],
  expires_at: '2026-12-31T23:59:59Z'
});

// Agent books a flight
const action = ledger.recordAction({
  agent_id: 'travel-agent',
  authorisation_id: auth.id,
  action_type: 'flight_booking',
  description: 'Booked flight to Paris for £320',
  parameters: { amount: 320, destination: 'Paris', currency: 'GBP' }
});

// Check consent
const match = ledger.checkConsent(action.id);
console.log(match.status); // 'within_bounds'

// Agent books an expensive flight
const action2 = ledger.recordAction({
  agent_id: 'travel-agent',
  authorisation_id: auth.id,
  action_type: 'flight_booking',
  description: 'Booked flight to Tokyo for £1200',
  parameters: { amount: 1200, destination: 'Tokyo', currency: 'GBP' }
});

const match2 = ledger.checkConsent(action2.id);
console.log(match2.status); // 'exceeded'
console.log(match2.violations); // monetary_limit and domain_restriction violations

// Detect scope creep over time
const patterns = ledger.detectScopeCreep();

// Verify integrity
console.log(ledger.verify());
```

## Test

```bash
npm test
```

26 tests covering: core ledger operations, authorisation with constraints, action recording, revocation, expiry detection, hash chain integrity, consent matching (within bounds, exceeded, domain violations, revoked, expired, multiple violations, no matching authorisation, emergency ratification), scope creep detection (gradual expansion, frequency escalation, domain drift, false positive avoidance), tamper detection on both chains, and JSON export/import roundtrip.

## Constraint types

| Type | Description | Example |
|------|-------------|---------|
| monetary_limit | Maximum spend per action | £500 |
| domain_restriction | Allowed domain or category | European destinations |
| time_window | Allowed time of operation | Business hours only |
| approval_required | Human must approve before action | Manager sign-off |
| recipient_restriction | Allowed recipients | Internal team only |
| frequency_limit | Maximum actions per period | 3 per day |
| custom | Free-form constraint | Any described condition |

## Scope creep patterns

| Pattern | Detection | Meaning |
|---------|-----------|---------|
| gradual_expansion | Actions progressively push constraint boundaries | Agent testing limits |
| constraint_erosion | Same constraint violated with increasing severity | Boundaries degrading |
| frequency_escalation | Action frequency increasing beyond original pattern | Agent becoming more autonomous |
| domain_drift | Actions increasingly outside authorised domain | Agent wandering from mandate |
| authority_inflation | Agent taking actions requiring higher authorisation | Agent exceeding its level |

## Schema

**AuthorisationEntry:** Hash-chained with SHA-256. Includes principal, agent, scope, constraints, expiry, and revocation status.

**ActionRecord:** Hash-chained independently. Includes agent, action type, parameters, and link to authorisation and optional Clearpath trace.

**ConsentMatch:** Result of comparing action against authorisation. Status, violations with severity, and timestamp.

## How it works

The Consent Ledger is a library, not a service. No server. No database. No UI. It is the protocol layer that other applications build on.

A healthcare AI imports the Consent Ledger → every action is checked against patient consent. An autonomous trading agent imports the Consent Ledger → every trade is verified against the mandate. A personal assistant imports the Consent Ledger → every action on your behalf has an authorisation trail.

The protocol is domain-agnostic. The consent mechanism is identical. The stakes change.

## Relationship to other protocols

Clearpath (CAP-1.0) traces what was decided. The Cognitive Ledger (CLP-1.0) profiles how the decision-maker reasons. The Consent Ledger (CNL-1.0) verifies whether the action was authorised. Together they answer: was the decision auditable, is the decision-maker reliable, and was the action permitted?

## Status

- 26 tests passing
- TypeScript, zero external dependencies
- Open-source (MIT)
- Part of the Omega reasoning infrastructure

## License

MIT
