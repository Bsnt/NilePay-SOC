// n8n Code node - "Triage & Playbook"  (mode: Run Once for All Items)
// Input : Webhook item, body = alert JSON from detect.py
// Output: triage result. SAFE actions are listed in `actions` (run now); DISRUPTIVE actions are returned in `pending`
//         and only run after an analyst approves them in the NilePay console (human-in-the-loop).
const alert = $input.first().json.body;
if (!alert || alert.id === undefined) {
  throw new Error('Webhook body must be the alert JSON (missing id)');
}

const SEV_BASE = { Critical: 55, High: 40, Medium: 25, Low: 10 };
const ASSET_BONUS = { 'core-db': 10, 'wallet-svc': 10, 'kyc-portal': 8, 'admin-vpn': 8, 'pay-api-01': 5, 'pay-api-02': 5, 'mobile-gw': 2 };
const BAD = ['185.220.', '45.155.', '91.108.'];
const CLEAN = ['41.', '156.', '197.', '102.', '10.'];
const ROLES = ['admin', 'svc_', 'merchant_', 'support'];

// [action, simulated seconds, needs analyst approval]
const PLAYBOOKS = {
  'Block-IP + Notify': [['enrich_ip', 2, false], ['notify_slack', 1, false], ['block_ip', 3, true]],
  'Lock-Account + MFA Reset': [['enrich_ip', 2, false], ['notify_user', 1, false], ['lock_account', 4, true], ['force_mfa_reset', 3, true]],
  'Freeze-Wallet + Escalate L2': [['enrich_ip', 2, false], ['create_ticket', 2, false], ['page_l2', 1, false], ['freeze_wallet', 3, true]],
  'Revoke-Session + Escalate L2': [['enrich_ip', 2, false], ['snapshot_logs', 4, false], ['create_ticket', 2, false], ['revoke_sessions', 3, true]],
  'Enrich IP + Ticket': [['enrich_ip', 2, false], ['create_ticket', 2, false]],
};

// 1) Enrich (offline reputation list - swap for AbuseIPDB/VirusTotal HTTP nodes if you add API keys)
const ip = String(alert.ip || '');
let rep = 'suspicious', rb = 10;
if (BAD.some(p => ip.startsWith(p))) { rep = 'malicious'; rb = 30; }
else if (CLEAN.some(p => ip.startsWith(p))) { rep = 'clean'; rb = 0; }

// 2) Score
const sev = SEV_BASE[alert.sev] ?? 10;
const asset = ASSET_BONUS[alert.asset] ?? 0;
const role = ROLES.some(p => String(alert.user || '').startsWith(p)) ? 8 : 0;
const score = Math.min(100, sev + asset + rb + role);
const priority = score >= 80 ? 'P1' : score >= 60 ? 'P2' : score >= 40 ? 'P3' : 'P4';

// 3) Decide what runs now and what needs approval
const base = PLAYBOOKS[alert.playbook] || PLAYBOOKS['Enrich IP + Ticket'];
let auto, gated;
if (score < 40) { auto = [['enrich_ip', 2]]; gated = []; }
else {
  auto = base.filter(s => !s[2]).map(s => [s[0], s[1]]);
  gated = score >= 50 ? base.filter(s => s[2]).map(s => s[0]) : [];
  if (score >= 80 && !auto.some(s => s[0] === 'page_l2')) auto.push(['page_l2', 1]);
}
const pending = gated.map(n => ({ action: n, target: n === 'block_ip' ? alert.ip : alert.user }));
const verdict = score >= 80 ? 'Likely true positive - high confidence' : score >= 60 ? 'Likely true positive - validate'
  : score >= 40 ? 'Suspicious - investigate' : 'Low risk - review and close';

return [{
  json: {
    id: alert.id,
    status: pending.length ? 'Pending Approval' : 'Triaged',
    verdict, score, priority, ip_reputation: rep,
    rationale: `score ${score} = severity ${sev} + asset ${asset} + ip reputation (${rep}) ${rb} + role ${role}`,
    actions: auto.map(s => s[0]),
    pending,
    ttr_s: auto.reduce((t, s) => t + s[1], 0),
  },
}];
