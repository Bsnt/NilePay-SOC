// n8n Code node - "Execute approved action"  (mode: Run Once for All Items)
// Called by the NilePay console ONLY after an analyst approved the action. Replace the simulated results with real calls
// (firewall API, IAM/IdP API, core-banking freeze API) using HTTP Request nodes.
const { action, target } = $input.first().json.body || {};
if (!action || !target) { throw new Error('body must contain action and target'); }
const RESULT = {
  block_ip: `Edge firewall rule added for ${target} (TTL 24h)`,
  lock_account: `Account ${target} locked and sessions invalidated`,
  force_mfa_reset: `MFA re-enrolment forced for ${target}`,
  freeze_wallet: `Wallet ${target} frozen; outgoing payouts held`,
  revoke_sessions: `All access tokens revoked for ${target}`,
};
if (!RESULT[action]) { throw new Error('unknown action: ' + action); }
return [{ json: { ok: true, action, target, result: RESULT[action], executed_at: new Date().toISOString() } }];
