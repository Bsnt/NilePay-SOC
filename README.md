# NilePay SOC Console - detection, approval-gated SOAR, AI analyst, hunting, metrics, GRC

Fictional fintech **NilePay** (wallet + payments, Egypt). Python standard library + SQLite + n8n (optional) + one-page console.
Nothing to install except Python 3.8+. All data is simulated.

## Run
    python run_all.py                 # data + detections + SOAR + AI assessments + console at http://localhost:8080
    python run_all.py --n8n           # route alerts/actions through your n8n workflows (auto-fallback to local if n8n is down)
    python run_all.py --no-history    # start with a completely untouched queue (no simulated prior shift)
    python -m unittest discover -s tests -v      # 26 tests
Options: --port 8090  --no-live  --no-browser  --seed 7.  A live attack is injected every 25 s unless --no-live.
`run_all.py` seeds a simulated prior shift (analysts l1.sara / l1.omar / l2.mona worked the older alerts) so metrics,
rule precision and AI feedback are not empty. It goes through the same code paths and audit log as real analyst work.

## How an alert flows (the way a SOC actually works)
1. **Detect** - enabled rules (editable in the UI) run every cycle; suppressions are honoured; alerts are de-duplicated.
2. **Triage (SOAR/n8n)** - enrich IP, score (severity + asset criticality + IP reputation + account role), priority P1-P4.
   **Safe actions run automatically** (enrich, notify, ticket, snapshot logs, page L2).
   **Disruptive actions never run on their own** (block IP, lock account, force MFA reset, freeze wallet, revoke sessions):
   they wait in **Approvals** until an analyst approves (executes) or rejects (reason mandatory).
3. **AI analyst** - explainable assessment with evidence, benign indicators, similar reviewed cases, questions to confirm,
   and a *recommendation* on the pending action. It advises; the analyst decides.
4. **Analyst** - Investigate / Escalate (recipient + reason) / Resolve as true positive / Close as benign or false positive
   (disposition + note mandatory). Closing cancels still-pending actions. Notes and a full timeline are kept.
5. **Learn** - dispositions drive rule precision and calibrate AI confidence; AI feedback is exported/forwarded; analysts can
   suppress recurring benign activity (by user/IP, expiring) and edit or disable the rule.
6. **Assure** - metrics (MTTD/MTTA/MTTR, SLA, FP rate, approvals), GRC controls, hash-chained audit log, PDF reports.

## Console pages
Overview | Alert queue (+ drawer: summary, AI analyst, evidence, response/approvals, notes) | Approvals |
Detections (create/edit/test/enable/disable rules, suppressions) | Threat hunting (hunts, read-only SQL workbench,
save as hunt, promote to rule, CSV export) | AI analyst (backend status, agreement, accuracy vs dispositions, feedback export) |
SOC metrics | GRC and compliance | Audit log. PDFs: escalation report per alert, SOC report, GRC report (also `python reports.py soc|grc|alert <id>`).
SQL safety: one SELECT, read-only, only `events`/`alerts` readable, 5 s limit, enforced by SQLite's authorizer.

## AI analyst - connecting it to VALOR
Tier 1 always works offline (deterministic analyst + local RAG over analyst-reviewed alerts). Optional tiers via environment:
    OLLAMA_URL=http://localhost:11434  OLLAMA_MODEL=llama3.1:8b   # LLM narrative + second-opinion verdict ("Ask LLM" button)
    VALOR_ANALYST_URL=<your VALOR analyst n8n webhook>            # "Ask VALOR analyst": we POST {alert, assessment, similar_cases, events}
    VALOR_FEEDBACK_URL=<your Analyst Feedback Ingestion webhook>  # every feedback is POSTed -> your RAG/Qdrant update
Payload fields for the feedback webhook are in `ai_analyst.forward_feedback()` - rename them to match your n8n workflow.
The VALOR analyst response is shown as-is (JSON) next to ours; we cannot know its exact schema.

## n8n (three workflows in `n8n/`; rules.json/hunts.json are NOT workflows)
1. `docker run -it --rm -p 5678:5678 n8nio/n8n` -> Import from file:
   - `workflow_alert_response.json` (Webhook -> Code -> Respond) path `nilepay-alert`: returns triage + pending actions.
   - `workflow_execute_action.json` path `nilepay-action`: runs an APPROVED action (replace the simulated result with real
     firewall / IdP / core-banking calls).
   - `workflow_hunt_digest.json`: runs all hunts every 15 min via http://host.docker.internal:8080/api/hunts/run-all.
2. Activate the workflows, then `python run_all.py --n8n`. Edit logic in `n8n/code_*.js` (a test keeps triage identical to soar.py).
Env overrides: N8N_WEBHOOK_URL, N8N_ACTION_URL. Regenerate with `python n8n/build_workflows.py <dashboard_url>`.

## Honest limits
Simulated logs, simulated response actions (nothing touches a real firewall), offline IP reputation list, framework mappings
(PCI DSS, ISO 27001, NIST CSF, CBE domains, Egypt PDPL) are indicative - verify against the official texts. The console was
tested by automated browser-style runs (jsdom), not by eye on every screen size.

## Team of 4
**Data and attack engineer** - gen_logs.py: new scenarios + more benign noise; `docs/attack_scenarios.md`.
**Detection engineer** - tune the 15 rules, add 5 via the Detections page (with tests), review precision weekly, manage suppressions.
**SOAR and AI engineer** - n8n enrichment (AbuseIPDB/VirusTotal), real execute-action integrations, Ollama + VALOR wiring, feedback review.
**Hunter and GRC owner** - 3+ new hunts documented with findings, close ATT&CK gaps, add manual GRC controls and evidence.
Weeks: 1 data + rules | 2 SOAR + approvals | 3 AI + hunts + tuning | 4 metrics, docs, demo.
