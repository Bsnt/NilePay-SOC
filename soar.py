"""SOAR core (Python mirror of the n8n 'Triage & Playbook' Code node) + human approval gate.
Safe actions run automatically. Disruptive actions (block IP, lock account, freeze wallet, revoke sessions, MFA reset)
are created as PENDING and only run after an analyst approves them."""
import json, os, time, urllib.request
from common import audit

SEV_BASE = {"Critical": 55, "High": 40, "Medium": 25, "Low": 10}
ASSET_BONUS = {"core-db": 10, "wallet-svc": 10, "kyc-portal": 8, "admin-vpn": 8, "pay-api-01": 5, "pay-api-02": 5, "mobile-gw": 2}
BAD_PREFIXES = ("185.220.", "45.155.", "91.108.")
CLEAN_PREFIXES = ("41.", "156.", "197.", "102.", "10.")
ROLE_PREFIXES = ("admin", "svc_", "merchant_", "support")
VALID_STATUS = {"New", "Triaged", "Pending Approval", "Contained", "Investigating", "Escalated", "Resolved", "Closed"}
OPEN_STATUS = ("New", "Triaged", "Pending Approval", "Investigating", "Escalated")
DISPOSITIONS = ("True Positive", "Benign True Positive", "False Positive")

# [action, simulated seconds, needs_approval]
PLAYBOOKS = [
    {"name": "Block-IP + Notify", "trigger": "Network-borne abuse", "steps": "Enrich IP > Notify SOC > [approval] Block IP",
     "actions": [["enrich_ip", 2, False], ["notify_slack", 1, False], ["block_ip", 3, True]]},
    {"name": "Lock-Account + MFA Reset", "trigger": "Account takeover / MFA abuse", "steps": "Enrich IP > Notify user > [approval] Lock account > [approval] Force MFA reset",
     "actions": [["enrich_ip", 2, False], ["notify_user", 1, False], ["lock_account", 4, True], ["force_mfa_reset", 3, True]]},
    {"name": "Freeze-Wallet + Escalate L2", "trigger": "Money movement / critical", "steps": "Enrich IP > Ticket > Page L2 > [approval] Freeze wallet",
     "actions": [["enrich_ip", 2, False], ["create_ticket", 2, False], ["page_l2", 1, False], ["freeze_wallet", 3, True]]},
    {"name": "Revoke-Session + Escalate L2", "trigger": "Admin / data access", "steps": "Enrich IP > Snapshot logs > Ticket > [approval] Revoke sessions",
     "actions": [["enrich_ip", 2, False], ["snapshot_logs", 4, False], ["create_ticket", 2, False], ["revoke_sessions", 3, True]]},
    {"name": "Enrich IP + Ticket", "trigger": "Medium / low severity", "steps": "Enrich IP > Ticket (no disruptive action)",
     "actions": [["enrich_ip", 2, False], ["create_ticket", 2, False]]},
]
AUTO_RESULT = {"enrich_ip": "IP reputation and geo retrieved", "notify_slack": "Posted to #soc-alerts", "notify_user": "Customer notification queued",
               "create_ticket": "Ticket opened in ITSM", "page_l2": "L2 on-call paged", "snapshot_logs": "Log snapshot stored as evidence"}
EXEC_RESULT = {"block_ip": "Edge firewall rule added for {t} (TTL 24h)", "lock_account": "Account {t} locked and sessions invalidated",
               "force_mfa_reset": "MFA re-enrolment forced for {t}", "freeze_wallet": "Wallet {t} frozen; outgoing payouts held",
               "revoke_sessions": "All access tokens revoked for {t}"}


def ip_reputation(ip):
    ip = str(ip or "")
    if ip.startswith(BAD_PREFIXES):
        return "malicious", 30
    if ip.startswith(CLEAN_PREFIXES):
        return "clean", 0
    return "suspicious", 10


def triage(a):
    rep, rb = ip_reputation(a.get("ip"))
    sev = SEV_BASE.get(a.get("sev"), 10)
    asset = ASSET_BONUS.get(a.get("asset"), 0)
    role = 8 if str(a.get("user", "")).startswith(ROLE_PREFIXES) else 0
    score = min(100, sev + asset + rb + role)
    priority = "P1" if score >= 80 else "P2" if score >= 60 else "P3" if score >= 40 else "P4"
    pb = next((p for p in PLAYBOOKS if p["name"] == a.get("playbook")), PLAYBOOKS[-1])
    if score < 40:
        auto, gated = [["enrich_ip", 2]], []
    else:
        auto = [[n, s] for n, s, g in pb["actions"] if not g]
        gated = [n for n, s, g in pb["actions"] if g] if score >= 50 else []
        if score >= 80 and not any(x[0] == "page_l2" for x in auto):
            auto.append(["page_l2", 1])
    pending = [{"action": n, "target": a.get("ip") if n == "block_ip" else a.get("user")} for n in gated]
    verdict = ("Likely true positive - high confidence" if score >= 80 else "Likely true positive - validate" if score >= 60
               else "Suspicious - investigate" if score >= 40 else "Low risk - review and close")
    return {"id": a["id"], "status": "Pending Approval" if pending else "Triaged", "verdict": verdict, "score": score,
            "priority": priority, "ip_reputation": rep,
            "rationale": "score %d = severity %d + asset %d + ip reputation (%s) %d + role %d" % (score, sev, asset, rep, rb, role),
            "actions": [x[0] for x in auto], "pending": pending, "ttr_s": sum(x[1] for x in auto)}


def apply_response(conn, r, actor="soar"):
    if r.get("status") not in VALID_STATUS:
        raise ValueError("invalid status: %r" % (r.get("status"),))
    aid, now = int(r["id"]), int(time.time())
    conn.execute("UPDATE alerts SET status=?, verdict=?, score=?, priority=?, rationale=?, actions=?, ttr_s=?, responded_ts=? WHERE id=?",
                 (r["status"], str(r.get("verdict", "")), int(r.get("score", 0)), r.get("priority", ""), r.get("rationale", ""),
                  json.dumps(r.get("actions", [])), int(r.get("ttr_s", 0)), now, aid))
    if conn.execute("SELECT COUNT(*) FROM actions WHERE alert_id=?", (aid,)).fetchone()[0] == 0:
        for name in r.get("actions", []):
            conn.execute("INSERT INTO actions(alert_id,action,target,kind,state,requested_ts,decided_ts,decided_by,result) VALUES (?,?,?,'auto','executed',?,?,?,?)",
                         (aid, name, "", now, now, actor, AUTO_RESULT.get(name, "Completed (simulated)")))
        for p in r.get("pending", []):
            conn.execute("INSERT INTO actions(alert_id,action,target,kind,state,requested_ts) VALUES (?,?,?,'gated','pending',?)",
                         (aid, p["action"], p.get("target") or "", now))
    conn.commit()
    audit(conn, actor, "SOAR_TRIAGE", "alert:%d" % aid, "%s score=%s auto=%s pending=%s" % (
        r["status"], r.get("score", 0), ",".join(r.get("actions", [])), ",".join(p["action"] for p in r.get("pending", []))))


def execute(action, target):
    """Run an APPROVED action: via n8n (N8N_ACTION_URL) if configured, else simulated."""
    url = os.environ.get("N8N_ACTION_URL", "")
    if url:
        try:
            req = urllib.request.Request(url, json.dumps({"action": action, "target": target}).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                out = json.loads(resp.read().decode("utf-8"))
            if isinstance(out, dict) and out.get("result"):
                return "n8n: " + str(out["result"])
        except Exception:
            pass
    return "Simulated: " + EXEC_RESULT.get(action, "{t}").format(t=target)


def decide(conn, action_id, decision, who, reason="", now=None):
    row = conn.execute("SELECT * FROM actions WHERE id=?", (int(action_id),)).fetchone()
    if not row:
        raise LookupError("action not found")
    if row["state"] != "pending":
        raise ValueError("action was already decided (%s)" % row["state"])
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    reason = (reason or "").strip()
    if decision == "reject" and not reason:
        raise ValueError("a reason is required to reject an action")
    now = int(now or time.time())
    if decision == "approve":
        state, result = "approved", execute(row["action"], row["target"])
    else:
        state, result = "rejected", "Not executed - rejected by analyst"
    conn.execute("UPDATE actions SET state=?, decided_ts=?, decided_by=?, reason=?, result=? WHERE id=?", (state, now, who, reason, result, row["id"]))
    aid = row["alert_id"]
    conn.execute("UPDATE alerts SET first_touch_ts=COALESCE(first_touch_ts, ?), assignee=COALESCE(assignee, ?) WHERE id=?", (now, who, aid))
    left = conn.execute("SELECT COUNT(*) FROM actions WHERE alert_id=? AND state='pending'", (aid,)).fetchone()[0]
    st = conn.execute("SELECT status FROM alerts WHERE id=?", (aid,)).fetchone()[0]
    new_status = st
    if left == 0 and st == "Pending Approval":
        approved = conn.execute("SELECT COUNT(*) FROM actions WHERE alert_id=? AND state='approved'", (aid,)).fetchone()[0]
        new_status = "Contained" if approved else "Investigating"
        conn.execute("UPDATE alerts SET status=?, closed_ts=? WHERE id=?", (new_status, now if approved else None, aid))
    conn.commit()
    audit(conn, who, "ACTION_APPROVED" if decision == "approve" else "ACTION_REJECTED", "alert:%d" % aid,
          "%s %s%s" % (row["action"], row["target"], (" reason=" + reason) if reason else ""), ts=now)
    return {"ok": True, "alert_id": aid, "state": state, "result": result, "alert_status": new_status}


def analyst_update(conn, aid, status, who, note="", disposition=None, to=None, now=None):
    """Analyst-driven status change with the controls a real SOC enforces (disposition on close, reason on escalation)."""
    aid, now = int(aid), int(now or time.time())
    if status not in VALID_STATUS or status == "New":
        raise ValueError("invalid status")
    note = (note or "").strip()
    if status == "Resolved" and disposition != "True Positive":
        raise ValueError("Resolved requires disposition 'True Positive'")
    if status == "Closed" and disposition not in ("False Positive", "Benign True Positive"):
        raise ValueError("Closed requires disposition 'False Positive' or 'Benign True Positive'")
    if status == "Escalated" and (not to or not note):
        raise ValueError("Escalation requires a recipient and a reason")
    if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (aid,)).fetchone():
        raise LookupError("alert not found")
    closing = status in ("Resolved", "Closed")
    conn.execute("UPDATE alerts SET status=?, disposition=COALESCE(?, disposition), first_touch_ts=COALESCE(first_touch_ts, ?), "
                 "assignee=COALESCE(assignee, ?), closed_ts=CASE WHEN ? THEN ? ELSE closed_ts END WHERE id=?",
                 (status, disposition if closing else None, now, who, 1 if closing else 0, now, aid))
    if closing:
        conn.execute("UPDATE actions SET state='cancelled', decided_ts=?, decided_by=?, result='Cancelled - alert closed' WHERE alert_id=? AND state='pending'", (now, who, aid))
    if note or status == "Escalated":
        kind = "closure" if closing else "escalation" if status == "Escalated" else "note"
        conn.execute("INSERT INTO notes(alert_id,ts,author,kind,text) VALUES (?,?,?,?,?)",
                     (aid, now, who, kind, (("To %s: " % to) if to else "") + note))
    conn.commit()
    audit(conn, who, "ANALYST_ACTION", "alert:%d" % aid, "status -> %s%s%s" % (status, (" disposition=" + disposition) if closing else "", (" to=" + to) if to else ""), ts=now)
