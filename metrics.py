"""SOC metrics (last 24h): MTTD/MTTA/MTTR, disposition quality, SLA, backlog, approvals, rule precision, ATT&CK coverage, hunting."""
import time
from common import connect
import soar

SLA = {"Critical": 600, "High": 1800, "Medium": 3600, "Low": 14400}  # seconds, detection -> analyst/SOAR disposition
TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
           "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
           "Exfiltration", "Impact"]


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def avg(xs):
    xs = list(xs)
    return round(sum(xs) / len(xs), 1) if xs else 0.0


def compute(conn, now=None):
    now = int(now or time.time())
    rows = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE ts>=?", (now - 86400,))]
    n = len(rows)
    by_sev = {s: 0 for s in SLA}
    by_status, tac, ips, users, rq = {}, {}, {}, {}, {}
    breached = {s: 0 for s in SLA}
    pending, disp = [], {"True Positive": 0, "Benign True Positive": 0, "False Positive": 0}
    for a in rows:
        by_sev[a["sev"]] = by_sev.get(a["sev"], 0) + 1
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
        tac[a["tactic"]] = tac.get(a["tactic"], 0) + 1
        ips[a["ip"]] = ips.get(a["ip"], 0) + 1
        users[a["user"]] = users.get(a["user"], 0) + 1
        q = rq.setdefault(a["rule_id"], {"rule_id": a["rule_id"], "rule": a["rule"], "alerts": 0, "tp": 0, "btp": 0, "fp": 0})
        q["alerts"] += 1
        if a["disposition"] in disp:
            disp[a["disposition"]] += 1
            q[{"True Positive": "tp", "Benign True Positive": "btp", "False Positive": "fp"}[a["disposition"]]] += 1
        if a["status"] in soar.OPEN_STATUS:
            age = now - (a["detected_ts"] or a["ts"])
            pending.append({"id": a["id"], "sev": a["sev"], "priority": a["priority"], "rule": a["rule"], "status": a["status"], "age_min": round(age / 60, 1)})
            if age > SLA[a["sev"]]:
                breached[a["sev"]] += 1
    nd = sum(disp.values())
    sla = [{"sev": s, "target_min": SLA[s] // 60, "total": by_sev[s], "breached": breached[s],
            "pct": pct(by_sev[s] - breached[s], by_sev[s]) if by_sev[s] else 100.0} for s in SLA]
    rules = [dict(r) for r in conn.execute("SELECT id,tactic FROM rules WHERE enabled=1")]
    hunts = [dict(r) for r in conn.execute("SELECT id,tactic FROM hunts")]
    cov = [{"name": t, "rules": sum(1 for r in rules if r["tactic"] == t), "hunts": sum(1 for h in hunts if h["tactic"] == t)} for t in TACTICS]
    covered = [c for c in cov if c["rules"] or c["hunts"]]
    last = {}
    for r in conn.execute("SELECT target, detail FROM audit_log WHERE action='HUNT_RUN' AND ts>=? ORDER BY id", (now - 86400,)):
        try:
            last[r["target"]] = int(r["detail"].split("=")[1])
        except Exception:
            last[r["target"]] = 0
    ap = [dict(r) for r in conn.execute("SELECT state, requested_ts, decided_ts FROM actions WHERE kind='gated' AND requested_ts>=?", (now - 86400,))]
    appr, rej = sum(a["state"] == "approved" for a in ap), sum(a["state"] == "rejected" for a in ap)
    pend_ap = [a for a in ap if a["state"] == "pending"]
    pending.sort(key=lambda x: -x["age_min"])
    quality = []
    for q in rq.values():
        d = q["tp"] + q["btp"] + q["fp"]
        q["precision"] = pct(q["tp"], d) if d else None
        quality.append(q)
    quality.sort(key=lambda q: -q["alerts"])
    return {
        "now": now, "total": n, "by_sev": by_sev, "by_status": by_status, "by_tactic": sorted(tac.items(), key=lambda x: -x[1]),
        "mttd_min": avg((a["ttd_s"] or 0) / 60.0 for a in rows),
        "mtta_min": avg((a["first_touch_ts"] - a["detected_ts"]) / 60.0 for a in rows if a["first_touch_ts"]),
        "mttr_min": avg((a["closed_ts"] - a["detected_ts"]) / 60.0 for a in rows if a["closed_ts"]),
        "auto_triage_s": avg(a["ttr_s"] for a in rows if a["ttr_s"] is not None),
        "dispositions": disp, "dispositioned": nd, "fp_rate": pct(disp["False Positive"], nd), "tp_rate": pct(disp["True Positive"], nd),
        "handled_rate": pct(sum(by_status.get(s, 0) for s in ("Contained", "Resolved", "Closed")), n),
        "sla": sla, "sla_pct": pct(n - sum(breached.values()), n) if n else 100.0,
        "backlog": len(pending), "oldest_min": pending[0]["age_min"] if pending else 0, "pending": pending[:12],
        "approvals": {"pending": len(pend_ap), "approved": appr, "rejected": rej, "approve_rate": pct(appr, appr + rej),
                      "oldest_pending_min": round((now - min(a["requested_ts"] for a in pend_ap)) / 60.0, 1) if pend_ap else 0,
                      "avg_decision_min": avg((a["decided_ts"] - a["requested_ts"]) / 60.0 for a in ap if a["decided_ts"] and a["state"] in ("approved", "rejected"))},
        "coverage": cov, "coverage_pct": pct(len(covered), len(TACTICS)), "gaps": [c["name"] for c in cov if not (c["rules"] or c["hunts"])],
        "rule_quality": quality[:10],
        "top_ips": [{"ip": k, "count": v, "rep": soar.ip_reputation(k)[0]} for k, v in sorted(ips.items(), key=lambda x: -x[1])[:6]],
        "top_users": [{"user": k, "count": v} for k, v in sorted(users.items(), key=lambda x: -x[1])[:6]],
        "hunts_run": len(last), "hunts_total": len(hunts), "hunt_leads": sum(last.values()),
    }
