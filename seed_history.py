"""Seeds a believable PRIOR SHIFT so a fresh install is not an empty console: simulated analysts (l1.sara, l1.omar, l2.mona)
worked alerts older than 3 hours - approving/rejecting actions, closing with dispositions, escalating, giving AI feedback.
Everything is written through the same code paths (and audit log) as real analyst actions. Demo data only."""
import random, time
from common import audit, rechain_audit
import soar, ai_analyst

ANALYSTS = ["l1.sara", "l1.omar", "l2.mona"]
BENIGN_TRUE_POSITIVE_RULES = {"R05", "R06", "R11"}


def seed_history(conn, seed=3, now=None):
    r = random.Random(seed)
    now = int(now or time.time())
    rows = [dict(x) for x in conn.execute("SELECT a.*, x.ai_verdict FROM alerts a LEFT JOIN ai_assessments x ON x.alert_id=a.id WHERE a.ts<? ORDER BY a.ts", (now - 3 * 3600,))]
    escalated = worked = 0
    old = now - 3 * 3600
    # alerts older than 3h were triaged back when they fired: back-date triage timestamps consistently
    conn.execute("UPDATE actions SET requested_ts=(SELECT detected_ts+30 FROM alerts WHERE alerts.id=actions.alert_id), "
                 "decided_ts=CASE WHEN kind='auto' THEN (SELECT detected_ts+30 FROM alerts WHERE alerts.id=actions.alert_id) ELSE decided_ts END "
                 "WHERE alert_id IN (SELECT id FROM alerts WHERE ts<?)", (old,))
    conn.execute("UPDATE alerts SET responded_ts=detected_ts+30 WHERE ts<?", (old,))
    for act, secs in (("ALERT_CREATED", 5), ("SOAR_TRIAGE", 30)):
        conn.execute("UPDATE audit_log SET ts=(SELECT a.detected_ts+%d FROM alerts a WHERE 'alert:'||a.id=audit_log.target) "
                     "WHERE action=? AND target IN (SELECT 'alert:'||id FROM alerts WHERE ts<?)" % secs, (act, old))
    conn.commit()
    overridden = False
    for a in rows:
        if r.random() < 0.08:
            continue  # a few old alerts stay unworked (shows backlog and SLA breach)
        who = r.choice(ANALYSTS)
        lo, hi = {"P1": (4, 12), "P2": (8, 25)}.get(a["priority"], (20, 70))
        t = a["detected_ts"] + int(r.uniform(lo, hi) * 60)
        if t > now - 120:
            continue
        v = a["ai_verdict"]
        truth = v == "True Positive" or (v == "Needs investigation" and r.random() < 0.5)
        override = False
        if v == "True Positive" and not overridden and a["rule_id"] in ("R03", "R05", "R01"):
            truth, override, overridden = False, True, True  # e.g. an authorised pentest the AI could not know about
        pend = [x[0] for x in conn.execute("SELECT id FROM actions WHERE alert_id=? AND state='pending'", (a["id"],))]
        ai = ai_analyst.get(conn, a["id"]) or {}
        if truth:
            for pid in pend:
                soar.decide(conn, pid, "approve", who, "", now=t)
                t += 20
            if a["priority"] == "P1" and escalated < 2:
                soar.analyst_update(conn, a["id"], "Escalated", who, "Confirmed attack chain; need IR lead to coordinate customer notification", to="IR Lead", now=t + 60)
                escalated += 1
                continue
            t2 = min(now - 60, t + int(r.uniform(5, 45) * 60))
            soar.analyst_update(conn, a["id"], "Resolved", who, "Confirmed malicious; containment executed and customer/owner informed.", "True Positive", now=t2)
        else:
            why = (ai.get("benign_indicators") or ["Validated with the account owner - legitimate activity"])[0]
            if override:
                why = "Scheduled red-team exercise (ticket PT-112) from the tester's source IP"
            for pid in pend:
                soar.decide(conn, pid, "reject", who, why[:140], now=t)
                t += 20
            t2 = min(now - 60, t + int(r.uniform(3, 25) * 60))
            disp = "Benign True Positive" if (override or a["rule_id"] in BENIGN_TRUE_POSITIVE_RULES) else "False Positive"
            soar.analyst_update(conn, a["id"], "Closed", who, "Verified benign: " + why[:160], disp, now=t2)
        worked += 1
        if override and ai:
            ai_analyst.add_feedback(conn, a["id"], who, "disagree", "Likely false positive",
                                    "Authorised pentest (PT-112). Needs a check against the engagement calendar before calling this a TP.", ts=t2 + 90)
        elif r.random() < 0.45 and ai:
            rating = "agree" if (v == "True Positive") == truth and v != "Needs investigation" else "partially"
            ai_analyst.add_feedback(conn, a["id"], who, rating, "True Positive" if truth else "Likely false positive",
                                    "Assessment matched what we found." if rating == "agree" else "Right direction, but the evidence was stronger/weaker than rated.", ts=t2 + 90)
    for (aid,) in conn.execute("SELECT id FROM alerts WHERE status IN ('New','Triaged','Pending Approval','Investigating','Escalated')").fetchall():
        ai_analyst.assess_and_store(conn, aid)  # re-assess open alerts so confidence reflects the new analyst history
    audit(conn, "system", "DEMO_HISTORY_SEEDED", "shift", "%d alerts worked by simulated analysts" % worked)
    rechain_audit(conn)
    return worked
