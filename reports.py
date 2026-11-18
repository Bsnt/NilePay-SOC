"""PDF reports: incident escalation (per alert), daily SOC report, GRC compliance report.
CLI:  python reports.py soc | grc | alert <id>   -> writes into ./reports/"""
import json, sys, time
from common import ROOT, connect, audit, verify_audit
import ai_analyst, knowledge
from pdfgen import PDF, RED, ORANGE, GREEN, GREY, TEAL
import metrics, grc, soar

REC = knowledge.REC


def fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts) + 7200)) + " (Cairo)"


def alert_report(conn, aid):
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        return None
    a = dict(a)
    rep = soar.ip_reputation(a["ip"])[0]
    p = PDF("Incident Escalation Report", "NilePay SOC | Alert #%d | Generated %s" % (aid, fmt(time.time())))
    p.banner("%s severity - status: %s" % (a["sev"].upper(), a["status"]), RED if a["sev"] in ("Critical", "High") else ORANGE)
    p.h2("1. Summary")
    p.table(["Field", "Value"], [["Rule", "%s (%s)" % (a["rule"], a["rule_id"])], ["Detected", fmt(a["ts"])],
            ["MITRE ATT&CK", "%s / %s" % (a["tactic"], a["tech"])], ["User / account", a["user"]], ["Asset", a["asset"]],
            ["Source IP", "%s (reputation: %s)" % (a["ip"], rep)], ["Description", a["detail"]]], [1, 4], 9)
    p.h2("2. Triage and automated response")
    acts = json.loads(a["actions"] or "[]")
    p.table(["Field", "Value"], [["Verdict", a["verdict"] or "pending"], ["Risk score", a["score"] if a["score"] is not None else "-"],
            ["Priority / rationale", "%s - %s" % (a["priority"], a["rationale"])], ["Playbook", a["playbook"]], ["Automatic actions", " > ".join(acts) or "-"],
            ["Time to detect", "%.1f min" % ((a["ttd_s"] or 0) / 60.0)], ["Disposition", a["disposition"] or "open"]], [1, 4], 9)
    ai = ai_analyst.get(conn, aid)
    if ai:
        p.h2("2b. AI analyst assessment")
        p.para("%s - %s%% confidence (suggested severity %s)" % (ai["verdict"], ai["confidence"], ai["suggested_severity"]), 10, GREY, 0, True)
        for f in ai["reasoning"]:
            p.para("- " + f, 9, indent=8)
        for f in ai["benign_indicators"]:
            p.para("- Benign indicator: " + f, 9, indent=8)
        p.para("SOAR recommendation: %s - %s" % (ai["soar_recommendation"]["decision"], ai["soar_recommendation"]["reason"]), 9)
    acts = conn.execute("SELECT action,target,kind,state,decided_by,reason,result FROM actions WHERE alert_id=? ORDER BY id", (aid,)).fetchall()
    p.h2("2c. Response actions and approvals")
    p.table(["Action", "Target", "Type", "State", "By", "Reason / result"], [[x["action"], x["target"] or "-", x["kind"], x["state"], x["decided_by"] or "-", x["reason"] or x["result"] or ""] for x in acts] or [["-"] * 6], [2.2, 3, 1.2, 1.5, 1.6, 5], 7.5, 3)
    p.h2("3. Evidence timeline (+/- 30 min, same user or IP)")
    ev = conn.execute("SELECT ts,etype,user,ip,country,asset,detail FROM events WHERE ts BETWEEN ? AND ? AND (user=? OR ip=?) ORDER BY ts LIMIT 15",
                      (a["ts"] - 1800, a["ts"] + 1800, a["user"], a["ip"])).fetchall()
    p.table(["Time", "Type", "User", "IP", "Ctry", "Asset", "Detail"],
            [[time.strftime("%H:%M:%S", time.gmtime(e["ts"] + 7200)), e["etype"], e["user"], e["ip"], e["country"], e["asset"], e["detail"] or ""] for e in ev] or [["-"] * 7],
            [2, 2.2, 2.6, 3, 1, 2.4, 4], 7.5)
    p.h2("4. Recommended L2 actions")
    p.para(REC.get(a["rule_id"], "Follow the standard incident response procedure."))
    p.h2("5. Audit trail for this alert")
    au = conn.execute("SELECT ts,actor,action,detail FROM audit_log WHERE target=? ORDER BY id LIMIT 10", ("alert:%d" % aid,)).fetchall()
    p.table(["Time", "Actor", "Action", "Detail"], [[fmt(r["ts"]), r["actor"], r["action"], r["detail"]] for r in au] or [["-"] * 4], [3, 2, 2.4, 6], 7.5)
    p.h2("6. Escalation sign-off")
    for line in ("Escalated by (L1): ______________________   Date/time: ______________",
                 "Escalated to (L2/IR lead): ______________   Accepted at: ______________",
                 "Customer / regulator notification required?   [ ] Yes   [ ] No   Decision by: ____________"):
        p.para(line, 10)
        p.y -= 6
    return p.save()


def soc_report(conn):
    m = metrics.compute(conn)
    p = PDF("Daily SOC Report", "NilePay SOC | Last 24h | Generated %s" % fmt(time.time()))
    p.h2("1. Key metrics")
    p.table(["Metric", "Value", "Metric", "Value"], [
        ["Alerts (24h)", m["total"], "MTTD", "%s min" % m["mttd_min"]],
        ["Critical alerts", m["by_sev"]["Critical"], "MTTA / MTTR", "%s / %s min" % (m["mtta_min"], m["mttr_min"])],
        ["Handled (contained/resolved/closed)", "%s%%" % m["handled_rate"], "False-positive rate (dispositioned)", "%s%% of %d" % (m["fp_rate"], m["dispositioned"])],
        ["Actions approved / rejected", "%d / %d" % (m["approvals"]["approved"], m["approvals"]["rejected"]), "SLA compliance", "%s%%" % m["sla_pct"]],
        ["Open backlog", m["backlog"], "Oldest open", "%s min" % m["oldest_min"]]], [3, 2, 3, 3], 9)
    p.h2("2. Alerts by severity")
    p.bars([(s, m["by_sev"][s]) for s in ("Critical", "High", "Medium", "Low")])
    p.h2("3. SLA by severity (pending alerts past target)")
    p.table(["Severity", "Target (min)", "Alerts", "Breached", "Compliance %"], [[s["sev"], s["target_min"], s["total"], s["breached"], s["pct"]] for s in m["sla"]], [2, 2, 2, 2, 2], 9, 0)
    p.h2("4. Open backlog (oldest first)")
    p.table(["ID", "Severity", "Rule", "Status", "Age (min)"], [["NP-%05d" % x["id"], x["sev"], x["rule"], x["status"], x["age_min"]] for x in m["pending"]] or [["-"] * 5], [1, 1.5, 6, 1.5, 1.5], 8, 1)
    p.h2("5. Rule quality (analyst dispositions)")
    p.table(["Rule", "Alerts", "TP", "Benign TP", "FP", "Precision"], [[r["rule"], r["alerts"], r["tp"], r["btp"], r["fp"], ("%s%%" % r["precision"]) if r["precision"] is not None else "-"] for r in m["rule_quality"]], [6, 1.2, 1, 1.5, 1, 1.5], 8.5)
    p.h2("6. Top source IPs and users")
    p.table(["IP", "Alerts", "Reputation"], [[i["ip"], i["count"], i["rep"]] for i in m["top_ips"]], [3, 1, 2], 8.5)
    p.table(["User", "Alerts"], [[u["user"], u["count"]] for u in m["top_users"]], [3, 1], 8.5)
    p.h2("7. MITRE ATT&CK coverage")
    p.para("%s%% of the 14 Enterprise tactics have at least one rule or hunt. Gaps: %s." % (m["coverage_pct"], ", ".join(m["gaps"]) or "none"))
    p.h2("8. Threat hunting")
    p.para("%d of %d hunts executed in the last 24h; %d lead(s) found." % (m["hunts_run"], m["hunts_total"], m["hunt_leads"]))
    ok, cnt, bad = verify_audit(conn)
    p.h2("9. Audit log integrity")
    p.para("Hash chain %s (%d records)." % ("VALID" if ok else "BROKEN at record %s" % bad, cnt))
    return p.save()


def grc_report(conn):
    g = grc.compute(conn)
    p = PDF("GRC Compliance and Audit Report", "NilePay | Automated control assessment | Generated %s" % fmt(time.time()))
    p.banner("Overall compliance score: %s%%   (PASS %d | WARN %d | FAIL %d)" % (g["overall"], g["counts"]["PASS"], g["counts"]["WARN"], g["counts"]["FAIL"]),
             GREEN if g["overall"] >= 80 else ORANGE if g["overall"] >= 60 else RED)
    p.h2("1. Framework scores")
    p.table(["Framework", "Score %", "Pass", "Warn", "Fail", "Controls"], [[f["name"], f["score"], f["pass"], f["warn"], f["fail"], f["total"]] for f in g["frameworks"]], [6, 1.5, 1, 1, 1, 1.5], 8.5)
    p.h2("2. Control assessment")
    p.table(["ID", "Control", "Status", "Evidence", "Mapped references"],
            [[c["id"], c["title"], c["status"], c["evidence"], "; ".join("%s %s" % (k, v) for k, v in c["refs"].items())] for c in g["controls"]],
            [1, 4, 1.3, 5, 4.5], 7.5, 2)
    p.h2("3. Risk register (auto-generated from non-passing controls)")
    p.table(["Risk", "Title", "Score", "Rating", "Owner", "Treatment"],
            [[r["id"], r["title"], r["score"], r["rating"], r["owner"], r["treatment"]] for r in g["risks"]] or [["-"] * 6], [1.6, 4, 1, 1.2, 2.2, 5], 7.5, 3)
    p.h2("4. Audit trail integrity")
    a = g["audit"]
    p.para("Tamper-evident audit log: %s (%d records, SHA-256 hash chain)." % ("VALID" if a["ok"] else "BROKEN at record %s" % a["broken_at"], a["count"]))
    p.h2("5. Notes")
    p.para("Framework references are indicative mappings prepared for a student project; they are not a certification and must be verified against the official PCI DSS, ISO/IEC 27001, NIST CSF, CBE and PDPL texts. Manual controls (policies, training, vendor management) are out of scope of this automated assessment.", 9, GREY)
    return p.save()


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "soc"
    conn = connect()
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    if kind == "alert":
        data, name = alert_report(conn, int(sys.argv[2])), "alert_%s.pdf" % sys.argv[2]
    elif kind == "grc":
        data, name = grc_report(conn), "grc_report.pdf"
    else:
        data, name = soc_report(conn), "soc_report.pdf"
    (out / name).write_bytes(data)
    audit(conn, "cli", "REPORT_GENERATED", kind, name)
    print("written", out / name)
