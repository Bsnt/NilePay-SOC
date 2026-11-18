"""GRC: automated control checks, framework scores, auto-generated risk register.
Framework references are INDICATIVE mappings for a student project - verify against the official standards."""
import time
from common import verify_audit, safe_query
from gen_logs import ASSETS
import metrics

FRAMEWORKS = [("PCI", "PCI DSS v4.0"), ("ISO", "ISO/IEC 27001:2022 Annex A"), ("NIST", "NIST CSF 2.0"),
              ("CBE", "CBE Cyber Security Framework (domains)"), ("PDPL", "Egypt PDPL (Law 151/2020)")]


def grade(v, ok, warn, higher_better=True):
    if not higher_better:
        v, ok, warn = -v, -ok, -warn
    return "PASS" if v >= ok else "WARN" if v >= warn else "FAIL"


def compute(conn, now=None):
    now = int(now or time.time())
    m = metrics.compute(conn, now)
    since = now - 86400
    hunts = {r["id"]: dict(r) for r in conn.execute("SELECT id, sql FROM hunts")}
    rule_ids = {r[0] for r in conn.execute("SELECT id FROM rules WHERE enabled=1")}

    def unres(*ids):
        q = "SELECT COUNT(*) FROM alerts WHERE ts>=? AND status IN ('New','Triaged','Pending Approval','Investigating','Escalated') AND rule_id IN (%s)" % ",".join("?" * len(ids))
        return conn.execute(q, (since,) + ids).fetchone()[0]

    def leads(hid):
        if hid not in hunts:
            return 0
        try:
            return len(safe_query(hunts[hid]["sql"], 1000)[1])
        except ValueError:
            return 0

    C = []

    def add(cid, title, refs, status, ev, fix, lik, imp, owner):
        C.append({"id": cid, "title": title, "refs": refs, "status": status, "evidence": ev,
                  "remediation": fix, "likelihood": lik, "impact": imp, "owner": owner})

    seen = conn.execute("SELECT COUNT(DISTINCT asset) FROM events WHERE ts>=?", (since,)).fetchone()[0]
    nev = conn.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (since,)).fetchone()[0]
    add("C01", "Central log collection from all critical assets", {"PCI": "10.2", "ISO": "A.8.15", "NIST": "DE.CM-01", "CBE": "Monitoring and logging"},
        grade(seen, len(ASSETS), len(ASSETS) - 2), "%d/%d critical assets sent logs (%d events in 24h)" % (seen, len(ASSETS), nev),
        "Onboard the missing assets to the log pipeline.", 3, 4, "Platform Team")
    ok, cnt, bad = verify_audit(conn)
    add("C02", "Tamper-evident audit trail", {"PCI": "10.3", "ISO": "A.8.15 / A.5.28", "NIST": "PR.PS-04", "CBE": "Audit and accountability", "PDPL": "Security of processing"},
        "PASS" if ok else "FAIL", ("hash chain valid, %d records" % cnt) if ok else "chain broken at record %s" % bad,
        "Investigate DB tampering; restore audit log from backup.", 2, 5, "SOC Manager")
    new_old = conn.execute("SELECT COUNT(*) FROM alerts WHERE ts>=? AND status='New' AND ?-COALESCE(detected_ts,ts)>900", (since, now)).fetchone()[0]
    add("C03", "Alerts triaged within 15 minutes", {"PCI": "10.4.1.1", "ISO": "A.8.16", "NIST": "DE.AE-02", "CBE": "Security monitoring"},
        grade(new_old, 0, 3, False), "%d alert(s) untriaged for more than 15 min" % new_old,
        "Check SOAR/n8n connectivity; add on-call coverage.", 3, 3, "SOC Manager")
    add("C04", "Detection coverage of MITRE ATT&CK tactics", {"ISO": "A.8.16", "NIST": "DE.AE-02", "CBE": "Threat detection"},
        grade(m["coverage_pct"], 70, 50), "%s%% tactics covered; gaps: %s" % (m["coverage_pct"], ", ".join(m["gaps"]) or "none"),
        "Write rules/hunts for the uncovered tactics.", 3, 3, "Detection Engineer")
    add("C05", "Incident response SLA met", {"PCI": "12.10", "ISO": "A.5.26", "NIST": "RS.MA-01", "CBE": "Incident management", "PDPL": "Breach response"},
        grade(m["sla_pct"], 100, 90), "%d alert(s) past SLA target; L2 backlog %d (oldest %s min)" % (sum(s["breached"] for s in m["sla"]), m["backlog"], m["oldest_min"]),
        "Work the backlog (approve/reject actions, investigate, close with a disposition); add L2 capacity.", 4, 4, "L2 Lead")
    nov = conn.execute("SELECT COUNT(*) FROM alerts WHERE ts>=? AND status NOT IN ('New','Triaged') AND (verdict IS NULL OR verdict='')", (since,)).fetchone()[0]
    add("C06", "Incident verdict and classification recorded", {"PCI": "12.10.1", "ISO": "A.5.25", "NIST": "RS.MA-02", "CBE": "Incident management"},
        grade(nov, 0, 2, False), "%d handled alert(s) without a recorded verdict" % nov, "Fix SOAR callback; require verdict on closure.", 2, 3, "SOC Manager")
    u = unres("R10")
    add("C07", "MFA abuse (push fatigue) monitored and handled", {"PCI": "8.4", "ISO": "A.8.5", "NIST": "PR.AA-03", "CBE": "Identity and access"},
        grade(u, 0, 0, False) if u == 0 else ("WARN" if u < 3 else "FAIL"), "%d unresolved MFA-flood alert(s)" % u,
        "Enable number matching; lock/reset affected accounts.", 3, 4, "IAM Team")
    h4 = leads("H4")
    add("C08", "No interactive use of service accounts", {"PCI": "8.6.1", "ISO": "A.8.2", "NIST": "PR.AA-05", "CBE": "Identity and access"},
        "PASS" if h4 == 0 else "FAIL", "Hunt H4: %d service account/channel combination(s) with interactive logins" % h4,
        "Block interactive login for svc_* accounts; rotate their credentials.", 4, 4, "IAM Team")
    u = unres("R06", "R12")
    add("C09", "Privileged access outside hours / new admin roles reviewed", {"PCI": "7.2", "ISO": "A.8.2", "NIST": "PR.AA-05", "CBE": "Privileged access"},
        grade(u, 0, 2, False), "%d unresolved privileged-access alert(s)" % u, "Verify with admins; revoke unauthorized access.", 3, 4, "IAM Team")
    u, h5 = unres("R07"), leads("H5")
    add("C10", "Bulk access to customer KYC data controlled", {"ISO": "A.8.12", "NIST": "PR.DS-01", "CBE": "Data protection", "PDPL": "Personal data security"},
        "FAIL" if u else "WARN" if h5 else "PASS", "%d unresolved mass-read alert(s); hunt H5 leads: %d" % (u, h5),
        "Review night-time KYC access; apply need-to-know and DLP limits.", 3, 5, "DPO")
    have = {"R01", "R02", "R04", "R13"} <= rule_ids
    add("C11", "Payment-fraud detection rules deployed", {"ISO": "A.8.16", "NIST": "DE.AE-02", "CBE": "Fraud and transaction monitoring"},
        "PASS" if have else "FAIL", "Card-testing, ATO, SIM-swap and dormant-payout rules %s" % ("deployed" if have else "missing"),
        "Deploy the missing fraud rules.", 2, 5, "Detection Engineer")
    u, h7 = unres("R09"), leads("H7")
    add("C12", "Merchant integration changes controlled", {"PCI": "6.5.1", "ISO": "A.8.32", "NIST": "PR.PS-01", "CBE": "Change management"},
        "FAIL" if u else "WARN" if h7 else "PASS", "%d unresolved webhook-change alert(s); hunt H7 leads: %d" % (u, h7),
        "Require approval + allow-list for webhook URL changes; review refunds after changes.", 3, 4, "Product Security")
    add("C13", "Proactive threat hunting performed (24h)", {"ISO": "A.5.7", "NIST": "DE.AE-02", "CBE": "Threat hunting"},
        "PASS" if m["hunts_run"] >= 5 else "WARN", "%d/%d hunts executed; %d lead(s) found" % (m["hunts_run"], m["hunts_total"], m["hunt_leads"]),
        "Run the hunt board (Run all hunts) and triage the leads.", 3, 3, "Threat Hunter")
    u = unres("R08")
    add("C14", "Data exfiltration from core DB monitored", {"ISO": "A.8.12", "NIST": "DE.CM-09", "CBE": "Data protection", "PDPL": "Personal data security"},
        grade(u, 0, 1, False), "%d unresolved DB-spike alert(s)" % u, "Rotate service credentials; review query logs.", 2, 5, "DBA / SOC")
    ap = m["approvals"]
    add("C16", "Containment actions are human-approved and decided promptly", {"PCI": "12.10", "ISO": "A.5.26", "NIST": "RS.MA-01", "CBE": "Incident management"},
        grade(ap["oldest_pending_min"], 30, 120, False), "%d action(s) awaiting approval (oldest %s min); %d approved / %d rejected in 24h" % (ap["pending"], ap["oldest_pending_min"], ap["approved"], ap["rejected"]),
        "Review the Approvals queue; approve or reject with a reason.", 3, 4, "SOC Manager")
    u = unres("R15")
    add("C15", "Malicious tooling on payment hosts handled", {"PCI": "5.2", "ISO": "A.8.7", "NIST": "DE.CM-09", "CBE": "Endpoint security"},
        grade(u, 0, 1, False), "%d unresolved suspicious-process alert(s)" % u, "Isolate host; hunt fleet-wide for the binary.", 2, 5, "L2 Lead")

    score = lambda cs: round(100.0 * sum(1 if c["status"] == "PASS" else .5 if c["status"] == "WARN" else 0 for c in cs) / len(cs), 1) if cs else 0.0
    fw = []
    for key, name in FRAMEWORKS:
        cs = [c for c in C if key in c["refs"]]
        fw.append({"name": name, "score": score(cs), "pass": sum(c["status"] == "PASS" for c in cs),
                   "warn": sum(c["status"] == "WARN" for c in cs), "fail": sum(c["status"] == "FAIL" for c in cs), "total": len(cs)})
    risks = []
    for c in C:
        if c["status"] != "PASS":
            sc = c["likelihood"] * c["impact"] * (1 if c["status"] == "FAIL" else .6)
            risks.append({"id": "RISK-" + c["id"], "title": c["title"], "status": c["status"], "score": round(sc, 1),
                          "rating": "High" if sc >= 12 else "Medium" if sc >= 6 else "Low", "owner": c["owner"],
                          "treatment": c["remediation"], "state": "Open"})
    risks.sort(key=lambda r: -r["score"])
    return {"overall": score(C), "controls": C, "frameworks": fw, "risks": risks,
            "audit": {"ok": ok, "count": cnt, "broken_at": bad},
            "counts": {s: sum(c["status"] == s for c in C) for s in ("PASS", "WARN", "FAIL")}}
