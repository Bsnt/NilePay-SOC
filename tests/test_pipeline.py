"""End-to-end tests (standard library). Run:  python -m unittest discover -s tests -v"""
import http.server, json, os, random, shutil, subprocess, sys, tempfile, threading, unittest, urllib.error, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp()
os.environ["NILEPAY_DB"] = os.path.join(TMP, "test.db")
for k in ("OLLAMA_URL", "VALOR_ANALYST_URL", "VALOR_FEEDBACK_URL", "N8N_ACTION_URL"):
    os.environ.pop(k, None)
import common, gen_logs, detect, soar, server, metrics, grc, reports, ai_analyst, seed_history  # noqa: E402


def fresh(history=False):
    conn = common.init_db(reset=True)
    gen_logs.generate(conn, seed=7)
    detect.run_detection(conn, use_n8n=False)
    if history:
        seed_history.seed_history(conn)
    return conn


def fake_server(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class Core(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = fresh()

    def alert(self, sql, args=()):
        r = self.conn.execute("SELECT * FROM alerts WHERE " + sql, args).fetchone()
        self.assertIsNotNone(r, sql)
        return dict(r)

    def test_every_rule_fires(self):
        got = {r[0] for r in self.conn.execute("SELECT DISTINCT rule_id FROM alerts")}
        want = {r[0] for r in self.conn.execute("SELECT id FROM rules")}
        self.assertEqual(want - got, set())

    def test_every_hunt_has_leads(self):
        for h in self.conn.execute("SELECT id, sql FROM hunts"):
            self.assertGreater(len(common.safe_query(h["sql"])[1]), 0, h["id"])

    def test_triage_state_and_approval_gate(self):
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alerts WHERE status='New'").fetchone()[0], 0)
        gated = self.conn.execute("SELECT COUNT(*) FROM actions WHERE kind='gated'").fetchone()[0]
        self.assertGreater(gated, 5)
        # disruptive actions must NEVER be executed without a decision
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions WHERE kind='gated' AND state NOT IN ('pending')").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions WHERE kind='auto' AND action IN ('block_ip','lock_account','freeze_wallet','revoke_sessions','force_mfa_reset')").fetchone()[0], 0)

    def test_redetect_is_idempotent(self):
        self.assertEqual(detect.run_detection(self.conn, False), 0)

    def test_ai_reads_benign_and_malicious_cases(self):
        v = lambda a: ai_analyst.get(self.conn, a["id"])["verdict"]
        self.assertEqual(v(self.alert("rule_id='R06' AND user='admin.nour'")), "Likely false positive")      # on-call ticket
        self.assertEqual(v(self.alert("rule_id='R06' AND ip LIKE '185.%' OR rule_id='R06' AND ip LIKE '45.%' OR rule_id='R06' AND ip LIKE '91.%'")), "True Positive")
        self.assertEqual(v(self.alert("rule_id='R11' AND ip LIKE '41.%'")), "Likely false positive")           # partner monitor
        self.assertEqual(v(self.alert("rule_id='R05' AND user='merchant_1288'")), "Likely false positive")     # new AE branch
        self.assertEqual(v(self.alert("rule_id='R05' AND user='merchant_9020'")), "True Positive")
        self.assertEqual(v(self.alert("rule_id='R10' AND ip NOT LIKE '185.%' AND ip NOT LIKE '45.%' AND ip NOT LIKE '91.%'")), "Likely false positive")
        self.assertEqual(v(self.alert("rule_id='R04'")), "True Positive")
        self.assertEqual(v(self.alert("rule_id='R15' AND detail LIKE '%mimikatz%'")), "True Positive")
        trav = [r["id"] for r in self.conn.execute("SELECT id FROM alerts WHERE rule_id='R02' AND ip LIKE '94.200.%'")]
        self.assertTrue(trav)
        self.assertNotEqual(v({"id": trav[0]}), "True Positive")                                               # plausible travel -> not a TP

    def test_ai_assessment_shape(self):
        for (aid,) in self.conn.execute("SELECT id FROM alerts").fetchall():
            x = ai_analyst.get(self.conn, aid)
            self.assertIn(x["verdict"], ai_analyst.VERDICTS)
            self.assertTrue(0 <= x["confidence"] <= 95)
            self.assertTrue(x["reasoning"] and x["questions"] and x["next_steps"])
            self.assertIn(x["soar_recommendation"]["decision"], ("approve", "reject", "review", "none"))

    def test_safe_query_blocks_writes_and_secrets(self):
        for bad in ("DROP TABLE events", "DELETE FROM events", "SELECT * FROM audit_log", "SELECT * FROM rules",
                    "SELECT 1; DROP TABLE events", "ATTACH DATABASE 'x.db' AS x", "PRAGMA table_info(events)", "UPDATE alerts SET status='Closed'"):
            with self.assertRaises(ValueError, msg=bad):
                common.safe_query(bad)
        self.assertEqual(common.safe_query("SELECT COUNT(*) AS n FROM events")[0], ["n"])
        self.assertTrue(common.safe_query("WITH t AS (SELECT etype FROM events) SELECT DISTINCT etype FROM t")[1])
        with self.assertRaises(ValueError):
            common.safe_query("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT COUNT(*) FROM c", seconds=1)
        self.assertGreater(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 10000)  # nothing was damaged

    def test_audit_chain_and_tamper_detection(self):
        self.assertTrue(common.verify_audit(self.conn)[0])
        old = self.conn.execute("SELECT detail FROM audit_log WHERE id=1").fetchone()[0]
        self.conn.execute("UPDATE audit_log SET detail='tampered' WHERE id=1"); self.conn.commit()
        self.assertFalse(common.verify_audit(self.conn)[0])
        self.conn.execute("UPDATE audit_log SET detail=? WHERE id=1", (old,)); self.conn.commit()
        self.assertTrue(common.verify_audit(self.conn)[0])

    def test_metrics_and_grc_shape(self):
        m = metrics.compute(self.conn)
        for k in ("mttd_min", "mtta_min", "mttr_min", "sla", "coverage", "rule_quality", "approvals", "dispositions", "backlog"):
            self.assertIn(k, m)
        self.assertGreater(m["approvals"]["pending"], 0)
        g = grc.compute(self.conn)
        self.assertEqual(len(g["controls"]), 16)
        self.assertEqual(len(g["frameworks"]), 5)

    def test_pdfs_are_valid(self):
        aid = self.conn.execute("SELECT alert_id FROM actions WHERE state='pending' LIMIT 1").fetchone()[0]
        outs = {"alert": reports.alert_report(self.conn, aid), "soc": reports.soc_report(self.conn), "grc": reports.grc_report(self.conn)}
        for k, data in outs.items():
            self.assertTrue(data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF"), k)
            path = os.path.join(TMP, k + ".pdf"); open(path, "wb").write(data)
            if shutil.which("pdftotext"):
                txt = subprocess.check_output(["pdftotext", path, "-"]).decode("utf-8", "replace")
                self.assertIn("NilePay", txt, k)
        self.assertIsNone(reports.alert_report(self.conn, 99999999))

    @unittest.skipUnless(shutil.which("node"), "node not installed - n8n JS parity check skipped")
    def test_n8n_js_matches_python(self):
        js = open(os.path.join(ROOT, "n8n", "code_triage.js"), encoding="utf-8").read()
        path = os.path.join(TMP, "w.js")
        open(path, "w").write("const a=JSON.parse(process.argv[2]);const $input={first:()=>({json:{body:a}})};const out=(function(){" + js + "})();console.log(JSON.stringify(out[0].json));")
        for (aid,) in self.conn.execute("SELECT id FROM alerts ORDER BY id").fetchall():
            a = detect.alert_dict(self.conn, aid)
            self.assertEqual(json.loads(subprocess.check_output(["node", path, json.dumps(a)])), soar.triage(a), a["rule_id"])

    def test_workflow_json_valid(self):
        for f in ("workflow_alert_response.json", "workflow_execute_action.json", "workflow_hunt_digest.json"):
            wf = json.load(open(os.path.join(ROOT, "n8n", f), encoding="utf-8"))
            names = {n["name"] for n in wf["nodes"]}
            for src, c in wf["connections"].items():
                self.assertIn(src, names)
                for branch in c["main"]:
                    for t in branch:
                        self.assertIn(t["node"], names)


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = fresh()
        cls.srv = server.make_server("127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path, None if body is None else json.dumps(body).encode(), {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers["Content-Type"].startswith("application/json") else raw)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def pending(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM actions WHERE state='pending' ORDER BY id")]

    def test_01_dashboard_and_state(self):
        self.assertIn(b"NilePay", urllib.request.urlopen(self.base + "/").read())
        c, st = self.call("/api/state")
        self.assertEqual(c, 200)
        self.assertGreater(len(st["alerts"]), 15)
        self.assertGreater(st["pending_approvals"], 0)
        a = st["alerts"][0]
        for k in ("priority", "score", "status", "ai_verdict", "ai_conf", "rationale"):
            self.assertIn(k, a)
        c, d = self.call("/api/alert?id=%d" % a["id"])
        self.assertEqual(c, 200)
        for k in ("alert", "events", "actions", "notes", "ai", "timeline", "feedback"):
            self.assertIn(k, d)
        self.assertEqual(self.call("/api/alert?id=99999999")[0], 404)

    def test_02_approval_gate(self):
        p = self.pending()
        self.assertTrue(len(p) >= 2)
        a1, a2 = p[0], p[1]
        c, r = self.call("/api/action/decide", {"action_id": a1["id"], "decision": "reject", "reason": "  "})
        self.assertEqual(c, 400)                                        # rejecting needs a reason
        self.assertEqual(self.call("/api/action/decide", {"action_id": a1["id"], "decision": "maybe"})[0], 400)
        c, r = self.call("/api/action/decide", {"action_id": a1["id"], "decision": "approve", "actor": "l1.test"})
        self.assertEqual(c, 200)
        self.assertTrue(r["result"].startswith("Simulated"))
        self.assertEqual(self.call("/api/action/decide", {"action_id": a1["id"], "decision": "approve"})[0], 400)  # double decision
        c, r = self.call("/api/action/decide", {"action_id": a2["id"], "decision": "reject", "reason": "Verified legitimate", "actor": "l1.test"})
        self.assertEqual(c, 200)
        st = {x["id"]: x["status"] for x in self.call("/api/state")[1]["alerts"]}
        self.assertIn(st[a1["alert_id"]], ("Contained", "Pending Approval"))
        self.assertTrue(self.conn.execute("SELECT 1 FROM audit_log WHERE action='ACTION_APPROVED' AND actor='l1.test'").fetchone())
        self.assertTrue(self.conn.execute("SELECT 1 FROM audit_log WHERE action='ACTION_REJECTED' AND detail LIKE '%Verified legitimate%'").fetchone())
        self.assertEqual(self.call("/api/approvals")[0], 200)

    def test_03_analyst_controls(self):
        aid = self.conn.execute("SELECT id FROM alerts WHERE status IN ('Triaged','Pending Approval') ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual(self.call("/api/alert/update", {"id": aid, "status": "Closed", "note": "x"})[0], 400)              # needs disposition
        self.assertEqual(self.call("/api/alert/update", {"id": aid, "status": "Resolved", "disposition": "False Positive"})[0], 400)
        self.assertEqual(self.call("/api/alert/update", {"id": aid, "status": "Escalated"})[0], 400)                       # needs recipient + reason
        self.assertEqual(self.call("/api/alert/update", {"id": aid, "status": "Escalated", "to": "IR lead", "note": "chain of events"})[0], 200)
        self.assertEqual(self.call("/api/alert/note", {"id": aid, "text": "called the customer"})[0], 200)
        self.assertEqual(self.call("/api/alert/update", {"id": aid, "status": "Closed", "disposition": "False Positive", "note": "verified"})[0], 200)
        left = self.conn.execute("SELECT COUNT(*) FROM actions WHERE alert_id=? AND state='pending'", (aid,)).fetchone()[0]
        self.assertEqual(left, 0)                                                                                          # pending actions cancelled on close
        self.assertEqual(self.call("/api/alert/update", {"id": 99999999, "status": "Investigating"})[0], 404)

    def test_04_ai_feedback_loop(self):
        aid = self.conn.execute("SELECT id FROM alerts WHERE rule_id='R04' LIMIT 1").fetchone()[0]
        self.assertEqual(self.call("/api/ai/feedback", {"alert_id": aid, "rating": "disagree"})[0], 400)                   # must give the correct verdict
        sent = []

        class Hook(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                sent.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
        hook, url = fake_server(Hook)
        os.environ["VALOR_FEEDBACK_URL"] = url
        try:
            c, r = self.call("/api/ai/feedback", {"alert_id": aid, "rating": "disagree", "correct_verdict": "Likely false positive", "comment": "pentest", "actor": "l2.test"})
        finally:
            os.environ.pop("VALOR_FEEDBACK_URL"); hook.shutdown()
        self.assertEqual(c, 200)
        self.assertTrue(r["forwarded_to_valor"])
        self.assertEqual(sent[0]["analyst_rating"], "disagree")
        self.assertEqual(sent[0]["analyst"], "l2.test")
        s = self.call("/api/ai/stats")[1]
        self.assertEqual(s["feedback_count"], 1)
        self.assertEqual(s["agreement_pct"], 0.0)
        raw = self.call("/api/ai/feedback.jsonl")[1]
        self.assertEqual(json.loads(raw.decode().splitlines()[0])["rule_id"], "R04")

    def test_05_calibration_from_dispositions(self):
        # analysts closing a rule's alerts as false positives must lower the AI's confidence for that rule
        target = self.conn.execute("SELECT id FROM alerts WHERE rule_id='R05' AND user='merchant_9020' LIMIT 1").fetchone()[0]
        others = [r[0] for r in self.conn.execute("SELECT id FROM alerts WHERE rule_id='R05' AND id<>?", (target,))]
        self.assertGreaterEqual(len(others), 3)
        first = ai_analyst.assess(self.conn, target)
        self.assertEqual(first["verdict"], "True Positive")
        before = first["confidence"]
        for i in others[:3]:
            soar.analyst_update(self.conn, i, "Closed", "l1.test", "recurring benign", "False Positive")
        after = ai_analyst.assess(self.conn, target)
        self.assertLess(after["confidence"], before)
        self.assertIn("Confidence lowered", after["calibration"])

    def test_06_rules_editor(self):
        sql = "SELECT MAX(ts) AS ts, user, MIN(ip) AS ip, MIN(asset) AS asset, COUNT(*)||' failed MFA' AS detail FROM events WHERE etype='mfa' AND ok=0 GROUP BY user, ts/600 HAVING COUNT(*)>=5"
        c, t = self.call("/api/rules/test", {"sql": sql})
        self.assertEqual(c, 200); self.assertGreater(t["count"], 0)
        self.assertEqual(self.call("/api/rules/test", {"sql": "SELECT ts FROM events"})[0], 400)                           # missing required columns
        self.assertEqual(self.call("/api/rules/test", {"sql": "DELETE FROM events"})[0], 400)
        body = {"name": "MFA burst (lab)", "sev": "Medium", "tactic": "Credential Access", "tech": "T1621", "playbook": "Lock-Account + MFA Reset", "bucket": 600, "sql": sql, "description": "test"}
        self.assertEqual(self.call("/api/rules/save", dict(body, sev="Urgent"))[0], 400)
        c, r = self.call("/api/rules/save", body)
        self.assertEqual(c, 200); rid = r["id"]
        self.assertTrue(rid.startswith("U"))
        n = detect.run_detection(self.conn, False)
        self.assertGreater(n, 0)                                                                                           # the new rule produced alerts, triaged by SOAR
        self.assertGreater(self.conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id=?", (rid,)).fetchone()[0], 0)
        self.assertEqual(self.call("/api/rules/toggle", {"id": rid, "enabled": False})[0], 200)
        self.assertEqual(self.call("/api/rules/delete", {"id": "R01"})[0], 400)                                            # built-ins cannot be deleted
        self.assertEqual(self.call("/api/rules/delete", {"id": rid})[0], 200)
        rules = self.call("/api/rules")[1]["rules"]
        self.assertNotIn(rid, [x["id"] for x in rules])
        self.assertIn("precision", rules[0])

    def test_07_broken_rule_does_not_stop_engine(self):
        self.conn.execute("INSERT INTO rules(id,name,sev,tactic,tech,playbook,bucket,sql,enabled,origin,version) VALUES ('U99','broken','Low','Impact','','Enrich IP + Ticket',600,'SELECT nope FROM nowhere',1,'custom',1)")
        self.conn.commit()
        detect.run_detection(self.conn, False)                                                                             # must not raise
        self.conn.execute("DELETE FROM rules WHERE id='U99'"); self.conn.commit()

    def test_08_suppression(self):
        ip = "185.220.9.9"
        self.assertEqual(self.call("/api/suppress", {"rule_id": "R11", "reason": "x"})[0], 400)                            # needs user or ip
        self.assertEqual(self.call("/api/suppress", {"rule_id": "R11", "ip": ip})[0], 400)                                 # needs reason
        self.assertEqual(self.call("/api/suppress", {"rule_id": "R11", "ip": ip, "reason": "known scanner", "days": 7})[0], 200)
        now = self.conn.execute("SELECT MAX(ts) FROM events").fetchone()[0]
        t = (now // 300) * 300 - 3600
        self.conn.executemany(gen_logs.INSERT, [(t + i, "api", "anonymous", ip, "NL", "mobile-gw", "curl/8.0", 1, 0.0, "") for i in range(150)])
        self.conn.commit()
        before = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        detect.run_detection(self.conn, False)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alerts WHERE ip=?", (ip,)).fetchone()[0], 0)
        sid = self.call("/api/suppressions")[1]["rows"][0]["id"]
        self.assertEqual(self.call("/api/suppress/delete", {"id": sid})[0], 200)
        detect.run_detection(self.conn, False)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM alerts WHERE ip=?", (ip,)).fetchone()[0], 1)             # alerts again once suppression is removed

    def test_09_hunting(self):
        h = self.call("/api/hunts")[1]
        self.assertEqual(len(h["hunts"]), 9)
        q = "SELECT user, COUNT(*) AS n FROM events WHERE etype='login' AND ok=0 GROUP BY user ORDER BY n DESC LIMIT 5"
        c, r = self.call("/api/query", {"sql": q}); self.assertEqual(c, 200); self.assertEqual(r["cols"], ["user", "n"])
        self.assertEqual(self.call("/api/query", {"sql": "DROP TABLE events"})[0], 400)
        c, r = self.call("/api/hunts/save", {"name": "Failed login leaders", "tactic": "Credential Access", "hyp": "who fails most", "sql": q, "status": "In progress"})
        self.assertEqual(c, 200); hid = r["id"]
        self.assertEqual(self.call("/api/hunts/save", {"name": "bad", "tactic": "Credential Access", "sql": "DELETE FROM events"})[0], 400)
        c, r = self.call("/api/hunts/run", {"id": hid}); self.assertEqual(c, 200); self.assertEqual(r["count"], 5)
        self.assertEqual(self.call("/api/hunts/delete", {"id": "H1"})[0], 400)
        self.assertEqual(self.call("/api/hunts/delete", {"id": hid})[0], 200)
        self.assertEqual(self.call("/api/hunts/run", {"id": "H999"})[0], 404)
        self.assertGreater(self.call("/api/hunts/run-all")[1]["total_hits"], 0)

    def test_10_reports_and_pages(self):
        aid = self.conn.execute("SELECT id FROM alerts LIMIT 1").fetchone()[0]
        for p in ("/api/report/soc", "/api/report/grc", "/api/report/alert?id=%d" % aid):
            c, raw = self.call(p); self.assertEqual(c, 200); self.assertTrue(raw.startswith(b"%PDF"))
        for p in ("/api/metrics", "/api/grc", "/api/audit"):
            self.assertEqual(self.call(p)[0], 200)
        self.assertTrue(self.call("/api/audit")[1]["chain"]["ok"])

    def test_11_n8n_triage_and_action_execution(self):
        class Fake(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                out = {"ok": True, "result": "firewall rule pushed for %s" % b["target"]} if "action" in b else soar.triage(b)
                raw = json.dumps(out).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        fake, url = fake_server(Fake)
        old = detect.N8N_URL
        detect.N8N_URL = url + "/webhook/nilepay-alert"
        os.environ["N8N_ACTION_URL"] = url + "/webhook/nilepay-action"
        try:
            gen_logs.live_attack(self.conn, "card_testing", random.Random(11))
            self.assertGreater(detect.run_detection(self.conn, use_n8n=True), 0)
            self.assertIn("n8n", {r[0] for r in self.conn.execute("SELECT actor FROM audit_log WHERE action='SOAR_TRIAGE'")})
            p = [x for x in self.pending() if x["action"] == "block_ip"][-1]
            c, r = self.call("/api/action/decide", {"action_id": p["id"], "decision": "approve"})
            self.assertEqual(c, 200); self.assertTrue(r["result"].startswith("n8n:"))
        finally:
            detect.N8N_URL = old; os.environ.pop("N8N_ACTION_URL"); fake.shutdown()

    def test_12_ollama_and_valor_tiers(self):
        aid = self.conn.execute("SELECT id FROM alerts WHERE rule_id='R04' LIMIT 1").fetchone()[0]

        class Fake(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                out = {"response": json.dumps({"summary": "Looks like a SIM-swap fraud chain.", "verdict": "True Positive", "concerns": ["verify with carrier"]})} if self.path == "/api/generate" else {"verdict": "malicious", "confidence": 0.9}
                raw = json.dumps(out).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        fake, url = fake_server(Fake)
        os.environ["OLLAMA_URL"] = url; os.environ["VALOR_ANALYST_URL"] = url + "/valor"
        try:
            c, r = self.call("/api/ai/assess", {"id": aid, "llm": True, "valor": True})
        finally:
            os.environ.pop("OLLAMA_URL"); os.environ.pop("VALOR_ANALYST_URL"); fake.shutdown()
        self.assertEqual(c, 200)
        self.assertIn("ollama", r["backend"])
        self.assertTrue(r["llm"]["agrees"])
        self.assertEqual(r["valor"]["verdict"], "malicious")
        c, r = self.call("/api/ai/assess", {"id": aid, "llm": True, "valor": True})                                        # not configured -> clear message, not a crash
        self.assertEqual(c, 200); self.assertIn("not set", r["llm_error"]); self.assertIn("not set", r["valor_error"])

    def test_13_grc_reacts_to_work(self):
        st = lambda: {c["id"]: c["status"] for c in grc.compute(self.conn)["controls"]}
        self.assertEqual(st()["C05"], "FAIL")
        for (i,) in self.conn.execute("SELECT id FROM alerts WHERE status IN ('New','Triaged','Pending Approval','Investigating','Escalated')").fetchall():
            soar.analyst_update(self.conn, i, "Closed", "l1.test", "bulk close for test", "Benign True Positive")
        self.call("/api/hunts/run-all")
        s = st()
        self.assertEqual(s["C05"], "PASS"); self.assertEqual(s["C13"], "PASS"); self.assertEqual(s["C16"], "PASS")
        self.assertEqual(s["C08"], "FAIL")                                                                                  # genuine finding stays until fixed
        self.assertTrue(common.verify_audit(self.conn)[0])


class History(unittest.TestCase):
    def test_seeded_prior_shift(self):
        conn = fresh(history=True)
        m = metrics.compute(conn)
        self.assertGreater(m["dispositioned"], 10)
        self.assertGreater(m["mtta_min"], 0); self.assertGreater(m["mttr_min"], 0)
        self.assertGreater(m["approvals"]["approved"], 5); self.assertGreaterEqual(m["approvals"]["avg_decision_min"], 0)
        self.assertGreater(m["backlog"], 0)
        s = ai_analyst.stats(conn)
        self.assertGreater(s["feedback_count"], 3)
        self.assertLess(s["accuracy_pct"], 100.0)
        self.assertTrue(common.verify_audit(conn)[0])
        self.assertTrue(any(q["precision"] is not None for q in m["rule_quality"]))


if __name__ == "__main__":
    unittest.main()
