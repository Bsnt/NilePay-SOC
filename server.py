"""NilePay SOC console server (standard library only): REST API + static dashboard."""
import argparse, json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from common import ROOT, connect, init_db, audit, verify_audit, safe_query
import soar, detect, gen_logs, metrics, grc, reports, ai_analyst

CFG = {"n8n": False}
ROUTES = {}
SEVS = ("Critical", "High", "Medium", "Low")
HUNT_STATUS = ("Planned", "In progress", "Done")


def route(method, path):
    def deco(fn):
        ROUTES[(method, path)] = fn
        return fn
    return deco


def alert_row(r):
    d = dict(r)
    return {"id": d["id"], "t": d["ts"] * 1000, "rule": d["rule"], "rule_id": d["rule_id"], "sev": d["sev"], "tactic": d["tactic"], "tech": d["tech"],
            "user": d["user"], "asset": d["asset"], "ip": d["ip"], "detail": d["detail"], "pb": d["playbook"], "status": d["status"],
            "verdict": d["verdict"] or "", "score": d["score"] or 0, "priority": d["priority"] or "", "rationale": d["rationale"] or "",
            "disposition": d["disposition"] or "", "assignee": d["assignee"] or "", "ttd": round((d["ttd_s"] or 0) / 60, 1), "ttr": d["ttr_s"] or 0,
            "ai_verdict": d.get("ai_verdict") or "", "ai_conf": d.get("ai_conf") or 0, "ai_rec": d.get("ai_rec") or ""}


def need(b, *keys):
    for k in keys:
        if b.get(k) in (None, ""):
            raise ValueError("missing field: %s" % k)


# ------------------------------------------------------------------ read APIs
@route("GET", "/api/health")
def _health(conn, q, b, who):
    return {"ok": True}


@route("GET", "/api/state")
def _state(conn, q, b, who):
    now = int(time.time())
    rows = conn.execute("SELECT a.*, x.ai_verdict, x.ai_conf, x.ai_rec FROM alerts a LEFT JOIN ai_assessments x ON x.alert_id=a.id "
                        "WHERE a.ts>=? ORDER BY a.ts DESC LIMIT 800", (now - 86400,)).fetchall()
    return {"now": now, "mode": "n8n" if CFG["n8n"] else "local", "alerts": [alert_row(r) for r in rows],
            "pending_approvals": conn.execute("SELECT COUNT(*) FROM actions WHERE state='pending'").fetchone()[0],
            "playbooks": [{"name": p["name"], "trigger": p["trigger"], "steps": p["steps"]} for p in soar.PLAYBOOKS],
            "ai": ai_analyst.backend_info()}


@route("GET", "/api/alert")
def _alert(conn, q, b, who):
    aid = int(q.get("id", ["0"])[0])
    r = conn.execute("SELECT a.*, x.ai_verdict, x.ai_conf, x.ai_rec FROM alerts a LEFT JOIN ai_assessments x ON x.alert_id=a.id WHERE a.id=?", (aid,)).fetchone()
    if not r:
        raise LookupError("alert not found")
    a = alert_row(r)
    ev = [dict(e) for e in conn.execute("SELECT ts,etype,user,ip,country,asset,ua,ok,amount,detail FROM events WHERE ts BETWEEN ? AND ? AND (user=? OR ip=?) ORDER BY ts LIMIT 40",
                                        (a["t"] // 1000 - 1800, a["t"] // 1000 + 1800, a["user"], a["ip"]))]
    tl = [dict(x) for x in conn.execute("SELECT ts,actor,action,detail FROM audit_log WHERE target=? ORDER BY id", ("alert:%d" % aid,))]
    rule = conn.execute("SELECT description FROM rules WHERE id=?", (a["rule_id"],)).fetchone()
    return {"alert": a, "rule_desc": rule[0] if rule else "", "events": ev, "timeline": tl,
            "actions": [dict(x) for x in conn.execute("SELECT * FROM actions WHERE alert_id=? ORDER BY id", (aid,))],
            "notes": [dict(x) for x in conn.execute("SELECT * FROM notes WHERE alert_id=? ORDER BY id", (aid,))],
            "ai": ai_analyst.get(conn, aid),
            "feedback": [dict(x) for x in conn.execute("SELECT * FROM ai_feedback WHERE alert_id=? ORDER BY id DESC LIMIT 3", (aid,))]}


@route("GET", "/api/approvals")
def _approvals(conn, q, b, who):
    rows = conn.execute("SELECT x.id AS action_id, x.action, x.target, x.requested_ts, a.id AS alert_id, a.sev, a.priority, a.rule, a.user, a.ip, a.asset, a.score, "
                        "i.ai_verdict, i.ai_conf, i.ai_rec FROM actions x JOIN alerts a ON a.id=x.alert_id LEFT JOIN ai_assessments i ON i.alert_id=a.id "
                        "WHERE x.state='pending' ORDER BY a.score DESC, x.requested_ts").fetchall()
    return {"rows": [dict(r) for r in rows]}


@route("GET", "/api/metrics")
def _metrics(conn, q, b, who):
    return metrics.compute(conn)


@route("GET", "/api/grc")
def _grc(conn, q, b, who):
    return grc.compute(conn)


@route("GET", "/api/audit")
def _audit(conn, q, b, who):
    rows = [dict(r) for r in conn.execute("SELECT id,ts,actor,action,target,detail FROM audit_log ORDER BY ts DESC, id DESC LIMIT 150")]
    ok, n, bad = verify_audit(conn)
    return {"chain": {"ok": ok, "count": n, "broken_at": bad}, "rows": rows}


@route("GET", "/api/ai/stats")
def _ai_stats(conn, q, b, who):
    return ai_analyst.stats(conn)


@route("GET", "/api/ai/feedback.jsonl")
def _ai_jsonl(conn, q, b, who):
    return ai_analyst.feedback_jsonl(conn), "application/x-ndjson", "nilepay_ai_feedback.jsonl"


@route("GET", "/api/report/soc")
def _r_soc(conn, q, b, who):
    audit(conn, who, "REPORT_GENERATED", "soc", "nilepay_soc_report.pdf")
    return reports.soc_report(conn), "application/pdf", "nilepay_soc_report.pdf"


@route("GET", "/api/report/grc")
def _r_grc(conn, q, b, who):
    audit(conn, who, "REPORT_GENERATED", "grc", "nilepay_grc_report.pdf")
    return reports.grc_report(conn), "application/pdf", "nilepay_grc_report.pdf"


@route("GET", "/api/report/alert")
def _r_alert(conn, q, b, who):
    aid = int(q.get("id", ["0"])[0])
    data = reports.alert_report(conn, aid)
    if data is None:
        raise LookupError("alert not found")
    audit(conn, who, "REPORT_GENERATED", "alert:%d" % aid, "nilepay_alert_%d.pdf" % aid)
    return data, "application/pdf", "nilepay_alert_%d.pdf" % aid


# ------------------------------------------------------------------ alert workflow
@route("POST", "/api/response")  # n8n callback (optional; detect.py also applies n8n's webhook response)
def _response(conn, q, b, who):
    soar.apply_response(conn, b, actor="n8n")
    return {"ok": True, "id": b["id"], "status": b["status"]}


@route("POST", "/api/action/decide")
def _decide(conn, q, b, who):
    need(b, "action_id", "decision")
    return soar.decide(conn, b["action_id"], b["decision"], who, b.get("reason", ""))


@route("POST", "/api/alert/update")
def _update(conn, q, b, who):
    need(b, "id", "status")
    soar.analyst_update(conn, b["id"], b["status"], who, b.get("note", ""), b.get("disposition"), b.get("to"))
    return {"ok": True, "id": int(b["id"]), "status": b["status"]}


@route("POST", "/api/alert/note")
def _note(conn, q, b, who):
    need(b, "id", "text")
    if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (int(b["id"]),)).fetchone():
        raise LookupError("alert not found")
    conn.execute("INSERT INTO notes(alert_id,ts,author,kind,text) VALUES (?,?,?,'note',?)", (int(b["id"]), int(time.time()), who, str(b["text"])[:2000]))
    conn.commit()
    audit(conn, who, "NOTE_ADDED", "alert:%d" % int(b["id"]), str(b["text"])[:80])
    return {"ok": True}


# ------------------------------------------------------------------ AI analyst
@route("POST", "/api/ai/assess")
def _assess(conn, q, b, who):
    need(b, "id")
    res = ai_analyst.assess_and_store(conn, b["id"], bool(b.get("llm")), bool(b.get("valor")))
    audit(conn, who, "AI_ASSESS", "alert:%d" % int(b["id"]), res["backend"])
    return res


@route("POST", "/api/ai/feedback")
def _feedback(conn, q, b, who):
    need(b, "alert_id", "rating")
    return ai_analyst.add_feedback(conn, b["alert_id"], who, b["rating"], b.get("correct_verdict", ""), b.get("comment", ""))


# ------------------------------------------------------------------ detection engineering
def rule_test(sql):
    cols, rows, trunc = safe_query(sql, 1000)
    missing = {"ts", "user", "ip", "asset", "detail"} - {c.lower() for c in cols}
    if missing:
        raise ValueError("A detection must return the columns ts, user, ip, asset, detail (missing: %s)" % ", ".join(sorted(missing)))
    return {"ok": True, "cols": cols, "count": len(rows), "truncated": trunc, "sample": rows[:8]}


@route("GET", "/api/rules")
def _rules(conn, q, b, who):
    now = int(time.time())
    out = []
    for r in conn.execute("SELECT * FROM rules ORDER BY id"):
        d = dict(r)
        st = conn.execute("SELECT COUNT(*), SUM(disposition='True Positive'), SUM(disposition='False Positive'), SUM(disposition='Benign True Positive') FROM alerts WHERE rule_id=?", (d["id"],)).fetchone()
        n24 = conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id=? AND ts>=?", (d["id"], now - 86400)).fetchone()[0]
        tp, fp, btp = st[1] or 0, st[2] or 0, st[3] or 0
        d.update({"alerts_total": st[0], "alerts_24h": n24, "tp": tp, "fp": fp, "btp": btp, "precision": round(100.0 * tp / (tp + fp + btp), 1) if tp + fp + btp else None})
        out.append(d)
    return {"rules": out, "playbooks": [p["name"] for p in soar.PLAYBOOKS], "tactics": metrics.TACTICS}


@route("POST", "/api/rules/test")
def _rule_test(conn, q, b, who):
    return rule_test(b.get("sql", ""))


@route("POST", "/api/rules/save")
def _rule_save(conn, q, b, who):
    need(b, "name", "sev", "tactic", "playbook", "sql")
    if b["sev"] not in SEVS:
        raise ValueError("invalid severity")
    if b["tactic"] not in metrics.TACTICS:
        raise ValueError("invalid ATT&CK tactic")
    if b["playbook"] not in [p["name"] for p in soar.PLAYBOOKS]:
        raise ValueError("unknown response playbook")
    bucket = int(b.get("bucket") or 3600)
    if not 60 <= bucket <= 86400:
        raise ValueError("dedupe window must be between 60 and 86400 seconds")
    t = rule_test(b["sql"])
    now = int(time.time())
    rid = b.get("id")
    if rid and conn.execute("SELECT 1 FROM rules WHERE id=?", (rid,)).fetchone():
        conn.execute("UPDATE rules SET name=?,description=?,sev=?,tactic=?,tech=?,playbook=?,bucket=?,sql=?,enabled=?,version=version+1,updated_ts=?,updated_by=? WHERE id=?",
                     (b["name"], b.get("description", ""), b["sev"], b["tactic"], b.get("tech", ""), b["playbook"], bucket, b["sql"], 1 if b.get("enabled", 1) else 0, now, who, rid))
        act = "RULE_UPDATED"
    else:
        n = conn.execute("SELECT COUNT(*) FROM rules WHERE origin='custom'").fetchone()[0] + 1
        rid = "U%02d" % n
        while conn.execute("SELECT 1 FROM rules WHERE id=?", (rid,)).fetchone():
            n += 1; rid = "U%02d" % n
        conn.execute("INSERT INTO rules(id,name,description,sev,tactic,tech,playbook,bucket,sql,enabled,origin,version,updated_ts,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,'custom',1,?,?)",
                     (rid, b["name"], b.get("description", ""), b["sev"], b["tactic"], b.get("tech", ""), b["playbook"], bucket, b["sql"], 1 if b.get("enabled", 1) else 0, now, who))
        act = "RULE_CREATED"
    conn.commit()
    audit(conn, who, act, "rule:" + rid, "%s (%d test hits)" % (b["name"], t["count"]))
    return {"ok": True, "id": rid, "test": t}


@route("POST", "/api/rules/toggle")
def _rule_toggle(conn, q, b, who):
    need(b, "id")
    cur = conn.execute("UPDATE rules SET enabled=?, updated_ts=?, updated_by=? WHERE id=?", (1 if b.get("enabled") else 0, int(time.time()), who, b["id"]))
    conn.commit()
    if cur.rowcount == 0:
        raise LookupError("rule not found")
    audit(conn, who, "RULE_ENABLED" if b.get("enabled") else "RULE_DISABLED", "rule:" + b["id"], "")
    return {"ok": True}


@route("POST", "/api/rules/delete")
def _rule_delete(conn, q, b, who):
    need(b, "id")
    r = conn.execute("SELECT origin FROM rules WHERE id=?", (b["id"],)).fetchone()
    if not r:
        raise LookupError("rule not found")
    if r[0] != "custom":
        raise ValueError("Built-in rules cannot be deleted - disable them instead")
    conn.execute("DELETE FROM rules WHERE id=?", (b["id"],))
    conn.commit()
    audit(conn, who, "RULE_DELETED", "rule:" + b["id"], "")
    return {"ok": True}


@route("GET", "/api/suppressions")
def _supp(conn, q, b, who):
    now = int(time.time())
    return {"rows": [dict(r, active=(r["expires_ts"] is None or r["expires_ts"] > now)) for r in conn.execute("SELECT * FROM suppressions ORDER BY id DESC")]}


@route("POST", "/api/suppress")
def _suppress(conn, q, b, who):
    need(b, "rule_id", "reason")
    user, ip = str(b.get("user") or "").strip(), str(b.get("ip") or "").strip()
    if not (user or ip):
        raise ValueError("Suppress by a user and/or an IP - suppressing a whole rule is not allowed (disable it instead)")
    days = max(1, min(90, int(b.get("days") or 7)))
    now = int(time.time())
    conn.execute("INSERT INTO suppressions(rule_id,user,ip,reason,created_by,created_ts,expires_ts) VALUES (?,?,?,?,?,?,?)",
                 (b["rule_id"], user, ip, str(b["reason"])[:300], who, now, now + days * 86400))
    conn.commit()
    audit(conn, who, "SUPPRESSION_ADDED", "rule:" + b["rule_id"], "user=%s ip=%s days=%d reason=%s" % (user or "*", ip or "*", days, str(b["reason"])[:80]))
    return {"ok": True}


@route("POST", "/api/suppress/delete")
def _supp_del(conn, q, b, who):
    need(b, "id")
    conn.execute("DELETE FROM suppressions WHERE id=?", (int(b["id"]),))
    conn.commit()
    audit(conn, who, "SUPPRESSION_REMOVED", "suppression:%d" % int(b["id"]), "")
    return {"ok": True}


# ------------------------------------------------------------------ threat hunting
def run_hunt_row(conn, h, who):
    t0 = time.time()
    cols, rows, trunc = safe_query(h["sql"], 200)
    conn.execute("UPDATE hunts SET last_run_ts=?, last_leads=? WHERE id=?", (int(time.time()), len(rows), h["id"]))
    conn.commit()
    audit(conn, who, "HUNT_RUN", "hunt:" + h["id"], "leads=%d" % len(rows))
    return {"id": h["id"], "name": h["name"], "cols": cols, "count": len(rows), "rows": rows[:25], "truncated": trunc, "ms": int((time.time() - t0) * 1000)}


@route("GET", "/api/hunts")
def _hunts(conn, q, b, who):
    return {"hunts": [dict(r) for r in conn.execute("SELECT * FROM hunts ORDER BY CAST(SUBSTR(id,2) AS INTEGER)")], "tactics": metrics.TACTICS, "statuses": HUNT_STATUS}


@route("POST", "/api/hunts/run")
def _hunt_run(conn, q, b, who):
    need(b, "id")
    h = conn.execute("SELECT * FROM hunts WHERE id=?", (b["id"],)).fetchone()
    if not h:
        raise LookupError("hunt not found")
    return run_hunt_row(conn, dict(h), who)


@route("GET", "/api/hunts/run-all")  # used by the n8n hunt-digest workflow
def _hunt_all(conn, q, b, who):
    res = []
    for h in conn.execute("SELECT * FROM hunts ORDER BY id").fetchall():
        try:
            r = run_hunt_row(conn, dict(h), "hunt-scheduler")
            res.append({"id": r["id"], "name": r["name"], "hits": r["count"]})
        except ValueError:
            res.append({"id": h["id"], "name": h["name"], "hits": 0})
    return {"hunts": res, "total_hits": sum(x["hits"] for x in res)}


@route("POST", "/api/hunts/save")
def _hunt_save(conn, q, b, who):
    need(b, "name", "tactic", "sql")
    if b["tactic"] not in metrics.TACTICS:
        raise ValueError("invalid ATT&CK tactic")
    status = b.get("status") or "Planned"
    if status not in HUNT_STATUS:
        raise ValueError("invalid status")
    safe_query(b["sql"], 1)  # must be a valid read-only query
    now, hid = int(time.time()), b.get("id")
    if hid and conn.execute("SELECT 1 FROM hunts WHERE id=?", (hid,)).fetchone():
        conn.execute("UPDATE hunts SET name=?,tactic=?,hyp=?,sql=?,status=?,findings=?,updated_ts=?,updated_by=? WHERE id=?",
                     (b["name"], b["tactic"], b.get("hyp", ""), b["sql"], status, b.get("findings", ""), now, who, hid))
        act = "HUNT_UPDATED"
    else:
        n = conn.execute("SELECT COALESCE(MAX(CAST(SUBSTR(id,2) AS INTEGER)),0)+1 FROM hunts").fetchone()[0]
        hid = "H%d" % n
        conn.execute("INSERT INTO hunts(id,name,tactic,hyp,sql,status,origin,updated_ts,updated_by,findings) VALUES (?,?,?,?,?,?,'custom',?,?,?)",
                     (hid, b["name"], b["tactic"], b.get("hyp", ""), b["sql"], status, now, who, b.get("findings", "")))
        act = "HUNT_CREATED"
    conn.commit()
    audit(conn, who, act, "hunt:" + hid, b["name"])
    return {"ok": True, "id": hid}


@route("POST", "/api/hunts/delete")
def _hunt_del(conn, q, b, who):
    need(b, "id")
    r = conn.execute("SELECT origin FROM hunts WHERE id=?", (b["id"],)).fetchone()
    if not r:
        raise LookupError("hunt not found")
    if r[0] != "custom":
        raise ValueError("Built-in hunts cannot be deleted")
    conn.execute("DELETE FROM hunts WHERE id=?", (b["id"],))
    conn.commit()
    audit(conn, who, "HUNT_DELETED", "hunt:" + b["id"], "")
    return {"ok": True}


@route("POST", "/api/query")
def _query(conn, q, b, who):
    t0 = time.time()
    cols, rows, trunc = safe_query(b.get("sql", ""), 200)
    audit(conn, who, "ADHOC_QUERY", "workbench", re.sub(r"\s+", " ", b.get("sql", ""))[:160])
    return {"cols": cols, "rows": rows, "count": len(rows), "truncated": trunc, "ms": int((time.time() - t0) * 1000)}


# ------------------------------------------------------------------ HTTP plumbing
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj, ctype="application/json; charset=utf-8", fname=None):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if fname:
            self.send_header("Content-Disposition", 'inline; filename="%s"' % fname)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self, method):
        u = urlparse(self.path)
        if method == "GET" and u.path in ("/", "/index.html"):
            return self.send(200, (ROOT / "dashboard" / "index.html").read_bytes(), "text/html; charset=utf-8")
        fn = ROUTES.get((method, u.path))
        if not fn:
            return self.send(404, {"error": "not found"})
        conn = None
        try:
            q = parse_qs(u.query)
            b = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                b = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                if not isinstance(b, dict):
                    raise ValueError("JSON object expected")
            who = re.sub(r"[^A-Za-z0-9_.@ -]", "", str(b.get("actor") or q.get("actor", ["analyst"])[0]))[:40] or "analyst"
            conn = connect()
            out = fn(conn, q, b, who)
            if isinstance(out, tuple):
                return self.send(200, out[0], out[1], out[2])
            self.send(200, out)
        except LookupError as e:
            self.send(404, {"error": str(e).strip("'")})
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            self.send(400, {"error": str(e).strip("'")})
        except Exception as e:
            self.send(500, {"error": "server error: %s" % e})
        finally:
            if conn:
                conn.close()

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def make_server(host="0.0.0.0", port=8080):
    srv = ThreadingHTTPServer((host, port), H)
    srv.daemon_threads = True
    return srv


def use_n8n_actions(flag):
    CFG["n8n"] = flag
    if flag:
        os.environ.setdefault("N8N_ACTION_URL", "http://localhost:5678/webhook/nilepay-action")


def live_loop(use_n8n, interval=25, stop=None):
    while not (stop and stop.is_set()):
        time.sleep(interval)
        try:
            conn = connect()
            kind = gen_logs.live_attack(conn)
            n = detect.run_detection(conn, use_n8n)
            conn.close()
            print("[live] %s -> %d new alert(s)" % (kind, n))
        except Exception as e:
            print("[live] error:", e)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--n8n", action="store_true")
    ap.add_argument("--no-live", action="store_true")
    a = ap.parse_args()
    init_db()
    use_n8n_actions(a.n8n)
    if not a.no_live:
        threading.Thread(target=live_loop, args=(a.n8n,), daemon=True).start()
    print("Console: http://localhost:%d" % a.port)
    make_server(a.host, a.port).serve_forever()
