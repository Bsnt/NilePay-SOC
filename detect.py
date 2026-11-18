"""Detection engine: runs enabled rules (stored in the DB, editable in the UI) over events, honours suppressions,
writes alerts, dispatches each new alert to n8n (or the local SOAR), then adds the AI analyst's assessment."""
import argparse, json, os, time, urllib.request
from common import connect, audit
import soar

N8N_URL = os.environ.get("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/nilepay-alert")
_warned = {"n8n": False}
COLS = "id,ts,rule_id,rule,sev,tactic,tech,user,ip,asset,detail,playbook"


def alert_dict(conn, aid):
    return dict(conn.execute("SELECT %s FROM alerts WHERE id=?" % COLS, (aid,)).fetchone())


def dispatch(conn, aid, use_n8n):
    a = alert_dict(conn, aid)
    if use_n8n:
        try:
            req = urllib.request.Request(N8N_URL, json.dumps(a).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
            try:  # n8n returns its triage result in the webhook response
                r = json.loads(body.decode("utf-8"))
                if isinstance(r, dict) and r.get("status") in soar.VALID_STATUS and int(r.get("id", -1)) == aid:
                    soar.apply_response(conn, r, actor="n8n")
            except (ValueError, UnicodeDecodeError):
                pass
        except Exception as e:
            if not _warned["n8n"]:
                print("[detect] n8n not reachable (%s) -> using local SOAR fallback" % e)
                _warned["n8n"] = True
        if conn.execute("SELECT status FROM alerts WHERE id=?", (aid,)).fetchone()[0] != "New":
            return "n8n"
    soar.apply_response(conn, soar.triage(a), actor="local-soar")
    return "local"


def suppressed(conn, rule_id, user, ip, now):
    return conn.execute("SELECT 1 FROM suppressions WHERE rule_id=? AND (expires_ts IS NULL OR expires_ts>?) AND (user='' OR user=?) AND (ip='' OR ip=?) LIMIT 1",
                        (rule_id, now, user, ip)).fetchone() is not None


def run_detection(conn, use_n8n=False, with_ai=True):
    now = int(time.time())
    new = []
    for rule in conn.execute("SELECT * FROM rules WHERE enabled=1 ORDER BY id").fetchall():
        try:
            rows = conn.execute(rule["sql"]).fetchall()
        except Exception as e:  # a broken custom rule must never stop the engine
            print("[detect] rule %s failed: %s" % (rule["id"], e))
            continue
        for row in rows:
            ts = int(row["ts"])
            if suppressed(conn, rule["id"], str(row["user"]), str(row["ip"]), now):
                continue
            key = "%s|%s|%s|%d" % (rule["id"], row["user"], row["ip"], ts // rule["bucket"])
            detected = ((ts // 300) + 1) * 300  # rules are scheduled every 5 minutes
            cur = conn.execute(
                "INSERT OR IGNORE INTO alerts(key,ts,detected_ts,rule_id,rule,sev,tactic,tech,user,ip,asset,detail,status,playbook,ttd_s) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'New', ?, ?)",
                (key, ts, detected, rule["id"], rule["name"], rule["sev"], rule["tactic"], rule["tech"], row["user"], row["ip"],
                 row["asset"], row["detail"], rule["playbook"], detected - ts))
            if cur.rowcount:
                aid = cur.lastrowid
                conn.commit()
                audit(conn, "detection-engine", "ALERT_CREATED", "alert:%d" % aid, "%s %s" % (rule["id"], rule["sev"]))
                new.append(aid)
    conn.commit()  # commit BEFORE dispatch so n8n callbacks can write
    for aid in new:
        dispatch(conn, aid, use_n8n)
        if with_ai:
            try:
                import ai_analyst
                ai_analyst.assess_and_store(conn, aid)
            except Exception as e:
                print("[detect] AI assessment failed for %d: %s" % (aid, e))
    return len(new)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n", action="store_true", help="send alerts to the n8n webhook")
    args = ap.parse_args()
    print("new alerts:", run_detection(connect(), args.n8n))
