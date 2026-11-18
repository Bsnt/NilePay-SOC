"""Shared helpers: DB, schema, seeding, safe read-only query runner, tamper-evident audit log. Standard library only."""
import hashlib, json, os, pathlib, sqlite3, threading, time

ROOT = pathlib.Path(__file__).resolve().parent
DB_PATH = os.environ.get("NILEPAY_DB", str(ROOT / "nilepay.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, etype TEXT, user TEXT, ip TEXT,
  country TEXT, asset TEXT, ua TEXT, ok INTEGER, amount REAL, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_e1 ON events(etype, user, ts);
CREATE INDEX IF NOT EXISTS ix_e2 ON events(etype, ip, ts);
CREATE INDEX IF NOT EXISTS ix_e3 ON events(ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, ts INTEGER, detected_ts INTEGER,
  rule_id TEXT, rule TEXT, sev TEXT, tactic TEXT, tech TEXT, user TEXT, ip TEXT, asset TEXT,
  detail TEXT, status TEXT DEFAULT 'New', playbook TEXT, verdict TEXT, score INTEGER,
  actions TEXT, ttd_s INTEGER, ttr_s INTEGER, responded_ts INTEGER,
  priority TEXT, rationale TEXT, disposition TEXT, assignee TEXT, first_touch_ts INTEGER, closed_ts INTEGER);
CREATE TABLE IF NOT EXISTS rules(
  id TEXT PRIMARY KEY, name TEXT, description TEXT, sev TEXT, tactic TEXT, tech TEXT, playbook TEXT,
  bucket INTEGER, sql TEXT, enabled INTEGER DEFAULT 1, origin TEXT, version INTEGER DEFAULT 1,
  updated_ts INTEGER, updated_by TEXT);
CREATE TABLE IF NOT EXISTS hunts(
  id TEXT PRIMARY KEY, name TEXT, tactic TEXT, hyp TEXT, sql TEXT, status TEXT DEFAULT 'Planned',
  origin TEXT, updated_ts INTEGER, updated_by TEXT, last_run_ts INTEGER, last_leads INTEGER, findings TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER, action TEXT, target TEXT, kind TEXT, state TEXT,
  requested_ts INTEGER, decided_ts INTEGER, decided_by TEXT, reason TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS ix_act ON actions(alert_id, state);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER, ts INTEGER, author TEXT, kind TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS suppressions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT, user TEXT, ip TEXT, reason TEXT,
  created_by TEXT, created_ts INTEGER, expires_ts INTEGER);
CREATE TABLE IF NOT EXISTS ai_assessments(
  alert_id INTEGER PRIMARY KEY, ts INTEGER, backend TEXT, ai_verdict TEXT, ai_conf INTEGER, ai_rec TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS ai_feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER, ts INTEGER, analyst TEXT, rating TEXT,
  correct_verdict TEXT, comment TEXT, ai_verdict TEXT, ai_confidence INTEGER, rule_id TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, action TEXT, target TEXT,
  detail TEXT, prev_hash TEXT, hash TEXT);
"""
ALERT_MIGRATE = {"priority": "TEXT", "rationale": "TEXT", "disposition": "TEXT", "assignee": "TEXT",
                 "first_touch_ts": "INTEGER", "closed_ts": "INTEGER"}


def connect():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass
    return c


def load_json(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def seed(conn):
    now = int(time.time())
    if conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0:
        for r in load_json("rules/rules.json"):
            conn.execute("INSERT INTO rules(id,name,description,sev,tactic,tech,playbook,bucket,sql,enabled,origin,version,updated_ts,updated_by) "
                         "VALUES (?,?,?,?,?,?,?,?,?,1,'builtin',1,?,'seed')",
                         (r["id"], r["name"], r.get("desc", ""), r["sev"], r["tactic"], r["tech"], r["playbook"], r["bucket"], r["sql"], now))
    if conn.execute("SELECT COUNT(*) FROM hunts").fetchone()[0] == 0:
        for h in load_json("hunts/hunts.json"):
            conn.execute("INSERT INTO hunts(id,name,tactic,hyp,sql,status,origin,updated_ts,updated_by,findings) VALUES (?,?,?,?,?,'Planned','builtin',?,'seed','')",
                         (h["id"], h["name"], h["tactic"], h["hyp"], h["sql"], now))
    conn.commit()


def init_db(reset=False):
    if reset:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(DB_PATH + suffix)
            except FileNotFoundError:
                pass
    c = connect()
    c.executescript(SCHEMA)
    have = {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
    for col, typ in ALERT_MIGRATE.items():
        if col not in have:
            c.execute("ALTER TABLE alerts ADD COLUMN %s %s" % (col, typ))
    c.commit()
    seed(c)
    return c


# ---------------- safe, read-only SQL for hunting / rule testing ----------------
_OK = getattr(sqlite3, "SQLITE_OK", 0)
_DENY = getattr(sqlite3, "SQLITE_DENY", 1)
_ALLOWED_ACTIONS = {getattr(sqlite3, "SQLITE_SELECT", 21), getattr(sqlite3, "SQLITE_FUNCTION", 31), getattr(sqlite3, "SQLITE_RECURSIVE", 33)}
_READ = getattr(sqlite3, "SQLITE_READ", 20)
READABLE_TABLES = {"events", "alerts"}


def _auth(action, a1, a2, a3, a4):
    if action in _ALLOWED_ACTIONS:
        return _OK
    if action == _READ and a1 in READABLE_TABLES:
        return _OK
    return _DENY


def safe_query(sql, limit=200, seconds=5):
    """Run ONE read-only SELECT on events/alerts. Raises ValueError with a readable message. Returns (cols, rows, truncated)."""
    sql = (sql or "").strip().rstrip(";").strip()
    if not sql or len(sql) > 6000:
        raise ValueError("Query is empty or longer than 6000 characters")
    if not sql.lower().startswith(("select", "with")):
        raise ValueError("Only SELECT queries are allowed")
    conn = connect()
    try:
        conn.execute("PRAGMA query_only=ON")
        deadline = time.time() + seconds
        conn.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 20000)
        conn.set_authorizer(_auth)
        try:
            cur = conn.execute(sql)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchmany(limit + 1)
        except sqlite3.OperationalError as e:
            raise ValueError("Query timed out after %ds" % seconds if "interrupted" in str(e) else "SQL error: %s" % e)
        except sqlite3.Error as e:
            raise ValueError("SQL error or not permitted: %s" % e)
        return cols, [list(r) for r in rows[:limit]], len(rows) > limit
    finally:
        conn.close()


# ---------------- tamper-evident audit log ----------------
_audit_lock = threading.Lock()


def _h(prev, ts, actor, action, target, detail):
    return hashlib.sha256(("%s|%d|%s|%s|%s|%s" % (prev, ts, actor, action, target, detail)).encode("utf-8")).hexdigest()


def audit(conn, actor, action, target="", detail="", ts=None):
    """Append a hash-chained audit record. Callers must have committed any open write first (avoids lock deadlocks)."""
    with _audit_lock:
        row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else "GENESIS"
        ts = int(ts or time.time())
        conn.execute("INSERT INTO audit_log(ts,actor,action,target,detail,prev_hash,hash) VALUES (?,?,?,?,?,?,?)",
                     (ts, actor, action, target, detail, prev, _h(prev, ts, actor, action, target, detail)))
        conn.commit()


def verify_audit(conn):
    """Returns (ok, record_count, first_broken_id)."""
    prev, n = "GENESIS", 0
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _h(prev, r["ts"], r["actor"], r["action"], r["target"], r["detail"]):
            return False, n, r["id"]
        prev, n = r["hash"], n + 1
    return True, n, None


def rechain_audit(conn):
    """DEMO SEEDING ONLY: recompute the hash chain after back-dating seeded history. Never called by normal operation."""
    prev = "GENESIS"
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
        h = _h(prev, r["ts"], r["actor"], r["action"], r["target"], r["detail"])
        conn.execute("UPDATE audit_log SET prev_hash=?, hash=? WHERE id=?", (prev, h, r["id"]))
        prev = h
    conn.commit()
