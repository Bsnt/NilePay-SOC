"""AI analyst (VALOR-style) - explainable assessment of every alert + analyst feedback loop.
Tier 1 (always on): deterministic analyst - gathers context (events, history, similar analyst-reviewed cases = local RAG),
                    scores benign vs malicious indicators, calibrates confidence with analyst dispositions.
Tier 2 (optional) : OLLAMA_URL (+OLLAMA_MODEL, default llama3.1:8b) writes the narrative and gives a second-opinion verdict.
Tier 3 (optional) : VALOR_ANALYST_URL - POSTs alert + context to your VALOR n8n analyst webhook; response shown next to ours.
Feedback          : stored locally (calibrates future confidence, exportable as JSONL) and forwarded to VALOR_FEEDBACK_URL
                    (your Analyst Feedback Ingestion workflow -> RAG update)."""
import json, os, re, time, urllib.request
from collections import Counter
from common import audit, load_json
import soar, knowledge

VERDICTS = ("True Positive", "Needs investigation", "Likely false positive")
RATINGS = {"agree": 1.0, "partially": 0.5, "disagree": 0.0}


def cfg():
    return {"ollama_url": os.environ.get("OLLAMA_URL", "").rstrip("/"), "ollama_model": os.environ.get("OLLAMA_MODEL", "llama3.1:8b"),
            "valor_url": os.environ.get("VALOR_ANALYST_URL", ""), "feedback_url": os.environ.get("VALOR_FEEDBACK_URL", "")}


def backend_info():
    c = cfg()
    return {"engine": "built-in deterministic analyst", "ollama": c["ollama_model"] if c["ollama_url"] else None,
            "valor_analyst": bool(c["valor_url"]), "feedback_forwarding": bool(c["feedback_url"])}


def _post(url, payload, timeout):
    req = urllib.request.Request(url, json.dumps(payload).encode("utf-8"), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def context(conn, a):
    ev = [dict(r) for r in conn.execute(
        "SELECT ts,etype,user,ip,country,asset,ua,ok,amount,detail FROM events WHERE ts BETWEEN ? AND ? AND (user=? OR ip=?) ORDER BY ts LIMIT 80",
        (a["ts"] - 3600, a["ts"] + 3600, a["user"], a["ip"]))]
    prior = [dict(r) for r in conn.execute("SELECT id,rule_id,rule,disposition FROM alerts WHERE id<>? AND ts>=? AND (user=? OR ip=?) LIMIT 20",
                                           (a["id"], a["ts"] - 86400, a["user"], a["ip"]))]
    disp = {r[0]: r[1] for r in conn.execute("SELECT disposition, COUNT(*) FROM alerts WHERE rule_id=? AND disposition IS NOT NULL GROUP BY disposition", (a["rule_id"],))}
    similar = [dict(r) for r in conn.execute(
        "SELECT a.id, a.user, a.ip, a.disposition, (SELECT text FROM notes n WHERE n.alert_id=a.id AND n.kind='closure' ORDER BY n.id DESC LIMIT 1) AS note "
        "FROM alerts a WHERE a.rule_id=? AND a.id<>? AND a.disposition IS NOT NULL ORDER BY (a.user=? OR a.ip=?) DESC, a.closed_ts DESC LIMIT 3",
        (a["rule_id"], a["id"], a["user"], a["ip"]))]
    fb = [dict(r) for r in conn.execute("SELECT rating, correct_verdict, comment FROM ai_feedback WHERE rule_id=? ORDER BY id DESC LIMIT 5", (a["rule_id"],))]
    pending = [dict(r) for r in conn.execute("SELECT id, action, target FROM actions WHERE alert_id=? AND state='pending'", (a["id"],))]
    return {"events": ev, "prior": prior, "disp": disp, "similar": similar, "feedback": fb, "pending": pending}


def _clock(ts):
    return time.strftime("%H:%M", time.gmtime(ts + 7200))


def analyze(a, ctx, conn):
    """Rule-specific evidence reading. Returns (score_adjustment, facts, benign_indicators)."""
    rid, ev, adj, facts, benign = a["rule_id"], ctx["events"], 0, [], []
    bad = a["ip"].startswith(soar.BAD_PREFIXES)
    scripted = lambda e: (e["ua"] or "").startswith(("python-requests", "curl"))
    if rid == "R01":
        f = [e for e in ev if e["etype"] == "payment" and not e["ok"] and e["amount"] < 2]
        cards = len({e["user"] for e in f})
        facts.append("%d failed micro-payments (< 2.00) against %d different customer accounts from one IP" % (len(f), cards))
        if any(scripted(e) for e in f):
            facts.append("Client identifies as a scripted HTTP library, not the NilePay app or a browser"); adj += 8
        if cards >= 10:
            adj += 5
    elif rid == "R02":
        lg = [e for e in ev if e["etype"] == "login" and e["ok"] and e["user"] == a["user"]]
        gap, pair = None, None
        for x, y in zip(lg, lg[1:]):
            if x["country"] != y["country"]:
                gap, pair = (y["ts"] - x["ts"]) // 60, (x["country"], y["country"])
        if pair:
            facts.append("Successful logins from %s then %s only %d minutes apart" % (pair[0], pair[1], gap))
            if not bad and pair[1] in knowledge.HUBS and gap >= 30:
                benign.append("%s is a common travel hub, the gap is compatible with a flight and the source IP has no bad reputation" % pair[1]); adj -= 20
    elif rid == "R03":
        f = [e for e in ev if e["etype"] == "login" and not e["ok"] and e["ip"] == a["ip"]]
        facts.append("%d failed logins across %d accounts from this IP in the window" % (len(f), len({e["user"] for e in f})))
        succ = [e for e in ev if e["etype"] == "login" and e["ok"] and e["ip"] == a["ip"]]
        facts.append("%d successful login(s) from the same IP - %s" % (len(succ), "possible compromised account" if succ else "no account takeover seen yet"))
        adj += 15 if succ else 10
    elif rid == "R04":
        names = {e["etype"] for e in ev}
        facts.append("SIM swap followed by a large payout (%s)" % a["detail"])
        if {"password_reset", "new_device"} <= names:
            facts.append("Password reset and an unknown new device appear between the SIM swap and the payout"); adj += 10
    elif rid == "R05":
        f = [e for e in ev if e["etype"] == "api" and e["country"] != "EG"]
        facts.append("%d API calls from %s, outside the merchant's baseline country (EG)" % (len(f), f[0]["country"] if f else "?"))
        if any(scripted(e) for e in f):
            facts.append("Calls use a scripted HTTP library instead of the merchant SDK"); adj += 10
        elif f and all((e["ua"] or "").startswith("merchant-sdk") for e in f) and not bad:
            benign.append("Requests use the merchant's normal SDK user-agent and the IP has no bad reputation (looks like a new branch or hosting region)"); adj -= 20
    elif rid == "R06":
        facts.append(a["detail"])
        tick = [e["detail"] for e in ev if e["etype"] == "vpn" and "oncall=" in (e["detail"] or "")]
        if tick:
            benign.append("VPN event carries an on-call ticket reference (%s)" % tick[0].split("oncall=")[1].split()[0]); adj -= 35
        if bad:
            facts.append("Connection comes from a known-bad IP range, not an administrator's usual network"); adj += 15
    elif rid == "R07":
        n = int(re.match(r"(\d+)", a["detail"]).group(1)) if re.match(r"(\d+)", a["detail"]) else 0
        tot = conn.execute("SELECT COUNT(*) FROM events WHERE etype='kyc_read'").fetchone()[0]
        usr = max(1, conn.execute("SELECT COUNT(DISTINCT user) FROM events WHERE etype='kyc_read'").fetchone()[0])
        base = max(1.0, tot / usr / 24.0)
        facts.append("%d KYC records read in one hour vs. a peer baseline of about %.0f per hour" % (n, base))
        if n > 10 * base:
            adj += 20
    elif rid == "R08":
        facts.append(a["detail"] + " by a service account (normal is a few thousand)"); adj += 10
    elif rid == "R09":
        big = [e for e in ev if e["etype"] == "refund" and e["amount"] >= 1000 and e["ts"] > a["ts"]]
        facts.append("%s; %d large refund(s) followed within the window" % (a["detail"], len(big)))
        if len(big) >= 3:
            adj += 15
    elif rid == "R10":
        f = [e for e in ev if e["etype"] == "mfa" and not e["ok"]]
        ok_after = [e for e in ev if e["etype"] == "mfa" and e["ok"] and e["ts"] >= a["ts"]]
        facts.append("%d failed MFA prompts in the window from %s" % (len(f), a["ip"]))
        if ok_after and not bad:
            benign.append("A successful MFA follows from the customer's own IP - consistent with a user mistyping codes"); adj -= 25
        elif not ok_after:
            facts.append("No successful MFA afterwards; prompts came from an IP outside the customer's baseline"); adj += 20
    elif rid == "R11":
        part = [e for e in ev if "partner=" in (e["detail"] or "") or "Partner-Monitor" in (e["ua"] or "")]
        facts.append(a["detail"] + " to the mobile gateway")
        if part:
            benign.append("Traffic matches a known partner monitoring agent (%s)" % (part[0]["detail"] or part[0]["ua"])); adj -= 40
        elif any(scripted(e) for e in ev):
            facts.append("Scripted client (curl/python) enumerating the gateway"); adj += 10
    elif rid == "R12":
        facts.append(a["detail"])
        if "granted_by=svc_" in a["detail"]:
            facts.append("Admin role granted by a service account - normally only IAM administrators do this"); adj += 20
    elif rid == "R13":
        foreign = [e for e in ev if e["etype"] == "payout" and e["country"] != "EG"]
        facts.append(a["detail"])
        if foreign:
            facts.append("Payout was requested from %s, not the customer's usual country" % foreign[0]["country"]); adj += 10
    elif rid == "R14":
        facts.append("Successful login through a TOR exit node")
        adj += 15
    elif rid == "R15":
        exe = a["detail"].split(": ", 1)[-1]
        facts.append("Process '%s' executed on payment host %s" % (exe, a["asset"]))
        adj += 25 if exe in ("mimikatz", "nc -e") else 20
    else:
        facts.append(a["detail"])
    if len(ctx["prior"]) >= 2:
        facts.append("%d other alert(s) involve the same user/IP in the last 24h" % len(ctx["prior"])); adj += 5
    return adj, facts, benign


def assess(conn, aid, llm=False, valor=False):
    r = conn.execute("SELECT * FROM alerts WHERE id=?", (int(aid),)).fetchone()
    if not r:
        raise LookupError("alert not found")
    a = dict(r)
    ctx = context(conn, a)
    base = soar.triage(a)["score"]
    adj, facts, benign = analyze(a, ctx, conn)
    score = max(0, min(100, base + adj))
    verdict = VERDICTS[0] if score >= 75 else VERDICTS[1] if score >= 45 else VERDICTS[2]
    conf = min(95.0, 50 + abs(score - 60) * 0.8)
    d, note = ctx["disp"], ""
    n = sum(d.values())
    prec = (d.get("True Positive", 0) + 1.0) / (n + 2)
    if n >= 3 and verdict == VERDICTS[0] and prec < 0.4:
        conf *= 0.8; note = "Confidence lowered: analysts closed %d of %d past '%s' alerts as benign/false positive" % (n - d.get("True Positive", 0), n, a["rule"])
    elif n >= 3 and verdict == VERDICTS[2] and prec > 0.7:
        conf *= 0.8; note = "Confidence lowered: %d of %d past '%s' alerts were true positives" % (d.get("True Positive", 0), n, a["rule"])
    elif n >= 3:
        note = "Rule history: %d of %d analyst-reviewed alerts were true positives" % (d.get("True Positive", 0), n)
    dis = [f for f in ctx["feedback"] if f["rating"] == "disagree"]
    if len(dis) >= 2:
        conf *= 0.9; note = (note + "; " if note else "") + "Analysts disagreed with the last %d assessments on this rule" % len(dis)
    sev = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 45 else "Low"
    pend = ctx["pending"]
    if not pend:
        rec = {"decision": "none", "reason": "No disruptive action is waiting for approval on this alert."}
    elif verdict == VERDICTS[0]:
        rec = {"decision": "approve", "reason": "Evidence supports malicious activity and the requested containment (%s) is proportionate." % ", ".join(p["action"] for p in pend)}
    elif verdict == VERDICTS[2]:
        rec = {"decision": "reject", "reason": "Evidence points to benign activity; containment would disrupt a legitimate user or service."}
    else:
        rec = {"decision": "review", "reason": "Evidence is inconclusive - validate with the owner (see questions) before any disruptive action."}
    summary = "%s (%d%% confidence). %s" % (verdict, round(conf), (benign[0] if benign and verdict == VERDICTS[2] else facts[0]) if (benign or facts) else a["detail"])
    out = {"alert_id": a["id"], "ts": int(time.time()), "backend": "built-in", "verdict": verdict, "confidence": round(conf), "ai_score": score,
           "soar_score": base, "suggested_severity": sev, "summary": summary, "reasoning": facts, "benign_indicators": benign,
           "similar_cases": ctx["similar"], "next_steps": [s.strip() for s in knowledge.REC.get(a["rule_id"], knowledge.DEFAULT_REC).split(";") if s.strip()],
           "soar_recommendation": rec, "questions": knowledge.QUESTIONS.get(a["rule_id"], []), "calibration": note}
    c = cfg()
    if llm and c["ollama_url"]:
        try:
            out["llm"] = _ollama(c, a, out)
            out["backend"] = "built-in + ollama (%s)" % c["ollama_model"]
        except Exception as e:
            out["llm_error"] = str(e)[:160]
    elif llm:
        out["llm_error"] = "OLLAMA_URL is not set"
    if valor and c["valor_url"]:
        try:
            out["valor"] = _post(c["valor_url"], {"alert": {k: a[k] for k in ("id", "rule_id", "rule", "sev", "user", "ip", "asset", "detail", "tactic", "tech")},
                                                  "assessment": {k: out[k] for k in ("verdict", "confidence", "reasoning", "benign_indicators")},
                                                  "similar_cases": ctx["similar"], "events": ctx["events"][:20]}, 30)
        except Exception as e:
            out["valor_error"] = str(e)[:160]
    elif valor:
        out["valor_error"] = "VALOR_ANALYST_URL is not set"
    return out


def _ollama(c, a, out):
    prompt = ("You are a senior SOC analyst for a payments company. Review the alert and the deterministic findings. "
              "Reply ONLY with JSON: {\"summary\": \"<=70 words\", \"verdict\": \"True Positive|Needs investigation|Likely false positive\", \"concerns\": [\"...\"]}\n"
              "ALERT: %s | severity %s | user %s | ip %s | asset %s | %s\nFINDINGS: %s\nBENIGN INDICATORS: %s\nSIMILAR PAST CASES: %s" % (
                  a["rule"], a["sev"], a["user"], a["ip"], a["asset"], a["detail"], "; ".join(out["reasoning"]),
                  "; ".join(out["benign_indicators"]) or "none", json.dumps(out["similar_cases"])))
    resp = _post(c["ollama_url"] + "/api/generate", {"model": c["ollama_model"], "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0.1}}, 90)
    txt = resp.get("response", "")
    m = re.search(r"\{.*\}", txt, re.S)
    j = json.loads(m.group(0)) if m else {}
    v = j.get("verdict") if j.get("verdict") in VERDICTS else None
    return {"model": c["ollama_model"], "summary": str(j.get("summary", txt))[:600], "verdict": v, "agrees": v == out["verdict"] if v else None,
            "concerns": [str(x)[:200] for x in j.get("concerns", [])][:4]}


def store(conn, res):
    conn.execute("INSERT OR REPLACE INTO ai_assessments(alert_id,ts,backend,ai_verdict,ai_conf,ai_rec,json) VALUES (?,?,?,?,?,?,?)",
                 (res["alert_id"], res["ts"], res["backend"], res["verdict"], res["confidence"], res["soar_recommendation"]["decision"], json.dumps(res)))
    conn.commit()


def get(conn, aid):
    r = conn.execute("SELECT json FROM ai_assessments WHERE alert_id=?", (int(aid),)).fetchone()
    return json.loads(r[0]) if r else None


def assess_and_store(conn, aid, llm=False, valor=False):
    res = assess(conn, aid, llm, valor)
    store(conn, res)
    return res


def add_feedback(conn, aid, analyst, rating, correct_verdict="", comment="", ts=None):
    if rating not in RATINGS:
        raise ValueError("rating must be agree, partially or disagree")
    if rating == "disagree" and correct_verdict not in VERDICTS:
        raise ValueError("when you disagree, choose the correct verdict")
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (int(aid),)).fetchone()
    if not a:
        raise LookupError("alert not found")
    ai = get(conn, aid) or {}
    conn.execute("INSERT INTO ai_feedback(alert_id,ts,analyst,rating,correct_verdict,comment,ai_verdict,ai_confidence,rule_id) VALUES (?,?,?,?,?,?,?,?,?)",
                 (int(aid), int(ts or time.time()), analyst, rating, correct_verdict, (comment or "")[:1000], ai.get("verdict", ""), ai.get("confidence", 0), a["rule_id"]))
    conn.commit()
    audit(conn, analyst, "AI_FEEDBACK", "alert:%d" % int(aid), "%s ai=%s correct=%s" % (rating, ai.get("verdict", ""), correct_verdict or "-"), ts=ts)
    forwarded = forward_feedback(a, ai, analyst, rating, correct_verdict, comment)
    return {"ok": True, "forwarded_to_valor": forwarded}


def forward_feedback(a, ai, analyst, rating, correct, comment):
    """Human-in-the-loop: push feedback to the VALOR 'Analyst Feedback Ingestion' n8n workflow (RAG update).
    Adjust the payload keys below to whatever your workflow expects."""
    url = cfg()["feedback_url"]
    if not url:
        return False
    try:
        _post(url, {"alert_id": "NP-%05d" % a["id"], "rule_id": a["rule_id"], "rule": a["rule"], "severity": a["sev"], "mitre": [a["tactic"], a["tech"]],
                    "alert_summary": a["detail"], "ai_verdict": ai.get("verdict"), "ai_confidence": ai.get("confidence"), "ai_summary": ai.get("summary"),
                    "analyst": analyst, "analyst_rating": rating, "analyst_verdict": correct or ai.get("verdict"), "analyst_comment": comment,
                    "disposition": a["disposition"], "timestamp": int(time.time())}, 8)
        return True
    except Exception:
        return False


def stats(conn):
    fb = [dict(r) for r in conn.execute("SELECT f.*, a.rule FROM ai_feedback f LEFT JOIN alerts a ON a.id=f.alert_id ORDER BY f.id DESC")]
    n = len(fb)
    agree = round(100.0 * sum(RATINGS[f["rating"]] for f in fb) / n, 1) if n else None
    by_rule = {}
    for f in fb:
        b = by_rule.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "rule": f["rule"], "n": 0, "score": 0.0})
        b["n"] += 1; b["score"] += RATINGS[f["rating"]]
    ok = bad = 0
    for r in conn.execute("SELECT a.disposition, x.ai_verdict FROM alerts a JOIN ai_assessments x ON x.alert_id=a.id WHERE a.disposition IS NOT NULL"):
        if r[1] == VERDICTS[1]:
            continue
        good = (r[1] == VERDICTS[0]) == (r[0] == "True Positive")
        ok += good; bad += not good
    return {"backend": backend_info(), "assessments": conn.execute("SELECT COUNT(*) FROM ai_assessments").fetchone()[0],
            "by_verdict": {r[0]: r[1] for r in conn.execute("SELECT ai_verdict, COUNT(*) FROM ai_assessments GROUP BY ai_verdict")},
            "feedback_count": n, "agreement_pct": agree,
            "accuracy_pct": round(100.0 * ok / (ok + bad), 1) if ok + bad else None, "accuracy_n": ok + bad,
            "by_rule": [{"rule_id": b["rule_id"], "rule": b["rule"], "n": b["n"], "agreement_pct": round(100 * b["score"] / b["n"], 1)} for b in by_rule.values()],
            "recent": fb[:12]}


def feedback_jsonl(conn):
    lines = []
    for r in conn.execute("SELECT f.*, a.rule, a.sev, a.tactic, a.tech, a.user, a.ip, a.asset, a.detail, a.disposition FROM ai_feedback f JOIN alerts a ON a.id=f.alert_id ORDER BY f.id"):
        lines.append(json.dumps({k: r[k] for k in r.keys()}))
    return ("\n".join(lines) + "\n").encode("utf-8")
