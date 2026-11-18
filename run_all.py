#!/usr/bin/env python3
"""ONE COMMAND: builds data, runs detections + SOAR, starts the dashboard.
   python run_all.py            -> local SOAR playbooks (no n8n needed)
   python run_all.py --n8n      -> alerts go through your n8n workflow (falls back to local if n8n is down)"""
import argparse, threading, time, webbrowser
import common, gen_logs, detect, server, seed_history


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--n8n", action="store_true")
    ap.add_argument("--no-live", action="store_true", help="disable the live attack simulator")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-history", action="store_true", help="start with a completely untouched queue")
    a = ap.parse_args()

    conn = common.init_db(reset=True)
    server.use_n8n_actions(a.n8n)
    try:
        srv = server.make_server("0.0.0.0", a.port)
    except OSError as e:
        raise SystemExit("Port %d is busy (%s). Try: python run_all.py --port 8090" % (a.port, e))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://localhost:%d" % a.port
    print("[1/3] generating NilePay logs ...")
    print("      events:", gen_logs.generate(conn, a.seed))
    print("[2/3] running 15 detection rules + SOAR (%s) ..." % ("n8n" if a.n8n else "local"))
    print("      alerts:", detect.run_detection(conn, a.n8n))
    if not a.no_history:
        print("      demo history: %d alerts already worked by simulated analysts" % seed_history.seed_history(conn))
    if not a.no_live:
        threading.Thread(target=server.live_loop, args=(a.n8n,), daemon=True).start()
    print("[3/3] dashboard ready ->", url, "(Ctrl+C to stop)")
    if not a.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
