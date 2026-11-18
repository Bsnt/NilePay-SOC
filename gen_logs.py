"""NilePay log generator: normal traffic + 5 attack scenarios planted in the last 24h.
Also provides live_attack() used by the dashboard server for the live demo."""
import argparse, random, time
from common import init_db

ASSETS = ["pay-api-01", "pay-api-02", "wallet-svc", "kyc-portal", "admin-vpn", "core-db", "mobile-gw"]
UA = ["Mozilla/5.0 (Windows NT 10.0) Chrome/120", "Mozilla/5.0 (iPhone) Safari/17", "NilePayApp/3.2 (Android)"]
DSTS = ["updates.ubuntu.com", "pay-gw.visa-eg.net", "api.stripe-sim.com", "ntp.pool.org",
        "mirror.pypi.org", "cdn.nilepay.eg", "smtp.nilepay.eg", "logs.nilepay.eg"]
EXES = ["nginx", "gunicorn", "python3", "cron", "sshd"]
LIVE_KINDS = ["card_testing", "stuffing", "mfa_flood", "scraper", "impossible_travel", "simswap"]
INSERT = ("INSERT INTO events(ts,etype,user,ip,country,asset,ua,ok,amount,detail) "
          "VALUES (?,?,?,?,?,?,?,?,?,?)")


def eg_ip(r):
    return "%d.%d.%d.%d" % (r.choice([41, 156, 197]), r.randint(1, 254), r.randint(1, 254), r.randint(1, 254))


def bad_ip(r):
    a, b = r.choice([(185, 220), (45, 155), (91, 108)])
    return "%d.%d.%d.%d" % (a, b, r.randint(1, 254), r.randint(1, 254))


def lh(ts):  # Cairo local hour (UTC+2)
    return ((ts + 7200) // 3600) % 24


def aligned(t, bucket, dur):
    """Shift t earlier if needed so t..t+dur stays inside one detection bucket."""
    b = (t // bucket) * bucket
    return b + 1 if t - b + dur >= bucket else t


def hour_block(r, now, h):
    c = []
    for k in range(1, 25):
        s = ((now - k * 3600) // 3600) * 3600
        if lh(s) == h:
            c.append(s)
    return r.choice(c) if c else now - 7200


class Emit:
    def __init__(self):
        self.rows = []

    def add(self, ts, etype, user, ip, country, asset, ua, ok, amount, detail):
        self.rows.append((int(ts), etype, user, ip, country, asset, ua, int(ok), float(amount), detail))


def build(seed=7, now=None):
    r = random.Random(seed)
    now = now or int(time.time())
    e = Emit()
    add = e.add
    custs = ["cust_%03d" % i for i in range(1, 121)]
    cip = {c: eg_ip(r) for c in custs}
    staff = ["support.dina", "support.mostafa", "support.laila"]
    admins = ["admin.tarek", "admin.nour"]
    merch = ["merchant_4471", "merchant_9020", "merchant_3310", "merchant_1288", "merchant_7755"]
    mip = {m: eg_ip(r) for m in merch}
    svc = ["svc_payout", "svc_kyc", "svc_report"]

    def rt():
        return now - r.randint(900, 86400)

    def rt_hours(lo, hi):
        for _ in range(300):
            t = rt()
            if lo <= lh(t) <= hi:
                return t
        return now - 3600

    def hrs(lo, hi):
        return now - r.randint(int(lo * 3600), int(hi * 3600))

    # ---------- normal traffic ----------
    for _ in range(2500):
        c = r.choice(custs)
        add(rt(), "login", c, cip[c], "EG", r.choice(["mobile-gw", "pay-api-01"]), r.choice(UA), r.random() < .95, 0, "")
    for _ in range(3000):
        c = r.choice(custs)
        add(rt(), "payment", c, cip[c], "EG", r.choice(["pay-api-01", "pay-api-02"]), r.choice(UA), r.random() < .97, r.uniform(5, 2000), "")
    for _ in range(300):
        u = r.choice(custs + merch)
        add(rt(), "payout", u, cip.get(u) or mip[u], "EG", "wallet-svc", "NilePayApp/3.2", 1, r.uniform(100, 4000), "")
    for _ in range(2500):
        m = r.choice(merch)
        add(rt(), "api", m, mip[m], "EG", r.choice(["pay-api-01", "pay-api-02"]), "merchant-sdk/1.4", 1, 0, "")
    for _ in range(150):
        add(rt_hours(9, 17), "kyc_read", r.choice(staff), "10.0.1.%d" % r.randint(2, 60), "EG", "kyc-portal", "internal-tool", 1, 0, "")
    for _ in range(400):
        add(rt(), "db_query", r.choice(svc), "10.0.2.%d" % r.randint(2, 20), "EG", "core-db", "psycopg", 1, r.randint(100, 5000), "")
    for _ in range(40):
        add(rt_hours(9, 18), "vpn", r.choice(admins), eg_ip(r), "EG", "admin-vpn", "openvpn", 1, 0, "")
    for _ in range(300):
        c = r.choice(custs)
        add(rt(), "mfa", c, cip[c], "EG", "mobile-gw", "NilePayApp/3.2", r.random() < .95, 0, "")
    for _ in range(10):
        add(rt(), "role_grant", r.choice(custs), "10.0.1.9", "EG", "kyc-portal", "internal-tool", 1, 0, "role=viewer")
    for _ in range(8):
        add(rt(), "webhook_change", r.choice(merch), "10.0.3.4", "EG", "pay-api-01", "merchant-portal", 1, 0, "internal:https://pay.nilepay.eg/hook")
    for _ in range(100):
        m = r.choice(merch)
        add(rt(), "refund", m, mip[m], "EG", "pay-api-01", "merchant-sdk/1.4", 1, r.uniform(20, 300), "")
    for a in ASSETS:
        for x in EXES:
            for _ in range(8):
                add(rt(), "proc", "root", "10.0.0.5", "EG", a, "", 1, 0, x)
    for _ in range(300):
        add(rt(), "conn", "root", "10.0.0.5", "EG", r.choice(ASSETS), "", 1, r.uniform(5, 3000), r.choice(DSTS))
    for _ in range(15):
        c = r.choice(custs)
        add(rt(), "password_reset", c, cip[c], "EG", "mobile-gw", "NilePayApp/3.2", 1, 0, "")

    # ---------- attack 1: card testing (R01) ----------
    for _ in range(3):
        t = aligned(hrs(2, 22), 300, 200); ip = bad_ip(r)
        for i in range(40):
            add(t + i * 5, "payment", r.choice(custs), ip, "RU", "pay-api-01", "python-requests/2.28", 0, r.uniform(.5, 1.5), "card_test")
    # ---------- attack 2: credential stuffing (R03, H1) ----------
    for _ in range(2):
        t = aligned(hrs(2, 22), 600, 480); ip = bad_ip(r); users = r.sample(custs, 30)
        for i in range(60):
            add(t + i * 8, "login", users[i % 30], ip, "RU", "mobile-gw", UA[0], 0, 0, "")
    for _ in range(45):
        add(hrs(1, 23), "login", r.choice(custs), bad_ip(r), r.choice(["RU", "CN", "VN"]), "mobile-gw", "python-requests/2.28", 0, 0, "")
    # ---------- attack 3: account takeover (R02, R04, R10, R13, R14, H6) ----------
    victims = r.sample(custs, 12)
    for c in victims[:4]:
        t = hrs(3, 20)
        add(t, "login", c, cip[c], "EG", "mobile-gw", UA[1], 1, 0, "")
        add(t + 1200, "login", c, bad_ip(r), "RU", "mobile-gw", UA[0], 1, 0, "")
    for c in victims[4:7]:
        t = hrs(3, 20); ip = bad_ip(r)
        add(t, "sim_swap", c, ip, "RU", "mobile-gw", "carrier-api", 1, 0, "sim_swap")
        add(t + 120, "password_reset", c, ip, "RU", "mobile-gw", UA[0], 1, 0, "")
        add(t + 300, "new_device", c, ip, "RU", "mobile-gw", UA[0], 1, 0, "device=unknown-android")
        add(t + 600, "payout", c, ip, "RU", "wallet-svc", UA[0], 1, r.randint(8000, 20000), "")
    t = aligned(hrs(2, 22), 600, 300); mip_bad = bad_ip(r)
    for i in range(12):
        add(t + i * 25, "mfa", victims[7], mip_bad, "RU", "mobile-gw", "NilePayApp/3.2", 0, 0, "")
    add(hrs(2, 20), "payout", victims[8], bad_ip(r), "RU", "wallet-svc", UA[0], 1, 6500, "dormant_90d")
    add(hrs(2, 20), "login", victims[9], bad_ip(r), "DE", "mobile-gw", UA[0], 1, 0, "tor_exit")
    # ---------- attack 4: insider / data theft (R06, R07, R08, R12, H4, H5) ----------
    t = aligned(hrs(3, 20), 3600, 3000)
    for i in range(140):
        add(t + i * 20, "kyc_read", "support.mostafa", "10.0.1.23", "EG", "kyc-portal", "internal-tool", 1, 0, "")
    s = hour_block(r, now, 2)
    for i in range(60):
        add(s + 60 + i * 50, "kyc_read", "support.dina", "10.0.1.31", "EG", "kyc-portal", "internal-tool", 1, 0, "")
    t = aligned(hrs(2, 20), 600, 100)
    for i in range(12):
        add(t + i * 8, "db_query", "svc_report", "10.0.2.9", "EG", "core-db", "psycopg", 1, 150000, "")
    for i in range(2):
        add(hrs(1, 20), "login", "svc_payout", eg_ip(r), "EG", "admin-vpn", UA[0], 1, 0, "")
    add(hrs(1, 20), "vpn", "svc_payout", eg_ip(r), "EG", "admin-vpn", "openvpn", 1, 0, "")
    s = hour_block(r, now, 3)
    add(s + 600, "vpn", "admin.tarek", bad_ip(r), "RO", "admin-vpn", "openvpn", 1, 0, "")
    add(s + 1500, "vpn", "admin.tarek", bad_ip(r), "RO", "admin-vpn", "openvpn", 1, 0, "")
    add(hrs(1, 20), "role_grant", "support.laila", "10.0.1.40", "EG", "kyc-portal", "internal-tool", 1, 0, "role=admin granted_by=svc_report")
    # ---------- attack 5: merchant / API abuse (R05, R09, R11, R15, H2, H3, H7, H8, H9) ----------
    t = hrs(2, 20)
    for i in range(8):
        add(t + i * 60, "api", "merchant_9020", "91.108.%d.%d" % (r.randint(1, 254), r.randint(1, 254)), "NL", "pay-api-02", "python-requests/2.28", 1, 0, "")
    for i in range(5):
        add(hrs(2, 20), "api", "merchant_3310", bad_ip(r), "TR", "pay-api-01", "python-requests/2.28", 1, 0, "")
    t = hrs(6, 22); ip = bad_ip(r)
    add(t, "webhook_change", "merchant_4471", ip, "NL", "pay-api-01", "merchant-portal", 1, 0, "external:https://evil-hook.example/x")
    for i in range(5):
        add(t + 600 + i * 300, "refund", "merchant_4471", ip, "NL", "pay-api-01", "python-requests/2.28", 1, r.randint(4000, 9000), "")
    t = aligned(hrs(2, 22), 300, 200); ip = bad_ip(r)
    for i in range(200):
        add(t + i, "api", "anonymous", ip, "NL", "mobile-gw", "curl/8.0", 1, 0, "")
    add(hrs(1, 20), "proc", "root", "10.0.0.9", "EG", "core-db", "", 1, 0, "mimikatz")
    add(hrs(1, 20), "proc", "root", "10.0.0.5", "EG", "pay-api-02", "", 1, 0, "powershell -enc")
    t0 = hrs(2, 10)
    for i in range(30):
        add(t0 + i * 60, "conn", "root", "10.0.0.9", "EG", "core-db", "", 1, 60 + r.uniform(-.5, .5), "185.220.101.4")
    for _ in range(4):
        add(hrs(1, 20), "payout", "merchant_7755", mip["merchant_7755"], "EG", "wallet-svc", "merchant-sdk/1.4", 1, r.randint(9600, 9900), "")
    # ---------- benign, alert-prone activity (what makes triage realistic) ----------
    c = victims[10]; t = hrs(4, 20)  # customer flies to Dubai: impossible-travel false positive
    add(t, "login", c, cip[c], "EG", "mobile-gw", UA[1], 1, 0, "")
    add(t + 2700, "login", c, "94.200.%d.%d" % (r.randint(1, 254), r.randint(1, 254)), "AE", "mobile-gw", UA[1], 1, 0, "")
    s = hour_block(r, now, 4)  # on-call admin working an incident at night
    add(s + 900, "vpn", "admin.nour", eg_ip(r), "EG", "admin-vpn", "openvpn", 1, 0, "oncall=INC-20481")
    t = aligned(hrs(2, 22), 300, 200); pip = "41.%d.%d.%d" % (r.randint(1, 254), r.randint(1, 254), r.randint(1, 254))
    for i in range(150):  # partner uptime monitor
        add(t + i, "api", "anonymous", pip, "EG", "mobile-gw", "NilePay-Partner-Monitor/2.1", 1, 0, "partner=pingdom-eg")
    t = hrs(2, 20); mip_ae = "94.200.%d.%d" % (r.randint(1, 254), r.randint(1, 254))
    for i in range(6):  # merchant opened an AE branch
        add(t + i * 90, "api", "merchant_1288", mip_ae, "AE", "pay-api-01", "merchant-sdk/1.4", 1, 0, "")
    c = victims[11]; t = aligned(hrs(2, 22), 600, 330)  # customer fumbling MFA codes, then succeeding
    for i in range(9):
        add(t + i * 30, "mfa", c, cip[c], "EG", "mobile-gw", "NilePayApp/3.2", 0, 0, "")
    add(t + 330, "mfa", c, cip[c], "EG", "mobile-gw", "NilePayApp/3.2", 1, 0, "")
    return e.rows


def generate(conn, seed=7):
    rows = build(seed)
    conn.executemany(INSERT, rows)
    conn.commit()
    return len(rows)


def live_attack(conn, kind=None, r=None):
    """Insert one fresh attack so the dashboard has live activity. Returns the kind used."""
    r = r or random.Random()
    kind = kind or r.choice(LIVE_KINDS)
    now = int(time.time())
    e = Emit(); add = e.add
    custs = ["cust_%03d" % i for i in range(1, 121)]
    if kind == "card_testing":
        t = aligned(now - 205, 300, 200); ip = bad_ip(r)
        for i in range(40):
            add(t + i * 5, "payment", r.choice(custs), ip, "RU", "pay-api-01", "python-requests/2.28", 0, r.uniform(.5, 1.5), "card_test")
    elif kind == "stuffing":
        t = aligned(now - 485, 600, 480); ip = bad_ip(r); users = r.sample(custs, 30)
        for i in range(60):
            add(t + i * 8, "login", users[i % 30], ip, "RU", "mobile-gw", UA[0], 0, 0, "")
    elif kind == "mfa_flood":
        t = aligned(now - 305, 600, 300); c = r.choice(custs); ip = bad_ip(r)
        for i in range(12):
            add(t + i * 25, "mfa", c, ip, "RU", "mobile-gw", "NilePayApp/3.2", 0, 0, "")
    elif kind == "scraper":
        t = aligned(now - 205, 300, 200); ip = bad_ip(r)
        for i in range(200):
            add(t + i, "api", "anonymous", ip, "NL", "mobile-gw", "curl/8.0", 1, 0, "")
    elif kind == "impossible_travel":
        c = r.choice(custs)
        add(now - 1300, "login", c, eg_ip(r), "EG", "mobile-gw", UA[1], 1, 0, "")
        add(now - 100, "login", c, bad_ip(r), "RU", "mobile-gw", UA[0], 1, 0, "")
    else:  # simswap
        c = r.choice(custs); ip = bad_ip(r); t = now - 700
        add(t, "sim_swap", c, ip, "RU", "mobile-gw", "carrier-api", 1, 0, "sim_swap")
        add(t + 600, "payout", c, ip, "RU", "wallet-svc", UA[0], 1, r.randint(8000, 20000), "")
    conn.executemany(INSERT, e.rows)
    conn.commit()
    return kind


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--reset", action="store_true")
    a = ap.parse_args()
    print("events inserted:", generate(init_db(a.reset), a.seed))
