"""Tiny dependency-free PDF writer (A4, Helvetica) used for SOC / GRC / escalation reports."""
import textwrap

W, H = 595, 842
NAVY, TEAL, GOLD = (0.03, 0.14, 0.2), (0.07, 0.6, 0.68), (0.88, 0.69, 0.29)
GREY, LIGHT, WHITE, BLACK = (0.4, 0.45, 0.48), (0.94, 0.97, 0.98), (1, 1, 1), (0.1, 0.1, 0.1)
RED, ORANGE, GREEN = (0.85, 0.2, 0.25), (0.9, 0.5, 0.1), (0.1, 0.6, 0.45)
STATUS = {"PASS": GREEN, "WARN": ORANGE, "FAIL": RED, "Critical": RED, "High": ORANGE, "Medium": (0.7, 0.5, 0.05), "Low": GREEN,
          "Escalated": RED, "Contained": GREEN, "Closed": GREY}


def esc(s):
    s = str(s).replace("\n", " ").replace("\r", " ").encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class PDF:
    def __init__(self, title, subtitle):
        self.title, self.subtitle, self.m, self.pages = title, subtitle, 40, []
        self.new_page()

    def col(self, c):
        return "%.3f %.3f %.3f" % c

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.rect(0, H - 58, W, 58, NAVY)
        self.rect(0, H - 61, W, 3, GOLD)
        self.text(40, H - 28, self.title, 16, True, WHITE)
        self.text(40, H - 45, self.subtitle, 9, False, GOLD)
        self.y = H - 85

    def text(self, x, y, s, size=10, bold=False, color=BLACK):
        self.ops.append("BT /F%d %.1f Tf %s rg %.1f %.1f Td (%s) Tj ET" % (2 if bold else 1, size, self.col(color), x, y, esc(s)))

    def rect(self, x, y, w, h, fill):
        self.ops.append("%s rg %.1f %.1f %.1f %.1f re f" % (self.col(fill), x, y, w, h))

    def ensure(self, h):
        if self.y - h < self.m + 25:
            self.new_page()
            return True
        return False

    def h2(self, s):
        self.ensure(40)
        self.y -= 10
        self.text(self.m, self.y, s, 13, True, TEAL)
        self.y -= 7
        self.rect(self.m, self.y, W - 2 * self.m, 1, GOLD)
        self.y -= 14

    def para(self, s, size=10, color=BLACK, indent=0, bold=False):
        for line in textwrap.wrap(str(s), max(10, int((W - 2 * self.m - indent) / (size * 0.52)))) or [""]:
            self.ensure(size + 6)
            self.text(self.m + indent, self.y, line, size, bold, color)
            self.y -= size + 3
        self.y -= 2

    def banner(self, s, color):
        self.ensure(30)
        self.rect(self.m, self.y - 20, W - 2 * self.m, 24, color)
        self.text(self.m + 8, self.y - 13, s, 12, True, WHITE)
        self.y -= 34

    def table(self, header, rows, widths, size=8, status_col=None):
        tot = float(sum(widths))
        widths = [w * (W - 2 * self.m) / tot for w in widths]

        def draw(row, fill, head=False):
            cells = [(textwrap.wrap(str(c), max(4, int(w / (size * 0.52)))) or [""])[:4] for c, w in zip(row, widths)]
            h = max(len(c) for c in cells) * (size + 2) + 6
            if not head and self.ensure(h + 2):
                draw(header, NAVY, True)
            self.rect(self.m, self.y - h, sum(widths), h, fill)
            x = self.m
            for ci, (lines, w) in enumerate(zip(cells, widths)):
                for li, l in enumerate(lines):
                    color, bold = (WHITE, True) if head else (BLACK, False)
                    if not head and ci == status_col and str(row[ci]) in STATUS:
                        color, bold = STATUS[str(row[ci])], True
                    self.text(x + 3, self.y - size - 1 - li * (size + 2), l, size, bold, color)
                x += w
            self.y -= h
        self.ensure(30)
        draw(header, NAVY, True)
        for i, r in enumerate(rows):
            draw(r, LIGHT if i % 2 == 0 else WHITE)
        self.y -= 8

    def bars(self, items, maxv=None, color=TEAL):
        maxv = maxv or max([v for _, v in items] + [1])
        for label, v in items:
            self.ensure(14)
            self.text(self.m, self.y, label, 9)
            self.rect(self.m + 120, self.y - 2, max(1, 300.0 * v / maxv), 9, color)
            self.text(self.m + 126 + 300.0 * v / maxv, self.y, str(v), 9, True, GREY)
            self.y -= 14
        self.y -= 4

    def save(self):
        n = len(self.pages)
        objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
                ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % (5 + 2 * i) for i in range(n)), n)).encode(),
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
        for i, ops in enumerate(self.pages):
            foot = "BT /F1 8 Tf %s rg 40 22 Td (%s) Tj ET" % (self.col(GREY), esc("NilePay SOC - Confidential - Page %d of %d" % (i + 1, n)))
            stream = "\n".join(ops + [foot]).encode("latin-1", "replace")
            objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>" % (W, H, 6 + 2 * i)).encode())
            objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        out, offs = bytearray(b"%PDF-1.4\n"), []
        for i, o in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
        return bytes(out)
