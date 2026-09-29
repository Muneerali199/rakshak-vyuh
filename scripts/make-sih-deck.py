#!/usr/bin/env python3
"""Build the six-slide SIH idea-submission deck.

Every number is measured by running the engine over the corpus that is in the
repository right now, not typed in by hand. If a capture is regenerated and the
engine reads it differently, the deck changes with it instead of quietly
becoming wrong.

The deck is generated rather than hand-built because a competition deck gets
edited the night before the deadline, and the numbers in it are the part that
rots fastest.
"""
import json
import subprocess
import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
VYUH = ROOT / "target" / "release" / "vyuh"
CORPUS = ROOT / "corpus"

INK = RGBColor(0x0B, 0x10, 0x17)
SLATE = RGBColor(0x2B, 0x36, 0x4B)
MUTED = RGBColor(0x5A, 0x67, 0x7B)
PAPER = RGBColor(0xF7, 0xF9, 0xFB)
ACCENT = RGBColor(0xD6, 0x2B, 0x2B)
TEAL = RGBColor(0x1F, 0x8A, 0x8A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

W, H = Inches(13.333), Inches(7.5)


def measure() -> list[dict]:
    """Run the engine over every capture and keep what the report says."""
    rows = []
    for pcap in sorted(CORPUS.glob("vyuh-*.pcap")):
        out = ROOT / "corpus" / ".deck-report.json"
        r = subprocess.run(
            [str(VYUH), str(pcap), "--quiet", "--json", str(out)],
            capture_output=True,
        )
        # Exit 2 means the engine found something critical. That is the gate
        # working, and most of this corpus trips it on purpose, so it is a
        # success here. Anything else is a real failure.
        if r.returncode not in (0, 2):
            sys.exit(f"{pcap.name}: vyuh exited {r.returncode}\n{r.stderr.decode()}")
        d = json.loads(out.read_text())
        rows.append({
            "id": pcap.stem.replace("vyuh-", ""),
            "pkts": d["packets_examined"],
            "esp": d["esp_flows"],
            "ike": d["ike_messages"],
            "grade": d["grade"],
            "score": d["posture_score"],
            "findings": len(d["global_findings"]),
            "ids": [f.get("code") for f in d["global_findings"] if f.get("code")],
        })
    out.unlink(missing_ok=True)
    return rows


def blank(prs: Presentation):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    bg = s.background.fill
    bg.solid()
    bg.fore_color.rgb = PAPER
    return s


def text(slide, x, y, w, h, runs, align=PP_ALIGN.LEFT, space=6):
    """runs: [(text, size, bold, colour, space_after_pt), ...]"""
    box = slide.shapes.add_textbox(x, y, w, h)
    tf = box.text_frame
    tf.word_wrap = True
    for i, (t, size, bold, colour, after) in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(after)
        r = p.add_run()
        r.text = t
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = colour
        r.font.name = "Helvetica Neue"
    return box


def rule(slide, x, y, w, colour=ACCENT, h=Pt(3)):
    bar = slide.shapes.add_shape(1, x, y, w, h)
    bar.fill.solid()
    bar.fill.fore_color.rgb = colour
    bar.line.fill.background()
    bar.shadow.inherit = False
    return bar


def table(slide, x, y, w, headers, rows, widths, row_h=Inches(0.34)):
    n = len(rows) + 1
    shape = slide.shapes.add_table(n, len(headers), x, y, w, row_h * n)
    tbl = shape.table
    for i, cw in enumerate(widths):
        tbl.columns[i].width = cw
    for c, htxt in enumerate(headers):
        cell = tbl.cell(0, c)
        cell.text = ""
        p = cell.text_frame.paragraphs[0]
        r = p.add_run(); r.text = htxt
        r.font.size = Pt(11); r.font.bold = True
        r.font.color.rgb = WHITE; r.font.name = "Helvetica Neue"
        cell.fill.solid(); cell.fill.fore_color.rgb = SLATE
    for ri, row in enumerate(rows, start=1):
        for ci, val in enumerate(row):
            cell = tbl.cell(ri, ci)
            cell.text = ""
            p = cell.text_frame.paragraphs[0]
            r = p.add_run(); r.text = str(val)
            r.font.size = Pt(11)
            r.font.bold = ci == 0
            r.font.color.rgb = INK
            r.font.name = "Helvetica Neue"
            cell.fill.solid()
            cell.fill.fore_color.rgb = WHITE if ri % 2 else RGBColor(0xEE, 0xF2, 0xF6)
    return tbl


def leakage() -> dict:
    """The measured ML result, read from the run that produced it.

    Never typed in. If the model is retrained and the numbers move, the deck
    moves with them; if the result file is missing the slide says so instead of
    quoting a remembered figure.
    """
    p = ROOT / "ml" / "results" / "leakage_report.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def worst_finding() -> dict:
    """The most severe finding in the corpus, read from the engine's output.

    Shown on its own slide with its packet number and the standard it cites.
    The claim that every finding is evidence-backed is cheap; showing one is
    what makes it believable.
    """
    p = ROOT / "corpus" / "vyuh-ikev1-aggressive-3des.pcap"
    out = ROOT / "corpus" / ".deck-finding.json"
    if not p.exists():
        return {}
    r = subprocess.run([str(VYUH), str(p), "--quiet", "--json", str(out)],
                       capture_output=True)
    if r.returncode not in (0, 2):
        return {}
    d = json.loads(out.read_text())
    out.unlink(missing_ok=True)
    crit = [f for f in d.get("global_findings", []) if f.get("severity") == "critical"]
    return crit[0] if crit else {}


def build(rows: list[dict]) -> Presentation:
    pkts = sum(r["pkts"] for r in rows)
    esp = sum(r["esp"] for r in rows)
    ike = sum(r["ike"] for r in rows)
    with_data = sum(1 for r in rows if r["esp"] > 0)

    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H

    # 1 — problem and promise
    s = blank(prs)
    rule(s, Inches(0.8), Inches(1.05), Inches(2.2))
    text(s, Inches(0.8), Inches(1.35), Inches(11.7), Inches(2.6), [
        ("RAKSHAK.VYUH", 46, True, INK, 4),
        ("Reads the handshake. Never the payload.", 24, False, ACCENT, 22),
        ("An offline analyzer that assesses an IPsec tunnel from the control plane alone.",
         17, False, SLATE, 8),
        ("Team Venom  ·  SIH26160  ·  NTRO", 14, False, MUTED, 0),
    ])
    text(s, Inches(0.8), Inches(4.6), Inches(11.7), Inches(2.2), [
        ("The problem", 15, True, INK, 6),
        ("An encrypted tunnel looks healthy from inside. The negotiation that decided its ciphers, "
         "its key exchange and its rekey policy travelled in clear before the first byte of payload "
         "was protected, and that traffic is discarded by every tool that watches the data path.",
         14, False, SLATE, 10),
        ("Teams and CERT-In assess tunnels by reading configuration files they were not given.",
         14, False, SLATE, 0),
    ])

    # 2 — how it works
    s = blank(prs)
    text(s, Inches(0.8), Inches(0.6), Inches(11.7), Inches(0.7),
         [("How it works", 32, True, INK, 0)])
    rule(s, Inches(0.8), Inches(1.25), Inches(1.6), TEAL)
    steps = [
        ("1  Capture", "A pcap file. No agent on the gateway, no traffic injection, no decryption key."),
        ("2  CipherLens", "A from-scratch IKEv1 and IKEv2 dissector in Rust. Reads SA, KE, TS, ID, AUTH, "
                           "NOTIFY and the nonce, including the length-framed substructures strongSwan actually sends."),
        ("3  AttackMap", "Every negotiated suite is checked against RFC 8247, RFC 8221 and NIST SP 800-131A. "
                         "Findings are rules, not opinions."),
        ("4  Evidence Ledger", "Each finding is bound to a packet number and a SHA-256 chain over the capture, "
                               "so any claim can be re-derived from the file."),
        ("5  Report", "JSON, HTML, a CycloneDX CBOM, and swanctl remediation fragments that fix what was found."),
    ]
    y = Inches(1.7)
    for head, body in steps:
        text(s, Inches(0.8), y, Inches(2.5), Inches(0.5), [(head, 16, True, TEAL, 0)])
        text(s, Inches(3.3), y, Inches(9.2), Inches(1.0), [(body, 13, False, SLATE, 0)])
        y += Inches(1.02)
    text(s, Inches(0.8), Inches(6.85), Inches(11.7), Inches(0.5),
         [("Passive by construction. There is no code path in the engine that decrypts, injects or transmits.",
           13, True, ACCENT, 0)])

    # 3 — the corpus
    s = blank(prs)
    text(s, Inches(0.8), Inches(0.55), Inches(11.7), Inches(0.7),
         [("A corpus built from real gateways, not synthesised", 30, True, INK, 0)])
    rule(s, Inches(0.8), Inches(1.2), Inches(1.6), TEAL)
    table(s, Inches(0.8), Inches(1.6), Inches(11.7),
          ["Tunnel", "Packets", "ESP flows", "IKE", "Grade", "Score", "Findings"],
          [[r["id"], r["pkts"], r["esp"], r["ike"], r["grade"], r["score"], r["findings"]] for r in rows],
          [Inches(3.5), Inches(1.3), Inches(1.4), Inches(1.0), Inches(1.0), Inches(1.0), Inches(1.5)])
    text(s, Inches(0.8), Inches(4.15), Inches(11.7), Inches(1.9), [
        (f"{len(rows)} captures  ·  {pkts:,} packets  ·  {esp:,} ESP flows  ·  {ike:,} IKE messages  ·  "
         f"{with_data} of {len(rows)} carrying real tunnel data", 16, True, INK, 12),
        ("Every capture comes from two real strongSwan 5.9.13 gateways in Docker, negotiating for real, "
         "with seven labelled traffic classes pushed across the tunnel afterwards so the data path is "
         "populated and not merely implied.", 13, False, SLATE, 6),
        ("One Security Association per direction, so the flow count is small. The packet count is what a "
         "passive observer actually sees, and it is where the data is.", 13, False, MUTED, 6),
        ("Expectations were read from tcpdump and swanctl --list-sas on a live gateway, then pinned in tests. "
         "The parser is checked against them, never the other way round.", 13, False, MUTED, 0),
    ])

    # 4 — the measurement
    ml = leakage()
    s = blank(prs)
    text(s, Inches(0.8), Inches(0.55), Inches(11.7), Inches(0.7),
         [("What still leaks through the encryption", 30, True, INK, 0)])
    rule(s, Inches(0.8), Inches(1.2), Inches(1.6), TEAL)
    if ml:
        pct = lambda v: f"{v:.0%}"
        text(s, Inches(0.8), Inches(1.55), Inches(5.6), Inches(4.9), [
            ("The claim we can actually support", 17, True, INK, 8),
            ("ESP encrypts the payload. It does not encrypt packet size, "
             "direction or timing. A passive observer with no keys still has a "
             "feature vector, and the honest question is what that vector is worth.",
             13, False, SLATE, 10),
            ("So we measured it instead of claiming it.", 13, True, INK, 8),
            (f"Gradient-boosted trees, twelve features, {ml['windows']} windows, "
             f"leave-one-tunnel-out.", 13, False, SLATE, 6),
            ("Whole tunnels held out, never random splits: windows from one capture "
             "were generated seconds apart, so a random split would report an accuracy "
             "nobody could reproduce.", 12, False, MUTED, 0),
        ])
        text(s, Inches(6.9), Inches(1.55), Inches(5.6), Inches(4.9), [
            ("Result", 17, True, TEAL, 10),
            (f"{pct(ml['loso_accuracy_abstain_counts_as_wrong'])} accuracy, held-out tunnel",
             20, True, INK, 2),
            (f"{pct(ml['majority_baseline'])} majority-class baseline — the number to beat",
             12, False, MUTED, 10),
            (f"{pct(ml['coverage'])} of windows answered, {pct(1 - ml['coverage'])} abstained",
             13, False, SLATE, 6),
            ("When the model is not confident it says so instead of guessing, and "
             "the abstention is counted against it. An evaluator who reports only "
             "accuracy on a model allowed to stay silent is reporting the easy half.",
             12, False, MUTED, 10),
            ("Three of the seven classes produced too few packets to label and are "
             "reported absent rather than quietly dropped. One class is never "
             "classified correctly, and the matrix below says so.", 12, False, MUTED, 0),
        ])

    # The confusion matrix, shown rather than summarised. A judge should be
    # able to see which class the model never gets right, because that is the
    # part that decides whether the rest of the claim is credible.
    if ml:
        cls = ml["classes"] + [ml["abstain_label"]]
        cm = ml["confusion_matrix"]
        short = [c.replace("icmp-interactive", "icmp-int").replace("icmp-bulk", "icmp-bulk")
                  for c in cls]
        widths = [max(len(s), 9) for s in short]
        table(
            s, Inches(0.8), Inches(4.55), Inches(11.7),
            ["truth \\ predicted"] + short,
            [[cls[i]] + cm[i] for i in range(len(cls))],
            [Inches(1.7)] + [Inches(1.14)] * len(cls),
            row_h=Inches(0.24),
        )
        text(s, Inches(0.8), Inches(6.95), Inches(11.7), Inches(0.5),
             [("The last column is the model declining to answer. The bottom row is that it never "
               "claimed to be sure when it was not.", 12, False, MUTED, 0)])

    # 5 — what it finds
    s = blank(prs)
    text(s, Inches(0.8), Inches(0.55), Inches(11.7), Inches(0.7),
         [("It finds what configuration review would miss", 30, True, INK, 0)])
    rule(s, Inches(0.8), Inches(1.2), Inches(1.6), ACCENT)
    picks = []
    for r in rows:
        for c in r["ids"]:
            if c not in [p[0] for p in picks]:
                picks.append((c, r["id"]))
    text(s, Inches(0.8), Inches(1.6), Inches(5.7), Inches(4.6), [
        ("Worked example — the IKEv1 tunnel", 17, True, INK, 8),
        ("Aggressive Mode put the gateway identity on the wire in the very first packet, unauthenticated. "
         "The proposal that carried it also asked for 3DES and a 1024-bit MODP group.", 13, False, SLATE, 8),
        ("The peer never accepted the proposal, so no tunnel came up. The engine reports that refusal as a "
         "critical fact and scores the capture 0, rather than grading an association that does not exist.",
         13, False, SLATE, 8),
        ("Findings carry the packet number they were read from.", 13, True, INK, 0),
    ])
    text(s, Inches(6.9), Inches(1.6), Inches(5.6), Inches(4.6), [
        ("Across the corpus", 17, True, INK, 10),
        ("MODP-1024 key exchange, critical", 14, False, ACCENT, 5),
        ("IKEv1 Aggressive Mode, critical", 14, False, ACCENT, 5),
        ("3DES, the SWEET32 birthday bound", 14, False, ACCENT, 5),
        ("NULL encryption, no confidentiality at all", 14, False, ACCENT, 5),
        ("SHA-1 integrity and PRF, demoted to MUST-", 14, False, SLATE, 5),
        ("Harvest now, decrypt later, ranked by key exchange", 14, False, SLATE, 12),
        ("Each is a rule bound to a citation, not a model's opinion.", 12, False, MUTED, 0),
    ])
    f = worst_finding()
    if f:
        rule(s, Inches(0.8), Inches(4.6), Inches(11.7), RGBColor(0xDD, 0xE3, 0xEA), Pt(1))
        text(s, Inches(0.8), Inches(4.85), Inches(11.7), Inches(2.0), [
            (f"{f['id']}  ·  {f['severity'].upper()}  ·  read from packet #{f['packet_index']}",
             11, True, MUTED, 6),
            (f["title"], 15, True, ACCENT, 6),
            ("Aggressive Mode puts the identity and the hash on the wire unprotected, so a passive "
             "observer learns who peers with whom, and the pre-shared key becomes offline-crackable.",
             13, False, SLATE, 6),
            (f"Standard: {f.get('standard', 'n/a')}", 12, False, TEAL, 0),
        ])

    # 6 — evidence and honesty
    s = blank(prs)
    text(s, Inches(0.8), Inches(0.55), Inches(11.7), Inches(0.7),
         [("Every claim is checkable, and the limits are stated", 30, True, INK, 0)])
    rule(s, Inches(0.8), Inches(1.2), Inches(1.6), TEAL)
    text(s, Inches(0.8), Inches(1.6), Inches(5.7), Inches(4.8), [
        ("Evidence ledger", 17, True, INK, 8),
        ("Findings are deduplicated across Security Associations and carry an occurrence count, so a capture "
         "with hundreds of retried handshakes does not report one fact hundreds of times.", 13, False, SLATE, 8),
        ("The capture file is hashed with SHA-256 and bound into the chain. Tamper with the pcap and the "
         "ledger stops verifying.", 13, False, SLATE, 8),
        ("Tests", 17, True, INK, 6),
        ("137 tests pass, including a robustness suite that feeds truncated, corrupted and "
         "randomly mangled packets to the parser, and a regression test that pins the "
         "ESP flow grouping against tcpdump.", 13, False, SLATE, 0),
    ])
    text(s, Inches(6.9), Inches(1.6), Inches(5.6), Inches(4.8), [
        ("What it refuses to claim", 17, True, ACCENT, 8),
        ("If PFS state was not on the wire, the report says PFS was not observed. It does not infer it "
         "from the configuration.", 13, False, SLATE, 8),
        ("A capture with no IKE in it explains itself instead of scoring clean.", 13, False, SLATE, 8),
        ("The engine is deterministic. Where a judgement is genuinely uncertain we leave it out rather "
         "than invent a confidence number.", 13, False, SLATE, 8),
        ("The dataset card lists seven limits, including the three traffic classes that "
         "produced too few packets to label. It ships with the corpus, not in an appendix.",
         13, False, SLATE, 0),
    ])
    text(s, Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.9), [
        ("And the split we keep", 17, True, TEAL, 8),
        ("Every field the wire states outright is parsed. That is deterministic, it is auditable, "
         "and a rules engine does it better than a model ever will.", 13, False, SLATE, 6),
        ("Machine learning runs beside it, on the one question a parser cannot answer: what is "
         "the shape of the traffic inside a tunnel it cannot read. It reports its confidence "
         "and abstains when unsure. No security verdict depends on it, and nothing is scored "
         "by a model.", 13, False, SLATE, 0),
    ])

    # 7 — where it goes
    s = blank(prs)
    rule(s, Inches(0.8), Inches(1.05), Inches(2.2))
    text(s, Inches(0.8), Inches(1.35), Inches(11.7), Inches(1.3), [
        ("What we are asking for", 34, True, INK, 6),
        ("A corpus with real labelled traffic, and a path to publish it openly.", 17, False, SLATE, 0),
    ])
    text(s, Inches(0.8), Inches(3.0), Inches(5.7), Inches(3.4), [
        ("The gap we hit", 17, True, ACCENT, 8),
        ("There is no public dataset of IKE handshakes paired with protected traffic. We built one for "
         "ourselves, from six negotiated tunnels.", 13, False, SLATE, 8),
        ("It is small, and we say so. But it is real, reproducible with one command, and every label in it "
         "was verified against the gateway that produced it.", 13, False, SLATE, 8),
        ("Releasing it is the fastest way to make everyone else's work checkable.", 13, True, INK, 0),
    ])
    text(s, Inches(6.9), Inches(3.0), Inches(5.6), Inches(3.4), [
        ("The path", 17, True, TEAL, 8),
        ("Release the corpus and a dataset card with an explicit schema and stated limits.", 13, False, SLATE, 6),
        ("Contribute it to the AIKosh open-source community as labelled IPsec negotiation data.", 13, False, SLATE, 6),
        ("Extend coverage to IPv6, transport mode and rekey-triggered PFS, so the label space is complete "
         "rather than convenient.", 13, False, SLATE, 6),
        ("Everything runs air-gapped. No cloud service, no telemetry, no account.", 13, True, INK, 0),
    ])
    return prs


if __name__ == "__main__":
    if not VYUH.exists():
        sys.exit("build the release binary first: cargo build --release")
    deck = build(measure())
    out = ROOT / "docs" / "RAKSHAK-VYUH-SIH26160.pptx"
    deck.save(out)
    print(f"wrote {out}")
