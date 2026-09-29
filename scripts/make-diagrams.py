#!/usr/bin/env python3
"""Draw the two diagrams the technical slide needs.

Hand-authored rather than generated. Mermaid, Graphviz and draw.io all produce
recognisable output: rounded boxes on an even grid, one accent colour, a title
in the top left. A judge has seen four hundred of those, and four hundred of
them look like four hundred of the same thing. These are laid out by hand so the
hierarchy is deliberate, the spacing is consistent, and the one thing the
viewer should read first is the only thing given weight and colour.

Two frames.

  architecture  What the tool is made of, left to right, and the property that
                holds across all of it: nothing in this path opens a socket,
                reads a key, or writes a packet.

  methodology   Why any of it can be believed. The dissector is checked against
                tcpdump and swanctl on a live gateway, not against itself.

Rendered as SVG and rasterised at three times slide scale, so a projector
throws the edges clean.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "diagrams"
OUT.mkdir(parents=True, exist_ok=True)

# One palette, used by both frames so they read as a pair.
INK = "#0B1017"
SLATE = "#2B364B"
MUTED = "#6B7688"
RULE = "#D9E0E8"
PAPER = "#FFFFFF"
ACCENT = "#D62B2B"
TEAL = "#1F8A8A"
AMBER = "#B4761A"
BAND = "#F2F5F8"
SCALE = 3


def esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=15, fill=SLATE, weight="400", anchor="start", ls=0):
    return (f'<text x="{x}" y="{y}" font-family="Arial, Helvetica, sans-serif" '
            f'font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}" letter-spacing="{ls}">{esc(s)}</text>')


def box(x, y, w, h, fill, stroke=None, rx=3, sw=1):
    s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{s}/>'


def arrow(x1, x2, y, colour=RULE):
    """A plain connector with a head. Not a chevron: a chevron implies a
    decision point, and there is none between these stages."""
    return (f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{colour}" '
            f'stroke-width="1.5"/>'
            f'<path d="M {x2} {y} l -6 -4 l 0 8 z" fill="{colour}"/>')


# ----------------------------------------------------------------- architecture
STAGES = [
    ("01", "Capture", ["pcap file", "no agent on", "the gateway"]),
    ("02", "CipherLens", ["from-scratch IKEv1", "and IKEv2", "in Rust"]),
    ("03", "AttackMap", ["rules against", "RFC 8247, 8221,", "SP 800-131A"]),
    ("04", "Ledger", ["packet number", "plus a SHA-256", "chain"]),
    ("05", "Report", ["JSON, HTML, CBOM,", "and the fix", "to apply"]),
]


def architecture() -> str:
    W, H = 1560, 980
    p = [f'<rect width="{W}" height="{H}" fill="{PAPER}"/>']
    p.append(text(64, 78, "WHAT THE TOOL IS MADE OF", 15, MUTED, "700", ls="2.2"))
    p.append(text(64, 122, "Passive capture in, cited findings out.", 30, INK, "700"))

    top, bw, bh, gap = 210, 258, 232, 42
    for i, (num, name, lines) in enumerate(STAGES):
        x = 64 + i * (bw + gap)
        p.append(box(x, top, bw, bh, PAPER, RULE, rx=4))
        # A one-pixel rule across the top of each card, in the stage colour.
        p.append(box(x, top, bw, 4, TEAL if i in (0, 4) else INK, rx=2))
        p.append(text(x + 24, top + 54, num, 14, MUTED, "700", ls="1.5"))
        p.append(text(x + 24, top + 92, name, 25, INK, "700"))
        for j, ln in enumerate(lines):
            p.append(text(x + 24, top + 128 + j * 25, ln, 15, SLATE))
        if i < len(STAGES) - 1:
            p.append(arrow(x + bw + 8, x + bw + gap - 10, top + bh / 2))

    # The property that holds across every stage. It is the claim that makes
    # the tool safe to point at a production capture, so it gets its own band
    # rather than a footnote.
    by = 512
    p.append(box(64, by, 1468, 132, BAND, None, rx=4))
    p.append(box(64, by, 5, 132, ACCENT, None, rx=0))
    p.append(text(96, by + 44, "Passive by construction", 22, INK, "700"))
    p.append(text(96, by + 78,
                  "No socket is opened, no key is read, no packet is written. "
                  "There is no code path in the engine that could.",
                  16, SLATE))
    p.append(text(96, by + 104,
                  "Payload bytes are never copied out of the parser, so the tool "
                  "cannot leak what it is not built to see.",
                  16, MUTED))

    # What comes out the other end.
    oy = 704
    p.append(text(64, oy - 22, "AND WHAT COMES OUT", 15, MUTED, "700", ls="2.2"))
    outs = [
        ("Finding", "severity, the packet it was\nread from, the standard\nthat makes it a finding", TEAL),
        ("Grade", "one number, capped by the\nworst finding so a failing\ntunnel cannot read as passing", AMBER),
        ("Fix", "a configuration fragment\nthat changes what was\nfound, not a complaint", ACCENT),
    ]
    for i, (name, body, col) in enumerate(outs):
        x = 64 + i * 502
        p.append(box(x, oy, 464, 168, PAPER, RULE, rx=4))
        p.append(box(x, oy, 464, 4, col, rx=2))
        p.append(text(x + 24, oy + 46, name, 21, INK, "700"))
        for j, ln in enumerate(body.split("\n")):
            p.append(text(x + 24, oy + 80 + j * 24, ln, 15, SLATE))
    p.append(text(64, 930,
                  "An unobserved field is reported as unobserved. It is never "
                  "inferred from a configuration file the tool never saw.",
                  15, MUTED))
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}">' + "".join(p) + "</svg>"


# ----------------------------------------------------------------- methodology
CHECKS = [
    ("Ground truth is not us",
     "Every expectation in the corpus tests was read from tcpdump -nvv or "
     "swanctl --list-sas on the live gateway that produced the capture.",
     "Parsed with the vendor's own tools, not with ours."),
    ("Disagreement means the parser is wrong",
     "Where the analyser and tcpdump differed, tcpdump was treated as correct "
     "and the parser was fixed. Twice, on real captures.",
     "This is how a dissector earns the right to be believed."),
    ("Malformed input is a test case, not an accident",
     "137 tests, including truncated, corrupted and randomly mangled packets, "
     "and a regression test that pins ESP flow grouping against tcpdump.",
     "A parser that panics on a bad capture is a parser that is not deployed."),
]


def methodology() -> str:
    W, H = 1560, 980
    p = [f'<rect width="{W}" height="{H}" fill="{PAPER}"/>']
    p.append(text(64, 78, "WHY ANY OF IT CAN BE BELIEVED", 15, MUTED, "700", ls="2.2"))
    p.append(text(64, 122, "The parser is checked against something else.", 30, INK, "700"))

    y = 208
    for i, (head, body, note) in enumerate(CHECKS):
        h = 178
        p.append(box(64, y, 1468, h, PAPER, RULE, rx=4))
        # Tick, not a number. The three items are not a sequence.
        p.append(f'<circle cx="112" cy="{y + 44}" r="15" fill="{TEAL}"/>')
        p.append(f'<path d="M 105 {y + 44} l 5 6 l 10 -12" stroke="#fff" '
                 f'stroke-width="2.4" fill="none" stroke-linecap="round" '
                 f'stroke-linejoin="round"/>')
        p.append(text(148, y + 52, head, 24, INK, "700"))
        # Wrap by hand. The body has to land inside the card, and an SVG
        # textPath or foreignObject would not survive being opened elsewhere.
        words, line, lines = body.split(), "", []
        for w_ in words:
            if len(line) + len(w_) + 1 > 78:
                lines.append(line)
                line = w_
            else:
                line = (line + " " + w_).strip()
        lines.append(line)
        for j, ln in enumerate(lines):
            p.append(text(148, y + 86 + j * 25, ln, 16, SLATE))
        p.append(text(148, y + 86 + len(lines) * 25 + 12, note, 15, MUTED))
        y += h + 26

    # The one comparison, kept small enough not to compete with the method.
    dy = 858
    p.append(box(64, dy, 1468, 88, BAND, None, rx=4))
    p.append(text(92, dy + 36, "Compared with a protocol analyser", 17, INK, "700"))
    p.append(text(92, dy + 64,
                  "Wireshark and tcpdump decode IKE. Neither grades a tunnel "
                  "against RFC 8247, and neither proposes the configuration that "
                  "would fix what it found. That gap is the product.",
                  16, SLATE))
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}">' + "".join(p) + "</svg>"


def render(name, svg):
    svg_path = OUT / f"{name}.svg"
    svg_path.write_text(svg)
    png = OUT / f"{name}.png"
    subprocess.run(
        ["cairosvg", "-o", str(png), str(svg_path), "-s", str(SCALE)],
        check=True, capture_output=True,
    ) if False else _cairosvg(svg_path, png)
    print(f"  {png.name}  ({png.stat().st_size // 1024} KB)")


def _cairosvg(svg_path: Path, png: Path) -> None:
    import cairosvg
    cairosvg.svg2png(url=str(svg_path), write_to=str(png), scale=SCALE)


if __name__ == "__main__":
    try:
        import cairosvg  # noqa: F401
    except ImportError:
        sys.exit("pip install cairosvg")
    print("rendering:")
    render("architecture", architecture())
    render("methodology", methodology())
