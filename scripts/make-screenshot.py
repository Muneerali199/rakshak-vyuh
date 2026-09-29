#!/usr/bin/env python3
"""Render the one screenshot the prototype needs to be understood.

A demo video shows that the tool runs. A single screenshot has to carry a
different argument: that the tool is trustworthy. Trust is visible in three
details that only appear together, so all three are in this frame.

  The capture is real. The filename, its SHA-256 and the packet count are on
  screen, so nothing here is hypothetical.

  Every finding is cited. Each line carries the packet number it was read from
  and the standard that makes it a finding. A posture score with no citation is
  an opinion, and this one is not.

  It says what it does not know. PFS is reported as not observed, because no
  capture in the corpus contains a rekey. An analyzer that cannot tell has to
  say so, and saying so is the part that makes the rest believable.

Run it after `cargo build --release`.
"""
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
VYUH = ROOT / "target" / "release" / "vyuh"
CAPTURE = "vyuh-ikev1-aggressive-3des.pcap"
OUT = ROOT / "docs" / "prototype-screenshot.png"

F = "/System/Library/Fonts/Supplemental/"


def font(size, bold=False):
    return ImageFont.truetype(F + ("Arial Bold.ttf" if bold else "Arial.ttf"), size)


def main() -> int:
    if not VYUH.exists():
        sys.exit("build first: cargo build --release")
    raw = subprocess.run([str(VYUH), str(ROOT / "corpus" / CAPTURE)],
                         capture_output=True, text=True, env={"COLUMNS": "150", "PATH": "/usr/bin"})
    lines = raw.stdout.splitlines()

    # Keep the header and the first Security Association block. The second SA
    # repeats it in the other direction, and a screenshot that shows the same
    # thing twice reads as padding rather than as evidence.
    # Cut at the SECOND Security Association, not the first. The first marker
    # opens the block we want to keep, so cutting there leaves a header and
    # nothing else, which is exactly what a screenshot must not be.
    sa = [i for i, l in enumerate(lines) if l.startswith("  [") and
          any(f"[{g}]" in l[:12] for g in "ABCDF")]
    cut = sa[1] if len(sa) > 1 else len(lines)
    shown = lines[:cut]
    while shown and not shown[-1].strip():
        shown.pop()

    SIZE = 17
    LH = SIZE + 11
    PAD_X, PAD_TOP, BAR = 30, 62, 40
    width_chars = max(len(l) for l in shown)
    W = max(1500, PAD_X * 2 + width_chars * 9)
    H = PAD_TOP + len(shown) * LH + 96

    BG = (13, 18, 26)
    PANEL = (18, 24, 34)
    FG = (222, 228, 236)
    DIM = (128, 141, 158)
    ACC = (214, 43, 43)
    SEV = {"critical": (255, 92, 92), "high": (255, 150, 80),
           "medium": (240, 196, 90), "low": (150, 200, 150),
           "info": (130, 170, 210)}

    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    # window chrome, so the frame reads as a tool rather than as a text file
    d.rectangle([0, 0, W, BAR], fill=PANEL)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 20, 15, 30 + i * 20, 27], fill=c)
    d.text((W // 2 - 150, 12), "vyuh  ·  capture analysis",
           font=font(15), fill=DIM)

    y = PAD_TOP
    for line in shown:
        s = line.rstrip()
        if not s.strip():
            y += LH
            continue
        col = FG
        if s.strip().startswith("["):
            key = s.strip().split("]")[0].lstrip("[").strip()
            col = SEV.get(key, FG)
        elif "RAKSHAK" in s or "  [F]" in s or "  [A]" in s or "  [B]" in s \
                or "  [C]" in s or s.strip().startswith("["):
            col = (255, 255, 255)
        elif s.startswith("                 ") or "RFC" in s or "NIST" in s \
                or "CVE" in s:
            col = DIM
        elif s.startswith("  capture") or s.startswith("  sha-256") \
                or s.startswith("  packets"):
            col = DIM
        d.text((PAD_X, y), s, font=font(SIZE, bold=col == (255, 255, 255)), fill=col)
        y += LH

    # The caption. Without it the image is output; with it, the image is a claim
    # about output, and a judge knows which one to check.
    d.line([PAD_X, y + 14, W - PAD_X, y + 14], fill=(38, 46, 58))
    d.text((PAD_X, y + 30),
           "Every line is cited to the packet it was read from and the standard that makes it a finding.",
           font=font(15), fill=DIM)
    d.text((PAD_X, y + 56),
           "PFS reads 'not observed' because no capture spans a rekey. It is not inferred from configuration.",
           font=font(15), fill=(130, 170, 210))

    im.save(OUT, optimize=True)
    print(f"wrote {OUT}  ({im.size[0]}x{im.size[1]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
