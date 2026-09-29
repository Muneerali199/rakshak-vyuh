# Tech stack marks

Official brand logos for the RAKSHAK.VYUH deck. All fetched from the projects'
own distribution channels, not redrawn.

| File | Source | Licence |
|------|--------|---------|
| `rust.svg` | [Simple Icons](https://simpleicons.org/?q=rust) | CC0-1.0 |
| `react.svg` | Simple Icons | CC0-1.0 |
| `typescript.svg` | Simple Icons | CC0-1.0 |
| `vite.svg` | Simple Icons | CC0-1.0 |
| `docker.svg` | Simple Icons | CC0-1.0 |
| `wireshark.svg` | Simple Icons | CC0-1.0 |
| `python.svg` | Simple Icons | CC0-1.0 |
| `openssl.svg` | Simple Icons | CC0-1.0 |
| `tauri.svg` | Simple Icons | CC0-1.0 |
| `strongswan.png` | [strongswan.org](https://www.strongswan.org/) favicon, 48px rendered to 512px | GPL-2.0 (logo use permitted) |
| `aikosh.svg` | [aikosh.indiaai.gov.in](https://aikosh.indiaai.gov.in) `/images/ai-kosh-header-logo.svg` | Government of India / MeitY mark |
| `indiaai.svg` | same host, `/images/india-ai-footer-logo.svg` | Government of India / MeitY mark |

Simple Icons are CC0. The strongSwan mark is the project's own favicon; using it
to name the software in a technical talk is nominative use, but check the
project's trademark note before printing merchandise.

The two AIKosh marks are official marks of the IndiaAI open-source platform and
are used to identify where the VYUH corpus is published. Nominative use only: no
endorsement is implied, and the mark is never modified or recoloured.

## Modification

One change was made to the Simple Icons files: `fill="currentColor"` was added to
the root `<svg>`. Simple Icons ships single-colour paths with no fill, which
render black and disappear on a dark slide. Inheriting `currentColor` means one
asset works on both backgrounds and can be recoloured in CSS or Keynote.

## Do not use

- **`tauri.svg`** — Tauri is planned but not built. Putting it on a slide claims
  a desktop app that does not exist.
- Any ML logo (XGBoost, PyTorch, scikit-learn). Drishti is deferred, not built.
  A logo is a claim of use.
- **`indiaai.svg` on a light background.** It is the platform's *footer* mark:
  16 of its fill attributes are `white`, so only 5.4% of the rendered area stays
  visible on the deck's `#F7F9FB` paper. Use it on a dark band or not at all.
  `aikosh.svg` is the *header* mark and is safe on light — 24.7% of its area is
  real ink, in `#231F20` and the AIKosh orange `#F06724`.

## Rendering

Each SVG has a 6× PNG counterpart in `png/` for slides that cannot take SVG.
`aikosh` lands at 744×336, `indiaai` at 690×456, both with an alpha channel so
they sit on the paper background without a white box behind them.
