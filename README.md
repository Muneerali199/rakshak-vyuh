# RAKSHAK.VYUH

**Reads the handshake. Never the payload.**

A passive IPsec / IKE posture analyser. SIH 2026 · PS `SIH26160` · Team Venom

It reads IKEv1 and IKEv2 negotiation out of a packet capture and turns it into
RFC-cited, packet-numbered security findings. It never decrypts a payload, never
sends a packet, and never touches the network.

---

## The problem

An encrypted VPN tunnel looks healthy from the inside. The negotiation that
decided its ciphers, its key exchange and its rekey policy travelled **in clear
before the first byte of payload was protected** — and that traffic is what every
data-path tool discards.

So teams assess tunnels by reading configuration files they were not given, and
CERT-In responders assess them by trusting the peer. Neither is evidence.

## What this does instead

| Stage | What happens |
|---|---|
| **CipherLens** | A from-scratch IKEv1/IKEv2 dissector. SA, KE, TS, ID, AUTH, NONCE, NOTIFY — both RFC 7296 framings, both ISAKMP transform ID spaces. |
| **AttackMap** | 15 posture rules against RFC 8221, RFC 8247, RFC 7296, RFC 4303 and NIST SP 800-131A. Every finding cites a standard and a packet number. |
| **Evidence Ledger** | SHA-256 chain over the capture. Each entry hashes the previous one; the first binds the capture digest. Tamper with any finding and every entry after it stops verifying. |
| **KalScore** | Harvest-now-decrypt-later exposure, derived from the key exchange family and observed PFS state. |
| **Report** | JSON, self-contained HTML, a CycloneDX 1.6 SBOM of the negotiated algorithms, and swanctl remediation records. |

## Quick start

```bash
cargo build --release

# Analyse one capture.
# Exit 2 means something critical was found — that is the gate working.
./target/release/vyuh corpus/vyuh-ikev2-modern.pcap

# Every capture in one comparable table
./target/release/vyuh --batch corpus

# Every artefact from one pass, all offline
./target/release/vyuh corpus/vyuh-ikev1-aggressive-3des.pcap \
  --json       report.json \
  --ledger     ledger.json \
  --html       report.html \
  --cbom       sbom.cdx.json \
  --remediate  remediation.json
```

```
vyuh <capture.pcap> [OPTIONS]
    --json <path>        full report
    --ledger <path>      tamper-evident evidence ledger
    --html <path>        self-contained HTML report
    --cbom <path>        CycloneDX 1.6 SBOM
    --remediate <path>   swanctl remediation records, JSON
    --batch <dir>        every .pcap in a directory, one table
    --max-packets <n>    stop early
    --quiet              suppress the human summary
```

Sample output:

```
  capture                              pkt   ike  grade  hndl  encryption         key exchange
  ----------------------------------------------------------------------------------------
  vyuh-ikev1-aggressive-3des.pcap       36    36      F    95  3DES               MODP-1024
  vyuh-ikev2-dh1536.pcap               588    16      C    95  ENCR_AES_CBC       KE_DH_1536
  vyuh-ikev2-legacy-integrity.pcap     588    16      B    70  ENCR_AES_CBC       KE_DH_2048
  vyuh-ikev2-modern.pcap               592    16      A    45  ENCR_AES_GCM_16    KE_ECDH_256
  vyuh-ikev2-x25519.pcap               588    16      A    45  ENCR_AES_GCM_16    KE_X25519

  weakest tunnel: 0/100. Every figure above came from a real
  strongSwan gateway; none of it is estimated.
```

## The rule set

Fifteen findings. Severity is fixed per rule, not per opinion.

| ID | Finding | Severity | Citation |
|---|---|---|---|
| VYU-001 | Legacy IKEv1 in use | Medium | RFC 7296 §1.1 |
| VYU-002 | IKEv1 Aggressive Mode sends peer identity in the clear | **Critical** | RFC 2407 §4.1, CVE-2018-5389 |
| VYU-003 | Negotiation refused; no SA established | **Critical** | RFC 7296 §3.15 |
| VYU-010 | ESP negotiated with NULL encryption | **Critical** | RFC 8221, RFC 8247 |
| VYU-011 | 3DES in use — SWEET32 birthday exposure | High | RFC 8221, NIST SP 800-131A |
| VYU-012 | Encryption outside the recommended set | Medium | RFC 8221 §5 |
| VYU-020 | Weak Diffie-Hellman group | **Critical**/High | RFC 8247 §3.3, NIST SP 800-57 |
| VYU-030 | MD5-based integrity | **Critical** | RFC 8247 §3.4 |
| VYU-031 | SHA-1 integrity demoted to MUST- | Low | RFC 8221 §6 |
| VYU-032 | MD5 pseudorandom function | High | RFC 8247 §3.2 |
| VYU-033 | SHA-1 PRF demoted to MUST- | Low | RFC 8247 §3.2 |
| VYU-040 | No perfect forward secrecy on the Child SA | High | NIST SP 800-77 Rev. 1 §5.3 |
| VYU-041 | PFS state not observed in this capture | Info | NIST SP 800-77 Rev. 1 §5.3 |
| VYU-050 | Security downgrade on the same SA | **Critical** | RFC 8247 §2 |
| VYU-060 | Gateway identities disclosed on the wire | Medium | RFC 4303 §3.1 |

A critical finding caps both the score and the grade. A capture with no IKE does
not score as clean — it explains itself.

## The corpus

Eleven captures, produced by two **real strongSwan 5.9.13 gateways in Docker**
that actually negotiated with each other. Not hand-written, not simulated.

**4,290 packets · 280 IKE messages · 3,530 ESP packets · 7 of 11 carrying tunnel data**

| ID | Capture | IKE | Suite on the wire | Grade | Score | Pkts | ESP |
|---|---|---|---|---|---|---|---|
| T1 | `vyuh-ikev2-modern` | v2 | AES-256-GCM / SHA2-256 / ECDH-256 | A | 99 | 592 | ✓ |
| T2 | `vyuh-ikev2-weak-dh` | v2 | AES-CBC-128 / SHA-1 / MODP-1024 | F | 39 | 588 | ✓ |
| T3 | `vyuh-ikev1-aggressive-3des` | v1 | 3DES / MD5 / PSK / MODP-1024 | F | 0 | 36 | — |
| T4 | `vyuh-ikev2-null-encryption` | v2 | ENCR_NULL / MD5 / MODP-1024 | F | 0 | 590 | ✓ |
| T5 | `vyuh-ikev2-x25519` | v2 | AES-256-GCM / SHA2-256 / X25519 | A | 99 | 588 | ✓ |
| T6 | `vyuh-ikev2-legacy-integrity` | v2 | AES-CBC-128 / SHA-1 / MODP-2048 | B | 89 | 588 | ✓ |
| T7 | `vyuh-ikev1-main-mode-3des` | v1 | 3DES / SHA-1 / PSK / MODP-1024 | F | 0 | 50 | — |
| T10 | `vyuh-ikev1-aggressive-dh2048` | v1 | 3DES / SHA-1 / PSK / MODP-2048 | F | 0 | 36 | — |
| T11 | `vyuh-ikev2-sha256-integrity` | v2 | AES-256-GCM / SHA2-256 / ECDH-384 | A | 99 | 588 | ✓ |
| T12 | `vyuh-ikev2-dh1536` | v2 | AES-CBC-128 / SHA2-256 / MODP-1536 | C | 74 | 588 | ✓ |
| T13 | `vyuh-ikev1-main-mode-des` | v1 | DES / SHA-1 / PSK / MODP-1024 | F | 0 | 46 | — |

Regenerate it (needs Docker):

```bash
python3 scripts/make-corpus.py                 # all eleven
python3 scripts/make-corpus.py --tunnels T1,T3   # a subset
```

Both sides of every tunnel capture their own traffic and the two files are
merged, so one tcpdump build and one link type produce the pcap.

### Ground truth

`crates/vyuh-core/tests/corpus.rs` pins the analyser's output for all eleven
captures. **Every expectation was read from `tcpdump -nvv` or
`swanctl --list-sas` on a live gateway, never from the parser under test.**

> When the analyser and tcpdump disagree, tcpdump is right until proven
> otherwise, and the fix belongs in the parser.

That file exists because a hand-written fixture cannot catch a parser that
encodes its own author's assumption. The synthetic fixtures in `ike.rs` and
`analysis.rs` were wrong for a long time and no test noticed, for exactly that
reason.

## Tests

```bash
cargo test --workspace      # 137 tests
```

```
115  unit          parser, registry, rule engine, ledger, CBOM, remediation
 15  corpus        analyser vs. tcpdump ground truth, all eleven captures
  6  robustness    truncated, corrupted and length-field-escalated captures
  1  doctest
```

The robustness suite asserts nothing panics. A peer chooses its own lengths, so
a dissector that trusts them is a crash.

```bash
VYUH_SWEEP=full cargo test -p vyuh-core --test robustness   # exhaustive
```

## The corpus as a dataset

`corpus/` is a releasable dataset, not just fixtures. Each capture ships with
the generator's own class log beside it, so every traffic label can be checked
against the record of when that class was sent.

```bash
python3 scripts/build-dataset.py     # DuckDB tables + CSV
python3 scripts/export-uploadable.py # packet-level CSV/Parquet for portals
```

Published as **VYUH IKE v0.1.0** on the
[IndiaAI AIKosh](https://aikosh.indiaai.gov.in) open-source data platform
(Ministry of Electronics and IT). Packaged copies are in `docs/`.

`corpus/DATASET-CARD.md` documents the schema, the seven traffic classes and
**nine known limits**. The limits are the interesting part: this is a small
corpus with synthetic traffic classes, and a dataset card that hid that would be
worthless.

The three most important limits:

- **The four IKEv1 captures have no data plane.** Handshakes parse fully and the
  findings are correct, but the child SA never settled, so they contribute zero
  labelled traffic.
- **PFS is never observed.** No capture contains a rekey. The analyser reports
  this as *not observed* rather than inferring it from configuration.
- **The traffic classes are shaped patterns, not real sessions.** `dns` is a
  genuine query; `voip_like` is a 20 ms echo cadence. Calling these "WhatsApp
  traffic" is the most misleading thing this dataset could do, so it does not.

Two further captures are built and deliberately withheld. They protect data with
3DES and with NULL *behind* a modern IKE suite, and the analyser scores the IKE
suite rather than the child SA — so both would currently read as grade A. That
is the wrong answer, and it ships in v0.2.0 when Child-SA evaluation lands.

## ML, and what it is not for

`ml/train/leakage.py` measures how much application identity survives ESP
encryption, using gradient-boosted trees over packet size and timing. Whole
tunnels are held out — never random splits, because windows from one capture are
generated seconds apart and a random split reports an accuracy nobody can
reproduce.

**No security verdict depends on it. Nothing is scored by a model.** The
deterministic engine decides; the ML measures one question a parser cannot
answer — the shape of traffic inside a tunnel it cannot read — and abstains when
unsure.

> **Reproducibility note:** the committed `ml/results/leakage_report.json` was
> generated when the corpus still included two captures that have since been
> withheld, so its held-out fold list does not match the current eleven. The
> method is current; the numbers need one `python3 ml/train/leakage.py` to
> regenerate. Treat the figures in that file as illustrative, not as the
> published result.

Reasoning for rejecting a large code model is in `docs/ML-QUESTION.md`: it is
trained on source code, so it does not transfer to packet captures.

## Console

```bash
npm --prefix dashboard install
npm --prefix dashboard run sync   # regenerates public/ from engine output
npm --prefix dashboard run dev
```

React + TypeScript, no UI framework. `sync-report.mjs` regenerates
`dashboard/public/` from the engine's own output, so the console cannot drift
from the code. Every number it shows is explainable by one line of the engine —
there is no client-side scoring and no client-side "confidence".

## Security properties

- **Never decrypts.** The ESP payload (IKEv2 type 46) is recorded as opaque bytes.
- **Never writes to the network.** The only input is a pcap the caller supplies.
  There is no live capture and no interface attachment, by design.
- **No live packet capture.** PCAP file input only. A dissector that can attach
  to an interface is a dissector that will eventually be asked to.
- **Zero cloud, zero telemetry, zero network calls** at runtime.
- **No secrets, keys or hardcoded addresses.** Testbed certificates are
  regenerated per run and live outside the source tree.

## What is not built

Stated so nobody is surprised at the demo:

- **Live capture / SPAN ingest** — deliberately out of scope. See above.
- **Hindi report** — English only. The report generator is locale-agnostic; the
  translation is not written.
- **Tauri desktop wrapper** — the console is a web app. Packaging is unwrapped.
- **cargo-fuzz** — not run. The hand-written robustness suite covers the same
  ground, but coverage-guided fuzzing has not been used.
- **IPv6, transport mode, AH** — the corpus is IPv4 tunnel mode only.
- **Child-SA cipher evaluation** — the analyser scores the IKE suite, not the
  negotiated ESP suite. This is the main v0.2.0 work.
- **Multi-vendor captures** — strongSwan only.

## Layout

```
crates/vyuh-core/    dissector, registry, rule engine, ledger, HTML, CBOM, remediation
crates/vyuh-cli/     the vyuh binary
corpus/              eleven real captures, class logs, dataset tables, dataset card
ml/train/            the leakage measurement
dashboard/           React analyst console
testbed/             strongSwan 5.9.13 in Docker
scripts/             corpus generation, dataset build, deck and diagram generation
docs/                release packages, logos, deck
```

Dependencies are deliberately thin: `serde` and `serde_json`, and nothing else.
The pcap reader and the IKE dissector are written here.

## Documentation

- `AGENTS.md` — engine invariants and testbed commands. Read this before
  changing a parser.
- `ROADMAP.md` — status and what is next.
- `corpus/DATASET-CARD.md` — schema, provenance, nine limits.
- `docs/ML-QUESTION.md` — why the ML is the shape it is.

## Citation

```bibtex
@misc{vyuh2026,
  title        = {RAKSHAK.VYUH: a passive IPsec/IKE posture analyser},
  author       = {{Team Venom}},
  year         = {2026},
  note         = {SIH26160, NTRO -- AI-Powered IPsec VPN Protocol Analyzer}
}
```

## Licence

MIT. See `LICENSE`.

Third-party marks in `docs/logos/` are used nominatively to identify the
software they belong to; see `docs/logos/SOURCES.md`.
