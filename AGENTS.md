# RAKSHAK.VYUH — Agent Rules

## Project Identity
- **Name:** RAKSHAK.VYUH
- **Tagline:** "Reads the handshake. Never the payload."
- **PS:** SIH26160 (NTRO) — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
- **Team:** Venom
- **Deadline:** Idea submission 20 September 2026

## Core Principles
1. **Passive-only.** Never decrypt, never inject, never touch payload.
2. **Evidence-first.** Every finding must cite a packet number and ledger entry.
3. **Honest AI.** Parser for deterministic fields, ML only for uncertainty. No fake confidence.
4. **Sovereign.** Zero cloud, zero telemetry, air-gapped, offline demo.
5. **No fake data.** Unknown is reported as unknown.

## Tech Stack (Locked)
| Layer | Choice | Do Not Change |
|-------|--------|---------------|
| Core engine | Rust (pcap, nom, rayon) | — |
| Testbed | Docker + strongSwan | — |
| ML | XGBoost + PyTorch 1-D CNN | — |
| Storage | DuckDB | — |
| Dashboard | Tauri + React | — |
| Reports | Typst | — |
| Ledger | SHA-256 + BLAKE3 | — |
| Fuzzing | cargo-fuzz | — |

## Code Rules
- Every parser function must have a test.
- Every finding must include: packet number, timestamp, SA ID, evidence hash.
- No hardcoded IPs, keys, or secrets.
- All config via environment variables or config files.
- Commit messages: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`

## What To Build (Priority Order)
1. CipherLens: Full IKEv1/v2 dissector (SA, KE, TS, ID, AUTH, NONCE, NOTIFY)
2. AttackMap: RFC 8221/8247 compliance checks + named exposures
3. Evidence Ledger: SHA-256 chain + PCAP hash binding
4. Drishti ML: XGBoost + 1-D CNN ensemble for traffic classification
5. Dashboard: Tauri desktop app with score → SA → packet drill-down
6. Reports: Typst PDF/HTML/JSON, Hindi/English
7. CBOM: CycloneDX 1.6 export
8. KalScore: Quantum/HNDL exposure scoring
9. CWE Remediation: swanctl config generation
10. Demo: 2-gateway failover scenario

## What NOT To Build
- Active scanning/injection
- Cloud services or APIs
- Mobile app
- Blockchain (PS theme is Blockchain & Cybersecurity but our solution doesn't need it)
- Real-time packet capture (PCAP file input is fine for demo)

## File Structure
```
rakshak-vyuh/
├── AGENTS.md          # This file
├── ROADMAP.md         # Development roadmap
├── README.md          # Project overview
├── Cargo.toml         # Rust workspace
├── crates/
│   ├── cipherlens/    # IKE dissector
│   ├── attackmap/     # Rules engine
│   ├── ledger/        # Evidence ledger
│   └── shared/        # Common types
├── ml/
│   ├── train/         # Training scripts
│   ├── models/        # Saved models
│   └── features/      # Feature extraction
├── dashboard/         # Tauri + React
├── reports/           # Typst templates
├── testbed/           # Docker + strongSwan configs
├── corpus/            # VYUH corpus (T1-T6)
└── docs/              # Documentation
```

## Definition of Done
- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] Benchmark results recorded
- [ ] Documentation updated
- [ ] Demo scenario works end-to-end

## Dashboard Conventions
- No UI framework. React + TypeScript + plain CSS variables. A component
  library would impose a look that does not belong to a security tool.
- Never duplicate a fact into a field that verification does not check. The
  ledger entry keeps one canonical statement; the UI derives the rest.
- Every number the console shows must be explainable by one line of the
  engine. No client-side scoring, no client-side "confidence".
- Severity filters default to all-on. Hiding a tier must be a deliberate act.
- The blindspot panel sits above the fold, not in a footer.

## Engine Invariants (do not regress)
- `parse_ike` returns `Ok(None)` for anything that is not a plausible
  handshake. Only a validated header is walked.
- Transform and algorithm identifiers come from the IANA registry, read live
  from <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml>,
  and are pinned by test. Never number them from an RFC's prose: RFC 3602
  allocates no IKEv2 numbers, and the SHA-2 PRFs are 5, 6 and 7, not 3, 4
  and 5.
- ISAKMP and IKEv2 have separate transform ID spaces, and ISAKMP has two of its
  own. Phase 1 transform 5 is 3DES while ESP transform 5 is IDEA. Never resolve
  one against another's table.
- In ISAKMP phase 1 the transform id is a placeholder and the suite lives in the
  transform attributes. Reading the id labels a 3DES tunnel "DES".
- An SA payload substructure is either bare (RFC 7296) or length-framed, and
  libstrongswan uses the framed form for both versions. Detect the framing per
  substructure; never assume it from the version.
- IKEv1 exchange 4 is Aggressive Mode and 2 is Main Mode, per RFC 2408. The
  numbering is not the order the modes are usually listed in.
- A transform octet has only bits 0x10 and 0x08 set; an attribute octet has
  0x80 or 0x40. That distinction is why attribute parsing peeks.
- A Security Association is a two-way relationship. Key records on the
  initiator SPI and the *unordered* peer pair, or the responder's copy carries
  no suite and half of every exchange reads as a failure.
- Every finding cites a real packet number. A capture with no suite for an SA
  must not inherit a clean score.
- A critical finding caps both the score and the grade. A failing tunnel must
  not read as a passing number.
- A capture with no IKE must not score as clean. It must explain itself.
- A refused negotiation is a fact. If the tunnel is never established, that is
  VYU-003 and critical; if a retry succeeds, record the refusal and grade the
  tunnel that exists.
- Findings are deduplicated across Security Associations and carry an
  occurrence count. A retried capture must not turn four facts into hundreds of
  ledger entries, because then a severity count is a packet count.

## Ground truth
`crates/vyuh-core/tests/corpus.rs` checks the analyser against the six real
captures in `corpus/`. Every expectation in it was read from `tcpdump -nvv` or
`swanctl --list-sas` on a live gateway, never from the parser under test. When
the analyser and tcpdump disagree, tcpdump is right until proven otherwise, and
the fix belongs in the parser.

The synthetic fixtures in `ike.rs` and `analysis.rs` are for framing and
robustness. They were wrong for a long time and no test noticed, because a
fixture written by the same author as the parser reproduces the author's
assumption. Add a real capture before trusting a new decoding rule.

## Testbed
```bash
# Regenerate the captures from real strongSwan gateways (Docker required)
# T1 modern, T2 weak DH, T3 IKEv1 aggressive, T4 NULL, T5 X25519,
# T6 legacy integrity
python3 scripts/make-corpus.py
python3 scripts/make-corpus.py --tunnels T1,T3   # or a subset

# Analyse one. Exit 2 means something critical was found; that is the gate
# working, not a failure.
cargo build --release
./target/release/vyuh corpus/vyuh-ikev2-modern.pcap

# Ground truth: the six captures checked against tcpdump output
cargo test --workspace

# Push a capture into the console (defaults to T3, which spans every tier)
npm --prefix dashboard run sync
npm --prefix dashboard run sync -- corpus/vyuh-ikev2-weak-dh.pcap
npm --prefix dashboard run dev
```
