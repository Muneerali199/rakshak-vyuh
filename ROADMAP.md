# RAKSHAK.VYUH — Development Roadmap

## SIH 2026 Timeline
- **Idea Submission:** 20 September 2026
- **Grand Finale:** December 2026 (proposed)
- **Total Weeks Remaining:** ~10 weeks

Status legend: **Done** = built, tested and verified against a real capture.
**Next** = queued. **Later** = will be cut if time runs short.

---

## Phase 1: Foundation (Week 1-2)
**Goal:** Testbed + CipherLens v1

| Task | Deliverable | Status |
|------|-------------|--------|
| Docker + strongSwan testbed (T1-T6) | `testbed/`, 5.9.13 | **Done** |
| Generate labelled captures | `corpus/*.pcap` + `manifest.json` | **Done** |
| CipherLens: IKEv2 SA/KE/TS parser | `crates/vyuh-core/src/ike.rs` | **Done** |
| CipherLens: IKEv1 parser (phase 1 attributes + ESP numbering) | `crates/vyuh-core/src/ike.rs` | **Done** |
| ESP/AH header parser | `crates/vyuh-core/src/esp.rs` | **Done** |
| NAT-T unwrap (UDP 4500) | `crates/vyuh-core/src/ike.rs` | **Done** |
| Unit tests for all parsers | 110 unit + 12 ground-truth | **Done** |

**Exit Criteria:** Parse all T1-T6 captures, extract SA parameters with 100% accuracy.
**MET — achieved.** Every capture resolves to the suite `tcpdump -nvv` reports, and
`crates/vyuh-core/tests/corpus.rs` pins all six. This phase is where the six real
bugs lived (SA framing, attribute header, IANA numbering, ISAKMP phase 1, exchange
numbering, directional SA keys). All fixed and regression-tested.

---

## Phase 2: Assessment Engine (Week 3-4)
**Goal:** AttackMap + Evidence Ledger

| Task | Deliverable | Status |
|------|-------------|--------|
| RFC 8221/8247 compliance checks | `crates/vyuh-core/src/posture.rs` | **Done** |
| NIST SP 800-77r1 checks | `crates/vyuh-core/src/posture.rs` | **Done** |
| Named exposures (Logjam, SWEET32, PSK-crack) | VYU-011/020/030/032 | **Done** |
| Evidence ledger (SHA-256 chain) | `crates/vyuh-core/src/ledger.rs` | **Done** |
| PCAP hash binding | entry 0 binds the capture digest | **Done** |
| Tamper detection | `verify()`, surfaced in JSON and HTML | **Done** |
| CWE mapping (CWE-327, CWE-326, etc.) | `posture::Cwe` | **Done** |

**Exit Criteria:** Every planted weakness in T2-T4 detected with packet citations. Zero false "strong" verdicts on T3.
**MET.** T2 and T3 fail on every planted weakness, and every finding cites a real
packet number. A refused negotiation is reported as VYU-003 rather than inheriting
a clean score, which was the last false-clean path.

---

## Phase 3: ML Layer (Week 5-6)
**Goal:** Drishti v1

**Deliberately deferred, and the reason is written down in
`docs/ML-QUESTION.md`.** The short version: the existing RAKSHAK.AI 14B model is
trained on source code, not packet captures, so it does not transfer, and its
own self-reported CWE accuracy is 27.8%. Size is not the problem, input type is.
Nothing below is built, and nothing below should be added to a slide until it is.

If it is picked up, the constraint from `AGENTS.md` still holds: ML handles
*uncertainty only*, never a deterministic field. An algorithm id is the most
deterministic field there is; it is read off the wire and every finding cites the
packet it came from. A model in that path is a regression.

| Task | Deliverable | Status |
|------|-------------|--------|
| Feature extraction from ISCX | `ml/features/` | Later |
| XGBoost baseline | `ml/train/xgboost.py` | Later |
| 1-D CNN (FlowPic-style) | `ml/train/cnn.py` | Later |
| Ensemble + calibration | `ml/train/ensemble.py` | Later |
| SHAP attributions | `ml/train/shap.py` | Later |
| SA-behaviour anomaly (IsolationForest) | `ml/train/anomaly.py` | Later |
| Risk scoring | `ml/train/risk.py` | Later |

**Exit Criteria:** Macro-F1 ≥ 0.90 on held-out ISCX split. Confidence calibration error ≤ 0.05.

---

## Phase 4: Product (Week 7-8)
**Goal:** Dashboard + Reports + CBOM

| Task | Deliverable | Status |
|------|-------------|--------|
| Analyst console (web) | `dashboard/`, React + TS | **Done** |
| Score → SA → packet drill-down | `dashboard/src/` | **Done** |
| Self-contained HTML report | `--html`, `core/src/html.rs` | **Done** |
| Hindi/English support | `reports/` | Later |
| CycloneDX 1.6 CBOM export | `--cbom`, `core/src/cbom.rs` | **Done** |
| KalScore (quantum exposure) | `posture::kal_score` | **Done** |
| CWE remediation (swanctl configs) | `--remediate`, `core/src/remediation.rs` | **Done** |

**Exit Criteria:** Full pipeline works end-to-end. Demo runs offline in < 2 minutes.
**MET** apart from Tauri packaging and Hindi. The pipeline is
`pcap → report.json + ledger.json + report.html + sbom.cdx + remediation.json`,
all offline, all from one binary.

---

## Phase 5: Hardening (Week 9-10)
**Goal:** Competition-ready

| Task | Deliverable | Status |
|------|-------------|--------|
| Parser robustness sweep | `crates/vyuh-core/tests/robustness.rs` | **Done** |
| cargo-fuzz on all dissectors | `fuzz/` | **Next** |
| Multi-capture batch mode | analyse all six, one table | **Next** |
| Criterion benchmarks | `benches/` | Later |
| Demo video | `docs/demo.mp4` | Later |
| Documentation | `AGENTS.md` + `README.md` | **Done** |
| PPT finalization | 6 slides, prompt written | **Next** |
| Rehearsal | — | **Next** |

**Exit Criteria:** All tests pass. Demo rehearsed 5+ times. PPT complete.

---

## Key Metrics to Track
| Metric | Target | Actual |
|--------|--------|--------|
| Parser accuracy (T1-T6) | 100% | 6/6 vs tcpdump |
| False "strong" rate on T3 | 0% | 0% |
| ML macro-F1 | ≥ 0.90 | not built |
| Confidence calibration error | ≤ 0.05 | not built |
| Demo runtime | < 2 minutes | ~0.1 s per capture |
| Test count | ≥ 141 (Rakshak lineage) | 123 (110 unit + 12 corpus + 1 doc) |
| Compiler warnings | 0 | 0 |

---

## Risk Mitigation
| Risk | Mitigation |
|------|------------|
| strongSwan learning curve | Sprint 1 dedicated; scripts become deliverable |
| ML accuracy on real traffic | Report held-out metrics; honest blindspot panel |
| 14B model VRAM | Templates cached; live inference optional |
| IKEv1 fragmentation | cargo-fuzz; fallback to tshark export |
| Time crunch | ML already cut to "Later"; parser is priority |
| Registry drift from a private numbering | IDs read from the live IANA registry and pinned by `tests/corpus.rs` |
| A synthetic fixture proving a wrong parser right | Ground-truth tests run against the six real captures |
