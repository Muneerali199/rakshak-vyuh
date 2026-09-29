# VYUH IKE — IPsec negotiation and protected traffic corpus

**Version** 0.1.0 · **Captures** 11 · **Packets** 4,290 · **ESP packets** 3,530
**Licence** MIT · **Produced by** RAKSHAK.VYUH, Team Venom (SIH26160)

---

## What this is

Six packet captures of real IPsec tunnels, each produced by two strongSwan 5.9.13
gateways that actually negotiated with each other. Each capture is paired with
the security suite that went onto the wire, the findings the analyzer derived
from it, and the SHA-256 of the capture file.

Every label in this dataset was set **before** the packet was sent, by the
component that generated it. Nothing here was inferred from traffic after the
fact. That is the single most important property of this release: a reviewer can
disagree with the analyzer and still know what the ground truth was.

## What this is not

- **Not real application traffic.** The seven traffic classes are deliberately
  shaped packet patterns, not sessions captured from WhatsApp, a mail client or
  a video call. See *Traffic classes* below. Calling these "WhatsApp traffic"
  would be the most misleading thing this dataset could do, so it does not.
- **Not a passive capture of anything in production.** Every gateway runs in a
  Docker network created for this purpose, on RFC 1918 addresses.
- **Not decrypted.** The payload of every ESP packet is opaque in these files,
  as it is on any real network. That is the point of the product, and it is why
  the labels describe *shape* rather than content.
- **Not large.** 2,986 packets across six tunnels. It is a seed corpus for
  testing a dissector and a rules engine, not a training set for a classifier.

## Files

| File | What it is |
|---|---|
| `vyuh-*.pcap` | The primary artefact. Six captures, one per tunnel. |
| `vyuh-*.classes.log` | The generator's own record of which class was sent when. This is where the traffic labels come from, and it is shipped so a reviewer can check them. |
| `vyuh-ike.duckdb` | Derived index. One row per capture, one row per traffic class. |
| `capture.csv` | The `capture` table as CSV, for reviewers without DuckDB. |
| `traffic_class.csv` | Definitions of the seven traffic classes. |

The pcaps are authoritative. The tables are derived and can be regenerated with
`python3 scripts/build-dataset.py`.

## The T-matrix

| # | Tunnel | IKE | Encryption | Key exchange | Grade | Score | Findings | ESP packets |
|---|---|---|---|---|---|---|---|---|
| 1 | ikev1-aggressive-3des | IKEv1 | 3DES | MODP-1024 | F | 0 | 8 | 0 |
| 2 | ikev1-aggressive-dh2048 | IKEv1 | 3DES | - | F | 0 | 7 | 0 |
| 3 | ikev1-main-mode-3des | IKEv1 | 3DES | MODP-1024 | F | 0 | 7 | 0 |
| 4 | ikev1-main-mode-des | IKEv1 | DES | MODP-1024 | F | 0 | 7 | 0 |
| 5 | ikev2-dh1536 | IKEv2 | AES-CBC | MODP-1536 | C | 74 | 2 | 412 |
| 6 | ikev2-legacy-integrity | IKEv2 | AES-CBC | MODP-2048 | B | 89 | 3 | 412 |
| 7 | ikev2-modern | IKEv2 | AES-256-GCM | ECDH-256 | A | 99 | 1 | 576 |
| 8 | ikev2-null-encryption | IKEv2 | NULL | MODP-1024 | F | 0 | 5 | 574 |
| 9 | ikev2-sha256-integrity | IKEv2 | AES-256-GCM | ECDH-384 | A | 99 | 1 | 572 |
| 10 | ikev2-weak-dh | IKEv2 | AES-CBC | MODP-1024 | F | 39 | 4 | 412 |
| 11 | ikev2-x25519 | IKEv2 | AES-256-GCM | X25519 | A | 99 | 1 | 572 |

The last column counts ESP **packets**, not flows. A tunnel carries one Security
Association per direction, so the flow count is small and uninteresting; the
packet count is what a passive observer actually sees.

`grade` and `score` are the analyzer's output, not a property of the capture.
They are included so a future dissector can be scored against a reference
implementation's opinion, and so a disagreement is visible rather than hidden.

## Traffic classes

Each class is a packet pattern chosen to be separable from the others by
interval and size alone, which is what a classifier would key on. None of them
is a real application.

| Class | Shape | Real application? |
|---|---|---|
| `icmp_interactive` | 64-byte echo, 400 ms apart | No — human-paced, for cadence |
| `icmp_bulk` | 1400-byte echo, 50 ms apart | No — transfer-shaped |
| `voip_like` | 160-byte echo, 20 ms apart, constant | No — voice-codec cadence |
| `video_like` | 1300-byte echo, 10 ms apart | No — streaming cadence |
| `dns` | one UDP query, unique label per tunnel | Yes — a genuine DNS query |
| `ssh` | TCP connect to port 22 | Partly — a real connect, no session |
| `http` | HTTP/1.0 GET, answered by the far side | Partly — a real request/response |

## Versions

This is a living dataset, released incrementally. Each version adds captures
and, where a capture would expose a gap in the reference analyser, holds it
back rather than publish a wrong grade.

| Version | Captures | What changed |
|---|---|---|
| 0.1.0 | 11 | IKEv1 and IKEv2, MODP-1024/1536/2048, ECDH-256/384, X25519, 3DES, DES, NULL, SHA-1 and SHA2 integrity, Aggressive and Main Mode |
| 0.2.0 | planned | Child-SA suite evaluation, so the data-plane cipher is scored and not only the IKE one. Unblocks the `ikev2-aes192-3des-esp` and `ikev2-null-esp` captures, which are already built and held back for exactly this reason. |

Two captures are built and deliberately not released. `ikev2-aes192-3des-esp`
protects data with 3DES behind a modern IKE suite, and `ikev2-null-esp`
protects data with NULL behind a perfect one. The reference analyser scores the
IKE suite, so both currently read as grade A. That is the wrong answer, and
publishing it as fact about a security posture is the one thing this dataset
must not do. They land in 0.2.0.

## Known limits

These are stated so nobody builds on top of this and finds out later.

1. **Four IKEv1 captures have no data plane.** The IKEv1 association never settled, so T3 contains
   the handshake and nothing else. Its 8 findings are real and its score of 0 is
   correct — a tunnel that does not come up is not a passing tunnel — but it
   contributes zero labelled traffic.
2. **The IKEv1 captures carry no ESP data.** strongSwan establishes the IKE SA
   and then the child does not settle, so the four IKEv1 rows in the table above
   show zero ESP packets. Their handshakes parse fully and their findings are
   correct; only the data plane is missing.
3. **IPv4 only.** Every address is RFC 1918 IPv4. IPv6 is not represented.
3. **Tunnel mode only.** No transport-mode association.
5. **The ESP flow count is a grouping, not a session count.** One SA per
   direction, so three flows per tunnel including the marked-NAT-T group. There
   is no per-application flow separation, because a single SA carries every
   class; traffic classes are separable at the packet-window level, not the flow
   level, and the ML work says so rather than papering over it.
6. **PFS is never observed.** No capture contains a rekey, so perfect forward
   secrecy can be neither confirmed nor denied from the wire. The analyzer
   reports this as *not observed* rather than inferring it from configuration.
   This is the most significant gap in the release.
7. **No real application sessions.** Stated above; repeated here because it is
   the limitation most likely to be overlooked.
8. **One vendor.** strongSwan only. Cisco, Juniper and Windows initiators encode
   proposals differently and are not represented.
9. **Addresses are synthetic.** Do not treat the IPs as anything but lab space.

## Provenance

```
python3 scripts/make-corpus.py        # regenerate all six captures
python3 scripts/build-dataset.py       # rebuild the tables
cargo test --workspace                 # check the dissector against tcpdump
```

`crates/vyuh-core/tests/corpus.rs` pins the analyzer's output for all six
captures. Each expectation was read from `tcpdump -nvv` or
`swanctl --list-sas` on a live gateway, then written down *before* trusting the
parser. Where the analyzer and tcpdump disagree, tcpdump is right.

## Citation

```bibtex
@misc{vyuh2026,
  title        = {VYUH IKE: an IPsec negotiation and protected traffic corpus},
  author       = {{Team Venom}},
  year         = {2026},
  note         = {SIH26160, RAKSHAK.VYUH},
  howpublished = {\url{https://github.com/team-venom/rakshak-vyuh}}
}
```

## Intended use

Testing and benchmarking IPsec dissectors, validating security posture rules
against known-bad configurations, and as a fixture for regression suites.

**Not** intended for training a traffic classifier on application identity. The
traffic classes are too few, too regular, and too synthetic for that, and a
model fitted on them would learn the generator rather than the network.
