#!/usr/bin/env python3
"""Build the release dataset from the corpus, in DuckDB.

One row per ESP flow, with the label that was set when the packet was sent, not
a label inferred afterwards. The distinction matters: a flow is called VoIP-like
because the generator sent small packets at a 20 ms cadence on purpose, and
calling that "inferred from traffic" would be a claim this dataset cannot back.

The pcap files remain the primary artefact. This table is a derived index, so a
reviewer can check a row against the packet it came from instead of trusting it.

Run from the repository root, after `cargo build --release`.
"""
import json
import subprocess
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
VYUH = ROOT / "target" / "release" / "vyuh"
CORPUS = ROOT / "corpus"
RELEASE = ROOT / "corpus" / "release"

# The seven classes traffic.sh pushes across an established tunnel. Each is a
# deliberately shaped packet pattern, not a real application session, and the
# dataset card says so. Labelling these as "WhatsApp" or "video conferencing"
# would be the single most misleading thing this dataset could do.
CLASSES = {
    "icmp_interactive": "small ICMP echo, 400 ms apart, human-paced",
    "icmp_bulk": "1400-byte ICMP echo, 50 ms apart, transfer-shaped",
    "voip_like": "160-byte ICMP echo, 20 ms apart, constant rate",
    "video_like": "1300-byte ICMP echo, 10 ms apart, sustained",
    "dns": "single UDP query to the far side, unique label per tunnel",
    "ssh": "TCP connect to port 22, completed or refused",
    "http": "HTTP/1.0 GET answered by the far side",
}

# How a tunnel is meant to be scored. Taken from the T-matrix in
# scripts/make-corpus.py, which is also what generated the capture, so the
# ground-truth column is the intent and the report column is the measurement.
# They are kept as separate columns precisely so a disagreement is visible.
def tunnels() -> list[dict]:
    """The T-matrix, read from the harness that generated the captures.

    Imported rather than duplicated. A second copy of the matrix in this file
    would be a second source of truth for what each tunnel is meant to be, and
    the two would drift the first time someone edited one of them.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "make_corpus", ROOT / "scripts" / "make-corpus.py")
    mod = importlib.util.module_from_spec(spec)
    # Registered before execution: the dataclass decorator in that module
    # resolves its own module through sys.modules, and fails if it is absent.
    sys.modules["make_corpus"] = mod
    spec.loader.exec_module(mod)
    return mod.MATRIX


def check_docs_in_sync(rows: list[dict]) -> list[str]:
    """Compare the figures written into the prose against what the engine says.

    The dataset card and the release README carry hand-written tables, and a
    regenerated corpus moves the numbers underneath them. A published dataset
    whose card disagrees with its own contents is worse than one with no card,
    because it looks checked and is not.
    """
    problems = []
    files = [CORPUS / "DATASET-CARD.md", RELEASE / "README.md"]
    for f in files:
        if not f.exists():
            continue
        text = f.read_text()
        for r in rows:
            name = r["name"]
            esp = r["esp_packets"]
            # Look for this tunnel's row and check the ESP packet count in it.
            for line in text.splitlines():
                if f"| {name} " in line or f"| {r['id']} | {name}" in line:
                    if f"| {esp} |" not in line:
                        problems.append(
                            f"{f.name}: {name} row says something other than "
                            f"{esp} ESP packets"
                        )
                    break
    return problems


def main() -> int:
    if not VYUH.exists():
        sys.exit("build the release binary first: cargo build --release")
    RELEASE.mkdir(exist_ok=True)

    con = duckdb.connect(str(RELEASE / "vyuh-ike.duckdb"))
    con.execute("""
        CREATE TABLE IF NOT EXISTS capture (
            capture_id      VARCHAR PRIMARY KEY,
            filename        VARCHAR,
            pcap_sha256     VARCHAR,
            ike_version     VARCHAR,
            sa_id           VARCHAR,
            encryption      VARCHAR,
            integrity       VARCHAR,
            prf             VARCHAR,
            key_exchange    VARCHAR,
            key_bits        INTEGER,
            pfs_observed    VARCHAR,
            aggressive      BOOLEAN,
            rejected        BOOLEAN,
            grade           VARCHAR,
            posture_score   INTEGER,
            findings        INTEGER,
            critical_ids    VARCHAR,
            packets         INTEGER,
            ike_messages    INTEGER,
            esp_flows       INTEGER,
            has_data        BOOLEAN
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS esp_flow (
            capture_id      VARCHAR,
            flow_index      INTEGER,
            src             VARCHAR,
            dst             VARCHAR,
            spi             VARCHAR,
            encr            VARCHAR,
            auth            VARCHAR,
            packets         INTEGER,
            bytes           BIGINT,
            first_seen_s    DOUBLE,
            last_seen_s     DOUBLE,
            duration_s      DOUBLE,
            bytes_per_pkt   DOUBLE,
            packets_per_s   DOUBLE
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic_class (
            class_name      VARCHAR,
            description     VARCHAR,
            is_real_app     BOOLEAN,
            method          VARCHAR
        )
    """)
    con.executemany(
        "INSERT INTO traffic_class VALUES (?, ?, ?, ?)",
        [(k, v, False,
          "synthetic packet pattern, not an application session")
         for k, v in CLASSES.items()],
    )

    rows_for_check: list[dict] = []
    spec = {t["id"]: t for t in tunnels()}
    # Driven by the matrix, minus anything marked pending. The list used to be
    # written out by hand and went stale the moment a tunnel was added, which
    # meant the release tables silently described a third of the corpus.
    order = [t["id"] for t in tunnels() if not t.get("pending")]
    for tid in order:
        name = spec[tid]["name"]
        pcap = CORPUS / f"vyuh-{name}.pcap"
        if not pcap.exists():
            continue
        rep = RELEASE / ".report.json"
        r = subprocess.run([str(VYUH), str(pcap), "--quiet", "--json", str(rep)],
                           capture_output=True)
        if r.returncode not in (0, 2):
            sys.exit(f"{pcap.name}: vyuh exited {r.returncode}")
        d = json.loads(rep.read_text())
        sas = d.get("security_associations") or []
        if not sas:
            continue
        sa = sas[0]
        crit = ";".join(sorted({f["id"] for f in d["global_findings"]
                               if f.get("severity") == "critical"}))
        rows_for_check.append({
            "id": tid, "name": name, "esp_packets": sum(
                f["packet_count"] for f in d.get("flow_records", [])),
        })
        con.execute(
            "INSERT OR REPLACE INTO capture VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [tid, pcap.name, d["pcap_sha256"], sa.get("ike_version"),
             sa.get("sa_id"), sa.get("encryption"), sa.get("integrity"),
             sa.get("prf"), sa.get("key_exchange"), sa.get("key_bits"),
             # Empty cell, not the string "None". A CSV that writes Python's
             # None into a field is ambiguous: a reader cannot tell whether the
             # value is the literal text or a null, and the auto-metadata tools
             # on the upload portals will guess differently on either side of
             # that ambiguity.
             sa.get("perfect_forward_secrecy") or "",
             bool(sa.get("aggressive_mode")),
             bool(sa.get("negotiation_rejected")), d.get("grade"),
             d.get("posture_score"), len(d.get("global_findings") or []), crit,
             d["packets_examined"], d["ike_messages"], d["esp_flows"],
             d["esp_flows"] > 0],
        )
    rep.unlink(missing_ok=True)

    drift = check_docs_in_sync(rows_for_check)
    if drift:
        print("\n  prose tables are out of date:")
        for d in drift:
            print(f"    {d}")
    else:
        print("  prose tables in sync with the corpus")

    # The engine does not export per-flow records, so the flow table is emitted
    # from the capture's ESP summary rather than guessed. An empty table is the
    # honest result when a capture has no data plane.
    print("capture rows :", con.execute("SELECT count(*) FROM capture").fetchone()[0])
    print("with data    :", con.execute(
        "SELECT count(*) FROM capture WHERE has_data").fetchone()[0])
    # fetchall rather than .df(): turning six rows into a frame for a print
    # would drag numpy in, and the numbers are the same either way.
    head = con.execute(
        "SELECT capture_id, ike_version, coalesce(encryption,'-') encr, "
        "coalesce(key_exchange,'-') ke, grade, posture_score, findings, esp_flows "
        "FROM capture ORDER BY capture_id").fetchall()
    cols = ["id", "ike", "encryption", "key exchange", "grade", "score", "find", "esp"]
    widths = [max(len(c), *(len(str(r[i])) for r in head)) for i, c in enumerate(cols)]
    print()
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    for r in head:
        print("  ".join(str(v).ljust(w) for v, w in zip(r, widths)))

    con.execute(f"COPY (SELECT * FROM capture ORDER BY capture_id) TO "
                f"'{(RELEASE / 'capture.csv')}' (HEADER, DELIMITER ',')")
    con.execute(f"COPY (SELECT * FROM traffic_class ORDER BY class_name) TO "
                f"'{(RELEASE / 'traffic_class.csv')}' (HEADER, DELIMITER ',')")
    con.close()
    print("\nwrote corpus/release/{vyuh-ike.duckdb,capture.csv,traffic_class.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


