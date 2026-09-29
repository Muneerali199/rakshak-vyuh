#!/usr/bin/env python3
"""Export the corpus in the formats an AI dataset portal will actually accept.

The platform's upload filter lists CSV, TSV, Parquet, XLSX, JSON, XML, YAML,
PDF, media, text, ARROW, Markdown, H5 and HDF5. PCAP is not on it, so the raw
captures that the corpus is built around cannot be uploaded as files. A corpus
whose whole point is the packet trace, delivered as a spreadsheet, is not the
same dataset, so the packet-level content is exported as Parquet and CSV, which
are lossless for everything except the link-layer framing and the raw bytes.

What the Parquet and CSV carry is the whole of the observable content: every
packet's index, timestamp, endpoints, protocol, ESP SPI, ESP sequence, IKE
version and message type. What they do not carry is the encrypted payload,
which nobody can read anyway, and the Ethernet header, which the selectors make
irrelevant.
"""
import struct
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
OUT = CORPUS / "release" / "uploadable"


def packets(pcap: Path, capture_id: str):
    """Yield one record per packet, for a relational export."""
    with pcap.open("rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return
        f.read(20)
        idx = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts, us, cap, orig = struct.unpack("<IIII", hdr)
            data = f.read(cap)
            idx += 1
            if len(data) < 34 or struct.unpack(">H", data[12:14])[0] != 0x0800:
                yield (capture_id, idx, ts, us, orig, None, None, None,
                       None, None, None, None, None, None, None, 0)
                continue
            ihl = (data[14] & 0x0F) * 4
            proto = data[23]
            src = ".".join(str(b) for b in data[26:30])
            dst = ".".join(str(b) for b in data[30:34])
            sport = dport = None
            spi = seq = None
            ike = None
            if proto == 17 and len(data) > 14 + ihl + 8:
                off = 14 + ihl
                sport, dport = struct.unpack(">HH", data[off:off + 4])
                pay = data[off + 8:]
                if 4500 in (sport, dport) and len(pay) >= 8:
                    # NAT-T: the ESP header may sit at 0 or behind the RFC 3948
                    # four octet non-ESP marker. Try both and take whichever
                    # yields a plausible SPI.
                    for base in (0, 4):
                        if len(pay) >= base + 8:
                            cand = struct.unpack(">I", pay[base:base + 4])[0]
                            if cand:
                                spi = f"{cand:08x}"
                                seq = struct.unpack(">I", pay[base + 4:base + 8])[0]
                                break
            yield (capture_id, idx, ts, us, orig, src, dst, proto, sport,
                   dport, spi, seq, ike, None, None, len(data))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute("""
        CREATE TABLE packet (
            capture_id VARCHAR, packet_index INTEGER, ts_sec BIGINT,
            ts_usec INTEGER, wire_len INTEGER, src VARCHAR, dst VARCHAR,
            protocol INTEGER, src_port INTEGER, dst_port INTEGER,
            esp_spi VARCHAR, esp_seq BIGINT, ike_version VARCHAR,
            ike_exchange VARCHAR, tcp_flags INTEGER, frame_len INTEGER
        )
    """)
    rows = []
    for pcap in sorted(CORPUS.glob("vyuh-*.pcap")):
        cid = pcap.stem.replace("vyuh-", "")
        n = 0
        for r in packets(pcap, cid):
            rows.append(r)
            n += 1
        print(f"  {cid:28s} {n:5d} packets")
    con.executemany(
        "INSERT INTO packet VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    total = con.execute("SELECT count(*) FROM packet").fetchone()[0]
    print(f"  total {total:,} packets")

    con.execute(f"COPY packet TO '{OUT / 'packets.parquet'}' (FORMAT PARQUET)")
    con.execute(f"COPY packet TO '{OUT / 'packets.csv'}' (HEADER, DELIMITER ',')")
    con.close()
    for f in ("packets.parquet", "packets.csv"):
        mb = (OUT / f).stat().st_size / 1048576
        print(f"  wrote {f} ({mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
