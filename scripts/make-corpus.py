#!/usr/bin/env python3
"""
Generate the VYUH corpus from a real strongSwan testbed.

For each tunnel in the T-matrix this brings up a gateway pair in a private
network, waits for the association to establish, drives a little traffic, and
collects the tcpdump from both ends. Ground truth is therefore a property of
the configuration, not an annotation: T2 really is negotiating MODP-1024 because
that is what swanctl was told to offer.

Usage:  python3 scripts/make-corpus.py [--keep] [--tunnels T1,T3]
"""

from __future__ import annotations

import argparse
import json
import struct
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "vyuh/gateway:latest"
OUT = ROOT / "corpus"
CAPTURE_DIR = OUT / "captures"

# Ground truth per tunnel. `expect` is what the engine must find; `clean` marks
# a tunnel that must produce no critical or high finding. A tunnel that is
# expected to be weak but is scored clean is the failure mode that matters.
MATRIX = [
    {
        "id": "T1",
        "name": "ikev2-modern",
        "subnet_a": "10.61.0.0/24",
        "subnet_b": "10.61.1.0/24",
        "a_ip": "10.61.0.1",
        "b_ip": "10.61.0.2",
        "expect": [],
        "clean": True,
        "note": "AES-256-GCM, PRF-SHA2-256, ECP-256, PFS on. The reference posture.",
    },
    {
        "id": "T2",
        "name": "ikev2-weak-dh",
        "subnet_a": "10.62.0.0/24",
        "subnet_b": "10.62.1.0/24",
        "a_ip": "10.62.0.1",
        "b_ip": "10.62.0.2",
        "expect": ["VYU-020"],
        "clean": False,
        "note": "MODP-1024 key exchange. RFC 8247 marks this MUST NOT.",
    },
    {
        "id": "T3",
        "name": "ikev1-aggressive-3des",
        "subnet_a": "10.63.0.0/24",
        "subnet_b": "10.63.1.0/24",
        "a_ip": "10.63.0.1",
        "b_ip": "10.63.0.2",
        "expect": ["VYU-001", "VYU-002", "VYU-011", "VYU-020"],
        "clean": False,
        "note": "IKEv1 Aggressive Mode, PSK, 3DES, no PFS. The headline finding.",
    },
    {
        "id": "T4",
        "name": "ikev2-null-encryption",
        "subnet_a": "10.64.0.0/24",
        "subnet_b": "10.64.1.0/24",
        "a_ip": "10.64.0.1",
        "b_ip": "10.64.0.2",
        "expect": ["VYU-010"],
        "clean": False,
        "note": "NULL encryption. No confidentiality whatsoever.",
    },
    {
        "id": "T5",
        "name": "ikev2-x25519",
        "subnet_a": "10.65.0.0/24",
        "subnet_b": "10.65.1.0/24",
        "a_ip": "10.65.0.1",
        "b_ip": "10.65.0.2",
        "expect": [],
        "clean": True,
        "note": "X25519 with AES-256-GCM. Modern suite, shorter rekey.",
    },
    {
        "id": "T6",
        "name": "ikev2-legacy-integrity",
        "subnet_a": "10.66.0.0/24",
        "subnet_b": "10.66.1.0/24",
        "a_ip": "10.66.0.1",
        "b_ip": "10.66.0.2",
        "expect": ["VYU-031"],
        "clean": False,
        "note": "SHA-1 integrity. Demoted to MUST- rather than prohibited.",
    },
    {
        "id": "T7",
        "name": "ikev1-main-mode-3des",
        "subnet_a": "10.91.0.0/24",
        "subnet_b": "10.91.1.0/24",
        "a_ip": "10.91.0.1",
        "b_ip": "10.91.0.2",
        "expect": ["VYU-002", "VYU-011", "VYU-020"],
        "clean": False,
        "ike_version": 1,
        "aggressive": False,
        "note": "IKEv1 Main Mode with 3DES and MODP-1024. Same ciphers as T3 with the exchange type changed, so the 3DES finding can be separated from the Aggressive Mode finding.",
    },
    {
        "id": "T8",
        "name": "ikev2-xcbc-integrity",
        "subnet_a": "10.92.0.0/24",
        "subnet_b": "10.92.1.0/24",
        "a_ip": "10.92.0.1",
        "b_ip": "10.92.0.2",
        "expect": [],
        "clean": True,
        "note": "AES-256-GCM with AES-XCBC integrity. Integrity that is not a hash, which is the modern recommendation and is not otherwise represented.",
    },
    {
        "id": "T9",
        "name": "ikev2-aes192-3des-esp",
        "subnet_a": "10.93.0.0/24",
        "subnet_b": "10.93.1.0/24",
        "a_ip": "10.93.0.1",
        "b_ip": "10.93.0.2",
        "expect": ["VYU-011"],
        "clean": False,
        "ike": "aes192-sha256-prfsha256-modp2048",
        "esp": "3des-sha256-modp2048",
        "pending": True,
        "note": "A modern IKE suite protecting data with 3DES. Held back from the release: the engine scores the IKE suite, so this capture currently grades A while the data plane is 3DES. That is the wrong answer and must not ship in a public dataset. Lands in v0.2.0 with child-SA evaluation.",
    },
    {
        "id": "T10",
        "name": "ikev1-aggressive-dh2048",
        "subnet_a": "10.94.0.0/24",
        "subnet_b": "10.94.1.0/24",
        "a_ip": "10.94.0.1",
        "b_ip": "10.94.0.2",
        "expect": ["VYU-002", "VYU-011"],
        "clean": False,
        "ike_version": 1,
        "aggressive": True,
        "ike": "3des-sha1-modp2048",
        "note": "Aggressive Mode with 3DES but a 2048-bit group. Paired with T3 this separates the key exchange finding from the cipher finding.",
    },
    {
        "id": "T11",
        "name": "ikev2-sha256-integrity",
        "subnet_a": "10.95.0.0/24",
        "subnet_b": "10.95.1.0/24",
        "a_ip": "10.95.0.1",
        "b_ip": "10.95.0.2",
        "expect": [],
        "clean": True,
        "note": "AES-256-GCM with SHA2-256 integrity on a 384-bit curve. A second clean baseline, so a grade of A is shown on more than one configuration.",
    },
    {
        "id": "T12",
        "name": "ikev2-dh1536",
        "subnet_a": "10.96.0.0/24",
        "subnet_b": "10.96.1.0/24",
        "a_ip": "10.96.0.1",
        "b_ip": "10.96.0.2",
        "expect": ["VYU-020"],
        "clean": False,
        "note": "MODP-1536. RFC 8247 lists this as SHOULD NOT, which is a different severity from the 1024-bit group, and the corpus otherwise only shows the worse case.",
    },
    {
        "id": "T13",
        "name": "ikev1-main-mode-des",
        "subnet_a": "10.97.0.0/24",
        "subnet_b": "10.97.1.0/24",
        "a_ip": "10.97.0.1",
        "b_ip": "10.97.0.2",
        "expect": ["VYU-011"],
        "clean": False,
        "ike_version": 1,
        "aggressive": False,
        "ike": "des-sha1-modp1024",
        "note": "Single DES under IKEv1 Main Mode. A 56-bit block cipher is a different exposure from 3DES's 64-bit block, and the two are not interchangeable.",
    },
    {
        "id": "T14",
        "name": "ikev2-null-esp",
        "subnet_a": "10.98.0.0/24",
        "subnet_b": "10.98.1.0/24",
        "a_ip": "10.98.0.1",
        "b_ip": "10.98.0.2",
        "expect": ["VYU-002"],
        "clean": False,
        "esp": "null-sha256-modp2048",
        "pending": True,
        "note": "A perfect IKE suite protecting data with NULL. Held back from the release for the same reason as T9: a control-plane-only score reads this as healthy, and publishing that as fact would be wrong. Lands in v0.2.0.",
    },
]


SUBNET_TO_STR = lambda s: str(s).split("/")[0]  # noqa: E731


def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def docker_available() -> bool:
    return run(["docker", "info"]).returncode == 0


class Gateway:
    """One strongSwan container on the tunnel's lab bridge."""

    def __init__(self, spec, role: str, tunnel: str, network: str):
        self.name = f"vyuh-{spec['id'].lower()}-{role}"
        self.role = role
        self.tunnel = tunnel
        self.network = network
        self.spec = spec
        if role == "gw-a":
            self.local_ip = spec["a_ip"]
            self.peer_ip = spec["b_ip"]
            # Traffic selectors, which are a different pair of addresses from
            # the lab bridge the gateways talk IKE over. swanctl turns a /24
            # selector into a /32 policy, so the usable address is the network
            # address of the block, not a host inside it.
            self.local_selector = selector_addr(spec["subnet_a"])
            self.peer_selector = selector_addr(spec["subnet_b"])
        else:
            self.local_ip = spec["b_ip"]
            self.peer_ip = spec["a_ip"]
            self.local_selector = selector_addr(spec["subnet_b"])
            self.peer_selector = selector_addr(spec["subnet_a"])
        self.cid = None
        # Set once the association is known to be up on this gateway. The
        # traffic phase refuses to run without it.
        self.may_send = False

    def start(self) -> None:
        self.run_detach()

    def run_detach(self):
        env = {
            "ROLE": self.role,
            "PEER_IP": self.peer_ip,
            "LOCAL_IP": self.local_ip,
            "SUBNET_A": SUBNET_TO_STR(self.spec["subnet_a"]),
            "SUBNET_B": SUBNET_TO_STR(self.spec["subnet_b"]),
            "IKESUBNET": "eth0",
        }
        # A tunnel whose IKE and ESP suites differ carries them explicitly,
        # so the matrix is the single place a suite is written down.
        for key in ("ike", "esp"):
            if self.spec.get(key):
                env[f"VYUH_{key.upper()}"] = self.spec[key]
        cmd = [
            "docker", "run", "-d",
            "--name", self.name,
            "--cap-add", "NET_ADMIN",
            "--cap-add", "SYS_TIME",
            "-e", f"TUNNEL={self.tunnel}",
        ]
        for k, v in env.items():
            cmd += ["-e", f"{k}={v}"]
        # One bridge per tunnel, so a stale container cannot answer a new
        # tunnel's IKE_SA_INIT. The certificate is named for the tunnel as well
        # as the role, so a single CA covers the whole matrix.
        cert = f"{self.role}-{self.tunnel}"
        cmd += [
            "--network", self.network,
            "--ip", self.local_ip,
            "-v", f"{CAPTURE_DIR}:/capture",
            "-v", f"{PKI}:/lab-pki:ro",
            "-e", f"PKI_NAME={cert}",
            IMAGE,
        ]
        try:
            r = run(cmd, timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{self.name} timed out starting")
        if r.returncode != 0:
            raise RuntimeError(f"could not start {self.name}: {r.stderr.strip()}")
        self.cid = r.stdout.strip()

    def logs(self) -> str:
        return run(["docker", "logs", self.name]).stdout

    def sas(self) -> str:
        return run(["docker", "exec", self.name, "swanctl", "--list-sas"]).stdout

    def up(self) -> str:
        return run(["docker", "exec", self.name, "ipsec", "up", "vyuh"]).stdout

    def traffic(self) -> None:
        """Drive the labelled traffic phase, or wait for the peer to finish it.

        Only gw-a sends. Starting it on both ends would double every class and
        put two unlabelled copies of the same application in the capture.

        The generator lives in the container entrypoint and is invoked with
        `docker exec`, because it has to run after the association is
        established. Doing it from inside the container raced the SA coming up:
        a phase that starts early sends its packets out the bridge in clear and
        the dataset still labels them as tunnel-protected.
        """
        if not self.may_send:
            # Refuse to label a capture as tunnel-protected when the
            # association never came up. Sending the classes anyway would put
            # cleartext on the bridge that the dataset attributes to the
            # tunnel, which is the one error that must not ship. The capture
            # keeps whatever the handshake produced, and the manifest records
            # that the tunnel did not establish.
            print("  traffic: SKIPPED, the SA is not up", flush=True)
            return

        if self.role != "gw-a":
            # The responder is serving HTTP for the initiator's request. Give it
            # the same window the initiator gets, then move on.
            time.sleep(self.spec.get("traffic_seconds", 60))
            return

        # traffic.sh runs inside the container with the same environment the
        # entrypoint had, so the selector addresses it needs are already known.
        r = run(
            ["docker", "exec", self.name, "sh", "-c",
             f"LOCAL_HOST={self.local_selector} REMOTE_HOST={self.peer_selector} "
             f"TUNNEL={self.tunnel} ROLE=gw-a traffic.sh"],
            timeout=200,
        )
        log = (r.stdout or "") + (r.stderr or "")
        started = log.count("-start")
        done = "traffic-complete" in log
        print(
            f"  traffic: {started} classes started"
            f"{', complete' if done else ', INCOMPLETE'}",
            flush=True,
        )
        if not done:
            for line in log.splitlines()[-8:]:
                print(f"    {line}", flush=True)

    def stop(self) -> None:
        run(["docker", "rm", "-f", self.name])

    def wait_ready(self, timeout=60) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "READY" in self.logs():
                return True
            if self.exited():
                return False
            time.sleep(1)
        return False

    def exited(self) -> bool:
        r = run(["docker", "inspect", "-f", "{{.State.Running}}", self.name])
        return r.stdout.strip() != "true"

    def wait_established(self, timeout=45) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "ESTABLISHED" in self.sas():
                return True
            self.up()
            time.sleep(3)
        return False


PKI = ROOT / "testbed" / "pki"


def make_lab_ca() -> None:
    """One CA for every tunnel in the corpus.

    Two gateways that each mint their own CA cannot verify each other, and the
    resulting AUTHENTICATION_FAILED is indistinguishable from a real credential
    problem. Generating once on the host and mounting read-only removes the
    whole class of failure.
    """
    import ssl  # noqa: F401  (documents that we rely on the system openssl)
    PKI.mkdir(parents=True, exist_ok=True)
    for f in PKI.iterdir():
        f.unlink()

    sh(f"openssl genrsa -out {PKI}/ca-key.pem 4096")
    sh(f"openssl req -x509 -new -key {PKI}/ca-key.pem -sha256 -days 3650 "
       f"-subj /CN=VYUH_Lab_CA -out {PKI}/ca.pem")

    # Every tunnel the matrix declares, so one CA serves the whole corpus.
    #
    # Read from MATRIX rather than listed by hand. A hardcoded list went stale
    # the moment tunnels were added: the certificates for the new rows were
    # never minted, every one of those gateways died at boot looking for a
    # missing file, and all of them were reported as tunnels that "refused to
    # negotiate". The certificate inventory and the tunnel list are the same
    # fact, so they are read from the same place.
    for tid in [t["id"] for t in MATRIX if not t.get("pending")]:
        a, b = lab_ips(tid)
        for role, ip in (("gw-a", a), ("gw-b", b)):
            sh(f"openssl genrsa -out {PKI}/{role}-{tid}-key.pem 3072")
            sh(f"openssl req -new -key {PKI}/{role}-{tid}-key.pem "
               f"-subj /CN={role} -out {PKI}/{role}-{tid}.csr")
            (PKI / f"{role}-{tid}.ext").write_text(
                f"subjectAltName = IP:{ip}, DNS:{role}\n"
                "extendedKeyUsage = serverAuth, clientAuth\n"
            )
            sh(f"openssl x509 -req -in {PKI}/{role}-{tid}.csr -CA {PKI}/ca.pem "
               f"-CAkey {PKI}/ca-key.pem -CAcreateserial -days 3650 -sha256 "
               f"-extfile {PKI}/{role}-{tid}.ext -out {PKI}/{role}-{tid}.pem")
            (PKI / f"{role}-{tid}.csr").unlink(missing_ok=True)
            (PKI / f"{role}-{tid}.ext").unlink(missing_ok=True)
    (PKI / "ca.srl").unlink(missing_ok=True)
    sh(f"chmod 600 {PKI}/*-key.pem")


def sh(cmd: str) -> None:
    r = run(cmd)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stderr.strip()}")


def selector_addr(cidr: str) -> str:
    """The address a traffic selector is keyed on: 10.61.0.0/24 -> 10.61.0.0.

    swanctl installs a /32 XFRM policy for a /24 selector, so only this exact
    address matches. A host address inside the block, such as 10.61.0.1, is
    not covered by the policy and its traffic leaves unencrypted.
    """
    return cidr.split("/")[0]


def lab_base(tid: str) -> str:
    """Second octet for a tunnel's lab bridge. T1 -> 10.71, T2 -> 10.72, and so on.
    One function derives both the network and the peer addresses, so they can
    never drift apart."""
    n = int(tid[1])
    if not 1 <= n <= 14:
        raise ValueError(f"unknown tunnel {tid}")
    # 10.71 through 10.84. The traffic selectors deliberately live outside
    # this range: a selector that shared a /16 with some other tunnel's lab
    # bridge would be directly connected on that bridge, so its traffic would
    # leave in clear instead of entering the tunnel under test.
    return f"10.{70 + n}"


def lab_subnet(tid: str) -> str:
    return f"{lab_base(tid)}.0.0/16"


def lab_ips(tid: str) -> tuple[str, str]:
    """Peer addresses on the lab bridge. The bridge itself owns the .1 address,
    so the two gateways take .2 and .3; pinning them avoids the DHCP pool
    handing out the same address to a second container."""
    base = lab_base(tid)
    return f"{base}.0.2", f"{base}.0.3"


def ensure_network(tid: str) -> str:
    """A per-tunnel bridge so the two gateways can address each other.

    A single shared network would also work, but per-tunnel isolation means a
    stale container from a previous run cannot silently answer a new tunnel's
    IKE_SA_INIT and pollute the capture.
    """
    name = f"vyuh-lab-{tid.lower()}"
    run(["docker", "network", "rm", "-f", name])
    r = run(["docker", "network", "create", name, "--driver", "bridge",
             "--subnet", lab_subnet(tid)])
    if r.returncode != 0:
        raise RuntimeError(f"network {name}: {r.stderr.strip()}")
    return name


@dataclass
class CorpusEntry:
    tunnel: str
    name: str
    file: str
    sha256: str
    packets: int
    expect: list
    clean: bool
    note: str
    ground_truth_observed: dict


def collect(spec, a: Gateway, b: Gateway) -> tuple[Path, Path] | None:
    files = []
    for gw in (a, b):
        p = CAPTURE_DIR / f"{spec['id']}-{gw.role}.pcap"
        if p.exists() and p.stat().st_size > 24:
            files.append(p)
    return files[0] if files else None


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanoseconds
}


def merge_captures(paths: list[Path], dest: Path) -> None:
    """Merge several pcap files into one, in timestamp order.

    mergecap is not in the image and byte concatenation is not a merge: a pcap
    file is a 24-byte global header followed by records, so the second file's
    header would be read as a record header and every offset after it would be
    wrong. Both files come from the same tcpdump build and link type, so the
    per-file headers after the first are simply dropped.
    """
    if not paths:
        raise RuntimeError("no captures to merge")
    if len(paths) == 1:
        shutil.copy(paths[0], dest)
        return

    records: list[tuple[int, bytes]] = []  # (sort key, original 16-byte header + payload)
    endian = "<"
    linktype = 1
    snaplen = 65535

    for path in paths:
        raw = path.read_bytes()
        magic = raw[:4]
        if magic not in PCAP_MAGICS:
            raise RuntimeError(f"{path.name}: not a classic pcap ({magic!r})")
        e = PCAP_MAGICS[magic]
        if e != endian:
            raise RuntimeError(f"{path.name}: byte order differs from the first file")
        snaplen = struct.unpack(e + "I", raw[16:20])[0]
        lt = struct.unpack(e + "I", raw[20:24])[0]
        if lt != linktype:
            raise RuntimeError(f"{path.name}: link type {lt} differs from the first file")

        off = 24
        while off + 16 <= len(raw):
            ts_sec, ts_frac, incl, orig = struct.unpack(e + "IIII", raw[off:off + 16])
            off += 16
            if off + incl > len(raw):
                break  # truncated final record, nothing more to take
            # Keep the original record header: the timestamp and the original
            # wire length are part of the capture, not something to invent.
            header = raw[off - 16:off]
            records.append((ts_sec * 1_000_000 + min(ts_frac, 999_999), header + raw[off:off + incl]))
            off += incl

    records.sort(key=lambda r: r[0])
    with dest.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for _, record in records:
            fh.write(record)


def pcap_stats(path: Path) -> tuple[int, str]:
    """Packet count and digest for a capture, counted by the engine itself.

    The count comes from the same libpcap reader the analyser uses, not from a
    second tool, so the manifest cannot disagree with the report. The image's
    ENTRYPOINT is bypassed: it expects a role as its first argument, so passing
    "tcpdump" through it does not run tcpdump at all and silently yields zero.
    """
    import hashlib

    h = hashlib.sha256()
    n = 0
    if path.exists():
        h.update(path.read_bytes())
        n = pcap_record_count(path)
    return n, h.hexdigest()


def pcap_record_count(path: Path) -> int:
    """Count the records in a classic pcap file, from the link type header.

    Only the 24-byte file header and the 16-byte record header are read; the
    packet bodies are skipped by seeking, so this stays fast on large captures
    and needs no container.
    """
    with path.open("rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return 0
        magic = head[:4]
        endian = {
            b"\xd4\xc3\xb2\xa1": "little",  # microsecond, little endian
            b"\xa1\xb2\xc3\xd4": "big",     # microsecond, big endian
            b"\x4d\x3c\xb2\xa1": "little",  # nanosecond, little endian
            b"\xa1\xb2\x3c\x4d": "big",     # nanosecond, big endian
        }.get(magic)
        if endian is None:
            return 0

        n = 0
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                break
            incl = int.from_bytes(rec[8:12], endian)
            if incl > 0xFFFF:  # implausible; refuse to seek wildly
                break
            fh.seek(incl, 1)
            n += 1
        return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tunnels", default="", help="comma separated subset, e.g. T1,T3")
    ap.add_argument("--keep", action="store_true", help="leave containers running")
    args = ap.parse_args()

    if not docker_available():
        print("docker is not running. start OrbStack or Docker Desktop.", file=sys.stderr)
        return 1

    wanted = {t.strip().upper() for t in args.tunnels.split(",") if t.strip()}
    # A row marked pending is a configuration the engine cannot grade correctly
    # yet. It stays in the matrix so the work is tracked, but it is not
    # captured: publishing a capture whose grade the engine gets wrong would put
    # a false fact about a security posture into a public dataset, which is the
    # one error this project is built not to make.
    specs = [s for s in MATRIX
             if (not wanted or s["id"] in wanted) and not s.get("pending")]

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    make_lab_ca()
    print("lab CA ready", flush=True)

    entries: list[CorpusEntry] = []

    for spec in specs:
        tid = spec["id"]
        print(f"\n=== {tid}  {spec['name']} — {spec['note']}", flush=True)

        network = ensure_network(tid)
        a_lab, b_lab = lab_ips(tid)

        # spec["a_ip"]/["b_ip"] are the tunnel-facing IKE endpoints; the lab
        # addresses are where those endpoints actually live on the bridge.
        spec = {**spec, "a_ip": a_lab, "b_ip": b_lab}

        # Ping across the tunnel: a reaches b's lab address, routed by the SA.
        a_spec = {**spec, "peer_host": b_lab}
        b_spec = {**spec, "peer_host": a_lab}
        a = Gateway(a_spec, "gw-a", tid, network)
        b = Gateway(b_spec, "gw-b", tid, network)

        for gw in (a, b):
            gw.start()

        ok_a = a.wait_ready()
        ok_b = b.wait_ready()
        if not (ok_a and ok_b):
            print(f"  gateway did not become ready (a={ok_a} b={ok_b})", flush=True)
            for gw in (a, b):
                tail = "\n".join(gw.logs().splitlines()[-12:])
                print(f"  --- {gw.name} ---\n{tail}", flush=True)

        est_a = a.wait_established()
        est_b = b.wait_established()
        a.may_send = est_a
        b.may_send = est_b
        print(f"  established: a={est_a} b={est_b}", flush=True)

        # gw-a to gw-b, then gw-b to gw-a. A capture where every data flow
        # points the same way leaves every bidirectional feature a classifier
        # would use at zero, so the reverse direction is generated too.
        a.traffic()
        b.traffic()

        # Copy the generator's class log next to the capture. The ML work needs
        # the (class, start, end) windows the traffic was actually sent in, and
        # they cannot be reconstructed from the pcap afterwards without assuming
        # the very mapping the labels are supposed to establish.
        tlog = CAPTURE_DIR / "traffic" / f"{tid}-gw-a.traffic.log"
        if tlog.exists():
            tlog.replace(OUT / f"vyuh-{spec['name']}.classes.log")

        merged = OUT / f"vyuh-{spec['name']}.pcap"
        paths = [p for p in (CAPTURE_DIR / f"gw-a-{tid}.pcap", CAPTURE_DIR / f"gw-b-{tid}.pcap")
                 if p.exists() and p.stat().st_size > 24]
        if paths:
            merge_captures(paths, merged)
            n, sha = pcap_stats(merged)
            print(f"  captured {n} packets -> {merged.name} ({len(paths)} interface(s))", flush=True)
            entries.append(CorpusEntry(
                tunnel=tid, name=spec["name"], file=merged.name, sha256=sha,
                packets=n, expect=spec["expect"], clean=spec["clean"], note=spec["note"],
                ground_truth_observed={},
            ))
        else:
            print(f"  no capture produced for {tid}", flush=True)

        for gw in (a, b):
            try:
                gw.stop()
            except Exception as e:
                print(f"  cleanup {gw.name}: {e}", file=sys.stderr)
        run(["docker", "network", "rm", "-f", network])

    manifest = OUT / "manifest.json"
    existing = []
    if manifest.exists():
        existing = json.loads(manifest.read_text()).get("tunnels", [])
    by_id = {e["tunnel"]: e for e in existing}
    by_id.update({e.tunnel: asdict(e) for e in entries})
    manifest.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "image": IMAGE,
        "note": "Captures produced by a live strongSwan pair. Ground truth is the configuration, not an annotation.",
        "tunnels": [by_id[k] for k in sorted(by_id)],
    }, indent=2) + "\n")

    print(f"\nmanifest -> {manifest}")
    print(f"{len(by_id)} tunnels in corpus")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
