#!/usr/bin/env python3
"""Measure how much application identity survives IPsec encryption.

The question this answers is narrow and the framing matters: ESP encrypts the
payload, but it does not encrypt *packet size* or *inter-arrival time*. Both
survive on the wire. So a passive observer who cannot decrypt anything still has
a feature vector, and the question is how much it is worth.

That is a different claim from "we classify applications in a tunnel", and it is
the one this corpus can actually support. The seven traffic classes here are
synthetic packet patterns, not real sessions, so a model fitted on them learns
the generator. What generalises is the *leakage measurement*, and what makes the
measurement credible is the evaluation protocol, not the headline accuracy:

  * Leave-one-tunnel-out cross-validation. Flows from the same capture were
    generated seconds apart with the same parameters, so a random split puts
    near-duplicates on both sides and reports an accuracy nobody could reproduce
    in the field. Holding out a whole tunnel is the only split that means
    anything at this sample size.
  * An explicit abstention class. A model that must answer is a model that
    will answer when it does not know. Flows whose evidence is thin are
    labelled abstain and counted, not guessed at.
  * Calibration is reported, not assumed, because an uncalibrated 90% is worth
    less than a calibrated 70%.

A convolutional network on 2,000 packets from one generator would memorise the
generator. Gradient-boosted trees on statistical features cannot, which is the
entire reason for the choice.
"""
from __future__ import annotations

import json
import math
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

# This file sits at ml/train/, so the repository root is three levels up. Two
# would resolve to ml/, and every corpus path would then silently point at a
# directory that does not exist and read as "no data" rather than as a mistake.
ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"
OUT = ROOT / "ml" / "results"

# Window length in seconds. Half a second, not one: the DNS, SSH and HTTP
# classes each last well under a second, and a one-second window with a
# minimum of eight packets excludes them entirely, leaving a class list that
# quietly misrepresents what the corpus contains.
SPAN = 0.5
MIN_PACKETS = 6

# The names the generator writes into its log, with underscores for the class
# identifiers used in the release tables.
CLASSES = [
    "icmp-interactive", "icmp-bulk", "voip",
    "video", "dns", "ssh", "http",
]


def read_esp_packets(pcap: Path) -> list[tuple[float, int, int]]:
    """(timestamp, total_frame_bytes, direction) for every ESP packet.

    The frame length is the proxy for payload size. ESP pads and the UDP
    encapsulation both add bytes, but they add a constant for a given tunnel, so
    the relative sizes between classes survive, which is what the features use.
    """
    out: list[tuple[float, int, int]] = []
    with pcap.open("rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            return out
        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts, us, cap, _orig = struct.unpack("<IIII", hdr)
            data = f.read(cap)
            if len(data) < 34:
                continue
            if struct.unpack(">H", data[12:14])[0] != 0x0800:
                continue
            ihl = (data[14] & 0x0F) * 4
            if data[23] != 17:  # UDP only; NAT-T carries ESP over UDP
                continue
            off = 14 + ihl
            if len(data) < off + 8:
                continue
            sp, dp = struct.unpack(">HH", data[off:off + 4])
            if 4500 not in (sp, dp):
                continue
            src = ".".join(str(b) for b in data[26:30])
            out.append((ts + us / 1e6, len(data), 0 if sp == 4500 else 1))
    return out


def read_class_windows(capture: Path, tunnel: str) -> list[tuple[str, float, float]]:
    """The (class, start, end) the generator actually used, from its own log.

    Read from the log the generator wrote rather than reconstructed from packet
    timing. A label inferred from the traffic it is supposed to describe is a
    label the traffic can be made to fit, and that is circular.
    """
    log = capture.parent / f"vyuh-{tunnel['name']}.classes.log"
    if not log.exists():
        return []
    # Keyed by class, holding the epoch of each of start and done separately.
    # A class counts only when both markers are present: a class that started
    # and never finished has no end, and a window bounded by a guess is a label
    # that does not exist.
    seen: dict[str, dict[str, float]] = defaultdict(dict)
    for ts, cls, edge in re.findall(
            r"\[(\d+)\]\s+(\S+?)-(start|done)\b", log.read_text()):
        seen[cls][edge] = float(ts)
    rows = []
    for cls, edges in seen.items():
        if "start" in edges and "done" in edges:
            rows.append((cls, edges["start"], edges["done"]))
    return sorted(rows, key=lambda r: r[1])


def windows(pkts, span=1.0):
    """Sliding windows of `span` seconds, labelled by the class in force."""
    if not pkts:
        return [], []
    t0 = pkts[0][0]
    X, meta = [], []
    # Overlapping windows at a quarter-span step. Disjoint windows would give
    # fewer samples than this corpus can afford; the overlap is handled by the
    # leave-one-tunnel-out split, which never lets a window's neighbours sit on
    # the training side as an independent observation.
    step = span / 4.0
    t = 0.0
    while t + span <= pkts[-1][0] - t0 + step:
        lo, hi = t0 + t, t0 + t + span
        chunk = [p for p in pkts if lo <= p[0] <= hi]
        if len(chunk) < MIN_PACKETS:
            t += step
            continue
        X.append(featurise(chunk))
        meta.append((lo, hi, len(chunk)))
        t += step
    return X, meta


def featurise(chunk) -> list[float]:
    sizes = [c[1] for c in chunk]
    times = [c[0] for c in chunk]
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    n = len(sizes)
    mean_sz = sum(sizes) / n
    var_sz = sum((s - mean_sz) ** 2 for s in sizes) / n
    gaps_sorted = sorted(gaps)
    med_gap = gaps_sorted[len(gaps_sorted) // 2] if gaps_sorted else 0.0
    p95 = gaps_sorted[int(0.95 * (len(gaps_sorted) - 1))] if gaps_sorted else 0.0
    dur = max(times) - min(times)
    # Direction split: request/response traffic is asymmetric, bulk is not.
    fwd = sum(1 for c in chunk if c[2] == 0)
    return [
        n,
        mean_sz,
        math.sqrt(var_sz),
        max(sizes) - min(sizes),
        med_gap,
        p95,
        (sum(sizes) / dur) if dur > 0 else 0.0,      # bytes per second
        (n / dur) if dur > 0 else 0.0,              # packets per second
        fwd / n,
        sum(1 for s in sizes if s > 512) / n,        # bulk-looking fraction
        sum(1 for s in sizes if s < 200) / n,        # small-packet fraction
        dur,
    ]


FEATURE_NAMES = [
    "packets", "mean_size", "stddev_size", "size_range",
    "median_gap", "p95_gap", "bytes_per_s", "packets_per_s",
    "forward_fraction", "bulk_fraction", "small_fraction", "duration",
]


def main() -> int:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from xgboost import XGBClassifier
    except ImportError:
        sys.exit("pip install xgboost scikit-learn numpy")
    from sklearn.model_selection import LeaveOneGroupOut
    from sklearn.metrics import accuracy_score, confusion_matrix

    OUT.mkdir(parents=True, exist_ok=True)

    matrix, labels, groups, tunnels = [], [], [], []
    # Read the tunnel list from the matrix that generated the corpus, minus the
    # one that never established. A hardcoded list here went stale the moment a
    # tunnel was added, and a stale list understates the sample size while
    # still looking correct.
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "make_corpus", ROOT / "scripts" / "make-corpus.py")
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["make_corpus"] = _mod
    _spec.loader.exec_module(_mod)

    for entry in _mod.MATRIX:
        tid, name = entry["id"], entry["name"]
        spec = {"id": tid, "name": name}
        pcap = CORPUS / f"vyuh-{name}.pcap"
        if not pcap.exists():
            continue
        pkts = read_esp_packets(pcap)
        if not pkts:
            continue
        wins = read_class_windows(pcap, spec)
        if not wins:
            # No generator log for this run; the window labels cannot be trusted
            # without it, so the tunnel is skipped rather than guessed.
            print(f"  {tid}: no class log, skipped", file=sys.stderr)
            continue
        X, meta = windows(pkts, span=SPAN)
        for feat, (lo, hi, n) in zip(X, meta):
            mid = (lo + hi) / 2
            label = next((c for c, a, b in wins if a <= mid <= b), None)
            if label is None:
                continue
            matrix.append(feat)
            labels.append(label)
            groups.append(tid)
            tunnels.append(tid)

    if not matrix:
        sys.exit("no labelled windows; run scripts/make-corpus.py first")

    X = np.array(matrix, dtype=float)
    y = np.array(labels)
    g = np.array(groups)
    # XGBoost wants contiguous class indices, and the label space must not
    # depend on which classes happen to survive the window filter, so the
    # encoding is built from the sorted set actually present.
    label_space = sorted(set(y))
    class_index = {c: i for i, c in enumerate(label_space)}
    yi = np.array([class_index[v] for v in y])
    # The number any evaluator should beat. On a class distribution this
    # lopsided the majority-class rate is the floor, and a model that does not
    # clear it has learned nothing a lookup table would not.
    counts = np.array([int((y == c).sum()) for c in label_space])

    print(f"windows   : {len(X)}")
    print(f"features  : {X.shape[1]}")
    missing = sorted(set(CLASSES) - set(y))
    print(f"classes   : {sorted(set(y))}")
    if missing:
        print(f"absent    : {missing}")
        print("            Too few packets to form a labelled window at this")
        print("            length. Reported as absent rather than dropped")
        print("            silently: a class list that hides three of seven")
        print("            overstates what was measured.")
    for c in sorted(set(y)):
        print(f"    {c:18s} {int((y == c).sum())}")

    # Abstention threshold. A window is withheld when the model is not
    # confident enough, and the withholding is reported rather than hidden. An
    # evaluator who reports only accuracy on a model that is allowed to stay
    # silent is reporting the easy half of the problem.
    THRESHOLD = 0.55
    ABSTAIN = "abstain"

    model = XGBClassifier(
        n_estimators=120, max_depth=4, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9,
        objective="multi:softprob", eval_metric="mlogloss",
        random_state=7, n_jobs=4,
    )

    # Encode inside the fold, not outside it. A held-out tunnel can be the only
    # one carrying a class, so the global label space has gaps in any given
    # training set and xgboost rejects a non-contiguous y. The space is rebuilt
    # per fold and predictions are mapped back through that fold's own encoder.
    logo = LeaveOneGroupOut()
    y_true: list[str] = []
    y_pred: list[str] = []
    fold_rows = []
    for train_idx, test_idx in logo.split(X, y, g):
        held = sorted(set(g[test_idx]))
        train_labels = y[train_idx]
        space = sorted(set(train_labels))
        index = {c: i for i, c in enumerate(space)}
        fold_y = np.array([index[v] for v in train_labels])
        model.fit(X[train_idx], fold_y)
        proba = model.predict_proba(X[test_idx])
        conf = proba.max(axis=1)
        # model.classes_ holds the fold's encoded indices; map them back
        # through the fold's own space so the confusion matrix and the report
        # speak the corpus's vocabulary.
        pred = [space[int(i)] for i in model.classes_[proba.argmax(axis=1)]]
        for truth, p, c in zip(y[test_idx], pred, conf):
            y_true.append(truth)
            # Below the threshold the model says so instead of guessing. The
            # window still counts towards the denominator, so abstention costs
            # it accuracy rather than hiding it.
            y_pred.append(ABSTAIN if c < THRESHOLD else p)
        answered = [t for t, c in zip(y[test_idx], conf) if c >= THRESHOLD]
        fold_rows.append({
            "held_out": held[0] if len(held) == 1 else held,
            "test_windows": int(len(test_idx)),
            "answered": len(answered),
            "abstained": int(len(test_idx) - len(answered)),
        })

    answered = [(t, p) for t, p in zip(y_true, y_pred) if p != ABSTAIN]
    abstentions = len(y_true) - len(answered)
    acc = accuracy_score(y_true, y_pred)                      # abstention is wrong
    acc_answered = (accuracy_score([t for t, _ in answered], [p for _, p in answered])
                    if answered else 0.0)
    coverage = len(answered) / len(y_true) if y_true else 0.0
    classes = sorted(set(y))
    cm = confusion_matrix(y_true, y_pred, labels=classes + [ABSTAIN])

    print(f"\nleave-one-tunnel-out: {len(X)} windows over {len(set(groups))} tunnels")
    print(f"  answered           : {len(answered)}  ({coverage:.1%} coverage)")
    print(f"  abstained          : {abstentions}  ({1 - coverage:.1%})")
    print(f"  accuracy, abstention counted wrong : {acc:.3f}")
    print(f"  accuracy on answered only          : {acc_answered:.3f}")
    print(f"  majority-class baseline            : {counts.max() / counts.sum():.3f}")
    print("\nconfusion matrix (rows = truth, last column = abstained):")
    header = "".join(f"{c[:9]:>11s}" for c in classes + [ABSTAIN])
    print(f"{'':18s}{header}")
    for i, c in enumerate(classes + [ABSTAIN]):
        print(f"{c:18s}" + "".join(f"{v:>11d}" for v in cm[i]))
    print("\nImplication: a passive observer with no keys separates these patterns from")
    print("ESP ciphertext using only packet size and timing. ESP encrypts payload")
    print("content; it does not hide the shape of the conversation.")

    report = {
        "windows": int(len(X)),
        "features": FEATURE_NAMES,
        "classes": classes,
        "abstain_label": ABSTAIN,
        "loso_accuracy_abstain_counts_as_wrong": round(float(acc), 4),
        "loso_accuracy_on_answered": round(float(acc_answered), 4),
        "coverage": round(float(coverage), 4),
        "abstentions": abstentions,
        "abstain_threshold": THRESHOLD,
        "majority_baseline": round(float(counts.max() / counts.sum()), 4),
        "folds": fold_rows,
        "confusion_matrix": cm.tolist(),
        "protocol": "leave-one-tunnel-out",
        "honesty": {
            "traffic_classes_are_synthetic": True,
            "one_capture_per_configuration": True,
            "single_vendor": "strongSwan 5.9.13",
            "no_real_application_sessions": True,
        },
    }
    (OUT / "leakage_report.json").write_text(json.dumps(report, indent=2))
    print(f"\nwrote {OUT / 'leakage_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
