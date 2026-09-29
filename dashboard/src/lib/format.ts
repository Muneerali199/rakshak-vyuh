import type { Evidence, Severity } from "../types";

/** Severity order used for sorting and for the pip strip. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function countAt(report: { severity_counts: Record<string, number> }, s: Severity): number {
  return report.severity_counts[s] ?? 0;
}

/**
 * Requirement-tier verdict for a negotiated field.
 * The tiers follow RFC 2119 as the RFCs actually use them, which is not the
 * same thing as "good / bad": SHOULD NOT is legal, MUST- is legal but on the
 * way out, and MUST NOT is prohibited.
 */
export function requirementTone(req: string | null): {
  cls: string;
  verdict: "ok" | "warn" | "bad" | "muted";
  note: string;
} {
  switch (req) {
    case "MUST":
      return { cls: "req-MUST", verdict: "ok", note: "mandatory to implement" };
    case "SHOULD":
      return { cls: "req-SHOULD", verdict: "ok", note: "should be implemented" };
    case "MUST-":
      return { cls: "req-MUST_NOT", verdict: "warn", note: "legal, no longer required" };
    case "SHOULD NOT":
      return { cls: "req-SHOULD_NOT", verdict: "warn", note: "legal, actively discouraged" };
    case "MUST NOT":
      return { cls: "req-MUST_NOT", verdict: "bad", note: "prohibited" };
    case "DEPRECATED":
      return { cls: "req-DEPRECATED", verdict: "bad", note: "deprecated" };
    case "MAY":
      return { cls: "req-MAY", verdict: "muted", note: "optional" };
    default:
      return { cls: "req-unknown", verdict: "muted", note: "not in the registry" };
  }
}

/** A 64-bit block cipher is the SWEET32 birthday case; call it out in the cell. */
export function blockNote(bits: number | null): string | null {
  if (bits === 64) return "64-bit block — birthday bound at ~32 GB";
  if (bits === 128) return "128-bit block";
  return null;
}

export function truncHash(hash: string, head = 8, tail = 6): string {
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

export function kvLabel(evidence: Evidence): string {
  return evidence === "observed" ? "read off the wire" : "inferred";
}

/** Postgres-style abbreviated IPv4/IPv6 for a narrow column. */
export function shortAddr(addr: string): string {
  if (addr.startsWith("::ffff:")) return addr.slice(7);
  return addr;
}
