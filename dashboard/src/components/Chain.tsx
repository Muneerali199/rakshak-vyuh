import type { Ledger } from "../types";
import { truncHash } from "../lib/format";

/** The four leading fields are readable without parsing; index 0,1,2,6. */
function field(entry: Ledger["entries"][number], i: number): string {
  return entry.canonical.split("\u0001")[i] ?? "";
}

export function Chain({ ledger, limit = 6 }: { ledger: Ledger; limit?: number }) {
  const shown = ledger.entries.slice(0, limit);
  const rest = ledger.entries.length - shown.length;

  return (
    <section className="panel">
      <div className="panel__head">
        <span className="panel__title">Evidence ledger</span>
        <span className="panel__badge" title="Each entry commits to the previous one. Editing any earlier finding invalidates every digest after it.">
          {ledger.entries.length} entries
        </span>
        <div className="masthead__spacer" />
        <span className={`tag ${ledger.intact ? "" : "tag--inferred"}`}>
          {ledger.intact ? "chain verified" : "CHAIN BROKEN"}
        </span>
      </div>

      <div className="panel__body" style={{ padding: "14px 20px 18px" }}>
        <div className="chain">
          {shown.map((e, i) => (
            <div key={e.digest} className={`chain__row${i === 0 ? " chain__row--head" : ""}`}>
              <span className="chain__seq">{String(e.sequence).padStart(3, "0")}</span>
              <span>
                <span className="chain__hash">
                  <span className="chain__link">{truncHash(e.previous, 10, 4)}</span>
                  {"  →  "}
                  {truncHash(e.digest, 10, 6)}
                </span>
                <br />
                <span className="chain__hash" style={{ color: "var(--line-strong)" }}>
                  {field(e, 0)} {field(e, 1).toUpperCase()} · {field(e, 2)}
                </span>
              </span>
            </div>
          ))}
          {rest > 0 && (
            <div className="chain__row">
              <span className="chain__seq">…</span>
              <span className="chain__hash">{rest} further entries in ledger.json</span>
            </div>
          )}
        </div>
        <p className="blindspot" style={{ marginTop: 12 }}>
          <span className="blindspot__mark">·</span>
          <span>
            The chain is bound to the capture digest{" "}
            <span style={{ color: "var(--ink-dim)" }}>{truncHash(ledger.capture_sha256, 10, 6)}</span>.
            A report cannot be re-pointed at a different pcap without breaking verification.
          </span>
        </p>
      </div>
    </section>
  );
}
