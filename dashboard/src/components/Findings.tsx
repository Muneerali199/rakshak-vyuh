import { useState } from "react";
import type { RatedFinding, Severity } from "../types";
import { SEVERITY_ORDER, countAt } from "../lib/format";

function FindingRow({
  finding,
  expanded,
  onToggle,
}: {
  finding: RatedFinding;
  expanded: boolean;
  onToggle: () => void;
}) {
  const id = `f-${finding.id}-${finding.observed.replace(/[^a-z0-9]/gi, "")}`;
  return (
    <div className={`finding finding--${finding.severity}`}>
      <button
        className="finding__row"
        aria-expanded={expanded}
        aria-controls={id}
        onClick={onToggle}
      >
        <span className={`finding__sev sev--${finding.severity}`}>{finding.severity}</span>
        <span className="finding__title">
          <span className="finding__id">{finding.id}</span>
          {finding.title}
        </span>
        <span className="finding__meta">
          {finding.cwe && <span className="tag">{finding.cwe}</span>}
          {finding.evidence === "inferred" && (
            <span className="tag tag--inferred" title="Derived by comparing observations, not read from a single header field">
              inferred
            </span>
          )}
          <span title={finding.packet_index > 0 ? "Packet in the source capture" : "Applies to the association as a whole, not one frame"}>
            {finding.packet_index > 0 ? `pkt #${finding.packet_index}` : "SA-scoped"}
          </span>
        </span>
      </button>

      {expanded && (
        <div className="finding__body" id={id}>
          <p className="prose">{finding.detail}</p>

          <div className="quote">
            <b>requirement.</b> {finding.standard}
          </div>

          <div className="fix">
            <span className="fix__label">remediation</span>
            {finding.remediation}
          </div>

          <div className="kv">
            <span className="kv__k">observed</span>
            <span className="kv__v">{finding.observed}</span>
            <span className="kv__k">peers</span>
            <span className="kv__v">
              {finding.src} → {finding.dst}
            </span>
            <span className="kv__k">packet</span>
            <span className="kv__v">
              {finding.packet_index > 0 ? `#${finding.packet_index}` : "SA-scoped"}
            </span>
            {finding.occurrences > 1 && (
              <>
                <span className="kv__k">corroborated by</span>
                <span className="kv__v">
                  {finding.occurrences} Security Associations
                </span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function Findings({
  findings,
  severityCounts,
}: {
  findings: RatedFinding[];
  severityCounts: Record<string, number>;
}) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [active, setActive] = useState<Set<Severity>>(() => new Set(SEVERITY_ORDER));

  const keyOf = (f: RatedFinding) => `${f.id}|${f.observed}`;

  const toggle = (k: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const toggleSeverity = (s: Severity) =>
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const visible = findings.filter((f) => active.has(f.severity));
  const totalActive = findings.filter((f) => active.has(f.severity)).length;

  return (
    <section className="panel">
      <div className="panel__head">
        <span className="panel__title">Findings</span>
        <span className="panel__badge">
          {totalActive} of {findings.length}
        </span>
        <div className="masthead__spacer" />
        <div className="filters" role="group" aria-label="Filter by severity">
          {SEVERITY_ORDER.map((s) => {
            const n = countAt({ severity_counts: severityCounts }, s);
            const on = active.has(s);
            return (
              <button
                key={s}
                className="toggle"
                aria-pressed={on}
                onClick={() => toggleSeverity(s)}
                title={`${n} ${s} findings in this capture`}
              >
                <span className={`toggle__dot`} style={{ background: on ? `var(--${s})` : "var(--line-strong)" }} />
                {s} {n > 0 ? n : ""}
              </button>
            );
          })}
        </div>
      </div>

      <div className="panel__body">
        {visible.length === 0 ? (
          <div className="blindspots">
            <p className="blindspot">
              <span className="blindspot__mark">—</span>
              <span>No findings at these severities.</span>
            </p>
          </div>
        ) : (
          <div className="findings">
            {visible.map((f) => (
              <FindingRow
                key={keyOf(f)}
                finding={f}
                expanded={open.has(keyOf(f))}
                onToggle={() => toggle(keyOf(f))}
              />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
