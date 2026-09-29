import { useEffect, useRef } from "react";
import type { SaPosture, Severity } from "../types";
import { SEVERITY_ORDER, severityRank, shortAddr } from "../lib/format";

/** One severity marker per distinct tier present, so density reads at a glance. */
function Pips({ sa }: { sa: SaPosture }) {
  const present = new Set(sa.findings.map((f) => f.severity as Severity));
  const shown = SEVERITY_ORDER.filter((s) => present.has(s)).slice(0, 6);
  if (shown.length === 0) return <div className="sa-row__pips" />;
  return (
    <div className="sa-row__pips" aria-hidden="true">
      {shown.map((s) => (
        <span key={s} className={`pip pip--${s}`} />
      ))}
    </div>
  );
}

export function SaList({
  sas,
  selected,
  onSelect,
  open,
}: {
  sas: SaPosture[];
  selected: string | null;
  onSelect: (id: string) => void;
  open: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);

  // Keep the selection in view when it changes from the keyboard or a deep link.
  useEffect(() => {
    if (!selected || !ref.current) return;
    const el = ref.current.querySelector<HTMLElement>(`[data-sa="${CSS.escape(selected)}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  return (
    <nav className={`rail${open ? " rail--open" : ""}`} aria-label="Security associations">
      <div className="rail__head">
        <span className="rail__title">Security associations</span>
        <span className="rail__count">{sas.length}</span>
      </div>

      <div className="rail__list" ref={ref} role="listbox" aria-label="Select a security association">
        {sas.map((sa) => {
          const key = `${sa.sa_id}|${sa.src}|${sa.dst}`;
          const worst = sa.findings.length
            ? sa.findings.reduce((acc, f) => (severityRank(f.severity) < severityRank(acc) ? f.severity : acc), sa.findings[0].severity)
            : null;
          return (
            <button
              key={key}
              data-sa={key}
              className="sa-row"
              role="option"
              aria-selected={selected === key}
              onClick={() => onSelect(key)}
            >
              <span className={`sa-row__grade grade-${sa.grade}`}>{sa.grade}</span>
              <span className="sa-row__body">
                <span className="sa-row__pair">
                  <span>{shortAddr(sa.src)}</span>
                  <span className="sa-row__arrow">→</span>
                  <span>{shortAddr(sa.dst)}</span>
                </span>
                <span className="sa-row__suite">
                  {sa.encryption ?? "no suite negotiated"} · {sa.ike_version}
                  {sa.aggressive_mode ? " · aggressive" : ""}
                  {sa.negotiation_rejected ? " · refused then retried" : ""}
                </span>
                <Pips sa={sa} />
                {worst && (
                  <span className="sr-only">
                    {sa.findings.length} findings, worst {worst}
                  </span>
                )}
              </span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
