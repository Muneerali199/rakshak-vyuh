import type { Report } from "../types";

/**
 * The blindspot panel. It is not a disclaimer, it is part of the finding set:
 * a posture score with no stated limits is not an assessment, it is a number.
 * Rendered above the fold rather than buried in an appendix.
 */
export function Blindspots({ report }: { report: Report }) {
  if (report.blindspots.length === 0) return null;
  return (
    <section className="panel">
      <div className="panel__head">
        <span className="panel__title">What this capture cannot tell you</span>
        <span className="panel__badge">{report.blindspots.length}</span>
      </div>
      <div className="blindspots">
        {report.blindspots.map((b, i) => (
          <p className="blindspot" key={i}>
            <span className="blindspot__mark">¬</span>
            <span>{b}</span>
          </p>
        ))}
      </div>
    </section>
  );
}
