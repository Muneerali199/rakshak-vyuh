import { Glyph } from "./Glyph";
import type { Report } from "../types";
import { truncHash } from "../lib/format";

export function Masthead({
  report,
  onReload,
  onToggleRail,
}: {
  report: Report;
  onReload: () => void;
  onToggleRail: () => void;
}) {
  return (
    <header className="masthead">
      <div className="masthead__mark">
        <Glyph />
        <div>
          <div className="masthead__name">{report.tool}</div>
          <div className="masthead__tag">reads the handshake, never the payload</div>
        </div>
      </div>

      <button className="rail-toggle" onClick={onToggleRail} aria-label="Toggle SA list">
        SAs
      </button>

      <div className="masthead__meta">
        <div className="meta">
          <span className="meta__label">capture</span>
          <span className="meta__value meta__value--truncate" title={report.capture}>
            {report.capture}
          </span>
        </div>
        <div className="meta meta--wide">
          <span className="meta__label">sha-256</span>
          <span
            className="meta__value"
            title={`${report.pcap_sha256}\n\nEvery finding is bound to this digest. Change the capture and the ledger no longer verifies.`}
          >
            {truncHash(report.pcap_sha256, 10, 6)}
          </span>
        </div>
        <div className="meta">
          <span className="meta__label">packets</span>
          <span className="meta__value">{report.packets_examined.toLocaleString()}</span>
        </div>
        <div className="meta">
          <span className="meta__label">ike</span>
          <span className="meta__value">{report.ike_messages}</span>
        </div>
        <div className="meta">
          <span className="meta__label">esp flows</span>
          <span className="meta__value">{report.esp_flows}</span>
        </div>
      </div>

      <div className="masthead__spacer" />

      <div className="masthead__tools">
        <button className="toggle" onClick={onReload} title="Reload report.json from disk">
          reload
        </button>
      </div>

      <div className="verdict" title="The capture is graded on its weakest security association.">
        <div>
          <div className={`verdict__grade grade-${report.grade}`}>{report.grade}</div>
          <div className="verdict__denom">grade</div>
        </div>
        <div>
          <div className="verdict__score">{report.posture_score}</div>
          <div className="verdict__denom">of 100</div>
        </div>
      </div>
    </header>
  );
}
