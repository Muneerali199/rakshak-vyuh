import { useCallback, useEffect, useMemo, useState } from "react";
import { Masthead } from "./components/Masthead";
import { SaList } from "./components/SaList";
import { SaDetail } from "./components/SaDetail";
import { Findings } from "./components/Findings";
import { Chain } from "./components/Chain";
import { Blindspots } from "./components/Blindspots";
import { useReport } from "./lib/load";
import { truncHash } from "./lib/format";

const keyOf = (src: string, dst: string, saId: string) => `${saId}|${src}|${dst}`;

export default function App() {
  const { report, ledger, error, loading, reload } = useReport();
  const [selected, setSelected] = useState<string | null>(null);
  const [railOpen, setRailOpen] = useState(false);

  const sas = report?.security_associations ?? [];

  // Default to the worst association: that is the one an analyst opens first.
  const initial = useMemo(() => {
    if (sas.length === 0) return null;
    const worst = sas.reduce((a, b) => (a.score <= b.score ? a : b));
    return keyOf(worst.src, worst.dst, worst.sa_id);
  }, [sas]);

  const current = selected ?? initial;

  useEffect(() => {
    if (initial && selected === null) setSelected(initial);
  }, [initial, selected]);

  // j / k move between associations, arrows between findings' parent panel.
  const onKey = useCallback(
    (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA"].includes(target.tagName)) return;

      if (e.key === "j" || e.key === "k") {
        if (sas.length === 0) return;
        e.preventDefault();
        const idx = sas.findIndex(
          (s) => keyOf(s.src, s.dst, s.sa_id) === current,
        );
        const next =
          e.key === "j"
            ? Math.min(sas.length - 1, idx + 1)
            : Math.max(0, idx <= 0 ? 0 : idx - 1);
        const s = sas[next];
        setSelected(keyOf(s.src, s.dst, s.sa_id));
        setRailOpen(false);
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        document.querySelector<HTMLButtonElement>(".rail-toggle")?.click();
      }
    },
    [sas, current],
  );

  useEffect(() => {
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onKey]);

  if (loading) {
    return (
      <div className="empty">
        <div className="empty__title">reading report.json</div>
        <div className="empty__hint">The console reads the engine's output from disk. Nothing is fetched from a network.</div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="empty">
        <div className="empty__title">no report</div>
        <div className="empty__hint">
          {error ? `Could not load the assessment: ${error}` : "The engine has not produced a report yet."}{" "}
          Run it against a capture, then reload.
        </div>
        <div className="empty__code">{`cd ..
cargo run --release -p vyuh-cli -- corpus/vyuh-demo.pcap \\
  --json dashboard/public/report.json \\
  --ledger dashboard/public/ledger.json
cd dashboard && npm run dev`}</div>
      </div>
    );
  }

  const sa = sas.find((s) => keyOf(s.src, s.dst, s.sa_id) === current) ?? null;
  const criticals = report.severity_counts["critical"] ?? 0;

  return (
    <div className="shell">
      <Masthead report={report} onReload={reload} onToggleRail={() => setRailOpen((v) => !v)} />

      <SaList
        sas={sas}
        selected={current}
        onSelect={(id) => {
          setSelected(id);
          setRailOpen(false);
        }}
        open={railOpen}
      />

      <main className="main">
        {sa ? (
          <>
            <section className="panel">
              <div className="detail__head" style={{ borderBottom: "1px solid var(--line)" }}>
                <span className="panel__title" style={{ display: "none" }} />
              </div>
              <SaDetail sa={sa} />
            </section>

            <Findings findings={sa.findings} severityCounts={report.severity_counts} />

            {ledger && <Chain ledger={ledger} />}

            <Blindspots report={report} />
          </>
        ) : (
          <div className="empty">
            <div className="empty__title">no security association</div>
            <div className="empty__hint">
              No IKE handshake was found on ports 500 or 4500. Either the capture window missed the negotiation, or the tunnel uses a non-standard port.
            </div>
          </div>
        )}
      </main>

      <footer className="status">
        <span className="status__item">
          <span className={`dot ${criticals > 0 ? "dot--bad" : "dot--ok"}`} />
          {criticals > 0 ? `${criticals} critical` : "no critical findings"}
        </span>
        <span className="status__item">
          <span className="dot dot--idle" />
          passive — no packet was sent
        </span>
        <span className="status__item">
          <span className="dot dot--idle" />
          payload never decrypted
        </span>
        <span className="status__spacer" />
        <span className="status__item">
          {report.tool} {report.version}
        </span>
        <span className="status__item" title="SHA-256 of the capture">
          {truncHash(report.pcap_sha256, 8, 4)}
        </span>
        {ledger && (
          <span className="status__item">
            <span className={`dot ${ledger.intact ? "dot--ok" : "dot--bad"}`} />
            ledger {ledger.intact ? "intact" : "broken"}
          </span>
        )}
      </footer>
    </div>
  );
}
