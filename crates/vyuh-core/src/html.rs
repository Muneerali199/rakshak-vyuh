//! Self-contained HTML report.
//!
//! One file, no network, no assets. An air-gapped analyst can open it on a
//! disconnected machine and everything still works, which a dashboard that
//! fetches a bundle cannot promise.
//!
//! The content is exactly the engine's output. Nothing is recomputed here: the
//! score, the grade and the severity counts are copied from the report, so the
//! page cannot disagree with the JSON. The one thing this module decides is
//! layout, and it escapes every value it prints. A capture is untrusted input
//! and a hostname from it ends up in a web page.

use crate::ledger::Ledger;
use crate::posture::{Report, SaPosture};

/// Render the report as a standalone HTML document.
pub fn render(report: &Report, ledger: &Ledger) -> String {
    let mut h = String::with_capacity(32 * 1024);
    h.push_str(HEAD);

    h.push_str(&format!(
        "<title>RAKSHAK.VYUH — {}</title>",
        esc(&report.capture)
    ));

    // -- masthead
    h.push_str("<header class=\"masthead\">");
    h.push_str("<div class=\"wordmark\">RAKSHAK<em>.VYUH</em></div>");
    h.push_str("<div class=\"tag\">Reads the handshake. Never the payload.</div>");
    h.push_str("<div class=\"meta\">");
    h.push_str(&kv("capture", esc(&report.capture)));
    h.push_str(&kv("pcap sha-256", format!("<code>{}</code>", short_hash(&report.pcap_sha256))));
    h.push_str(&kv("packets", report.packets_examined.to_string()));
    h.push_str(&kv("ike messages", report.ike_messages.to_string()));
    h.push_str(&kv("esp flows", report.esp_flows.to_string()));
    h.push_str("</div>");
    h.push_str("<div class=\"verdict\">");
    h.push_str(&format!(
        "<div class=\"grade grade-{}\">{}</div>",
        esc(&report.grade),
        esc(&report.grade)
    ));
    h.push_str(&format!(
        "<div class=\"score\">{}<span>/100</span></div>",
        report.posture_score
    ));
    h.push_str("</div>");
    h.push_str("</header>");

    // -- severity strip
    h.push_str("<section class=\"strip\">");
    for (label, key) in [
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("info", "info"),
    ] {
        let n = report.severity_counts.get(key).copied().unwrap_or(0);
        if n == 0 && (label == "low" || label == "info") {
            continue;
        }
        h.push_str(&format!(
            "<div class=\"sev sev-{} \"><span class=\"sev__n\">{}</span><span class=\"sev__l\">{}</span></div>",
            label, n, label
        ));
    }
    h.push_str("</section>");

    // -- security associations
    h.push_str("<h2>Security Associations</h2>");
    h.push_str("<p class=\"lede\">One record per negotiated tunnel, keyed on the initiator SPI and the unordered peer pair. Every finding cites the packet that carries the suite.</p>");
    for sa in &report.security_associations {
        h.push_str(&sa_card(sa));
    }

    // -- findings
    h.push_str("<h2>Findings</h2>");
    if report.global_findings.is_empty() {
        h.push_str("<p class=\"empty\">No weakness was observed in the captured window. This is not a statement that the tunnel is well configured; it is a statement about these frames.</p>");
    } else {
        h.push_str("<p class=\"lede\">Deduplicated across Security Associations. The occurrence count is how many tunnels showed the same fact.</p>");
        h.push_str("<table class=\"findings\"><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Observed</th><th>Packet</th><th>Seen in</th></tr></thead><tbody>");
        for f in &report.global_findings {
            h.push_str(&format!(
                "<tr class=\"f f-{}\"><td class=\"mono\">{}</td><td><span class=\"tag-{} \">{}</span></td><td><strong>{}</strong><br><span class=\"muted\">{}</span></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
                f.finding.severity.as_str(),
                esc(&f.finding.id),
                f.finding.severity.as_str(),
                f.finding.severity.as_str(),
                esc(&f.finding.title),
                esc(&f.finding.standard),
                esc(&f.finding.observed),
                if f.finding.packet_index > 0 { format!("#{}", f.finding.packet_index) } else { "SA".into() },
                if f.occurrences > 1 { format!("{} SAs", f.occurrences) } else { "1 SA".into() },
            ));
            h.push_str(&format!(
                "<tr class=\"detail\"><td colspan=\"6\"><p>{}</p><p class=\"fix\"><b>remediation.</b> {}</p>{}</td></tr>",
                esc(&f.finding.detail),
                esc(&f.finding.remediation),
                f.finding
                    .cwe
                    .map(|c| format!("<p class=\"cwe\">{}</p>", cwe_name(c)))
                    .unwrap_or_default(),
            ));
        }
        h.push_str("</tbody></table>");
    }

    // -- evidence chain
    h.push_str("<h2>Evidence Ledger</h2>");
    h.push_str("<p class=\"lede\">Every entry hashes the previous one, so altering any finding invalidates every entry after it. The first entry binds the capture digest.</p>");
    h.push_str(&format!(
        "<p class=\"chain-status {} \">{}</p>",
        if ledger.intact { "ok" } else { "bad" },
        if ledger.intact {
            "chain verified"
        } else {
            "CHAIN BROKEN — do not rely on this report"
        }
    ));
    h.push_str("<table class=\"chain\"><thead><tr><th>#</th><th>Statement</th><th>Digest</th></tr></thead><tbody>");
    for e in &ledger.entries {
        h.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono hash\">{}</td></tr>",
            e.sequence,
            esc(&ledger_statement(&e.canonical)),
            short_hash(&e.digest),
        ));
    }
    h.push_str("</tbody></table>");

    // -- blindspots
    h.push_str("<h2>What this report cannot tell you</h2>");
    h.push_str("<ul class=\"blind\">");
    for b in &report.blindspots {
        h.push_str(&format!("<li>{}</li>", esc(b)));
    }
    h.push_str("</ul>");

    h.push_str(FOOT);
    h
}

fn sa_card(sa: &SaPosture) -> String {
    let mut h = String::new();
    h.push_str(&format!(
        "<article class=\"sa grade-border-{}\">",
        esc(&sa.grade)
    ));
    h.push_str("<div class=\"sa__head\">");
    h.push_str(&format!(
        "<span class=\"grade grade-{}\">{}</span>",
        esc(&sa.grade),
        esc(&sa.grade)
    ));
    h.push_str(&format!(
        "<span class=\"sa__pair\"><b>{}</b> → {}</span>",
        esc(&sa.src),
        esc(&sa.dst)
    ));
    h.push_str(&format!(
        "<span class=\"sa__id mono\">{}</span>",
        esc(&sa.sa_id)
    ));
    h.push_str("</div>");

    h.push_str("<div class=\"sa__grid\">");
    h.push_str(&kv("version", esc(&sa.ike_version)));
    h.push_str(&kv("encryption", sa.encryption.as_deref().map(esc).unwrap_or_else(|| "<i>none negotiated</i>".into())));
    if let Some(b) = sa.key_bits {
        h.push_str(&kv("key length", format!("{b} bits")));
    }
    if let Some(i) = &sa.integrity {
        h.push_str(&kv("integrity", esc(i)));
    }
    if let Some(p) = &sa.prf {
        h.push_str(&kv("prf", esc(p)));
    }
    h.push_str(&kv(
        "key exchange",
        sa.key_exchange.as_deref().map(esc).unwrap_or_else(|| "<i>unknown</i>".into()),
    ));
    h.push_str(&kv(
        "perfect forward secrecy",
        match sa.perfect_forward_secrecy {
            Some(true) => "yes".into(),
            Some(false) => "no".into(),
            None => "<i>not observed</i>".into(),
        },
    ));
    h.push_str(&kv("harvest-now-decrypt-later", format!("{} / 100", sa.quantum_exposure)));
    h.push_str("</div>");

    if sa.negotiation_rejected {
        h.push_str(&format!(
            "<p class=\"note\">The peer refused at least one attempt{}.</p>",
            if sa.rejection_notifies.is_empty() {
                String::new()
            } else {
                format!(
                    " (notification {})",
                    sa.rejection_notifies
                        .iter()
                        .map(|n| format!("0x{n:04x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ));
    }
    if !sa.identities_in_clear.is_empty() {
        h.push_str(&format!(
            "<p class=\"note\">Identities readable without decryption: {}</p>",
            esc(&sa.identities_in_clear.join(", "))
        ));
    }

    h.push_str("</article>");
    h
}

/// The first 32 hex characters of a digest, or all of it if it is shorter.
///
/// Sliced safely on purpose. The digest is a byte count the reader does not
/// control, and a truncated slice would turn a malformed report into a panic in
/// the middle of rendering, losing the findings that did parse.
fn short_hash(digest: &str) -> &str {
    match digest.char_indices().nth(32) {
        Some((i, _)) => &digest[..i],
        None => digest,
    }
}

/// Pull the human-readable claim out of a canonical entry.
///
/// The canonical string is the only statement the ledger makes; parallel fields
/// would be a second source of truth that verification cannot police. The
/// fields are unit-separated, so the first one is the finding's title.
fn ledger_statement(canonical: &str) -> String {
    canonical
        .split('\u{1}')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(canonical)
        .to_string()
}

fn kv(k: &str, v: String) -> String {
    format!(
        "<div class=\"kv\"><span class=\"kv__k\">{}</span><span class=\"kv__v\">{}</span></div>",
        esc(k), v
    )
}

/// The CWE identifier as a string, e.g. "CWE-327".
///
/// Read off the serde rename rather than a second mapping: a hand-written
/// table would drift from the enum, and a wrong CWE in an audit report is worse
/// than a missing one.
fn cwe_name(c: crate::posture::Cwe) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "CWE".into())
}

/// Escape for HTML text and attribute context.
///
/// A capture is untrusted: a peer can put any bytes it likes into an identity
/// payload or a notify string, and those end up in this page. Escaping is the
/// only thing standing between a crafted packet and script execution in the
/// analyst's browser.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The CSS. No web fonts, no imports: the report has to render identically on a
/// machine that cannot reach the internet.
const HEAD: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0a0e14;--panel:#111823;--line:#1e2733;--fg:#e6edf3;--muted:#8b98a5;
--cy:#22d3ee;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#38bdf8;--info:#64748b;--ok:#22c55e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--cy)}
.wrap{max-width:1100px;margin:0 auto;padding:0 24px 80px}
.masthead{max-width:1100px;margin:0 auto;padding:48px 24px 32px;
display:grid;grid-template-columns:1fr auto;gap:32px;align-items:start;
border-bottom:1px solid var(--line)}
.wordmark{font-size:28px;font-weight:700;letter-spacing:-.02em}
.wordmark em{font-style:normal;color:var(--cy)}
.tag{color:var(--muted);margin-top:4px}
.meta{grid-column:1;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:8px 24px;margin-top:24px}
.kv{display:flex;gap:8px;align-items:baseline;min-width:0}
.kv__k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;
white-space:nowrap}
.kv__v{font-size:13px;overflow-wrap:anywhere}
.verdict{text-align:right}
.grade{font-size:34px;font-weight:800;line-height:1}
.grade-A{color:var(--ok)}.grade-B{color:var(--low)}.grade-C{color:var(--med)}
.grade-D{color:var(--high)}.grade-F{color:var(--crit)}.grade-unknown{color:var(--info)}
.score{font-size:30px;font-weight:700;margin-top:6px}
.score span{font-size:14px;color:var(--muted);font-weight:400}
.strip{max-width:1100px;margin:0 auto;padding:20px 24px;display:flex;gap:10px;flex-wrap:wrap}
.sev{display:flex;align-items:baseline;gap:8px;padding:8px 14px;
background:var(--panel);border:1px solid var(--line);border-radius:8px}
.sev__n{font-size:20px;font-weight:700}
.sev__l{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.sev-critical .sev__n{color:var(--crit)}.sev-high .sev__n{color:var(--high)}
.sev-medium .sev__n{color:var(--med)}.sev-low .sev__n{color:var(--low)}
.sev-info .sev__n{color:var(--info)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);
margin:44px 0 6px;font-weight:600}
.lede{color:var(--muted);font-size:13px;margin:0 0 16px;max-width:70ch}
.empty{color:var(--muted);font-style:italic}
.sa{background:var(--panel);border:1px solid var(--line);border-left-width:3px;
border-radius:8px;padding:18px 20px;margin-bottom:12px}
.grade-border-A{border-left-color:var(--ok)}.grade-border-B{border-left-color:var(--low)}
.grade-border-C{border-left-color:var(--med)}.grade-border-D{border-left-color:var(--high)}
.grade-border-F{border-left-color:var(--crit)}
.sa__head{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.sa__head .grade{font-size:20px}
.sa__pair{font-size:15px}
.sa__id{color:var(--muted);margin-left:auto}
.sa__grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:6px 24px}
.note{margin:12px 0 0;padding:8px 12px;background:#1a1410;border-left:2px solid var(--med);
font-size:13px;color:#e6d9c3;border-radius:0 4px 4px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
.findings th{text-align:left;color:var(--muted);font-weight:600;font-size:11px;
text-transform:uppercase;letter-spacing:.08em;padding:8px 10px;
border-bottom:1px solid var(--line)}
.findings td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
.f-critical td:first-child{border-left:2px solid var(--crit)}
.f-high td:first-child{border-left:2px solid var(--high)}
.f-medium td:first-child{border-left:2px solid var(--med)}
.f-low td:first-child{border-left:2px solid var(--low)}
.f-info td:first-child{border-left:2px solid var(--info)}
.detail td{background:#0d131b;padding:14px 18px}
.detail p{margin:0 0 10px;max-width:80ch}
.muted{color:var(--muted);font-size:12px}
.fix{color:#cfe8f5}
.cwe{color:var(--muted);font-size:12px}
.tag-critical{color:var(--crit)}.tag-high{color:var(--high)}.tag-medium{color:var(--med)}
.tag-low{color:var(--low)}.tag-info{color:var(--info)}
.chain-status{font-weight:600;margin:0 0 12px}
.chain-status.ok{color:var(--ok)}.chain-status.bad{color:var(--crit)}
.hash{color:var(--muted)}
.blind{margin:0;padding-left:20px;color:var(--muted);font-size:13px}
.blind li{margin-bottom:8px;max-width:80ch}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);
color:var(--muted);font-size:12px}
@media(max-width:640px){.masthead{grid-template-columns:1fr}.verdict{text-align:left}
.findings thead{display:none}.findings tr{display:block;margin-bottom:12px;
border:1px solid var(--line);border-radius:6px}.findings td{display:grid;
grid-template-columns:90px 1fr;gap:8px;border:none;padding:6px 10px}
.findings td::before{content:attr(data-l);color:var(--muted);font-size:11px;
text-transform:uppercase}.detail td{display:block}}
@media print{body{background:#fff;color:#111}.sa,.sev{background:#f7f7f7;border-color:#ccc}
.masthead{border-color:#ccc}.detail td{background:#eee}}
</style></head><body><div class="wrap">
"#;

const FOOT: &str = r#"<footer>
RAKSHAK.VYUH — passive IPsec posture analysis. This report was produced from a packet
capture without decrypting a payload, injecting a packet, or contacting the network.
Every finding is reproducible: open the cited packet and the field is there.
</footer></div></body></html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyse_file, AnalysisOptions};
    use std::path::PathBuf;

    fn corpus(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(name)
    }

    #[test]
    fn escapes_a_hostile_value() {
        // A capture is untrusted input. If this is not escaped, a crafted
        // identity payload becomes script execution in the analyst's browser.
        let x = esc("<img src=x onerror=alert(1)> & \" '");
        assert!(!x.contains('<'));
        assert!(!x.contains('>'));
        assert!(x.contains("&lt;"));
        assert!(x.contains("&amp;"));
        assert!(x.contains("&quot;"));
        assert!(x.contains("&#39;"));
    }

    #[test]
    fn renders_a_real_capture() {
        let path = corpus("vyuh-ikev1-aggressive-3des.pcap");
        if !path.exists() {
            return; // corpus not generated; the CLI path covers this
        }
        let report = analyse_file(&path, &AnalysisOptions::default()).unwrap();
        let ledger = crate::Ledger::build(
            &report.pcap_sha256,
            &report.tool,
            &report.version,
            &report.global_findings,
        );
        let html = render(&report, &ledger);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("RAKSHAK<em>.VYUH</em>"));
        assert!(html.contains("3DES"), "the observed suite must appear");
        assert!(html.contains("MODP-1024"), "the weak group must appear");
        assert!(html.contains("chain verified"));
    }

    #[test]
    fn the_page_has_no_external_references() {
        // An air-gapped report cannot fetch anything.
        let report = crate::posture::Report {
            tool: "RAKSHAK.VYUH".into(),
            version: "0.1.0".into(),
            capture: "x.pcap".into(),
            pcap_sha256: "abc".into(),
            packets_examined: 1,
            ike_messages: 1,
            esp_flows: 0,
            security_associations: vec![],
            posture_score: 100,
            grade: "A".into(),
            severity_counts: Default::default(),
            global_findings: vec![],
            blindspots: vec![],
            flow_records: Vec::new(),
        };
        let ledger = crate::Ledger::build("abc", "RAKSHAK.VYUH", "0.1.0", &[]);
        let html = render(&report, &ledger);
        assert!(!html.contains("http://"), "no external origin");
        assert!(!html.contains("https://"), "no external origin");
        assert!(!html.contains("<script"), "no script, so no injection sink");
    }

    #[test]
    fn a_broken_chain_is_stated_rather_than_hidden() {
        let mut ledger = crate::Ledger::build("abc", "RAKSHAK.VYUH", "0.1.0", &[]);
        ledger.intact = false;
        let report = crate::posture::Report {
            tool: "RAKSHAK.VYUH".into(),
            version: "0.1.0".into(),
            capture: "x.pcap".into(),
            pcap_sha256: "abc".into(),
            packets_examined: 1,
            ike_messages: 0,
            esp_flows: 0,
            security_associations: vec![],
            posture_score: 0,
            grade: "F".into(),
            severity_counts: Default::default(),
            global_findings: vec![],
            blindspots: vec![],
            flow_records: Vec::new(),
        };
        let html = render(&report, &ledger);
        assert!(html.contains("CHAIN BROKEN"));
    }
}
