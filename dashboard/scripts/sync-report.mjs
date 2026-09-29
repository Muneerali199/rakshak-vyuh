// Regenerate dashboard/public/{report,ledger}.json from a capture, so the
// console always shows the engine's real output rather than a checked-in
// fixture that can drift from the code.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..");
const bin = resolve(root, "target/release/vyuh");

// Default to a real strongSwan capture. The default is T3, the IKEv1 Aggressive
// Mode tunnel: it exercises every severity tier in one file, so the console
// shows the full range rather than a single clean result. A path argument is
// resolved against the repository root, because npm runs this with the
// dashboard directory as its working directory.
const DEFAULT_CAPTURE = "corpus/vyuh-ikev1-aggressive-3des.pcap";
const arg = process.argv[2] ?? DEFAULT_CAPTURE;
const capture = resolve(root, arg);

if (!existsSync(bin)) {
  console.error(`engine not built: ${bin}\n  cargo build --release --manifest-path ${resolve(root, "Cargo.toml")}`);
  process.exit(1);
}
if (!existsSync(capture)) {
  console.error(`capture not found: ${capture}`);
  console.error(`available:\n${readdirSync(resolve(root, "corpus"))
    .filter((f) => f.endsWith(".pcap"))
    .map((f) => `  ${f}`)
    .join("\n")}`);
  process.exit(1);
}

// The analyser exits 2 when it finds something critical. That is the intended
// gate behaviour, not a failure of the sync, so it is accepted here.
try {
  execFileSync(
    bin,
    [
      capture,
      "--json",
      resolve(here, "..", "public/report.json"),
      "--ledger",
      resolve(here, "..", "public/ledger.json"),
      "--quiet",
    ],
    { stdio: "inherit" },
  );
} catch (err) {
  if (err.status !== 2) throw err;
}
console.log(`synced from ${capture}`);
