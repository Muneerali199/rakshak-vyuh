import { useCallback, useEffect, useState } from "react";
import type { Ledger, Report } from "../types";

interface LoadState {
  report: Report | null;
  ledger: Ledger | null;
  error: string | null;
  loading: boolean;
}

/**
 * The engine is a CLI, not a server. Two files on disk are the entire data
 * source: the assessment and the evidence ledger. `npm run sync` regenerates
 * both, so the console never needs a network round trip and the demo works
 * with the machine offline.
 */
export function useReport(): LoadState & { reload: () => void } {
  const [state, setState] = useState<LoadState>({
    report: null,
    ledger: null,
    error: null,
    loading: true,
  });
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));

    const load = async () => {
      try {
        const [r, l] = await Promise.all([
          fetch(`./report.json?t=${nonce}`, { cache: "no-store" }).then((res) => {
            if (!res.ok) throw new Error(`report.json — HTTP ${res.status}`);
            return res.json();
          }),
          fetch(`./ledger.json?t=${nonce}`, { cache: "no-store" })
            .then((res) => (res.ok ? res.json() : null))
            .catch(() => null),
        ]);
        if (!cancelled) setState({ report: r, ledger: l, error: null, loading: false });
      } catch (e) {
        if (!cancelled) {
          setState({
            report: null,
            ledger: null,
            error: e instanceof Error ? e.message : String(e),
            loading: false,
          });
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  return { ...state, reload };
}
