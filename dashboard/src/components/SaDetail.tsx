import type { SaPosture } from "../types";
import { Suite } from "./Suite";

/**
 * Header for one association. The quantum score is shown next to the posture
 * score deliberately: one is "how weak is this now", the other is "how much
 * of this traffic is exposed if the adversary is patient". They answer
 * different questions and a single blended number would answer neither.
 */
export function SaDetail({ sa }: { sa: SaPosture }) {
  return (
    <>
      <div className="detail__head">
        <div className="detail__ident">
          <div className="detail__spi">SA {sa.sa_id}</div>
          <div className="detail__pair">
            {sa.src}
            <span className="arrow">→</span>
            {sa.dst}
          </div>
          <div className="detail__chips">
            <span className="chip">{sa.ike_version}</span>
            {sa.exchanges_seen.map((e) => (
              <span key={e} className="chip">
                {e}
              </span>
            ))}
            {sa.aggressive_mode && (
              <span className="chip chip--alert" title="Identity and HASH travel unprotected">
                aggressive mode
              </span>
            )}
            {sa.downgrade_observed && (
              <span className="chip chip--alert">suite changed on this SA</span>
            )}
            {sa.perfect_forward_secrecy === true && <span className="chip chip--ok">PFS</span>}
            {sa.identities_in_clear.map((id) => (
              <span key={id} className="chip chip--warn" title="Readable without decryption">
                {id}
              </span>
            ))}
            {sa.vendor_ids.map((v) => (
              <span key={v} className="chip" title="Vendor ID payload, in the clear">
                vid {v.slice(0, 12)}
              </span>
            ))}
          </div>
        </div>

        <div className="gauges">
          <div className="gauge">
            <div className={`gauge__value grade-${sa.grade}`}>{sa.score}</div>
            <div className="gauge__label">posture</div>
            <div className="gauge__note">grade {sa.grade}</div>
          </div>
          <div className="gauge">
            <div
              className="gauge__value"
              style={{
                color:
                  sa.quantum_exposure >= 70
                    ? "var(--critical)"
                    : sa.quantum_exposure >= 40
                      ? "var(--warn)"
                      : "var(--ok)",
              }}
            >
              {sa.quantum_exposure}
            </div>
            <div className="gauge__label">KalScore</div>
            <div className="gauge__note">
              {sa.quantum_exposure === 0 ? "post-quantum ready" : "HNDL exposure"}
            </div>
          </div>
        </div>
      </div>

      <Suite sa={sa} />
    </>
  );
}
