import type { SaPosture } from "../types";
import { blockNote, requirementTone } from "../lib/format";

/**
 * One cell per negotiated field. The requirement tier sits next to the value
 * because the value alone does not carry the verdict: AES-CBC-256 and 3DES are
 * both "AES" and "3DES" in the same column, and only the tier says which one
 * the RFCs currently permit.
 */
function Cell({
  label,
  value,
  requirement,
  blockBits,
  fallback = "not observed",
  badge,
}: {
  label: string;
  value: string | null | undefined;
  requirement?: string | null;
  blockBits?: number | null;
  fallback?: string;
  badge?: string;
}) {
  const tone = requirementTone(requirement ?? null);
  const present = value !== null && value !== undefined && value !== "";
  const note = blockNote(blockBits ?? null);

  return (
    <div className="suite__cell">
      <div className="suite__label">
        <span>{label}</span>
        {badge && <span>{badge}</span>}
      </div>
      <div
        className={`suite__value ${present ? `value-${tone.verdict}` : "value-muted"}`}
        title={present ? (note ?? value!) : fallback}
      >
        {present ? value : fallback}
      </div>
      {present && (requirement || note) && (
        <div className={`suite__req ${tone.cls}`}>
          {requirement && `${requirement} · `}
          {note ?? tone.note}
        </div>
      )}
    </div>
  );
}

export function Suite({ sa }: { sa: SaPosture }) {
  const pfs = sa.perfect_forward_secrecy;

  return (
    <div className="suite">
      <Cell
        label="encryption"
        value={sa.encryption}
        requirement={null}
        fallback="none negotiated"
        badge={sa.key_bits ? `${sa.key_bits} bit` : undefined}
      />
      <Cell
        label="key exchange"
        value={sa.key_exchange}
        requirement={null}
        fallback="none negotiated"
      />
      <Cell label="integrity" value={sa.integrity} fallback="not negotiated separately" />
      <Cell
        label="pseudorandom fn"
        value={sa.prf}
        fallback="not negotiated separately"
      />
      <div className="suite__cell">
        <div className="suite__label">forward secrecy</div>
        <div
          className={`suite__value ${
            pfs === true ? "value-ok" : pfs === false ? "value-bad" : "value-muted"
          }`}
        >
          {pfs === true ? "yes" : pfs === false ? "no" : "not observed"}
        </div>
        <div className={`suite__req ${pfs === false ? "req-SHOULD_NOT" : "req-unknown"}`}>
          {pfs === true
            ? "fresh KE per child SA"
            : pfs === false
              ? "no rekey observed · NIST SP 800-77r1 §5.3"
              : "needs a capture spanning a rekey"}
        </div>
      </div>
      <Cell label="mode" value={sa.transport_or_tunnel} fallback="not observed" />
    </div>
  );
}
