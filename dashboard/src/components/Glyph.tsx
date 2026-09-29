/**
 * The tool mark: a maze-like glyph, drawn rather than imported, so the
 * console carries no binary asset and the mark scales at 16px without
 * artefacts. It reads as a set of passages seen from above.
 */
export function Glyph({ size = 22 }: { size?: number }) {
  return (
    <svg
      className="masthead__glyph"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <rect x="0.5" y="0.5" width="23" height="23" stroke="#2a313c" />
      <path d="M3 3h7v4H3z" fill="#2f81f7" opacity="0.9" />
      <path d="M3 7h4v10h7" stroke="#2f81f7" strokeWidth="1.4" fill="none" />
      <path d="M10 3v4h4" stroke="#3a424e" strokeWidth="1.4" fill="none" />
      <path d="M14 7h7v4h-7z" fill="#1c212a" stroke="#3a424e" strokeWidth="1" />
      <path d="M14 11v10" stroke="#3a424e" strokeWidth="1.4" fill="none" />
      <path d="M7 17h7v4H7z" fill="#1c212a" stroke="#3a424e" strokeWidth="1" />
      <rect x="19" y="15" width="2" height="2" fill="#f0883e" />
    </svg>
  );
}
