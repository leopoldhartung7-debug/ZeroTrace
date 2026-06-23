/* ZeroTrace brand logo — ZT monogram mark + wordmark */

const SIZES = {
  sm: { box: 30, brand: '1.05rem', sub: '0.52rem', gap: 10 },
  md: { box: 40, brand: '1.45rem', sub: '0.58rem', gap: 13 },
  lg: { box: 54, brand: '2.2rem',  sub: '0.68rem', gap: 18 },
}

/*
  ZT monogram — constructed from three white bars:
    · Full-width top bar  (Z crossbar = T crossbar)
    · Full-width bottom bar (Z base)
    · Full-height right bar (T stem)
  Plus a triangular dark "slash" in the middle-left = the Z diagonal.
  Outer shape has chamfered corners top-left and bottom-right.

  viewBox "0 0 58 50"
  Outer: M 10,0 H 58 V 40 L 48,50 H 0 V 10 Z
  Hole:  M 43,13 V 37 H 0 Z
*/
export default function Logo({ size = 'md', sub = false }) {
  const s = SIZES[size] || SIZES.md
  const h = s.box * (50 / 58)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: s.gap }}>
      <span style={{ width: s.box, height: h, flexShrink: 0, display: 'block' }}>
        <svg viewBox="0 0 58 50" fill="none" width="100%" height="100%">
          <defs>
            <linearGradient id="zt-grad" x1="0" y1="0" x2="58" y2="50" gradientUnits="userSpaceOnUse">
              <stop offset="0%"   stopColor="#ffffff" />
              <stop offset="40%"  stopColor="#e8e8f2" />
              <stop offset="100%" stopColor="#b0b0c4" />
            </linearGradient>
          </defs>
          <path
            fillRule="evenodd"
            fill="url(#zt-grad)"
            d="M 10,0 H 58 V 40 L 48,50 H 0 V 10 Z M 43,13 V 37 H 0 Z"
          />
        </svg>
      </span>

      <span style={{ display: 'flex', flexDirection: 'column', gap: 2, lineHeight: 1 }}>
        <span
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontWeight: 800,
            fontSize: s.brand,
            letterSpacing: '-0.015em',
            color: 'var(--text)',
          }}
        >
          Zero<span style={{ color: 'var(--muted)' }}>Trace</span>
        </span>
        {sub && (
          <span
            style={{
              fontFamily: "'Inter', system-ui, sans-serif",
              fontWeight: 600,
              fontSize: s.sub,
              letterSpacing: '0.2em',
              color: 'var(--muted)',
              textTransform: 'uppercase',
              opacity: 0.65,
            }}
          >
            Anticheat Scanner
          </span>
        )}
      </span>
    </div>
  )
}
