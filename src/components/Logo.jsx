/* ZeroTrace brand logo — ZT monogram mark + wordmark */

const SIZES = {
  sm: { box: 28, brand: '1.05rem', sub: '0.52rem', gap: 10 },
  md: { box: 38, brand: '1.45rem', sub: '0.58rem', gap: 13 },
  lg: { box: 52, brand: '2.2rem',  sub: '0.68rem', gap: 18 },
}

export default function Logo({ size = 'md', sub = false }) {
  const s = SIZES[size] || SIZES.md
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: s.gap }}>
      <span style={{ width: s.box, height: s.box * (52 / 60), flexShrink: 0, display: 'block' }}>
        <svg viewBox="0 0 60 52" fill="none" width="100%" height="100%">
          <defs>
            <linearGradient id="zt-silver" x1="0" y1="0" x2="60" y2="52" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#f4f4f8" />
              <stop offset="55%" stopColor="#d8d8e4" />
              <stop offset="100%" stopColor="#b8b8c8" />
            </linearGradient>
          </defs>
          {/*
            ZT monogram:
            - Outer chamfered rectangle (chamfer top-left + bottom-right)
            - Diagonal triangle hole = Z diagonal cut, leaves T stem intact
          */}
          <path
            fillRule="evenodd"
            fill="url(#zt-silver)"
            d="M 5,0 H 60 V 46 L 55,52 H 0 V 5 Z M 44,14 V 38 H 0 Z"
          />
        </svg>
      </span>

      <span style={{ display: 'flex', flexDirection: 'column', gap: 2, lineHeight: 1 }}>
        <span
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontWeight: 800,
            fontSize: s.brand,
            letterSpacing: '-0.01em',
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
              opacity: 0.7,
            }}
          >
            Anticheat Scanner
          </span>
        )}
      </span>
    </div>
  )
}
