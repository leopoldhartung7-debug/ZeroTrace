/* ZeroTrace brand logo — ZT monogram mark + wordmark */

const SIZES = {
  sm: { box: 32, brand: '1.05rem', sub: '0.52rem', gap: 10 },
  md: { box: 44, brand: '1.45rem', sub: '0.58rem', gap: 13 },
  lg: { box: 60, brand: '2.2rem',  sub: '0.68rem', gap: 18 },
}

/*
  ZT monogram — exact shape from the ZeroTrace logo:

  Outer boundary: parallelogram-ish with italic left edge
    - Top-left: pointed at (12, 0) — the logo leans forward
    - Top edge: horizontal from (12,0) to (58,0)
    - Right edge: vertical from (58,0) to (58,42)
    - Bottom-right: chamfer (58,42) → (48,52)
    - Bottom edge: horizontal from (48,52) to (0,52)
    - Left edge: SLANTED from (0,52) diagonally back to (12,0)
      → this italic left edge is the key visual detail

  Z diagonal cut (dark hole):
    Triangle (44,13) → (44,39) → (4,39)
    - Creates Z diagonal going upper-right to lower-left
    - Upper-left of hole = white (Z body connecting top bar to left)
    - Inside hole = dark background visible = Z diagonal slash

  T stem: the right portion x=44-58 stays solid white full height
  Top bar: y=0-13 full width (shared Z crossbar + T crossbar)
  Bottom bar: y=39-52 full width (Z base)
*/
export default function Logo({ size = 'md', sub = false }) {
  const s = SIZES[size] || SIZES.md
  const h = s.box * (52 / 58)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: s.gap }}>
      <span style={{ width: s.box, height: h, flexShrink: 0, display: 'block' }}>
        <svg viewBox="0 0 58 52" fill="none" width="100%" height="100%">
          <defs>
            <linearGradient id="zt-grad" x1="12" y1="0" x2="46" y2="52" gradientUnits="userSpaceOnUse">
              <stop offset="0%"   stopColor="#ffffff" />
              <stop offset="40%"  stopColor="#ececf4" />
              <stop offset="100%" stopColor="#b4b4c8" />
            </linearGradient>
          </defs>
          <path
            fillRule="evenodd"
            fill="url(#zt-grad)"
            d="M 12,0 H 58 V 42 L 48,52 H 0 Z M 44,13 V 39 H 4 Z"
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
