/* ZeroTrace brand logo — original ZT monogram (extracted 1:1) + wordmark */
import ztLogo from '../assets/zt-logo.png'

const SIZES = {
  sm: { box: 30, brand: '1.05rem', sub: '0.52rem', gap: 10 },
  md: { box: 40, brand: '1.45rem', sub: '0.58rem', gap: 13 },
  lg: { box: 54, brand: '2.2rem',  sub: '0.68rem', gap: 18 },
}

const ASPECT = 341 / 263 // intrinsic logo aspect ratio (w/h)

export default function Logo({ size = 'md', sub = false }) {
  const s = SIZES[size] || SIZES.md
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: s.gap }}>
      <img
        src={ztLogo}
        alt="ZeroTrace"
        style={{ height: s.box, width: s.box * ASPECT, flexShrink: 0, display: 'block', objectFit: 'contain' }}
      />

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
