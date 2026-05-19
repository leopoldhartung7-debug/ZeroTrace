/* ZeroTrace brand logo — crosshair mark + wordmark. */

const SIZES = {
  sm: { box: 30, brand: '1.05rem', sub: '0.55rem', gap: 10 },
  md: { box: 40, brand: '1.5rem', sub: '0.62rem', gap: 14 },
  lg: { box: 52, brand: '2.4rem', sub: '0.7rem', gap: 20 },
}

export default function Logo({ size = 'md', sub = false }) {
  const s = SIZES[size] || SIZES.md
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: s.gap }}>
      <span style={{ width: s.box, height: s.box, flexShrink: 0, display: 'block' }}>
        <svg viewBox="0 0 52 52" fill="none" width="100%" height="100%">
          <circle cx="26" cy="26" r="22" stroke="#0d9488" strokeWidth="1.5" opacity="0.5" />
          <circle cx="26" cy="26" r="5" stroke="#2dd4bf" strokeWidth="1.5" />
          <circle cx="26" cy="26" r="1.5" fill="#2dd4bf" />
          <line x1="26" y1="4" x2="26" y2="18" stroke="#2dd4bf" strokeWidth="1.8" strokeLinecap="round" />
          <line x1="26" y1="34" x2="26" y2="48" stroke="#2dd4bf" strokeWidth="1.8" strokeLinecap="round" />
          <line x1="4" y1="26" x2="18" y2="26" stroke="#2dd4bf" strokeWidth="1.8" strokeLinecap="round" />
          <line x1="34" y1="26" x2="48" y2="26" stroke="#2dd4bf" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      </span>
      <span style={{ display: 'flex', flexDirection: 'column', gap: 2, lineHeight: 1 }}>
        <span
          style={{
            fontFamily: "'Oxanium', sans-serif",
            fontWeight: 800,
            fontSize: s.brand,
            letterSpacing: '0.02em',
          }}
        >
          <span style={{ color: '#2dd4bf' }}>Zero</span>
          <span style={{ color: '#b0b0c0' }}>Trace</span>
        </span>
        {sub && (
          <span
            style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontWeight: 600,
              fontSize: s.sub,
              letterSpacing: '0.25em',
              color: '#2a6b65',
              textTransform: 'uppercase',
            }}
          >
            Anticheat Scanner
          </span>
        )}
      </span>
    </div>
  )
}
