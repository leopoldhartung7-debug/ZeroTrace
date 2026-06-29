/* Tiny EN | DE pill toggle for the public marketing pages.
   Reads/writes the same state.settings.lang as the Sidebar's globe
   popover, so the choice flows into the rest of the app on login. */
import { useStore } from '../store.jsx'

export default function LanguageToggle({ className = '', size = 'md' }) {
  const { state, dispatch } = useStore()
  const lang = state.settings?.lang === 'de' ? 'de' : 'en'
  const set = (value) => {
    if (value !== lang) dispatch({ type: 'set-setting', key: 'lang', value })
    // Mark as chosen so the auto-detect won't run again.
    try { localStorage.setItem('zt-lang-chosen', '1') } catch {}
  }

  const compact = size === 'sm'
  const padX = compact ? '8px' : '10px'
  const padY = compact ? '3px' : '4px'
  const fontSize = compact ? 11 : 12

  const cell = (code, label) => {
    const active = lang === code
    return (
      <button
        type="button"
        onClick={() => set(code)}
        aria-pressed={active}
        aria-label={`Switch to ${label}`}
        data-no-i18n
        style={{
          padding: `${padY} ${padX}`,
          borderRadius: 999,
          fontSize,
          fontWeight: 700,
          letterSpacing: '0.06em',
          color: active ? '#ffffff' : 'rgba(255,255,255,0.55)',
          background: active ? 'rgba(139,110,245,0.30)' : 'transparent',
          boxShadow: active ? '0 0 14px rgba(139,110,245,0.35)' : 'none',
          transition: 'all 0.18s ease',
          cursor: 'pointer',
        }}
      >
        {code.toUpperCase()}
      </button>
    )
  }

  return (
    <div
      className={className}
      data-no-i18n
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 2,
        padding: '2px',
        borderRadius: 999,
        border: '1px solid rgba(255,255,255,0.12)',
        background: 'rgba(255,255,255,0.04)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
    >
      {cell('en', 'English')}
      {cell('de', 'Deutsch')}
    </div>
  )
}
