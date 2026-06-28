import { useCountUp } from '../hooks/useCountUp.js'

export function PageHeader({ eyebrow, title, action }) {
  return (
    <div className="mb-8 flex items-end justify-between gap-4 animate-fade-up">
      <div>
        <p className="caps-label mb-2">{eyebrow}</p>
        <h1 className="bg-gradient-to-br from-white via-white to-zinc-400 bg-clip-text text-3xl font-bold tracking-tight text-transparent">
          {title}
        </h1>
      </div>
      {action}
    </div>
  )
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="relative inline-flex gap-1 rounded-lg border border-ink-700 bg-ink-900 p-1">
      {tabs.map((tab) => {
        const value = typeof tab === 'string' ? tab : tab.value
        const label = typeof tab === 'string' ? tab : tab.label
        const isActive = value === active
        return (
          <button
            key={value}
            type="button"
            onClick={() => onChange(value)}
            className={`relative rounded-md px-4 py-1.5 text-sm font-medium transition-all duration-200 ${
              isActive
                ? 'bg-accent-soft text-accent shadow-glow'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {label}
          </button>
        )
      })}
    </div>
  )
}

const badgeStyles = {
  FINISHED: 'bg-success/15 text-success border-success/30',
  ONLINE: 'bg-success/15 text-success border-success/30',
  CLEAN: 'bg-success/15 text-success border-success/30',
  CHEATING: 'bg-danger/15 text-danger border-danger/30',
  SUSPICIOUS: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  PENDING: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  EXPIRED: 'bg-zinc-600/20 text-zinc-400 border-zinc-600/40',
  PRIVATE: 'bg-zinc-600/20 text-zinc-400 border-zinc-600/40',
  SHARED: 'bg-accent-soft text-accent border-accent/30',
  PUBLIC: 'bg-accent-soft text-accent border-accent/30',
}

const pulsingBadges = new Set(['PENDING', 'CHEATING'])

export function Badge({ children }) {
  const style = badgeStyles[children] || badgeStyles.EXPIRED
  const pulse = pulsingBadges.has(children)
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold tracking-wide transition-all duration-200 ${style}`}
    >
      {pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-75" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />
        </span>
      )}
      {children}
    </span>
  )
}

export function StatCard({ icon: Icon, label, value, delta }) {
  const animated = useCountUp(value)
  return (
    <div className="card card-interactive group flex items-center gap-4 p-5">
      <div className="grid h-11 w-11 shrink-0 place-items-center rounded-lg border border-ink-700 bg-ink-850 text-accent transition-all duration-300 group-hover:scale-110 group-hover:border-accent/50 group-hover:bg-accent-soft">
        <Icon size={20} strokeWidth={1.8} />
      </div>
      <div className="min-w-0">
        <p className="caps-label">{label}</p>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="stat-value text-2xl font-bold tabular-nums">
            {animated.toLocaleString()}
          </span>
          {delta && (
            <span className="text-xs font-semibold text-success transition-transform duration-200 group-hover:translate-x-0.5">
              {delta}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
