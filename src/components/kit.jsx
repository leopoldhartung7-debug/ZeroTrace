import { useState } from 'react'
import { ChevronDown } from 'lucide-react'

export function PageHeader({ kicker, title, subtitle, actions, icon: Icon }) {
  return (
    <div className="mb-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          {kicker && <p className="caps-label mb-2">{kicker}</p>}
          <h1 className="txt flex items-center gap-3 text-[28px] font-bold tracking-[-0.03em] md:text-4xl">
            {Icon && (
              <span className="tile flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border shadow-[var(--elev-1)]">
                <Icon size={19} className="text-sky-300" />
              </span>
            )}
            {title}
          </h1>
          {subtitle && <p className="muted mt-2 text-sm">{subtitle}</p>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
      </div>
      <div className="accent-rule mt-5" />
    </div>
  )
}

export function Card({ className = '', children }) {
  return (
    <div className={`card-glass card-hover rounded-2xl ${className}`}>{children}</div>
  )
}

const SEV = {
  Critical: 'border-red-500/30 bg-red-500/10 text-red-400',
  High:     'border-orange-500/30 bg-orange-500/10 text-orange-400',
  Medium:   'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
  Low:      'border-sky-500/30 bg-sky-500/10 text-sky-400',
  Open:     'border-sky-500/30 bg-sky-500/10 text-sky-400',
  Resolved: 'border-green-500/30 bg-green-500/10 text-green-400',
  Closed:   'border-zinc-600/30 bg-zinc-600/10 muted',
}

export function Badge({ children, tone }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${SEV[tone] || 'bd txt'}`}>
      {children}
    </span>
  )
}

export function EmptyState({ icon: Icon, title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="tile mb-4 flex h-12 w-12 items-center justify-center rounded-xl border">
        <Icon size={20} className="muted" />
      </div>
      <p className="txt text-sm font-medium">{title}</p>
      {hint && <p className="muted mt-1 max-w-sm text-xs leading-relaxed">{hint}</p>}
    </div>
  )
}

export function StatTile({ icon: Icon, label, value, accent = 'muted', sub }) {
  return (
    <div className="card-glass card-hover rounded-2xl p-4">
      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <p className="caps-label mb-1">{label}</p>
          <p className="txt text-2xl font-semibold tracking-tight" style={{ overflowWrap: 'anywhere' }}>
            {value}
          </p>
          {sub && <p className="muted mt-0.5 text-xs">{sub}</p>}
        </div>
        <div className="tile ml-3 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border shadow-[var(--elev-1)]">
          <Icon size={17} className={accent} />
        </div>
      </div>
    </div>
  )
}

export function Accordion({ items }) {
  const [open, setOpen] = useState(0)
  return (
    <div className="divide-y divide-[var(--border)] overflow-hidden rounded-xl border bd">
      {items.map((it, i) => (
        <div key={i}>
          <button
            onClick={() => setOpen(open === i ? -1 : i)}
            className="hoverable flex w-full items-center justify-between px-4 py-3.5 text-left"
          >
            <span className="txt text-sm font-medium">{it.q}</span>
            <ChevronDown
              size={15}
              className={`muted shrink-0 transition-transform ${open === i ? 'rotate-180' : ''}`}
            />
          </button>
          {open === i && <p className="muted bd border-t px-4 py-3 text-sm leading-relaxed">{it.a}</p>}
        </div>
      ))}
    </div>
  )
}

export function ProgressBar({ value, max = 100, color }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--border)' }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, background: color || 'var(--accent)' }}
      />
    </div>
  )
}

export function Ring({ value, max = 100, color, size = 52, thickness = 4 }) {
  const pct = max > 0 ? Math.min(value / max, 1) : 0
  const r = (size - thickness) / 2
  const circ = 2 * Math.PI * r
  const dash = circ * pct
  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', display: 'block' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={thickness} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color || 'var(--accent)'} strokeWidth={thickness}
        strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
    </svg>
  )
}

export function Field({ label, hint, children, className = '' }) {
  return (
    <div className={className}>
      <label className="txt mb-1.5 block text-sm font-medium">{label}</label>
      {children}
      {hint && <p className="muted mt-1 text-xs">{hint}</p>}
    </div>
  )
}

export function Textarea(props) {
  return (
    <textarea
      {...props}
      className={`bd tile txt w-full rounded-lg border p-3 text-sm focus:outline-none focus:ring-1 focus:ring-sky-500/30 ${props.className || ''}`}
    />
  )
}

export function Input(props) {
  return (
    <input
      {...props}
      className={`bd tile txt w-full rounded-lg border px-3.5 py-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-sky-500/30 ${props.className || ''}`}
    />
  )
}
