import { useState } from 'react'
import { ChevronDown } from 'lucide-react'

export function PageHeader({ kicker, title, subtitle, actions, icon: Icon }) {
  return (
    <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="caps-label">{kicker}</p>
        <h1 className="txt mt-2 flex items-center gap-3 text-3xl font-bold tracking-tight md:text-4xl">
          {Icon && (
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500 to-sky-700 text-white shadow-lg shadow-sky-600/20">
              <Icon size={20} />
            </span>
          )}
          {title}
        </h1>
        {subtitle && <p className="muted mt-2 text-sm">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 gap-3">{actions}</div>}
    </div>
  )
}

export function Card({ className = '', children }) {
  return <div className={`panel rounded-2xl border ${className}`}>{children}</div>
}

const SEV = {
  Critical: 'border-red-600/40 bg-red-600/15 text-red-500',
  High: 'border-orange-500/40 bg-orange-500/15 text-orange-400',
  Medium: 'border-yellow-500/40 bg-yellow-500/15 text-yellow-400',
  Low: 'border-sky-500/40 bg-sky-500/15 text-sky-400',
  Open: 'border-sky-500/40 bg-sky-500/15 text-sky-400',
  Resolved: 'border-green-600/40 bg-green-600/15 text-green-500',
  Closed: 'border-neutral-600/40 bg-neutral-600/15 muted',
}

export function Badge({ children, tone }) {
  return (
    <span
      className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${
        SEV[tone] || 'bd txt'
      }`}
    >
      {children}
    </span>
  )
}

export function EmptyState({ icon: Icon, title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="tile mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border">
        <Icon size={24} className="muted" />
      </div>
      <p className="txt text-sm font-medium">{title}</p>
      {hint && <p className="muted mt-1 max-w-sm text-xs">{hint}</p>}
    </div>
  )
}

export function StatTile({ icon: Icon, label, value, accent = 'muted', sub }) {
  return (
    <div className="panel group overflow-hidden rounded-xl border p-3 transition-transform hover:-translate-y-0.5 sm:p-4 md:p-5">
      <div className="flex items-start gap-2 sm:gap-3">
        <div className="tile flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border sm:h-9 sm:w-9 md:h-10 md:w-10">
          <Icon size={16} className={accent} />
        </div>
        <div className="min-w-0 flex-1">
          <p
            className="caps-label whitespace-normal leading-snug"
            style={{
              overflowWrap: 'anywhere',
              wordBreak: 'break-word',
              hyphens: 'auto',
              letterSpacing: '0.06em',
            }}
          >
            {label}
          </p>
          <p
            className="txt mt-1 text-lg font-bold leading-tight sm:text-xl md:text-2xl"
            style={{ overflowWrap: 'anywhere' }}
          >
            {value}
          </p>
          {sub && (
            <p className="muted mt-0.5 text-xs" style={{ overflowWrap: 'anywhere' }}>
              {sub}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

export function Accordion({ items }) {
  const [open, setOpen] = useState(0)
  return (
    <div className="space-y-2">
      {items.map((it, i) => (
        <div key={i} className="tile overflow-hidden rounded-lg border">
          <button
            onClick={() => setOpen(open === i ? -1 : i)}
            className="hoverable flex w-full items-center justify-between px-4 py-3 text-left"
          >
            <span className="txt text-sm font-medium">{it.q}</span>
            <ChevronDown
              size={16}
              className={`muted transition-transform ${open === i ? 'rotate-180' : ''}`}
            />
          </button>
          {open === i && <p className="muted bd border-t px-4 py-3 text-sm">{it.a}</p>}
        </div>
      ))}
    </div>
  )
}

export function Field({ label, children }) {
  return (
    <div>
      <label className="txt mb-1.5 block text-sm font-medium">{label}</label>
      {children}
    </div>
  )
}

export function Textarea(props) {
  return (
    <textarea
      {...props}
      className={`bd tile txt w-full rounded-lg border p-3 text-sm focus:outline-none focus:ring-1 focus:ring-sky-500/40 ${
        props.className || ''
      }`}
    />
  )
}

export function Input(props) {
  return (
    <input
      {...props}
      className={`bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-sky-500/40 ${
        props.className || ''
      }`}
    />
  )
}
