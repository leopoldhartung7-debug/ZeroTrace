import { useEffect, useRef, useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutGrid, Pin, FileText, LifeBuoy, BookText,
  Wifi, Bell, Globe, Moon, Sun, ChevronRight, ChevronsUpDown, Trash2, Check,
} from 'lucide-react'
import { useStore, useT } from '../store.jsx'

function SectionLabel({ children }) {
  return <p className="caps-label mb-2 mt-6 px-3">{children}</p>
}

function ExpandableItem({ icon: Icon, label }) {
  return (
    <button className="hoverable flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium">
      <span className="flex items-center gap-3">
        <Icon size={18} className="muted" />
        <span className="txt">{label}</span>
      </span>
      <ChevronRight size={16} className="muted" />
    </button>
  )
}

function Popover({ open, onClose, children, className = '' }) {
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return
    const h = (e) => ref.current && !ref.current.contains(e.target) && onClose()
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [open, onClose])
  if (!open) return null
  return (
    <div ref={ref} className={`panel absolute z-30 rounded-xl border shadow-2xl ${className}`}>
      {children}
    </div>
  )
}

export default function Sidebar() {
  const { state, dispatch } = useStore()
  const t = useT()
  const [openPanel, setOpenPanel] = useState(null)
  const dark = state.settings.theme === 'dark'
  const unread = state.notifications.filter((n) => !n.read).length

  const services = [
    { to: '/dashboard', label: t('nav.dashboard'), icon: LayoutGrid },
    { to: '/pins', label: t('nav.pins'), icon: Pin },
    { to: '/strings', label: t('nav.strings'), icon: FileText },
  ]

  return (
    <aside className="panel flex w-[280px] shrink-0 flex-col border-r">
      <div className="flex items-center gap-3 px-6 py-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600 font-mono text-sm font-bold text-white">
          {'(*>'}
        </div>
        <div>
          <p className="txt text-[15px] font-semibold leading-tight">Ocean</p>
          <p className="muted text-xs tracking-wide">anticheat.ac</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3">
        <SectionLabel>{t('cat.services')}</SectionLabel>
        {services.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium ${
                isActive
                  ? 'bg-blue-600/15 text-blue-500 shadow-[inset_0_0_0_1px_rgba(59,130,246,0.18)]'
                  : 'hoverable'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <Icon size={18} className={isActive ? '' : 'muted'} />
                <span className={isActive ? '' : 'txt'}>{label}</span>
              </>
            )}
          </NavLink>
        ))}

        <SectionLabel>{t('cat.support')}</SectionLabel>
        <ExpandableItem icon={LifeBuoy} label={t('nav.support')} />

        <SectionLabel>{t('cat.others')}</SectionLabel>
        <ExpandableItem icon={BookText} label={t('nav.resources')} />
      </nav>

      <div className="bd border-t px-4 py-4">
        <div className="relative mb-4 flex items-center gap-5 px-2">
          <span title="Online">
            <Wifi size={16} className="text-green-500" />
          </span>

          <button
            className="muted hover:txt relative"
            onClick={() => setOpenPanel(openPanel === 'notif' ? null : 'notif')}
            title="Notifications"
          >
            <Bell size={16} />
            {unread > 0 && (
              <span className="absolute -right-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
                {unread}
              </span>
            )}
          </button>

          <button
            className="muted hover:txt"
            onClick={() => setOpenPanel(openPanel === 'lang' ? null : 'lang')}
            title="Language"
          >
            <Globe size={16} />
          </button>

          <button
            className="muted hover:txt"
            onClick={() =>
              dispatch({ type: 'set-setting', key: 'theme', value: dark ? 'light' : 'dark' })
            }
            title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {dark ? <Moon size={16} /> : <Sun size={16} />}
          </button>

          <Popover
            open={openPanel === 'notif'}
            onClose={() => setOpenPanel(null)}
            className="bottom-10 left-0 w-72"
          >
            <div className="bd flex items-center justify-between border-b px-4 py-3">
              <p className="txt text-sm font-semibold">Notifications</p>
              <button
                className="muted hover:txt text-xs"
                onClick={() => dispatch({ type: 'mark-notifications-read' })}
              >
                Mark all read
              </button>
            </div>
            <div className="max-h-72 overflow-y-auto">
              {state.notifications.length === 0 && (
                <p className="muted px-4 py-6 text-center text-sm">No notifications</p>
              )}
              {state.notifications.map((n) => (
                <div key={n.id} className="bd border-b px-4 py-3 last:border-0">
                  <div className="flex items-center gap-2">
                    {!n.read && <span className="h-2 w-2 rounded-full bg-blue-500" />}
                    <p className="txt text-sm font-medium">{n.title}</p>
                  </div>
                  <p className="muted mt-0.5 text-xs">{n.body}</p>
                </div>
              ))}
            </div>
            {state.notifications.length > 0 && (
              <button
                className="muted hover:txt bd flex w-full items-center justify-center gap-2 border-t py-2.5 text-xs"
                onClick={() => dispatch({ type: 'clear-notifications' })}
              >
                <Trash2 size={13} /> Clear all
              </button>
            )}
          </Popover>

          <Popover
            open={openPanel === 'lang'}
            onClose={() => setOpenPanel(null)}
            className="bottom-10 left-0 w-40 py-1"
          >
            {[
              { code: 'en', label: 'English' },
              { code: 'de', label: 'Deutsch' },
            ].map((l) => (
              <button
                key={l.code}
                onClick={() => {
                  dispatch({ type: 'set-setting', key: 'lang', value: l.code })
                  setOpenPanel(null)
                }}
                className="hoverable txt flex w-full items-center justify-between px-3 py-2 text-sm"
              >
                {l.label}
                {state.settings.lang === l.code && <Check size={14} className="text-blue-500" />}
              </button>
            ))}
          </Popover>
        </div>

        <button className="hoverable flex w-full items-center gap-3 rounded-lg px-2 py-2">
          <div className="tile txt flex h-9 w-9 items-center justify-center rounded-lg border text-sm font-semibold">
            H
          </div>
          <div className="flex-1 text-left">
            <p className="txt text-sm font-medium leading-tight">Ham</p>
            <p className="muted text-xs">ham@anticheat.ac</p>
          </div>
          <ChevronsUpDown size={16} className="muted" />
        </button>
      </div>
    </aside>
  )
}
