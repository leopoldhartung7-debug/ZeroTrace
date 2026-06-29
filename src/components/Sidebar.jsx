import { useEffect, useRef, useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import Logo from './Logo.jsx'
import {
  LayoutGrid, Pin, FileText, Database, Wrench, History,
  LifeBuoy, BookOpen, Settings, Wifi, Bell, Globe, Moon, Sun,
  ChevronsUpDown, Trash2, Check, Command, Trophy, ShoppingCart,
  Download, Scale, ChevronDown, ChevronRight, LogOut, KeyRound, GitCompareArrows,
  ShieldCheck, Mail, Ban, Activity, BarChart3, Megaphone, Wrench as WrenchIcon, Coins, Ticket, ListChecks,
} from 'lucide-react'
import { useStore, useT } from '../store.jsx'

function SectionLabel({ children }) {
  return <p className="caps-label mb-2 mt-5 px-3">{children}</p>
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
    <div
      ref={ref}
      className={`absolute z-50 overflow-hidden rounded-xl border shadow-[0_30px_80px_-20px_rgba(0,0,0,0.85)] ${className}`}
      style={{
        background: 'var(--panel-2)',
        borderColor: 'var(--border)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
    >
      {children}
    </div>
  )
}

export default function Sidebar() {
  const { state, dispatch } = useStore()
  const t = useT()
  const navTo = useNavigate()
  const [panel, setPanel] = useState(null)
  const [resOpen, setResOpen] = useState(false)
  const dark = state.settings.theme === 'dark'
  const visibleNotifications = (state.notifications || []).filter((n) => {
    if (n.ownerId == null) return true
    if (state.role === 'admin') return n.ownerId === 'admin'
    return n.ownerId === state.session?.userId
  })
  const unread = visibleNotifications.filter((n) => !n.read).length

  const isAdmin = state.role === 'admin'
  const groups = [
    {
      label: t('cat.services'),
      items: [
        { to: '/dashboard', label: t('nav.dashboard'), icon: LayoutGrid },
        { to: '/pins', label: t('nav.pins'), icon: Pin },
        { to: '/strings', label: t('nav.strings'), icon: FileText },
        { to: '/tools', label: t('nav.tools'), icon: Wrench },
        { to: '/scoreboard', label: t('nav.scoreboard'), icon: Trophy },
        { to: '/compare', label: t('nav.compare'), icon: GitCompareArrows },
        { to: '/casino', label: t('nav.casino'), icon: Coins },
      ],
    },
    {
      label: t('cat.activity'),
      items: [{ to: '/history', label: t('nav.history'), icon: History }],
    },
    {
      label: t('cat.support'),
      items: [{ to: '/support', label: t('nav.support'), icon: LifeBuoy }],
    },
    ...(isAdmin
      ? [
          {
            label: t('cat.admin'),
            items: [
              { to: '/database', label: t('nav.database'), icon: Database },
              { to: '/keys', label: t('nav.keys'), icon: KeyRound },
              { to: '/admin/analytics', label: t('nav.analytics'), icon: BarChart3 },
              { to: '/admin/blacklists', label: t('nav.blacklists'), icon: Ban },
              { to: '/admin/webhooks', label: t('nav.webhookHealth'), icon: Activity },
              { to: '/admin/announcement', label: t('nav.announcement'), icon: Megaphone },
              { to: '/admin/discounts', label: t('nav.discounts'), icon: Ticket },
              { to: '/admin/maintenance', label: t('nav.maintenance'), icon: WrenchIcon },
              { to: '/admin/audit', label: t('nav.audit'), icon: History },
              { to: '/admin/proposals', label: t('nav.proposals'), icon: ListChecks },
              { to: '/admin/stats', label: 'DB Statistiken', icon: BarChart3 },
              { to: '/admin/activity', label: 'Aktivitäts-Log', icon: Activity },
            ],
          },
        ]
      : []),
    {
      label: t('cat.others'),
      items: [
        {
          label: t('nav.resources'),
          icon: BookOpen,
          children: [
            { to: '/resources/leaderboard', label: 'Leaderboard', icon: Trophy },
            { to: '/resources/documentation', label: 'Documentation', icon: BookOpen },
            { to: '/resources/pricing', label: 'Pricing', icon: ShoppingCart },
            { to: '/resources/download', label: 'Download', icon: Download },
            { to: '/resources/terms', label: 'Terms of Service', icon: FileText },
            { to: '/resources/privacy', label: 'Privacy Policy', icon: FileText },
            { to: '/resources/legal', label: 'Legal', icon: Scale },
            { to: '/resources/changelogs', label: 'Changelogs', icon: History },
          ],
        },
        { to: '/settings', label: t('nav.settings'), icon: Settings },
      ],
    },
  ]

  return (
    <aside className="panel bd relative flex h-full w-[256px] shrink-0 flex-col overflow-hidden rounded-2xl border" style={{ boxShadow: 'var(--elev-2), inset 0 0 40px rgba(139,110,245,0.03)' }}>
      <NavLink to="/" className="bd relative z-10 flex items-center gap-3 border-b px-6 py-5 transition-opacity hover:opacity-80" title="Back to home">
        <Logo size="sm" sub />
      </NavLink>

      <nav className="relative z-10 flex-1 overflow-y-auto px-3 pb-2">
        {groups.map((g) => (
          <div key={g.label}>
            <SectionLabel>{g.label}</SectionLabel>
            {g.items.map((item) => {
              const { to, label, icon: Icon, children } = item
              if (children) {
                return (
                  <div key={label} className="mb-1">
                    <button
                      onClick={() => setResOpen((o) => !o)}
                      className="hoverable flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium"
                    >
                      <Icon size={18} className="muted" />
                      <span className="txt flex-1 text-left">{label}</span>
                      {resOpen ? (
                        <ChevronDown size={16} className="muted" />
                      ) : (
                        <ChevronRight size={16} className="muted" />
                      )}
                    </button>
                    {resOpen && (
                      <div className="bd ml-5 mt-1 space-y-1 border-l pl-3">
                        {children.map((c) => (
                          <NavLink
                            key={c.to}
                            to={c.to}
                            className={({ isActive }) =>
                              `relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200 ${
                                isActive
                                  ? 'bg-sky-500/14 text-sky-100 before:absolute before:left-0 before:top-1/2 before:h-4 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-sky-400'
                                  : 'hoverable hover:translate-x-0.5'
                              }`
                            }
                          >
                            {({ isActive }) => (
                              <>
                                <c.icon size={16} className={isActive ? '' : 'text-sky-400/70'} />
                                <span className={isActive ? '' : 'txt'}>{c.label}</span>
                              </>
                            )}
                          </NavLink>
                        ))}
                      </div>
                    )}
                  </div>
                )
              }
              return (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `group relative mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${
                      isActive
                        ? 'bg-sky-500/14 text-sky-100 before:absolute before:left-0 before:top-1/2 before:h-5 before:w-[3px] before:-translate-y-1/2 before:rounded-r-full before:bg-sky-400'
                        : 'hoverable hover:translate-x-0.5'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon size={18} className={`shrink-0 transition-colors ${isActive ? 'text-sky-300' : 'muted group-hover:txt'}`} />
                      <span className={`truncate ${isActive ? '' : 'txt'}`}>{label}</span>
                    </>
                  )}
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      <div className="bd panel sticky bottom-0 shrink-0 border-t px-4 py-3">
        <button
          onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))}
          className="hoverable bd muted mb-3 flex w-full items-center justify-between rounded-lg border px-3 py-2 text-xs"
        >
          <span className="flex items-center gap-2">
            <Command size={13} /> Quick search
          </span>
          <kbd className="bd rounded border px-1.5 py-0.5">⌘K</kbd>
        </button>

        <div className="relative mb-3 flex items-center gap-2 px-1">
          <span title="Online" className="grid h-8 w-8 place-items-center rounded-lg">
            <Wifi size={15} className="text-green-500" />
          </span>
          <button
            className="hoverable muted hover:txt relative grid h-8 w-8 place-items-center rounded-lg"
            title="Notifications"
            onClick={() => setPanel(panel === 'n' ? null : 'n')}
          >
            <Bell size={15} />
            {unread > 0 && (
              <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
                {unread}
              </span>
            )}
          </button>
          <button
            className="hoverable muted hover:txt grid h-8 w-8 place-items-center rounded-lg"
            title="Language"
            onClick={() => setPanel(panel === 'l' ? null : 'l')}
          >
            <Globe size={15} />
          </button>
          <button
            className="hoverable muted hover:txt grid h-8 w-8 place-items-center rounded-lg"
            title="Theme"
            onClick={() => dispatch({ type: 'set-setting', key: 'theme', value: dark ? 'light' : 'dark' })}
          >
            {dark ? <Moon size={15} /> : <Sun size={15} />}
          </button>

          <Popover open={panel === 'n'} onClose={() => setPanel(null)} className="bottom-10 left-0 w-72">
            <div className="bd flex items-center justify-between border-b px-4 py-3">
              <p className="txt text-sm font-semibold">Notifications</p>
              <button className="muted hover:txt text-xs" onClick={() => dispatch({ type: 'mark-notifications-read', role: state.role, userId: state.session?.userId })}>
                Mark all read
              </button>
            </div>
            <div className="max-h-72 overflow-y-auto">
              {visibleNotifications.length === 0 && <p className="muted px-4 py-6 text-center text-sm">No notifications</p>}
              {visibleNotifications.map((n) => (
                <div key={n.id} className="bd border-b px-4 py-3 last:border-0">
                  <div className="flex items-center gap-2">
                    {!n.read && <span className="h-2 w-2 rounded-full bg-sky-500" />}
                    <p className="txt text-sm font-medium">{n.title}</p>
                  </div>
                  <p className="muted mt-0.5 text-xs">{n.body}</p>
                </div>
              ))}
            </div>
            {visibleNotifications.length > 0 && (
              <button
                className="muted hover:txt bd flex w-full items-center justify-center gap-2 border-t py-2.5 text-xs"
                onClick={() => dispatch({ type: 'clear-notifications' })}
              >
                <Trash2 size={13} /> Clear all
              </button>
            )}
          </Popover>

          <Popover open={panel === 'l'} onClose={() => setPanel(null)} className="bottom-10 left-0 w-40 py-1">
            {[
              { code: 'en', label: 'English' },
              { code: 'de', label: 'Deutsch' },
            ].map((l) => (
              <button
                key={l.code}
                onClick={() => {
                  dispatch({ type: 'set-setting', key: 'lang', value: l.code })
                  setPanel(null)
                }}
                className="hoverable txt flex w-full items-center justify-between px-3 py-2 text-sm"
              >
                {l.label}
                {state.settings.lang === l.code && <Check size={14} className="text-sky-500" />}
              </button>
            ))}
          </Popover>
        </div>

        <div className="relative">
          {(() => {
            const sessionUser = state.session?.userId
              ? (state.users || []).find((u) => u.id === state.session.userId)
              : null
            const displayName = sessionUser
              ? sessionUser.username
              : state.role === 'admin' ? 'Admin' : 'Analyst'
            const displayEmail = sessionUser
              ? sessionUser.email
              : state.role === 'admin' ? 'admin@anticheat.ac' : 'analyst@anticheat.ac'
            const initial = (displayName || '?').trim().charAt(0).toUpperCase()
            return (
          <>
          <button
            onClick={() => setPanel(panel === 'user' ? null : 'user')}
            className="hoverable flex w-full items-center gap-3 rounded-lg px-2 py-2"
          >
            <div className="tile txt flex h-9 w-9 items-center justify-center rounded-lg border text-sm font-semibold">{initial}</div>
            <div className="min-w-0 flex-1 text-left">
              <p className="txt truncate text-sm font-medium leading-tight">{displayName}</p>
              <p className="muted truncate text-xs">{displayEmail}</p>
            </div>
            <ChevronsUpDown size={16} className="muted" />
          </button>

          <Popover
            open={panel === 'user'}
            onClose={() => setPanel(null)}
            className="bottom-full left-0 right-0 mb-2 py-1"
          >
            <div className="bd border-b px-4 py-3">
              <p className="txt truncate text-sm font-semibold">{displayName}</p>
              <p className="muted truncate text-xs">{displayEmail}</p>
            </div>
            <button
              onClick={() => {
                setPanel(null)
                navTo('/account')
              }}
              className="hoverable txt flex w-full items-center gap-3 px-4 py-2.5 text-sm"
            >
              <Settings size={16} className="muted" /> Settings
            </button>
            <button
              onClick={() => {
                dispatch({ type: 'logout' })
                navTo('/')
              }}
              className="hoverable flex w-full items-center gap-3 px-4 py-2.5 text-sm text-red-500"
            >
              <LogOut size={16} /> Logout
            </button>
          </Popover>
          </>
            )
          })()}
        </div>
      </div>
    </aside>
  )
}
