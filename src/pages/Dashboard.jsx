import { useState } from 'react'
import {
  Pin, ScanLine, Eye, ShieldAlert, Users, Globe2,
  Megaphone, Info, CheckCircle2, AlertTriangle, XCircle, Bell, X, TrendingUp,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar, Legend,
} from 'recharts'
import { useStats, usePlatformStats, useT, useStore } from '../store.jsx'

/* ─── tone map for announcements ─────────────────────────────── */
const TONE_STYLES = {
  info:    { box: 'border-sky-500/40 bg-sky-500/10',     icon: 'text-sky-400',   Icon: Info },
  success: { box: 'border-green-600/40 bg-green-600/10', icon: 'text-green-500', Icon: CheckCircle2 },
  warning: { box: 'border-yellow-500/40 bg-yellow-500/10',icon: 'text-yellow-400',Icon: AlertTriangle },
  danger:  { box: 'border-red-600/40 bg-red-600/10',     icon: 'text-red-500',   Icon: XCircle },
}

/* ─── AnnouncementCard ────────────────────────────────────────── */
function AnnouncementCard() {
  const { state } = useStore()
  const a = state.announcement || {}
  if (!a.enabled || !a.text?.trim()) return null
  const tone = TONE_STYLES[a.tone] || TONE_STYLES.info
  const Icon = tone.Icon
  return (
    <div className={`rounded-2xl border p-5 ${tone.box}`}>
      <div className="flex items-start gap-3">
        <div className="tile flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border">
          <Megaphone size={16} className={tone.icon} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Icon size={13} className={tone.icon} />
            <p className="caps-label">Announcement</p>
          </div>
          <p className="txt mt-2 break-words text-sm leading-relaxed">{a.text}</p>
          {a.updatedAt > 0 && (
            <p className="muted mt-2 text-[11px]">Posted {new Date(a.updatedAt).toLocaleString()}</p>
          )}
        </div>
      </div>
    </div>
  )
}

/* ─── WatchlistCard ───────────────────────────────────────────── */
function WatchlistCard() {
  const { state, dispatch } = useStore()
  const uid = state.session?.userId || null
  const mine = (state.watchlist || []).filter((w) => w.ownerId === uid)
  if (mine.length === 0) return null
  return (
    <div className="panel rounded-2xl border p-5">
      <div className="mb-4 flex items-center justify-between">
        <p className="caps-label flex items-center gap-2"><Bell size={12} /> Watched players</p>
        <span className="tile rounded-md border px-2 py-0.5 text-xs font-semibold" style={{ color: 'var(--muted)' }}>{mine.length}</span>
      </div>
      <div className="space-y-2">
        {mine.map((w) => {
          const lastPin = (state.pins || [])
            .filter((p) => p.discordId === w.discordId)
            .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))[0]
          return (
            <div key={w.id} className="bd tile flex items-center justify-between gap-3 rounded-xl border px-4 py-2.5 text-sm">
              <span className="min-w-0">
                <span className="txt font-mono text-xs">{w.discordId}</span>
                {w.note && <span className="muted ml-2 truncate text-xs">{w.note}</span>}
              </span>
              <span className="flex shrink-0 items-center gap-3">
                {lastPin && <span className="muted text-[11px]">{lastPin.result || lastPin.status}</span>}
                <button onClick={() => dispatch({ type: 'remove-watchlist', id: w.id })} className="muted transition-colors hover:text-red-500">
                  <X size={14} />
                </button>
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ─── Metric tile — pure number, no icon box ─────────────────── */
const NUM_COLOR = { neutral: 'var(--text)', red: '#f87171', yellow: '#facc15', blue: '#38bdf8' }

function MetricTile({ label, value, accent = 'neutral', icon: Icon }) {
  const color = NUM_COLOR[accent]
  return (
    <div className="tile rounded-2xl border p-6 text-center transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[var(--elev-2)]">
      {Icon && (
        <div className="mb-3 flex justify-center">
          <div className="rounded-xl p-2" style={{ background: color + '18' }}>
            <Icon size={16} style={{ color }} />
          </div>
        </div>
      )}
      <p className="text-3xl font-black tracking-tight sm:text-4xl" style={{ color }}>{value}</p>
      <div className="mx-auto mt-2 h-px w-10 rounded-full" style={{ background: color + '60' }} />
      <p className="caps-label mt-2">{label}</p>
    </div>
  )
}

/* ─── Rate pill (horizontal detection strip) ─────────────────── */
function RatePill({ label, value, color }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border px-3 py-1.5"
      style={{ borderColor: color + '50', background: color + '18' }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      <span className="text-sm font-bold tabular-nums" style={{ color }}>{value}%</span>
      <span className="muted text-xs">{label}</span>
    </div>
  )
}

/* ─── Rate bar (in left panel) ───────────────────────────────── */
function RateBar({ label, value, color }) {
  return (
    <div className="mb-4">
      <div className="mb-1.5 flex items-center justify-between text-sm">
        <span className="txt">{label}</span>
        <span className="font-bold tabular-nums" style={{ color }}>{value}%</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--border)' }}>
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  )
}

/* ─── Chart tooltip ──────────────────────────────────────────── */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="panel rounded-xl border px-3 py-2 text-xs shadow-xl">
      <p className="txt mb-1.5 font-semibold">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="muted flex items-center gap-1.5">
          <span style={{ color: p.color }}>●</span> {p.name}: <span className="txt font-medium">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

function fmtNum(n) { return typeof n === 'number' ? n.toLocaleString() : n }

const SUB_TABS = ['Overview', 'Trends', 'By Game', 'Activity']

/* ─── Dashboard ──────────────────────────────────────────────── */
export default function Dashboard() {
  const t = useT()
  const { state } = useStore()
  const myStats = useStats()
  const platformStats = usePlatformStats()
  const [topTab, setTopTab] = useState('My Statistics')
  const [subTab, setSubTab] = useState('Overview')

  const platform = topTab === 'Platform'
  const stats = platform ? platformStats : myStats

  const cards = platform
    ? [
        { icon: Users,       label: 'Active Users',  value: fmtNum(platformStats.activeUsers) },
        { icon: ScanLine,    label: 'Scans Today',   value: fmtNum(platformStats.scansToday) },
        { icon: Eye,         label: 'Detections',    value: fmtNum(platformStats.detections),   accent: 'red' },
        { icon: Globe2,      label: 'Games Covered', value: fmtNum(platformStats.gamesCovered), accent: 'blue' },
      ]
    : [
        { icon: Pin,         label: 'Total Pins',    value: fmtNum(myStats.totalPins) },
        { icon: ScanLine,    label: 'Total Scans',   value: fmtNum(myStats.totalScans) },
        { icon: Eye,         label: 'Detections',    value: fmtNum(myStats.detections),   accent: 'red' },
        { icon: ShieldAlert, label: 'Unique Cheats', value: fmtNum(myStats.uniqueCheats), accent: 'yellow' },
      ]

  const sessionUser = state.session?.userId
    ? (state.users || []).find((u) => u.id === state.session.userId) : null
  const displayName = sessionUser ? sessionUser.username : state.role === 'admin' ? 'Admin' : 'Analyst'
  const welcomeBack = (state.settings?.lang === 'de' ? 'Willkommen zurück, ' : 'Welcome back, ') + displayName + '.'

  return (
    <div className="w-full min-w-0 space-y-5">

      {/* ── Header ──────────────────────────────────────────── */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="caps-label flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-500" />
            {t('dash.kicker')}
          </p>
          <h1 className="txt mt-2 break-words text-3xl font-black tracking-tight sm:text-4xl">
            {welcomeBack}
          </h1>
        </div>
        <div className="tile flex items-center rounded-xl border p-1">
          {['My Statistics', 'Platform'].map((tab) => (
            <button key={tab} onClick={() => setTopTab(tab)}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition-all duration-150 ${
                topTab === tab ? 'bg-sky-500/15 text-sky-300' : 'muted hover:text-[var(--text)]'
              }`}>
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* ── Metric tiles ────────────────────────────────────── */}
      <div className="zt-stagger grid grid-cols-2 gap-3 lg:grid-cols-4">
        {cards.map((c) => <MetricTile key={c.label} {...c} />)}
      </div>

      {/* ── Detection quick-strip ───────────────────────────── */}
      <div className="panel flex flex-wrap items-center gap-3 rounded-2xl border px-5 py-3.5">
        <TrendingUp size={14} className="shrink-0 text-sky-500" />
        <span className="caps-label mr-1">Detection rates</span>
        <RatePill label="Cheating"   value={stats.rates.cheating}   color="#f87171" />
        <RatePill label="Suspicious" value={stats.rates.suspicious} color="#facc15" />
        <RatePill label="Legit"      value={stats.rates.legit}      color="#4ade80" />
        <span className="muted ml-auto hidden text-xs sm:block">{fmtNum(stats.totalScans)} total scans</span>
      </div>

      {/* ── Analytics — 2-col split ──────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-3">

        {/* Left: distribution + rate bars */}
        <div className="panel flex flex-col gap-6 rounded-2xl border p-5">
          <div>
            <p className="caps-label mb-4">Results distribution</p>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.distribution.length ? stats.distribution : [{ name: 'No data', value: 1, color: '#3f3f46' }]}
                    dataKey="value" innerRadius={50} outerRadius={76}
                    startAngle={90} endAngle={-270} stroke="none"
                  >
                    {(stats.distribution.length ? stats.distribution : [{ color: '#3f3f46' }]).map((e, i) => (
                      <Cell key={i} fill={e.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 flex flex-wrap justify-center gap-3 text-xs">
              {stats.distribution.map((d) => (
                <span key={d.name} className="muted flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: d.color }} /> {d.name}
                </span>
              ))}
            </div>
          </div>

          <div>
            <p className="caps-label mb-4">Detection rates</p>
            <RateBar label="Cheating"   value={stats.rates.cheating}   color="#dc2626" />
            <RateBar label="Suspicious" value={stats.rates.suspicious} color="#eab308" />
            <RateBar label="Legit"      value={stats.rates.legit}      color="#22c55e" />
          </div>
        </div>

        {/* Right: tabbed chart panel (2/3 width) */}
        <div className="panel overflow-hidden rounded-2xl border lg:col-span-2">
          <div className="bd flex flex-wrap items-center gap-1 border-b px-5 py-3">
            {SUB_TABS.map((tab) => (
              <button key={tab} onClick={() => setSubTab(tab)}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-all duration-150 ${
                  subTab === tab ? 'bg-sky-500/15 text-sky-300' : 'muted hover:text-[var(--text)]'
                }`}>
                {tab}
              </button>
            ))}
          </div>

          <div className="p-5 md:p-7">

            {subTab === 'Overview' && (
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={stats.trend}>
                    <defs>
                      <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#848eb0" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#848eb0" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gD" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#dc2626" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis dataKey="date" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                    <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                    <Tooltip content={<ChartTooltip />} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Area type="monotone" dataKey="scans"      stroke="#848eb0" fill="url(#gS)" name="Scans" />
                    <Area type="monotone" dataKey="detections" stroke="#dc2626" fill="url(#gD)" name="Detections" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}

            {subTab === 'Trends' && (
              <>
                <p className="caps-label mb-5">Scans &amp; Detections — last 14 days</p>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={stats.trend}>
                      <defs>
                        <linearGradient id="gS2" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="#848eb0" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#848eb0" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gD2" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="#dc2626" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                      <XAxis dataKey="date" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                      <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Area type="monotone" dataKey="scans"      stroke="#848eb0" fill="url(#gS2)" name="Scans" />
                      <Area type="monotone" dataKey="detections" stroke="#dc2626" fill="url(#gD2)" name="Detections" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}

            {subTab === 'By Game' && (
              <>
                <p className="caps-label mb-5">Detections by Game</p>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={stats.byGame}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                      <XAxis dataKey="game" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                      <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                      <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Bar dataKey="detections" fill="#dc2626" name="Detections" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="scans"      fill="#848eb0" name="Scans"      radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}

            {subTab === 'Activity' && (
              <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
                <div>
                  <p className="caps-label mb-4">By Hour of Day</p>
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={(() => {
                        const counts = Array.from({ length: 24 }, (_, h) => ({ hour: String(h).padStart(2, '0') + ':00', count: 0 }))
                        ;(state.scans || []).forEach((s) => {
                          const d = new Date(s.importedAt || s.createdAt || s.date)
                          if (!isNaN(d)) counts[d.getHours()].count += 1
                        })
                        return counts
                      })()}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                        <XAxis dataKey="hour" tick={{ fill: 'var(--muted)', fontSize: 9 }} stroke="var(--border)" interval={3} />
                        <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                        <Bar dataKey="count" fill="#848eb0" name="Scans" radius={[3, 3, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div>
                  <p className="caps-label mb-4">By Day of Week</p>
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={(() => {
                        const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                        const counts = days.map((d) => ({ day: d, count: 0 }))
                        ;(state.scans || []).forEach((s) => {
                          const d = new Date(s.importedAt || s.createdAt || s.date)
                          if (!isNaN(d)) { const dow = (d.getDay() + 6) % 7; counts[dow].count += 1 }
                        })
                        return counts
                      })()}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                        <XAxis dataKey="day" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                        <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                        <Bar dataKey="count" fill="#22c55e" name="Scans" radius={[3, 3, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            )}

          </div>
        </div>
      </div>

      <AnnouncementCard />
      <WatchlistCard />
    </div>
  )
}
