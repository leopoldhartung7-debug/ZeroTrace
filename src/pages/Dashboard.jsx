import { useState } from 'react'
import {
  Activity, Pin, ScanLine, Eye, ShieldAlert, Users, Globe2,
  Megaphone, Info, CheckCircle2, AlertTriangle, XCircle, Bell, X,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar, Legend,
} from 'recharts'
import Tabs from '../components/Tabs.jsx'
import { useStats, usePlatformStats, useT, useStore } from '../store.jsx'

const TONE_STYLES = {
  info: { box: 'border-sky-500/40 bg-sky-500/10', icon: 'text-sky-400', Icon: Info },
  success: { box: 'border-green-600/40 bg-green-600/10', icon: 'text-green-500', Icon: CheckCircle2 },
  warning: { box: 'border-yellow-500/40 bg-yellow-500/10', icon: 'text-yellow-400', Icon: AlertTriangle },
  danger: { box: 'border-red-600/40 bg-red-600/10', icon: 'text-red-500', Icon: XCircle },
}

function AnnouncementCard() {
  const { state } = useStore()
  const a = state.announcement || {}
  if (!a.enabled || !a.text?.trim()) return null
  const tone = TONE_STYLES[a.tone] || TONE_STYLES.info
  const Icon = tone.Icon
  return (
    <div className={`mt-6 rounded-2xl border p-5 ${tone.box}`}>
      <div className="flex items-start gap-3">
        <div className="tile flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border">
          <Megaphone size={18} className={tone.icon} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Icon size={14} className={tone.icon} />
            <p className="caps-label">Announcement</p>
          </div>
          <p className="txt mt-2 break-words text-sm leading-relaxed">{a.text}</p>
          {a.updatedAt > 0 && (
            <p className="muted mt-3 text-[11px]">
              Posted {new Date(a.updatedAt).toLocaleString()}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

function WatchlistCard() {
  const { state, dispatch } = useStore()
  const uid = state.session?.userId || null
  const mine = (state.watchlist || []).filter((w) => w.ownerId === uid)
  if (mine.length === 0) return null
  return (
    <div className="panel mt-6 rounded-2xl border p-5">
      <p className="caps-label mb-3 flex items-center gap-2"><Bell size={12} /> Watched players ({mine.length})</p>
      <div className="space-y-2">
        {mine.map((w) => {
          const lastPin = (state.pins || [])
            .filter((p) => p.discordId === w.discordId)
            .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))[0]
          return (
            <div key={w.id} className="bd flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
              <span className="min-w-0">
                <span className="txt font-mono text-xs">{w.discordId}</span>
                {w.note && <span className="muted ml-2 truncate">{w.note}</span>}
              </span>
              <span className="flex shrink-0 items-center gap-2">
                {lastPin && (
                  <span className="muted text-[11px]">last: {lastPin.result || lastPin.status}</span>
                )}
                <button
                  onClick={() => dispatch({ type: 'remove-watchlist', id: w.id })}
                  className="muted hover:text-red-500"
                  title="Remove"
                >
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

const accentMap = {
  neutral: 'muted',
  red: 'text-red-500',
  yellow: 'text-yellow-500',
  blue: 'text-sky-500',
}

function StatCard({ icon: Icon, label, value, accent = 'neutral' }) {
  return (
    <div className="card-glass card-hover overflow-hidden rounded-2xl p-3 sm:p-4 md:p-5">
      <div className="flex items-start gap-2 sm:gap-3">
        <div className="tile flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border shadow-[var(--elev-1)] sm:h-9 sm:w-9 md:h-10 md:w-10">
          <Icon size={16} className={accentMap[accent]} />
        </div>
        <div className="min-w-0 flex-1">
          <p
            className="caps-label leading-snug"
            style={{
              letterSpacing: '0.06em',
              overflowWrap: 'anywhere',
              wordBreak: 'break-word',
              hyphens: 'auto',
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
        </div>
      </div>
    </div>
  )
}

function RateBar({ label, value, color }) {
  return (
    <div className="mb-5">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-sm txt">{label}</span>
        <span className="text-sm font-semibold txt">{value}%</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--border)' }}>
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${value}%`, background: color }}
        />
      </div>
    </div>
  )
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="panel rounded-lg border px-3 py-2 text-xs shadow-xl">
      <p className="txt mb-1 font-medium">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="muted">
          <span style={{ color: p.color }}>●</span> {p.name}: <span className="txt">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

function fmtNum(n) {
  return typeof n === 'number' ? n.toLocaleString() : n
}

export default function Dashboard() {
  const t = useT()
  const { state } = useStore()
  const myStats = useStats()
  const platformStats = usePlatformStats()
  const [topTab, setTopTab] = useState('My Statistics')
  const [subTab, setSubTab] = useState('Overview')

  const platform = topTab === 'Platform'
  // Charts + rates + distribution follow the selected scope.
  const stats = platform ? platformStats : myStats
  const cards = platform
    ? [
        { icon: Users, label: 'Active Users', value: fmtNum(platformStats.activeUsers) },
        { icon: ScanLine, label: 'Scans Today', value: fmtNum(platformStats.scansToday) },
        { icon: Eye, label: 'Detections', value: fmtNum(platformStats.detections), accent: 'red' },
        { icon: Globe2, label: 'Games Covered', value: fmtNum(platformStats.gamesCovered), accent: 'blue' },
      ]
    : [
        { icon: Pin, label: 'Total Pins', value: fmtNum(myStats.totalPins) },
        { icon: ScanLine, label: 'Total Scans', value: fmtNum(myStats.totalScans) },
        { icon: Eye, label: 'Detections', value: fmtNum(myStats.detections), accent: 'red' },
        { icon: ShieldAlert, label: 'Unique Cheats', value: fmtNum(myStats.uniqueCheats), accent: 'yellow' },
      ]

  const sessionUser = state.session?.userId
    ? (state.users || []).find((u) => u.id === state.session.userId)
    : null
  const displayName = sessionUser
    ? sessionUser.username
    : state.role === 'admin'
      ? 'Admin'
      : 'Analyst'
  const welcomeBack = (state.settings?.lang === 'de' ? 'Willkommen zurück, ' : 'Welcome back, ') + displayName + '.'

  return (
    <div className="w-full min-w-0">
      <p className="caps-label">{t('dash.kicker')}</p>
      <h1 className="txt mt-3 break-words text-3xl font-bold tracking-tight sm:text-4xl">{welcomeBack}</h1>

      <div className="mt-8">
        <Tabs tabs={['My Statistics', 'Platform']} active={topTab} onChange={setTopTab} />
      </div>

      <div className="panel mt-8 w-full min-w-0 overflow-hidden rounded-2xl border p-4 sm:p-6 md:p-8">
        <p className="caps-label">Overview of your scan activity and detection results</p>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <h2 className="txt flex items-center gap-2 text-lg font-semibold sm:text-xl">
            <Activity size={20} className="shrink-0 text-sky-500" />
            <span className="break-words">{platform ? 'Platform Statistics' : 'Your Statistics'}</span>
          </h2>
          <span className="bd txt shrink-0 rounded-md border px-3 py-1.5 text-xs font-semibold tracking-wide">
            {stats.totalScans} TOTAL SCANS
          </span>
        </div>

        <div className="zt-stagger mt-6 grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
          {cards.map((c) => (
            <StatCard key={c.label} {...c} />
          ))}
        </div>

        <div className="mt-10">
          <Tabs tabs={['Overview', 'Trends', 'By Game', 'Activity']} active={subTab} onChange={setSubTab} />
        </div>

        {subTab === 'Overview' && (
          <div className="mt-8 grid grid-cols-1 gap-10 lg:grid-cols-2">
            <div>
              <h3 className="txt mb-6 text-base font-medium">Detection Rates</h3>
              <RateBar label="Cheating Rate" value={stats.rates.cheating} color="#dc2626" />
              <RateBar label="Suspicious Rate" value={stats.rates.suspicious} color="#eab308" />
              <RateBar label="Legit Rate" value={stats.rates.legit} color="#22c55e" />
            </div>
            <div>
              <h3 className="txt mb-6 text-base font-medium">Results Distribution</h3>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={stats.distribution.length ? stats.distribution : [{ name: 'No data', value: 1, color: '#3f3f46' }]}
                      dataKey="value"
                      innerRadius={62}
                      outerRadius={92}
                      startAngle={90}
                      endAngle={-270}
                      stroke="none"
                    >
                      {(stats.distribution.length ? stats.distribution : [{ color: '#3f3f46' }]).map(
                        (e, i) => (
                          <Cell key={i} fill={e.color} />
                        ),
                      )}
                    </Pie>
                    <Tooltip content={<ChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 flex flex-wrap justify-center gap-4 text-sm">
                {stats.distribution.map((d) => (
                  <span key={d.name} className="muted flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full" style={{ background: d.color }} />
                    {d.name}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {subTab === 'Trends' && (
          <div className="mt-8">
            <h3 className="txt mb-6 text-base font-medium">Scans & Detections (last 14 days)</h3>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.trend}>
                  <defs>
                    <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#848eb0" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#848eb0" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gD" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="date" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                  <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Area type="monotone" dataKey="scans" stroke="#848eb0" fill="url(#gS)" name="Scans" />
                  <Area type="monotone" dataKey="detections" stroke="#dc2626" fill="url(#gD)" name="Detections" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {subTab === 'By Game' && (
          <div className="mt-8">
            <h3 className="txt mb-6 text-base font-medium">Detections by Game</h3>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.byGame}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="game" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                  <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="detections" fill="#dc2626" name="Detections" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="scans" fill="#848eb0" name="Scans" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {subTab === 'Activity' && (
          <div className="mt-8 grid grid-cols-1 gap-10 lg:grid-cols-2">
            <div>
              <h3 className="txt mb-6 text-base font-medium">Scans by Hour of Day</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={(() => {
                    const counts = Array.from({ length: 24 }, (_, h) => ({ hour: String(h).padStart(2, '0') + ':00', count: 0 }))
                    ;(state.scans || []).forEach(s => {
                      const d = new Date(s.importedAt || s.createdAt || s.date)
                      if (!isNaN(d)) counts[d.getHours()].count += 1
                    })
                    return counts
                  })()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="hour" tick={{ fill: 'var(--muted)', fontSize: 10 }} stroke="var(--border)" interval={2} />
                    <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                    <Bar dataKey="count" fill="#848eb0" name="Scans" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div>
              <h3 className="txt mb-6 text-base font-medium">Scans by Day of Week</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={(() => {
                    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                    const counts = days.map(d => ({ day: d, count: 0 }))
                    ;(state.scans || []).forEach(s => {
                      const d = new Date(s.importedAt || s.createdAt || s.date)
                      if (!isNaN(d)) {
                        const dow = (d.getDay() + 6) % 7 // 0=Mon
                        counts[dow].count += 1
                      }
                    })
                    return counts
                  })()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="day" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
                    <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--hover)' }} />
                    <Bar dataKey="count" fill="#22c55e" name="Scans" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}
      </div>

      <AnnouncementCard />
      <WatchlistCard />
    </div>
  )
}
