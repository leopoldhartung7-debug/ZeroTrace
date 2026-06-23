import { useMemo } from 'react'
import {
  BarChart3, Users, ScanLine, ShieldAlert, Globe2, TrendingUp, AlertCircle,
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  BarChart, Bar, Legend, PieChart, Pie, Cell,
} from 'recharts'
import { PageHeader, Card, StatTile } from '../components/kit.jsx'
import { useStore } from '../store.jsx'

const day = 86_400_000

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

export default function AdminAnalytics() {
  const { state } = useStore()

  const users = state.users || []
  const pins = state.pins || []
  const finishedPins = pins.filter((p) => p.status === 'Finished')
  const cheating = finishedPins.filter((p) => p.result === 'Cheating')

  const activeUsers30d = useMemo(() => {
    const cutoff = Date.now() - 30 * day
    const recent = new Set(
      pins.filter((p) => (p.createdAt || 0) >= cutoff && p.ownerId).map((p) => p.ownerId),
    )
    return recent.size
  }, [pins])

  const avgRisk = useMemo(() => {
    const scored = finishedPins.filter((p) => typeof p.risk === 'number')
    if (!scored.length) return 0
    return Math.round(scored.reduce((a, p) => a + p.risk, 0) / scored.length)
  }, [finishedPins])

  const trend14d = useMemo(() => {
    const days = []
    for (let i = 13; i >= 0; i--) {
      const start = Date.now() - i * day
      const date = new Date(start).toISOString().slice(5, 10)
      const dayPins = pins.filter((p) => {
        const t = p.createdAt || 0
        return t >= start - day / 2 && t < start + day / 2
      })
      days.push({
        date,
        scans: dayPins.filter((p) => p.status === 'Finished').length,
        detections: dayPins.filter((p) => p.result === 'Cheating').length,
      })
    }
    return days
  }, [pins])

  const byGame = useMemo(() => {
    const map = {}
    pins.forEach((p) => {
      if (!map[p.game]) map[p.game] = { game: p.game, scans: 0, detections: 0 }
      if (p.status === 'Finished') map[p.game].scans++
      if (p.result === 'Cheating') map[p.game].detections++
    })
    return Object.values(map)
  }, [pins])

  const topCheats = useMemo(() => {
    const counts = {}
    cheating.forEach((p) => {
      ;(p.cheats || []).forEach((c) => { counts[c] = (counts[c] || 0) + 1 })
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }))
  }, [cheating])

  const distribution = useMemo(() => {
    const c = { Cheating: 0, Suspicious: 0, Clean: 0 }
    finishedPins.forEach((p) => { if (c[p.result] != null) c[p.result]++ })
    return [
      { name: 'Cheating', value: c.Cheating, color: '#dc2626' },
      { name: 'Suspicious', value: c.Suspicious, color: '#eab308' },
      { name: 'Clean', value: c.Clean, color: '#22c55e' },
    ].filter((e) => e.value > 0)
  }, [finishedPins])

  const geoCounts = useMemo(() => {
    const map = {}
    pins.forEach((p) => {
      const country = p.geo?.country
      if (!country) return
      map[country] = (map[country] || 0) + 1
    })
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([country, count]) => ({ country, count }))
  }, [pins])

  return (
    <div>
      <PageHeader
        icon={BarChart3}
        kicker="System Analytics"
        title="Platform Overview"
        subtitle="Aggregate metrics across every analyst on this instance."
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile icon={Users} label="Total users" value={users.length} />
        <StatTile icon={TrendingUp} label="Active 30d" value={activeUsers30d} />
        <StatTile icon={ScanLine} label="Scans completed" value={finishedPins.length} />
        <StatTile icon={ShieldAlert} label="Average risk" value={avgRisk} accent="text-red-500" />
      </div>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-4 text-base font-semibold">Scans & detections (last 14 days)</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trend14d}>
              <defs>
                <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#848eb0" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#848eb0" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="date" tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} stroke="var(--border)" allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Area type="monotone" dataKey="scans" stroke="#848eb0" fill="url(#gA)" name="Scans" />
              <Area type="monotone" dataKey="detections" stroke="#dc2626" fill="url(#gB)" name="Detections" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-4 text-base font-semibold">By game</h3>
          {byGame.length === 0 ? (
            <p className="muted py-8 text-center text-sm">No scans yet.</p>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={byGame}>
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
          )}
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-4 text-base font-semibold">Verdict distribution</h3>
          {distribution.length === 0 ? (
            <p className="muted py-8 text-center text-sm">No data.</p>
          ) : (
            <>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={distribution} dataKey="value" innerRadius={50} outerRadius={80} stroke="none">
                      {distribution.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip content={<ChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 flex flex-wrap justify-center gap-4 text-sm">
                {distribution.map((d) => (
                  <span key={d.name} className="muted flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full" style={{ background: d.color }} />
                    {d.name} · {d.value}
                  </span>
                ))}
              </div>
            </>
          )}
        </Card>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-4 flex items-center gap-2 text-base font-semibold">
            <AlertCircle size={16} className="text-red-500" /> Top detected cheats
          </h3>
          {topCheats.length === 0 ? (
            <p className="muted py-8 text-center text-sm">No detections recorded.</p>
          ) : (
            <ol className="space-y-2 text-sm">
              {topCheats.map((c, i) => (
                <li key={c.name} className="bd flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="txt"><span className="muted mr-2 font-mono text-xs">#{i + 1}</span>{c.name}</span>
                  <span className="rounded-md border border-red-600/40 bg-red-600/15 px-2 py-0.5 text-[11px] font-semibold text-red-500">{c.count}</span>
                </li>
              ))}
            </ol>
          )}
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-4 flex items-center gap-2 text-base font-semibold">
            <Globe2 size={16} className="text-sky-500" /> Scans by country
          </h3>
          {geoCounts.length === 0 ? (
            <p className="muted py-8 text-center text-sm">No geo data yet. Enable IP lookup in scan results.</p>
          ) : (
            <ol className="space-y-2 text-sm">
              {geoCounts.map((g, i) => (
                <li key={g.country} className="bd flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="txt"><span className="muted mr-2 font-mono text-xs">#{i + 1}</span>{g.country}</span>
                  <span className="bd muted rounded-md border px-2 py-0.5 text-[11px] font-semibold">{g.count}</span>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>
    </div>
  )
}
