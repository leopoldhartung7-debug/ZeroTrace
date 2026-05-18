import { useState } from 'react'
import { Activity, Pin, ScanLine, Eye, ShieldAlert, Users, Globe2 } from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar, Legend,
} from 'recharts'
import Tabs from '../components/Tabs.jsx'
import { useStats, useT } from '../store.jsx'

const accentMap = {
  neutral: 'muted',
  red: 'text-red-500',
  yellow: 'text-yellow-500',
  blue: 'text-blue-500',
}

function StatCard({ icon: Icon, label, value, accent = 'neutral' }) {
  return (
    <div className="panel rounded-xl border p-5">
      <div className="flex items-start gap-4">
        <div className="tile flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border">
          <Icon size={18} className={accentMap[accent]} />
        </div>
        <div className="min-w-0">
          <p className="caps-label">{label}</p>
          <p className="txt mt-1 text-2xl font-bold">{value}</p>
        </div>
      </div>
    </div>
  )
}

function RateBar({ label, value, color }) {
  return (
    <div className="mb-6">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="txt">{label}</span>
        <span className="txt font-semibold">{value}%</span>
      </div>
      <div className="tile h-2 w-full overflow-hidden rounded-full border-0">
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

export default function Dashboard() {
  const t = useT()
  const stats = useStats()
  const [topTab, setTopTab] = useState('My Statistics')
  const [subTab, setSubTab] = useState('Overview')

  const platform = topTab === 'Platform'
  const cards = platform
    ? [
        { icon: Users, label: 'Active Users', value: '1,284' },
        { icon: ScanLine, label: 'Scans Today', value: '342' },
        { icon: Eye, label: 'Detections', value: '4,901', accent: 'red' },
        { icon: Globe2, label: 'Games Covered', value: '6', accent: 'blue' },
      ]
    : [
        { icon: Pin, label: 'Total Pins', value: stats.totalPins },
        { icon: ScanLine, label: 'Total Scans', value: stats.totalScans },
        { icon: Eye, label: 'Detections', value: stats.detections, accent: 'red' },
        { icon: ShieldAlert, label: 'Unique Cheats', value: stats.uniqueCheats, accent: 'yellow' },
      ]

  return (
    <div>
      <p className="caps-label">{t('dash.kicker')}</p>
      <h1 className="txt mt-3 text-4xl font-bold tracking-tight">{t('dash.welcome')}</h1>

      <div className="mt-8">
        <Tabs tabs={['My Statistics', 'Platform']} active={topTab} onChange={setTopTab} />
      </div>

      <div className="panel mt-8 rounded-2xl border p-6 md:p-8">
        <p className="caps-label">Overview of your scan activity and detection results</p>
        <div className="mt-2 flex items-center justify-between">
          <h2 className="txt flex items-center gap-2 text-xl font-semibold">
            <Activity size={20} className="text-blue-500" />
            {platform ? 'Platform Statistics' : 'Your Statistics'}
          </h2>
          <span className="bd txt rounded-md border px-3 py-1.5 text-xs font-semibold tracking-wide">
            {stats.totalScans} TOTAL SCANS
          </span>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
          {cards.map((c) => (
            <StatCard key={c.label} {...c} />
          ))}
        </div>

        <div className="mt-10">
          <Tabs tabs={['Overview', 'Trends', 'By Game']} active={subTab} onChange={setSubTab} />
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
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
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
                  <Area type="monotone" dataKey="scans" stroke="#3b82f6" fill="url(#gS)" name="Scans" />
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
                  <Bar dataKey="scans" fill="#3b82f6" name="Scans" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
