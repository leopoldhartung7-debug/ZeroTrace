import { useEffect, useState } from 'react'
import {
  Pin,
  ScanLine,
  ShieldAlert,
  Bug,
  AlignLeft,
} from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
} from 'recharts'
import { PageHeader, Tabs, StatCard } from '../components/ui.jsx'
import {
  currentUser,
  dashboardStats,
  detectionRates,
  resultsDistribution,
  scanTrends,
  byGame,
} from '../data.js'

const iconMap = { Pin, ScanLine, ShieldAlert, Bug }

const tooltipStyle = {
  background: '#111',
  border: '1px solid #262626',
  borderRadius: 8,
  fontSize: 12,
}

function DetectionRates() {
  // Grow the bars from zero on mount for a smooth reveal
  const [shown, setShown] = useState(false)
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(true))
    return () => cancelAnimationFrame(id)
  }, [])

  return (
    <div className="card animate-fade-in-up p-6">
      <h3 className="text-sm font-semibold text-white">Detection Rates</h3>
      <p className="mt-1 text-xs text-zinc-500">
        Distribution across all completed scans
      </p>
      <div className="mt-6 space-y-5">
        {detectionRates.map((rate) => (
          <div key={rate.label}>
            <div className="mb-1.5 flex items-center justify-between text-sm">
              <span className="text-zinc-400">{rate.label}</span>
              <span className="font-semibold text-white">{rate.value}%</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-ink-700">
              <div
                className="h-full rounded-full transition-[width] duration-700 ease-out"
                style={{
                  width: shown ? `${rate.value}%` : '0%',
                  backgroundColor: rate.color,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ResultsDonut() {
  const total = resultsDistribution.reduce((sum, d) => sum + d.value, 0)
  return (
    <div className="card animate-fade-in-up p-6" style={{ animationDelay: '80ms' }}>
      <h3 className="text-sm font-semibold text-white">Results Distribution</h3>
      <p className="mt-1 text-xs text-zinc-500">Clean vs. flagged outcomes</p>
      <div className="relative mt-2 h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={resultsDistribution}
              dataKey="value"
              nameKey="name"
              innerRadius={62}
              outerRadius={88}
              paddingAngle={2}
              stroke="none"
            >
              {resultsDistribution.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-white">
            {total.toLocaleString()}
          </span>
          <span className="text-xs text-zinc-500">Total</span>
        </div>
      </div>
      <div className="mt-2 flex justify-center gap-6">
        {resultsDistribution.map((d) => (
          <div key={d.name} className="flex items-center gap-2 text-xs">
            <span
              className="h-2.5 w-2.5 rounded-sm"
              style={{ backgroundColor: d.color }}
            />
            <span className="text-zinc-400">{d.name}</span>
            <span className="font-semibold text-white">
              {d.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TrendsChart() {
  return (
    <div className="card animate-fade-in-up p-6">
      <h3 className="text-sm font-semibold text-white">Scan Activity</h3>
      <p className="mt-1 text-xs text-zinc-500">Last 7 days</p>
      <div className="mt-6 h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={scanTrends} margin={{ left: -16, right: 8 }}>
            <defs>
              <linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1f1f1f" vertical={false} />
            <XAxis
              dataKey="day"
              stroke="#52525b"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#52525b"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip contentStyle={tooltipStyle} />
            <Area
              type="monotone"
              dataKey="scans"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#scanFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function ByGameChart() {
  return (
    <div className="card animate-fade-in-up p-6">
      <h3 className="text-sm font-semibold text-white">Scans by Game</h3>
      <p className="mt-1 text-xs text-zinc-500">
        Scans and detections per title
      </p>
      <div className="mt-6 h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={byGame} margin={{ left: -16, right: 8 }}>
            <CartesianGrid stroke="#1f1f1f" vertical={false} />
            <XAxis
              dataKey="game"
              stroke="#52525b"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#52525b"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#1a1a1a' }} />
            <Bar dataKey="scans" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            <Bar dataKey="detections" fill="#dc2626" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [topTab, setTopTab] = useState('My Statistics')
  const [chartTab, setChartTab] = useState('Overview')

  const totalScans = dashboardStats.find((s) => s.key === 'scans')?.value ?? 0

  return (
    <div>
      <PageHeader
        eyebrow="View statistics, events, and announcements on the Ocean"
        title={`Welcome back, ${currentUser.name}.`}
      />

      <div className="mb-8">
        <Tabs
          tabs={['My Statistics', 'Platform']}
          active={topTab}
          onChange={setTopTab}
        />
      </div>

      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlignLeft size={18} className="text-accent" />
          <h2 className="text-lg font-semibold text-white">Your Statistics</h2>
        </div>
        <span className="caps-label">
          {totalScans.toLocaleString()} Total Scans
        </span>
      </div>

      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {dashboardStats.map((stat, i) => (
          <div
            key={stat.key}
            className="animate-fade-in-up"
            style={{ animationDelay: `${i * 70}ms` }}
          >
            <StatCard
              icon={iconMap[stat.icon]}
              label={stat.label}
              value={stat.value}
              delta={stat.delta}
            />
          </div>
        ))}
      </div>

      <div className="mb-6">
        <Tabs
          tabs={['Overview', 'Trends', 'By Game']}
          active={chartTab}
          onChange={setChartTab}
        />
      </div>

      {chartTab === 'Overview' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <DetectionRates />
          <ResultsDonut />
        </div>
      )}
      {chartTab === 'Trends' && <TrendsChart />}
      {chartTab === 'By Game' && <ByGameChart />}
    </div>
  )
}
