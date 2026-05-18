import { useState } from 'react'
import { Activity, Pin, ScanLine, Eye, ShieldAlert } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import Tabs from '../components/Tabs.jsx'

const accentMap = {
  neutral: 'text-neutral-400',
  red: 'text-red-500',
  yellow: 'text-yellow-500',
  blue: 'text-blue-500',
}

function StatCard({ icon: Icon, label, value, accent = 'neutral' }) {
  return (
    <div className="card p-5">
      <div className="flex items-start gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-ink-950">
          <Icon size={18} className={accentMap[accent]} />
        </div>
        <div className="min-w-0">
          <p className="caps-label">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        </div>
      </div>
    </div>
  )
}

function RateBar({ label, value, color }) {
  return (
    <div className="mb-6">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="text-neutral-300">{label}</span>
        <span className="font-semibold text-white">{value}%</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-ink-800">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${value}%`, background: color }}
        />
      </div>
    </div>
  )
}

const donutData = [{ name: 'Cheating', value: 100 }]

export default function Dashboard() {
  const [topTab, setTopTab] = useState('My Statistics')
  const [subTab, setSubTab] = useState('Overview')

  return (
    <div>
      <p className="caps-label">
        View statistics, events, and announcements on the Ocean.
      </p>
      <h1 className="mt-3 text-4xl font-bold tracking-tight text-white">
        Welcome back, Ham.
      </h1>

      <div className="mt-8">
        <Tabs
          tabs={['My Statistics', 'Platform']}
          active={topTab}
          onChange={setTopTab}
        />
      </div>

      <div className="mt-8 rounded-2xl border border-line bg-ink-900/40 p-6 md:p-8">
        <p className="caps-label">
          Overview of your scan activity and detection results
        </p>
        <div className="mt-2 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-xl font-semibold text-white">
            <Activity size={20} className="text-blue-500" />
            Your Statistics
          </h2>
          <span className="rounded-md border border-line px-3 py-1.5 text-xs font-semibold tracking-wide text-neutral-300">
            1 TOTAL SCANS
          </span>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard icon={Pin} label="Total Pins" value="1" />
          <StatCard icon={ScanLine} label="Total Scans" value="1" />
          <StatCard icon={Eye} label="Detections" value="11" accent="red" />
          <StatCard
            icon={ShieldAlert}
            label="Unique Cheats"
            value="3"
            accent="yellow"
          />
        </div>

        <div className="mt-10">
          <Tabs
            tabs={['Overview', 'Trends', 'By Game']}
            active={subTab}
            onChange={setSubTab}
          />
        </div>

        <div className="mt-8 grid grid-cols-1 gap-10 lg:grid-cols-2">
          <div>
            <h3 className="mb-6 text-base font-medium text-white">
              Detection Rates
            </h3>
            <RateBar label="Cheating Rate" value={100} color="#dc2626" />
            <RateBar label="Suspicious Rate" value={0} color="#eab308" />
            <RateBar label="Legit Rate" value={0} color="#22c55e" />
          </div>

          <div>
            <h3 className="mb-6 text-base font-medium text-white">
              Results Distribution
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    dataKey="value"
                    innerRadius={62}
                    outerRadius={92}
                    startAngle={90}
                    endAngle={-270}
                    stroke="none"
                  >
                    {donutData.map((entry, i) => (
                      <Cell key={i} fill="#dc2626" />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-3 flex items-center justify-center gap-2 text-sm text-neutral-400">
              <span className="h-2 w-2 rounded-full bg-red-600" />
              Cheating
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
