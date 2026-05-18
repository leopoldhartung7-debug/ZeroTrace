import { useState } from 'react'
import {
  Plus,
  Search,
  Filter,
  CalendarCheck,
  MessageSquare,
  Clock,
  CheckCircle2,
  AlertCircle,
  Info,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  Link2,
  ChevronDown,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'

function PinStatCard({ icon: Icon, label, value, valueClass = 'text-white', children }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between">
        <p className="caps-label">{label}</p>
        <Icon size={16} className="text-neutral-500" />
      </div>
      <p className={`mt-3 text-2xl font-bold ${valueClass}`}>{value}</p>
      {children}
    </div>
  )
}

const rows = [
  {
    pin: 'F1T5F8C0',
    name: 'Test',
    game: 'HYTALE',
    status: 'FINISHED',
    used: 'YES',
    result: 'CHEATING',
    visibility: 'PRIVATE',
  },
]

function Pill({ children, tone }) {
  const tones = {
    green: 'text-green-500',
    red: 'text-red-500',
    grey: 'border border-line rounded-md px-2.5 py-1 text-neutral-300',
    game: 'border border-line rounded-md px-2.5 py-1 text-neutral-200',
  }
  return (
    <span className={`text-xs font-semibold tracking-wide ${tones[tone]}`}>
      {children}
    </span>
  )
}

export default function Pins() {
  const [tab, setTab] = useState('My Pins (1)')

  return (
    <div>
      <p className="caps-label">View and manage your scan pins and results</p>
      <h1 className="mt-3 text-4xl font-bold tracking-tight text-white">
        My Pins
      </h1>

      <button className="mt-7 flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black transition-opacity hover:opacity-90">
        <Plus size={18} />
        Create Pin
      </button>

      <div className="mt-8">
        <Tabs
          tabs={['My Pins (1)', 'Shared with Me (0)']}
          active={tab}
          onChange={setTab}
        />
      </div>

      <div className="mt-8 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <PinStatCard
          icon={CalendarCheck}
          label="Daily Pins"
          value="1/1"
          valueClass="text-red-500"
        >
          <button className="mt-2 flex items-center gap-1.5 text-xs font-medium text-blue-500 hover:text-blue-400">
            <Link2 size={13} />
            Link Discord for more
          </button>
        </PinStatCard>
        <PinStatCard icon={MessageSquare} label="Total Pins" value="1" />
        <PinStatCard icon={Clock} label="Pending" value="0" />
        <PinStatCard icon={CheckCircle2} label="Finished" value="1" />
        <PinStatCard icon={AlertCircle} label="Expired" value="0" />
      </div>

      <div className="mt-8 rounded-2xl border border-line bg-ink-900/40 p-5">
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search
              size={16}
              className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-500"
            />
            <input
              type="text"
              placeholder="Search by pin or name..."
              className="w-full rounded-lg border border-line bg-ink-950 py-2.5 pl-10 pr-4 text-sm text-neutral-200 placeholder:text-neutral-600 focus:border-neutral-700 focus:outline-none"
            />
          </div>
          <button className="flex items-center justify-between gap-3 rounded-lg border border-line bg-ink-950 px-4 py-2.5 text-sm text-neutral-300 hover:border-neutral-700">
            All Status
            <ChevronDown size={15} className="text-neutral-500" />
          </button>
          <button className="flex items-center justify-between gap-3 rounded-lg border border-line bg-ink-950 px-4 py-2.5 text-sm text-neutral-300 hover:border-neutral-700">
            All Games
            <ChevronDown size={15} className="text-neutral-500" />
          </button>
          <button className="flex items-center gap-2 rounded-lg border border-line bg-ink-950 px-4 py-2.5 text-sm text-neutral-300 hover:border-neutral-700">
            <Filter size={15} className="text-neutral-500" />
            More
          </button>
        </div>

        <div className="mt-5 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left">
            <thead>
              <tr className="caps-label border-b border-line">
                {['Pin', 'Name', 'Game', 'Status', 'Used', 'Result', 'Visibility', 'Actions'].map(
                  (h) => (
                    <th key={h} className="px-3 py-3 font-semibold">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.pin}
                  className="border-b border-line/60 text-sm transition-colors hover:bg-white/[0.02]"
                >
                  <td className="px-3 py-4 font-mono text-neutral-200">{r.pin}</td>
                  <td className="px-3 py-4 text-neutral-300">{r.name}</td>
                  <td className="px-3 py-4">
                    <Pill tone="game">{r.game}</Pill>
                  </td>
                  <td className="px-3 py-4">
                    <Pill tone="green">{r.status}</Pill>
                  </td>
                  <td className="px-3 py-4">
                    <Pill tone="green">{r.used}</Pill>
                  </td>
                  <td className="px-3 py-4">
                    <Pill tone="red">{r.result}</Pill>
                  </td>
                  <td className="px-3 py-4">
                    <Pill tone="grey">{r.visibility}</Pill>
                  </td>
                  <td className="px-3 py-4">
                    <div className="flex items-center gap-3 text-neutral-500">
                      <button className="hover:text-neutral-300">
                        <Info size={16} />
                      </button>
                      <button className="hover:text-neutral-300">
                        <MoreHorizontal size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mt-5 flex items-center justify-between text-sm text-neutral-500">
          <span>
            <span className="text-neutral-300">1-1</span> of{' '}
            <span className="text-neutral-300">1</span> results
          </span>
          <div className="flex items-center gap-2">
            <button className="rounded-md border border-line p-1.5 text-neutral-500 hover:border-neutral-700">
              <ChevronLeft size={15} />
            </button>
            <span className="rounded-md border border-blue-600/40 bg-blue-600/15 px-3 py-1 text-sm font-medium text-blue-400">
              1
            </span>
            <button className="rounded-md border border-line p-1.5 text-neutral-500 hover:border-neutral-700">
              <ChevronRight size={15} />
            </button>
            <button className="ml-2 flex items-center gap-2 rounded-md border border-line px-3 py-1.5 text-sm text-neutral-300 hover:border-neutral-700">
              10 / page
              <ChevronDown size={14} className="text-neutral-500" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
