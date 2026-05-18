import { useMemo, useState } from 'react'
import {
  Plus,
  Search,
  ChevronDown,
  SlidersHorizontal,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { PageHeader, Tabs, Badge } from '../components/ui.jsx'
import { pins, pinStats } from '../data.js'

const columns = [
  'PIN',
  'NAME',
  'GAME',
  'STATUS',
  'USED',
  'RESULT',
  'VISIBILITY',
  'ACTIONS',
]

function Select({ label }) {
  return (
    <button
      type="button"
      className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200"
    >
      {label}
      <ChevronDown size={15} className="text-zinc-600" />
    </button>
  )
}

export default function Pins() {
  const [tab, setTab] = useState('mine')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 5

  const sharedCount = pins.filter((p) => p.visibility === 'SHARED').length

  const filtered = useMemo(() => {
    const base =
      tab === 'shared' ? pins.filter((p) => p.visibility === 'SHARED') : pins
    if (!query.trim()) return base
    const q = query.toLowerCase()
    return base.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.pin.toLowerCase().includes(q) ||
        p.game.toLowerCase().includes(q)
    )
  }, [tab, query])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(page, totalPages)
  const visible = filtered.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize
  )

  return (
    <div>
      <PageHeader
        eyebrow="View and manage your scan pins and results"
        title="My Pins"
        action={
          <button
            type="button"
            className="flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-ink-950 transition-colors hover:bg-zinc-200"
          >
            <Plus size={16} strokeWidth={2.4} />
            Create Pin
          </button>
        }
      />

      <div className="mb-8">
        <Tabs
          tabs={[
            { value: 'mine', label: 'My Pins' },
            { value: 'shared', label: `Shared with Me (${sharedCount})` },
          ]}
          active={tab}
          onChange={(v) => {
            setTab(v)
            setPage(1)
          }}
        />
      </div>

      <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        {pinStats.map((stat) => (
          <div key={stat.key} className="card p-5">
            <p className="caps-label">{stat.label}</p>
            <p className="mt-2 text-2xl font-bold text-white">
              {stat.value.toLocaleString()}
            </p>
          </div>
        ))}
      </div>

      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-700 p-4">
          <div className="relative min-w-[220px] flex-1">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600"
            />
            <input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setPage(1)
              }}
              placeholder="Search pins..."
              className="w-full rounded-lg border border-ink-700 bg-ink-950 py-2 pl-9 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-accent focus:outline-none"
            />
          </div>
          <Select label="All Status" />
          <Select label="All Games" />
          <button
            type="button"
            className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200"
          >
            <SlidersHorizontal size={15} />
            More
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-ink-700">
                {columns.map((col) => (
                  <th
                    key={col}
                    className="px-4 py-3 text-[11px] font-semibold uppercase tracking-wider text-zinc-500"
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((p) => (
                <tr
                  key={p.pin}
                  className="border-b border-ink-800 last:border-0 hover:bg-ink-850"
                >
                  <td className="px-4 py-3 font-mono text-xs text-accent">
                    {p.pin}
                  </td>
                  <td className="px-4 py-3 font-medium text-zinc-200">
                    {p.name}
                  </td>
                  <td className="px-4 py-3 text-zinc-400">{p.game}</td>
                  <td className="px-4 py-3">
                    <Badge>{p.status}</Badge>
                  </td>
                  <td className="px-4 py-3 text-zinc-400">{p.used}</td>
                  <td className="px-4 py-3">
                    <Badge>{p.result}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge>{p.visibility}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      className="rounded-md p-1.5 text-zinc-500 hover:bg-ink-800 hover:text-zinc-200"
                    >
                      <MoreHorizontal size={16} />
                    </button>
                  </td>
                </tr>
              ))}
              {visible.length === 0 && (
                <tr>
                  <td
                    colSpan={columns.length}
                    className="px-4 py-10 text-center text-sm text-zinc-500"
                  >
                    No pins match your search.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between border-t border-ink-700 px-4 py-3 text-sm text-zinc-500">
          <span>
            Showing {visible.length} of {filtered.length} pins
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="rounded-md border border-ink-700 p-1.5 text-zinc-400 hover:text-zinc-200 disabled:opacity-40"
            >
              <ChevronLeft size={16} />
            </button>
            <span className="px-3 text-zinc-300">
              {safePage} / {totalPages}
            </span>
            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="rounded-md border border-ink-700 p-1.5 text-zinc-400 hover:text-zinc-200 disabled:opacity-40"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
