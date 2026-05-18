import { useMemo, useState } from 'react'
import {
  Plus, Search, Filter, CalendarCheck, MessageSquare, Clock, CheckCircle2,
  AlertCircle, Info, MoreHorizontal, ChevronLeft, ChevronRight, Link2,
  Copy, Trash2, Play, Eye, EyeOff,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'
import { Modal, Drawer, Menu, Select, useToast } from '../components/ui.jsx'
import { useStore, useStats, useT } from '../store.jsx'

const GAMES = ['HYTALE', 'MINECRAFT', 'CS2', 'VALORANT', 'RUST', 'FIVEM']

function PinStatCard({ icon: Icon, label, value, valueClass = 'txt', children }) {
  return (
    <div className="panel rounded-xl border p-5">
      <div className="flex items-center justify-between">
        <p className="caps-label">{label}</p>
        <Icon size={16} className="muted" />
      </div>
      <p className={`mt-3 text-2xl font-bold ${valueClass}`}>{value}</p>
      {children}
    </div>
  )
}

const RESULT_TONE = { Cheating: 'text-red-500', Suspicious: 'text-yellow-500', Clean: 'text-green-500' }
const STATUS_TONE = { Finished: 'text-green-500', Pending: 'text-yellow-500', Expired: 'text-red-500' }

export default function Pins() {
  const { state, dispatch } = useStore()
  const stats = useStats()
  const t = useT()
  const toast = useToast()

  const [tab, setTab] = useState('mine')
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [gameFilter, setGameFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [createOpen, setCreateOpen] = useState(false)
  const [detail, setDetail] = useState(null)
  const [form, setForm] = useState({ name: '', game: 'HYTALE', visibility: 'Private' })

  const filtered = useMemo(() => {
    if (tab === 'shared') return []
    return state.pins.filter((p) => {
      if (query && !`${p.pin} ${p.name}`.toLowerCase().includes(query.toLowerCase())) return false
      if (statusFilter !== 'all' && p.status !== statusFilter) return false
      if (gameFilter !== 'all' && p.game !== gameFilter) return false
      return true
    })
  }, [state.pins, query, statusFilter, gameFilter, tab])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageRows = filtered.slice((page - 1) * pageSize, page * pageSize)
  const safePage = Math.min(page, totalPages)

  const submitCreate = () => {
    if (!form.name.trim()) {
      toast({ type: 'error', title: 'Name required' })
      return
    }
    dispatch({ type: 'add-pin', ...form, name: form.name.trim() })
    toast({ type: 'success', title: 'Pin created', body: `${form.name} (${form.game})` })
    setForm({ name: '', game: 'HYTALE', visibility: 'Private' })
    setCreateOpen(false)
    setPage(1)
  }

  const copyPin = (pin) => {
    navigator.clipboard?.writeText(pin).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: pin })
  }

  return (
    <div>
      <p className="caps-label">{t('pins.kicker')}</p>
      <h1 className="txt mt-3 text-4xl font-bold tracking-tight">{t('pins.title')}</h1>

      <button
        onClick={() => setCreateOpen(true)}
        className="mt-7 flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black transition-opacity hover:opacity-90"
      >
        <Plus size={18} />
        {t('pins.create')}
      </button>

      <div className="mt-8">
        <Tabs
          tabs={[
            { label: `My Pins (${state.pins.length})`, key: 'mine' },
            { label: 'Shared with Me (0)', key: 'shared' },
          ].map((x) => x.label)}
          active={tab === 'mine' ? `My Pins (${state.pins.length})` : 'Shared with Me (0)'}
          onChange={(l) => setTab(l.startsWith('My') ? 'mine' : 'shared')}
        />
      </div>

      <div className="mt-8 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <PinStatCard icon={CalendarCheck} label="Daily Pins" value="1/1" valueClass="text-red-500">
          <button className="mt-2 flex items-center gap-1.5 text-xs font-medium text-blue-500 hover:text-blue-400">
            <Link2 size={13} />
            Link Discord for more
          </button>
        </PinStatCard>
        <PinStatCard icon={MessageSquare} label="Total Pins" value={stats.totalPins} />
        <PinStatCard icon={Clock} label="Pending" value={stats.pending} />
        <PinStatCard icon={CheckCircle2} label="Finished" value={stats.finished} />
        <PinStatCard icon={AlertCircle} label="Expired" value={stats.expired} />
      </div>

      <div className="panel mt-8 rounded-2xl border p-5">
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search size={16} className="muted absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setPage(1)
              }}
              placeholder="Search by pin or name..."
              className="bd tile txt w-full rounded-lg border py-2.5 pl-10 pr-4 text-sm focus:outline-none"
            />
          </div>
          <Select
            className="sm:w-40"
            value={statusFilter}
            onChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
            options={[
              { value: 'all', label: 'All Status' },
              { value: 'Pending', label: 'Pending' },
              { value: 'Finished', label: 'Finished' },
              { value: 'Expired', label: 'Expired' },
            ]}
          />
          <Select
            className="sm:w-40"
            value={gameFilter}
            onChange={(v) => {
              setGameFilter(v)
              setPage(1)
            }}
            options={[{ value: 'all', label: 'All Games' }, ...GAMES.map((g) => ({ value: g, label: g }))]}
          />
          <button
            onClick={() => {
              setQuery('')
              setStatusFilter('all')
              setGameFilter('all')
            }}
            className="bd tile txt flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm"
          >
            <Filter size={15} className="muted" />
            Reset
          </button>
        </div>

        <div className="mt-5 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left">
            <thead>
              <tr className="caps-label bd border-b">
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
              {pageRows.length === 0 && (
                <tr>
                  <td colSpan={8} className="muted px-3 py-12 text-center text-sm">
                    {tab === 'shared' ? 'Nothing shared with you yet.' : 'No pins match your filters.'}
                  </td>
                </tr>
              )}
              {pageRows.map((r) => (
                <tr key={r.id} className="hoverable bd border-b text-sm">
                  <td className="txt px-3 py-4 font-mono">{r.pin}</td>
                  <td className="txt px-3 py-4">{r.name}</td>
                  <td className="px-3 py-4">
                    <span className="bd txt rounded-md border px-2.5 py-1 text-xs font-semibold">
                      {r.game}
                    </span>
                  </td>
                  <td className={`px-3 py-4 text-xs font-semibold ${STATUS_TONE[r.status]}`}>
                    {r.status.toUpperCase()}
                  </td>
                  <td
                    className={`px-3 py-4 text-xs font-semibold ${
                      r.used ? 'text-green-500' : 'muted'
                    }`}
                  >
                    {r.used ? 'YES' : 'NO'}
                  </td>
                  <td
                    className={`px-3 py-4 text-xs font-semibold ${
                      RESULT_TONE[r.result] || 'muted'
                    }`}
                  >
                    {r.result ? r.result.toUpperCase() : '—'}
                  </td>
                  <td className="px-3 py-4">
                    <span className="bd txt rounded-md border px-2.5 py-1 text-xs font-semibold">
                      {r.visibility.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-3 py-4">
                    <div className="muted flex items-center gap-3">
                      <button className="hover:txt" onClick={() => setDetail(r)} title="Details">
                        <Info size={16} />
                      </button>
                      <Menu
                        trigger={
                          <button className="hover:txt" title="Actions">
                            <MoreHorizontal size={16} />
                          </button>
                        }
                        items={[
                          ...(r.status === 'Pending'
                            ? [
                                {
                                  label: 'Run scan',
                                  icon: <Play size={14} />,
                                  onClick: () => {
                                    dispatch({ type: 'run-scan', id: r.id })
                                    toast({ type: 'info', title: 'Scan complete', body: r.pin })
                                  },
                                },
                              ]
                            : []),
                          { label: 'Copy pin', icon: <Copy size={14} />, onClick: () => copyPin(r.pin) },
                          {
                            label: r.visibility === 'Private' ? 'Make public' : 'Make private',
                            icon: r.visibility === 'Private' ? <Eye size={14} /> : <EyeOff size={14} />,
                            onClick: () => dispatch({ type: 'toggle-visibility', id: r.id }),
                          },
                          {
                            label: 'Delete',
                            icon: <Trash2 size={14} />,
                            danger: true,
                            onClick: () => {
                              dispatch({ type: 'delete-pin', id: r.id })
                              toast({ type: 'success', title: 'Pin deleted', body: r.pin })
                            },
                          },
                        ]}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="muted mt-5 flex items-center justify-between text-sm">
          <span>
            <span className="txt">
              {filtered.length === 0 ? 0 : (safePage - 1) * pageSize + 1}-
              {Math.min(safePage * pageSize, filtered.length)}
            </span>{' '}
            of <span className="txt">{filtered.length}</span> results
          </span>
          <div className="flex items-center gap-2">
            <button
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="bd rounded-md border p-1.5 disabled:opacity-40"
            >
              <ChevronLeft size={15} />
            </button>
            <span className="rounded-md border border-blue-600/40 bg-blue-600/15 px-3 py-1 text-sm font-medium text-blue-500">
              {safePage}
            </span>
            <button
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="bd rounded-md border p-1.5 disabled:opacity-40"
            >
              <ChevronRight size={15} />
            </button>
            <Select
              className="ml-2 w-28"
              value={String(pageSize)}
              onChange={(v) => {
                setPageSize(Number(v))
                setPage(1)
              }}
              options={[
                { value: '10', label: '10 / page' },
                { value: '25', label: '25 / page' },
                { value: '50', label: '50 / page' },
              ]}
            />
          </div>
        </div>
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create Pin"
        footer={
          <>
            <button
              onClick={() => setCreateOpen(false)}
              className="bd txt rounded-lg border px-4 py-2 text-sm"
            >
              Cancel
            </button>
            <button
              onClick={submitCreate}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Create
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="muted mb-1.5 block text-sm">Name</label>
            <input
              autoFocus
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              onKeyDown={(e) => e.key === 'Enter' && submitCreate()}
              placeholder="e.g. Suspect #42"
              className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
            />
          </div>
          <div>
            <label className="muted mb-1.5 block text-sm">Game</label>
            <Select
              value={form.game}
              onChange={(v) => setForm({ ...form, game: v })}
              options={GAMES.map((g) => ({ value: g, label: g }))}
            />
          </div>
          <div>
            <label className="muted mb-1.5 block text-sm">Visibility</label>
            <Select
              value={form.visibility}
              onChange={(v) => setForm({ ...form, visibility: v })}
              options={[
                { value: 'Private', label: 'Private' },
                { value: 'Public', label: 'Public' },
              ]}
            />
          </div>
        </div>
      </Modal>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title="Pin Details">
        {detail && (
          <div className="space-y-5">
            <div className="tile rounded-xl border p-4">
              <p className="caps-label">Pin Code</p>
              <p className="txt mt-1 font-mono text-lg">{detail.pin}</p>
            </div>
            {[
              ['Name', detail.name],
              ['Game', detail.game],
              ['Status', detail.status],
              ['Used', detail.used ? 'Yes' : 'No'],
              ['Result', detail.result || '—'],
              ['Visibility', detail.visibility],
              ['Detections', detail.detections],
              ['Created', new Date(detail.createdAt).toLocaleString()],
            ].map(([k, v]) => (
              <div key={k} className="bd flex items-center justify-between border-b pb-3 text-sm">
                <span className="muted">{k}</span>
                <span className="txt font-medium">{String(v)}</span>
              </div>
            ))}
            <div>
              <p className="caps-label mb-2">Detected Cheats</p>
              {detail.cheats?.length ? (
                <div className="flex flex-wrap gap-2">
                  {detail.cheats.map((c) => (
                    <span
                      key={c}
                      className="rounded-md border border-red-600/30 bg-red-600/10 px-2.5 py-1 text-xs font-medium text-red-500"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="muted text-sm">None</p>
              )}
            </div>
            {detail.status === 'Pending' && (
              <button
                onClick={() => {
                  dispatch({ type: 'run-scan', id: detail.id })
                  setDetail(null)
                  toast({ type: 'info', title: 'Scan complete', body: detail.pin })
                }}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
              >
                <Play size={15} /> Run scan now
              </button>
            )}
          </div>
        )}
      </Drawer>
    </div>
  )
}
