import { useMemo, useState } from 'react'
import {
  Plus, Search, Filter, CalendarCheck, MessageSquare, Clock, CheckCircle2,
  AlertCircle, MoreHorizontal, ChevronLeft, ChevronRight, Link2,
  Copy, Trash2, Play, Download, Pencil, Users,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'
import { Modal, Drawer, Menu, Select, useToast } from '../components/ui.jsx'
import { useStore, useStats, useT, generatePinCode } from '../store.jsx'

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
const SEV_TONE = {
  Critical: 'text-red-500',
  High: 'text-orange-400',
  Medium: 'text-yellow-400',
  Low: 'text-blue-400',
}

function decodeToken(raw) {
  const s = (raw || '').trim()
  const b64 = s.startsWith('OCEAN1.') ? s.slice(7) : s
  if (!b64) throw new Error('Empty token')
  const json = decodeURIComponent(escape(atob(b64)))
  const obj = JSON.parse(json)
  if (!obj || !obj.code) throw new Error('Token missing session code')
  return obj
}

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
  const [created, setCreated] = useState(null)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [detail, setDetail] = useState(null)
  const [editing, setEditing] = useState(null)
  const [editForm, setEditForm] = useState({ name: '', game: 'HYTALE', visibility: 'Private' })
  const [access, setAccess] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [deleteInput, setDeleteInput] = useState('')
  const [form, setForm] = useState({
    name: '',
    game: state.settings.defaultGame || 'HYTALE',
    visibility: 'Private',
  })

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
    const code = generatePinCode()
    const name = form.name.trim()
    dispatch({ type: 'add-pin', ...form, name, code })
    const createdAt = Date.now()
    setCreated({ pin: code, name, game: form.game, visibility: form.visibility, createdAt })
    toast({ type: 'success', title: 'Pin Created', body: `Your pin ${code} has been created successfully.` })
    setForm({ name: '', game: state.settings.defaultGame || 'HYTALE', visibility: 'Private' })
    setCreateOpen(false)
    setPage(1)
  }

  const copyText = (text, label) => {
    navigator.clipboard?.writeText(text).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: label })
  }

  const downloadSession = (c) => {
    const session = {
      v: 1,
      product: 'Ocean FiveM Scanner',
      pin: c.pin,
      game: c.game,
      name: c.name,
      visibility: c.visibility,
      createdAt: c.createdAt,
      expiresAt: c.createdAt + 24 * 3600 * 1000,
    }
    const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `OceanScan-${c.pin}.ocean`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Session file downloaded', body: `OceanScan-${c.pin}.ocean` })
  }

  const submitImport = () => {
    try {
      const payload = decodeToken(importText)
      dispatch({ type: 'import-scan', payload })
      toast({
        type: payload.verdict === 'Cheating' ? 'error' : 'success',
        title: 'Scan result imported',
        body: `${payload.code} — ${payload.verdict}`,
      })
      setImportText('')
      setImportOpen(false)
      setPage(1)
    } catch (e) {
      toast({ type: 'error', title: 'Invalid token', body: e.message })
    }
  }

  const copyPin = (pin) => {
    navigator.clipboard?.writeText(pin).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: pin })
  }

  return (
    <div>
      <p className="caps-label">{t('pins.kicker')}</p>
      <h1 className="txt mt-3 text-4xl font-bold tracking-tight">{t('pins.title')}</h1>

      <div className="mt-7 flex flex-wrap gap-3">
        <button
          onClick={() => setCreateOpen(true)}
          className="flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black transition-opacity hover:opacity-90"
        >
          <Plus size={18} />
          {t('pins.create')}
        </button>
        <button
          onClick={() => setImportOpen(true)}
          className="bd txt flex items-center gap-2 rounded-xl border px-5 py-3 text-sm font-semibold transition-colors hover:border-blue-500"
        >
          <Download size={18} />
          Import Result
        </button>
      </div>

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

        <div className="mt-5">
          <table className="w-full table-fixed text-left">
            <colgroup>
              <col className="w-[14%]" />
              <col className="w-[17%]" />
              <col className="w-[13%]" />
              <col className="w-[12%]" />
              <col className="w-[9%]" />
              <col className="w-[13%]" />
              <col className="w-[13%]" />
              <col className="w-[9%]" />
            </colgroup>
            <thead>
              <tr className="caps-label bd border-b">
                {['Pin', 'Name', 'Game', 'Status', 'Used', 'Result', 'Visibility', ''].map(
                  (h, i) => (
                    <th key={i} className="px-2 py-3 font-semibold">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {pageRows.length === 0 && (
                <tr>
                  <td colSpan={8} className="muted px-2 py-12 text-center text-sm">
                    {tab === 'shared' ? 'Nothing shared with you yet.' : 'No pins match your filters.'}
                  </td>
                </tr>
              )}
              {pageRows.map((r) => {
                const scanned = r.used || r.status === 'Finished' || !!r.result
                return (
                <tr key={r.id} className="hoverable bd border-b align-middle text-sm">
                  <td className="txt truncate px-2 py-4 font-mono text-xs" title={r.pin}>
                    {r.pin}
                  </td>
                  <td className="txt truncate px-2 py-4" title={r.name}>
                    {r.name}
                  </td>
                  <td className="px-2 py-4">
                    <span className="bd txt inline-block max-w-full truncate rounded-md border px-2 py-0.5 text-[11px] font-semibold">
                      {r.game}
                    </span>
                  </td>
                  <td className={`px-2 py-4 text-[11px] font-semibold ${STATUS_TONE[r.status]}`}>
                    {r.status.toUpperCase()}
                  </td>
                  <td
                    className={`px-2 py-4 text-[11px] font-semibold ${
                      r.used ? 'text-green-500' : 'muted'
                    }`}
                  >
                    {r.used ? 'YES' : 'NO'}
                  </td>
                  <td
                    className={`px-2 py-4 text-[11px] font-semibold ${
                      RESULT_TONE[r.result] || 'muted'
                    }`}
                  >
                    {r.result ? r.result.toUpperCase() : '—'}
                  </td>
                  <td className="px-2 py-4">
                    <span className="bd txt inline-block max-w-full truncate rounded-md border px-2 py-0.5 text-[11px] font-semibold">
                      {r.visibility.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-2 py-4">
                    <div className="muted flex items-center justify-end">
                      <Menu
                        header="Actions"
                        trigger={
                          <button className="hover:txt p-1" title="Actions">
                            <MoreHorizontal size={18} />
                          </button>
                        }
                        items={[
                          {
                            label: 'View Results',
                            icon: <Search size={15} />,
                            onClick: () => setDetail(r),
                          },
                          {
                            label: 'Edit',
                            icon: <Pencil size={15} />,
                            onClick: () => {
                              setEditing(r)
                              setEditForm({ name: r.name, game: r.game, visibility: r.visibility })
                            },
                          },
                          { divider: true },
                          {
                            label: 'Manage Access',
                            icon: <Users size={15} />,
                            onClick: () => setAccess(r),
                          },
                          { divider: true },
                          {
                            label: scanned ? 'Delete (scanned)' : 'Delete',
                            icon: <Trash2 size={15} />,
                            danger: !scanned,
                            disabled: scanned,
                            disabledHint: 'A scan was already performed with this pin — it can no longer be deleted.',
                            onClick: () => {
                              setDeleting(r)
                              setDeleteInput('')
                            },
                          },
                          {
                            label: 'Copy Pin',
                            icon: <Copy size={15} />,
                            onClick: () => copyPin(r.pin),
                          },
                        ]}
                      />
                    </div>
                  </td>
                </tr>
                )
              })}
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

      <Modal
        open={!!created}
        onClose={() => setCreated(null)}
        title="Pin Created Successfully"
        footer={
          <button
            onClick={() => setCreated(null)}
            className="bd txt w-full rounded-lg border px-4 py-2.5 text-sm font-medium"
          >
            Close
          </button>
        }
      >
        {created && (
          <div className="space-y-4">
            <div className="tile flex items-center justify-between rounded-xl border p-4">
              <span className="txt font-mono text-xl tracking-wide">{created.pin}</span>
              <button
                onClick={() => copyText(created.pin, created.pin)}
                className="bd txt flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:border-blue-500"
              >
                <Copy size={15} /> Copy
              </button>
            </div>

            <div className="tile rounded-xl border p-4">
              <p className="muted text-sm">Scanner session file:</p>
              <p className="txt mt-1 break-all font-mono text-xs">OceanScan-{created.pin}.ocean</p>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => downloadSession(created)}
                  className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-500"
                >
                  <Download size={15} /> Download
                </button>
                <button
                  onClick={() =>
                    copyText(
                      JSON.stringify({ pin: created.pin, game: created.game, name: created.name }),
                      'Session data',
                    )
                  }
                  className="bd txt flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:border-blue-500"
                >
                  <Copy size={15} /> Copy
                </button>
              </div>
              <p className="muted mt-2 text-xs">
                Open this file with OceanScanner.exe — the pin is filled in automatically, you only
                need to accept the consent prompt and scan.
              </p>
            </div>

            <div className="tile rounded-xl border p-4">
              <p className="txt mb-3 text-sm font-semibold">Pin Details</p>
              {[
                ['Game', created.game],
                ['Pin Name', created.name],
                ['Visibility', created.visibility],
              ].map(([k, v]) => (
                <div key={k} className="mb-2 flex items-center justify-between text-sm last:mb-0">
                  <span className="muted">{k}:</span>
                  <span className="txt font-medium">{v}</span>
                </div>
              ))}
            </div>

            <div className="tile rounded-xl border p-4">
              <p className="txt mb-3 text-sm font-semibold">Scan Status</p>
              <div className="flex items-center gap-2">
                <span className="rounded-md border border-yellow-500/40 bg-yellow-500/15 px-2 py-0.5 text-xs font-bold text-yellow-500">
                  PENDING
                </span>
                <span className="flex items-center gap-1.5 text-sm text-yellow-500">
                  <Clock size={14} /> Waiting to be scanned
                </span>
              </div>
              <div className="mt-3 flex items-center gap-3">
                <div className="tile h-2 flex-1 overflow-hidden rounded-full border-0">
                  <div className="h-full w-0 rounded-full bg-blue-600" />
                </div>
                <span className="muted text-sm">0%</span>
              </div>
              <p className="muted mt-2 text-xs">Your pin is in queue and waiting to be scanned…</p>
            </div>

            <p className="muted text-xs">
              This pin will be available for 24 hours. Make sure you use it before it expires.
            </p>
          </div>
        )}
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import Scan Result"
        footer={
          <>
            <button onClick={() => setImportOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">
              Cancel
            </button>
            <button
              onClick={submitImport}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Import
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="muted text-sm">
            Paste the <code className="txt">OCEAN1.…</code> token produced by the FiveM Scanner.
            It will be matched to its session code and update the pin, dashboard and activity log.
          </p>
          <textarea
            autoFocus
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="OCEAN1.eyJ2IjoxLCJjb2RlIjoi..."
            rows={6}
            className="bd tile txt w-full rounded-lg border p-3 font-mono text-xs focus:outline-none"
          />
        </div>
      </Modal>

      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title="Edit Pin"
        footer={
          <>
            <button onClick={() => setEditing(null)} className="bd txt rounded-lg border px-4 py-2 text-sm">
              Cancel
            </button>
            <button
              onClick={() => {
                if (!editForm.name.trim()) {
                  toast({ type: 'error', title: 'Name required' })
                  return
                }
                dispatch({
                  type: 'update-pin',
                  id: editing.id,
                  patch: { name: editForm.name.trim(), game: editForm.game, visibility: editForm.visibility },
                  label: `${editing.pin} — ${editForm.name.trim()}`,
                })
                toast({ type: 'success', title: 'Pin updated', body: editing.pin })
                setEditing(null)
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Save
            </button>
          </>
        }
      >
        {editing && (
          <div className="space-y-4">
            <div>
              <label className="muted mb-1.5 block text-sm">Name</label>
              <input
                autoFocus
                value={editForm.name}
                onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
              />
            </div>
            <div>
              <label className="muted mb-1.5 block text-sm">Game</label>
              <Select
                value={editForm.game}
                onChange={(v) => setEditForm({ ...editForm, game: v })}
                options={GAMES.map((g) => ({ value: g, label: g }))}
              />
            </div>
            <div>
              <label className="muted mb-1.5 block text-sm">Visibility</label>
              <Select
                value={editForm.visibility}
                onChange={(v) => setEditForm({ ...editForm, visibility: v })}
                options={[
                  { value: 'Private', label: 'Private' },
                  { value: 'Public', label: 'Public' },
                ]}
              />
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={!!access}
        onClose={() => setAccess(null)}
        title="Manage Access"
        footer={
          <button onClick={() => setAccess(null)} className="bd txt w-full rounded-lg border px-4 py-2.5 text-sm font-medium">
            Done
          </button>
        }
      >
        {access && (
          <div className="space-y-5">
            <div>
              <p className="caps-label mb-2">Visibility</p>
              <div className="grid grid-cols-2 gap-3">
                {['Private', 'Public'].map((v) => {
                  const current =
                    (state.pins.find((p) => p.id === access.id) || access).visibility === v
                  return (
                    <button
                      key={v}
                      onClick={() => {
                        dispatch({ type: 'set-visibility', id: access.id, visibility: v })
                        toast({ type: 'success', title: `Pin is now ${v}` })
                      }}
                      className={`rounded-lg border px-4 py-3 text-sm font-medium ${
                        current
                          ? 'border-blue-600/50 bg-blue-600/15 text-blue-400'
                          : 'bd txt hover:border-neutral-600'
                      }`}
                    >
                      {v}
                      <span className="muted mt-0.5 block text-[11px] font-normal">
                        {v === 'Private' ? 'Only you can view' : 'Anyone with the pin'}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>
            <div>
              <p className="caps-label mb-2">Share</p>
              <div className="tile flex items-center justify-between rounded-lg border px-3 py-2.5">
                <span className="txt font-mono text-sm">{access.pin}</span>
                <button
                  onClick={() => copyPin(access.pin)}
                  className="bd txt flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs hover:border-blue-500"
                >
                  <Copy size={13} /> Copy pin
                </button>
              </div>
              <p className="muted mt-2 text-xs">
                Share this pin with the user so they can run the scanner against it.
              </p>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title="Delete Pin"
        footer={
          deleting && (
            <button
              disabled={deleteInput.trim() !== deleting.pin}
              onClick={() => {
                dispatch({ type: 'delete-pin', id: deleting.id, pin: deleting.pin })
                toast({ type: 'success', title: 'Pin deleted', body: deleting.pin })
                setDeleting(null)
              }}
              className={`w-full rounded-lg px-4 py-3 text-sm font-semibold transition-colors ${
                deleteInput.trim() === deleting.pin
                  ? 'bg-red-600 text-white hover:bg-red-500'
                  : 'cursor-not-allowed border border-red-900/50 bg-red-950/40 text-red-300/40'
              }`}
            >
              Delete Pin
            </button>
          )
        }
      >
        {deleting && (
          <div className="space-y-4">
            <p className="muted text-sm leading-relaxed">
              Are you sure you want to delete this pin? This action cannot be undone. Please enter
              the pin code to confirm deletion.
            </p>
            <div>
              <label className="txt mb-1.5 block text-sm font-medium">Pin Code</label>
              <input
                autoFocus
                value={deleteInput}
                onChange={(e) => setDeleteInput(e.target.value.toUpperCase())}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && deleteInput.trim() === deleting.pin) {
                    dispatch({ type: 'delete-pin', id: deleting.id, pin: deleting.pin })
                    toast({ type: 'success', title: 'Pin deleted', body: deleting.pin })
                    setDeleting(null)
                  }
                }}
                placeholder={deleting.pin}
                className="bd tile txt w-full rounded-lg border px-4 py-3 font-mono text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500/40"
              />
              <p className="muted mt-2 text-xs">
                Pin Code: <span className="txt font-mono">{deleting.pin}</span>
              </p>
            </div>
          </div>
        )}
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
              ...(detail.host ? [['Host', detail.host]] : []),
              ...(detail.os ? [['OS', detail.os]] : []),
              ['Created', new Date(detail.createdAt).toLocaleString()],
              ...(detail.scannedAt ? [['Scanned', new Date(detail.scannedAt).toLocaleString()]] : []),
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
            {detail.scanDetections?.length > 0 && (
              <div>
                <p className="caps-label mb-2">Scanner Findings ({detail.scanDetections.length})</p>
                <div className="bd tile divide-y divide-[var(--border)] overflow-hidden rounded-lg border">
                  {detail.scanDetections.map((d, i) => (
                    <div key={i} className="px-3 py-2.5">
                      <div className="flex items-center justify-between">
                        <span className="txt text-sm font-medium">{d.name}</span>
                        <span className={`text-xs font-semibold ${SEV_TONE[d.severity] || 'muted'}`}>
                          {d.severity}
                        </span>
                      </div>
                      <p className="muted mt-0.5 text-xs">
                        {d.type} · {d.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
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
