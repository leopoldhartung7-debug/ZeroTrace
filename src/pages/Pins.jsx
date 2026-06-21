import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Plus, Search, CalendarCheck, MessageSquare, Clock, CheckCircle2,
  AlertCircle, MoreHorizontal, ChevronLeft, ChevronRight, Link2,
  Copy, Trash2, Download, Pencil, Users, Star, Bookmark, X,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'
import { Modal, Menu, Select, useToast } from '../components/ui.jsx'
import { useStore, useStats, useT, generatePinCode, deriveScanReport } from '../store.jsx'
import { makeZip } from '../lib/zip.js'

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

function decodeToken(raw) {
  let s = (raw || '').trim()
  // Tolerate scanners that wrap the token in quotes or whitespace/newlines.
  s = s.replace(/^["']|["']$/g, '').trim()
  // Strip a "ZEROTRACE1." / legacy "OCEAN1." prefix case-insensitively, then
  // remove any internal whitespace.
  let b64 = (/^(zerotrace1|ocean1)\./i.test(s) ? s.slice(s.indexOf('.') + 1) : s).replace(/\s+/g, '')
  if (!b64) throw new Error('Empty token')
  let json
  try {
    json = decodeURIComponent(escape(atob(b64)))
  } catch {
    // Maybe it's raw JSON rather than base64.
    if (b64.startsWith('{')) json = s
    else throw new Error('Token is not valid Base64')
  }
  let obj
  try {
    obj = JSON.parse(json)
  } catch {
    throw new Error('Token does not contain valid JSON')
  }
  if (!obj || !obj.code) throw new Error('Token is missing the session code')
  return obj
}

export default function Pins() {
  const { state, dispatch } = useStore()
  const stats = useStats()
  const t = useT()
  const toast = useToast()
  const nav = useNavigate()
  const loc = useLocation()

  const [tab, setTab] = useState('mine')
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [gameFilter, setGameFilter] = useState('all')
  const [starOnly, setStarOnly] = useState(false)
  const [selected, setSelected] = useState([])
  const uid = state.session?.userId || null
  const savedFilters = (state.savedFilters || []).filter((f) => f.ownerId === uid || (state.role === 'admin' && f.ownerId == null))
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [createOpen, setCreateOpen] = useState(false)
  const [created, setCreated] = useState(null)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [editing, setEditing] = useState(null)
  const [editForm, setEditForm] = useState({ name: '', game: 'HYTALE', visibility: 'Private' })
  const [access, setAccess] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [deleteInput, setDeleteInput] = useState('')
  const [adminMode, setAdminMode] = useState(false)
  const [priorScan, setPriorScan] = useState(null)
  const [form, setForm] = useState({
    name: '',
    discordId: '',
    game: state.settings.defaultGame || 'HYTALE',
    visibility: 'Private',
  })

  // Each analyst only sees the pins they own; admins see everything.
  const ownPins = useMemo(() => {
    if (state.role === 'admin') return state.pins
    const uid = state.session?.userId
    return state.pins.filter((p) => p.ownerId && p.ownerId === uid)
  }, [state.pins, state.role, state.session])

  const filtered = useMemo(() => {
    if (tab === 'shared') return []
    return ownPins.filter((p) => {
      if (query && !`${p.pin} ${p.name}`.toLowerCase().includes(query.toLowerCase())) return false
      if (statusFilter !== 'all' && p.status !== statusFilter) return false
      if (gameFilter !== 'all' && p.game !== gameFilter) return false
      if (starOnly && !p.starred) return false
      return true
    })
  }, [ownPins, query, statusFilter, gameFilter, starOnly, tab])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageRows = filtered.slice((page - 1) * pageSize, page * pageSize)
  const safePage = Math.min(page, totalPages)

  const submitCreate = () => {
    if (!form.name.trim()) {
      toast({ type: 'error', title: 'Name required' })
      return
    }
    if (!form.discordId.trim()) {
      toast({ type: 'error', title: 'Discord ID required', body: 'Enter the scanned user’s Discord ID.' })
      return
    }
    const code = generatePinCode()
    const name = form.name.trim()
    const discordId = form.discordId.trim()

    const prior = ownPins.find(
      (p) =>
        p.discordId &&
        p.discordId === discordId &&
        (p.status === 'Finished' || p.result),
    )

    dispatch({
      type: 'add-pin',
      ...form,
      name,
      discordId,
      code,
      ownerId: state.session?.userId || (state.role === 'admin' ? 'admin' : null),
    })
    const createdAt = Date.now()
    setCreated({ pin: code, name, discordId, game: form.game, visibility: form.visibility, createdAt })
    toast({ type: 'success', title: 'Pin Created', body: `Your pin ${code} has been created successfully.` })

    if (prior) {
      toast({
        type: 'success',
        title: 'User already scanned',
        body: `This Discord ID (${discordId}) was scanned before. Tap to view the previous scan results.`,
        onClick: () => setPriorScan(prior),
      })
    }

    setForm({ name: '', discordId: '', game: state.settings.defaultGame || 'HYTALE', visibility: 'Private' })
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
      product: 'ZeroTrace FiveM Scanner',
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
    a.download = `ZeroTraceScan-${c.pin}.zerotrace`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Session file downloaded', body: `ZeroTraceScan-${c.pin}.zerotrace` })
  }

  // Where the scanner exe is hosted. Defaults to the build bundled with the
  // site (same-origin → no CORS), unless an admin set a custom URL.
  const scannerBase = () => state.settings?.scannerUrl || 'ZeroTrace.exe'

  // A copy-paste link to the scanner with the PIN in the URL. If a Scanner API
  // (the bot's /scanner endpoint) is configured, the link is a real one-click
  // ZIP download with the PIN already baked in. Otherwise it falls back to a
  // static link that just carries the PIN for reference.
  const scannerLink = (c) => {
    const api = state.settings?.scannerApiUrl?.trim()
    if (api) {
      return api.replace(/\/+$/, '') + '/scanner?pin=' + encodeURIComponent(c.pin)
    }
    const abs = new URL(scannerBase(), window.location.href).href
    return abs + (abs.includes('?') ? '&' : '?') + 'pin=' + encodeURIComponent(c.pin)
  }

  // Download the scanner with the PIN baked in. The new ZeroTrace scanner
  // reads the PIN from a "zerotrace.pin" file next to the exe, so we hand the
  // player a single .zip containing ZeroTrace.exe + zerotrace.pin. On first
  // launch the PIN is pre-filled and locked.
  // If saved strings are configured, a "zerotrace.strings" file is also
  // bundled so the scanner's custom-strings module picks them up automatically.
  const downloadScannerWithPin = async (c) => {
    const base0 = scannerBase()
    // Cache-bust so the browser never serves an old scanner build.
    const url = base0 + (base0.includes('?') ? '&' : '?') + 't=' + Date.now()
    try {
      toast({ type: 'info', title: 'Preparing scanner…' })
      const res = await fetch(url, { cache: 'no-store' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const exeBytes = new Uint8Array(await res.arrayBuffer())
      const pinBytes = new TextEncoder().encode(String(c.pin))

      // Collect all saved strings visible to the current user (admins see all).
      const me = state.role === 'admin' ? 'admin' : (state.session?.userId || null)
      const savedStrings = (state.savedStrings || [])
        .map((s) => (typeof s === 'string' ? { value: s, ownerId: null } : s))
        .filter((s) => state.role === 'admin' ? true : s.ownerId === me)
        .map((s) => s.value)
        .filter((v) => v && v.length >= 3)

      const zipFiles = [
        { name: 'ZeroTrace.exe', data: exeBytes },
        { name: 'zerotrace.pin', data: pinBytes },
      ]
      if (savedStrings.length > 0) {
        const stringsBytes = new TextEncoder().encode(savedStrings.join('\n'))
        zipFiles.push({ name: 'zerotrace.strings', data: stringsBytes })
      }
      const reportUrl = state.settings?.scannerApiUrl?.trim()
      if (reportUrl) {
        const webhookUrl = reportUrl.replace(/\/+$/, '') + '/report'
        zipFiles.push({ name: 'zerotrace.webhook', data: new TextEncoder().encode(webhookUrl) })
      }

      const zip = makeZip(zipFiles)
      const a = document.createElement('a')
      a.href = URL.createObjectURL(zip)
      a.download = `ZeroTrace-${c.pin}.zip`
      a.click()
      URL.revokeObjectURL(a.href)
      toast({ type: 'success', title: 'Scanner ready', body: `PIN ${c.pin} is built in` })
    } catch (e) {
      toast({
        type: 'error',
        title: 'Could not prepare scanner',
        body: `${e.message}. Falling back to the session file.`,
      })
      downloadSession(c)
    }
  }

  // Live preview of the pasted/loaded token (null until something valid).
  const importPreview = useMemo(() => {
    if (!importText.trim()) return null
    try {
      return { ok: true, payload: decodeToken(importText) }
    } catch (e) {
      return { ok: false, error: e.message }
    }
  }, [importText])

  const onImportFile = (file) => {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setImportText(String(reader.result || ''))
    reader.readAsText(file)
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
      // The result overview is sent to the webhook automatically by
      // ScanWebhookNotifier as soon as the pin reaches "Finished".
    } catch (e) {
      toast({ type: 'error', title: 'Invalid token', body: e.message })
    }
  }

  const copyPin = (pin) => {
    navigator.clipboard?.writeText(pin).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: pin })
  }

  // Re-scan prefill: arrive from a scan result with player data, open create modal.
  useEffect(() => {
    const pre = loc.state?.prefill
    if (pre) {
      setForm((f) => ({ ...f, name: pre.name || '', discordId: pre.discordId || '', game: pre.game || f.game }))
      setCreateOpen(true)
      nav('/pins', { replace: true, state: null })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loc.state])

  const toggleSelect = (id) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))
  const allOnPageSelected = pageRows.length > 0 && pageRows.every((r) => selected.includes(r.id))
  const toggleSelectAllOnPage = () =>
    setSelected((s) =>
      allOnPageSelected
        ? s.filter((id) => !pageRows.some((r) => r.id === id))
        : [...new Set([...s, ...pageRows.map((r) => r.id)])],
    )

  const bulkDelete = () => {
    if (!selected.length) return
    if (!confirm(`Delete ${selected.length} selected pin(s)? This cannot be undone.`)) return
    dispatch({ type: 'bulk-delete-pins', ids: selected })
    toast({ type: 'success', title: `${selected.length} pins deleted` })
    setSelected([])
  }
  const bulkStar = (value) => {
    if (!selected.length) return
    dispatch({ type: 'bulk-star-pins', ids: selected, value })
    toast({ type: 'success', title: value ? 'Starred' : 'Unstarred', body: `${selected.length} pins` })
  }
  const bulkExport = () => {
    if (!selected.length) return
    const rows = state.pins.filter((p) => selected.includes(p.id))
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `zerotrace-pins-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: `${selected.length} pins exported` })
  }

  const saveCurrentFilter = () => {
    const name = prompt('Name this filter:')
    if (!name?.trim()) return
    dispatch({
      type: 'add-saved-filter',
      ownerId: uid,
      filter: { name: name.trim(), query, statusFilter, gameFilter, starOnly },
    })
    toast({ type: 'success', title: 'Filter saved', body: name.trim() })
  }
  const applyFilter = (f) => {
    setQuery(f.query || '')
    setStatusFilter(f.statusFilter || 'all')
    setGameFilter(f.gameFilter || 'all')
    setStarOnly(!!f.starOnly)
    setPage(1)
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
          className="bd txt flex items-center gap-2 rounded-xl border px-5 py-3 text-sm font-semibold transition-colors hover:border-sky-500"
        >
          <Download size={18} />
          Import Result
        </button>
      </div>

      <div className="mt-8">
        <Tabs
          tabs={[
            { label: `My Pins (${ownPins.length})`, key: 'mine' },
            { label: 'Shared with Me (0)', key: 'shared' },
          ].map((x) => x.label)}
          active={tab === 'mine' ? `My Pins (${ownPins.length})` : 'Shared with Me (0)'}
          onChange={(l) => setTab(l.startsWith('My') ? 'mine' : 'shared')}
        />
      </div>

      <div className="mt-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <PinStatCard icon={MessageSquare} label="Total Pins" value={ownPins.length} />
        <PinStatCard icon={Clock} label="Pending" value={ownPins.filter((p) => p.status === 'Pending').length} />
        <PinStatCard icon={CheckCircle2} label="Finished" value={ownPins.filter((p) => p.status === 'Finished').length} />
        <PinStatCard icon={AlertCircle} label="Expired" value={ownPins.filter((p) => p.status === 'Expired').length} />
      </div>

      {(() => {
        const recent = (state.recentlyViewed || [])
          .filter((r) => r.ownerId === uid)
          .map((r) => ownPins.find((p) => p.id === r.pinId))
          .filter(Boolean)
          .slice(0, 6)
        if (recent.length === 0) return null
        return (
          <div className="panel mt-6 rounded-2xl border p-4">
            <p className="caps-label mb-2 flex items-center gap-2"><Clock size={12} /> Recently viewed</p>
            <div className="flex flex-wrap gap-2">
              {recent.map((p) => (
                <button
                  key={p.id}
                  onClick={() => nav(`/scan/${p.id}`)}
                  className="bd tile hoverable flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs"
                >
                  <span className="txt font-mono">{p.pin}</span>
                  <span className="muted truncate max-w-[120px]">{p.name}</span>
                </button>
              ))}
            </div>
          </div>
        )
      })()}

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
            onClick={() => setStarOnly((s) => !s)}
            className={`flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm ${
              starOnly ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400' : 'bd tile txt'
            }`}
          >
            <Star size={15} className={starOnly ? 'fill-yellow-400 text-yellow-400' : 'muted'} />
            Starred
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            onClick={saveCurrentFilter}
            className="bd muted flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500"
          >
            <Bookmark size={12} /> Save filter
          </button>
          {savedFilters.map((f) => (
            <span key={f.id} className="bd tile flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs">
              <button onClick={() => applyFilter(f)} className="txt hover:text-sky-400">{f.name}</button>
              <button onClick={() => dispatch({ type: 'delete-saved-filter', id: f.id })} className="muted hover:text-red-500">
                <X size={11} />
              </button>
            </span>
          ))}
        </div>

        {selected.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2.5 text-sm">
            <span className="txt font-semibold">{selected.length} selected</span>
            <div className="flex flex-wrap gap-2 sm:ml-auto">
              <button onClick={() => bulkStar(true)} className="bd flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:border-yellow-500">
                <Star size={12} /> Star
              </button>
              <button onClick={() => bulkStar(false)} className="bd flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
                Unstar
              </button>
              <button onClick={bulkExport} className="bd flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
                <Download size={12} /> Export
              </button>
              <button onClick={bulkDelete} className="bd flex items-center gap-1 rounded-md border border-red-600/40 px-2.5 py-1 text-xs text-red-500 hover:bg-red-600/10">
                <Trash2 size={12} /> Delete
              </button>
              <button onClick={() => setSelected([])} className="muted px-2 py-1 text-xs hover:text-sky-400">
                Clear
              </button>
            </div>
          </div>
        )}

        <div className="mt-5">
          <table className="w-full table-fixed text-left">
            <colgroup>
              <col className="w-[5%]" />
              <col className="w-[14%]" />
              <col className="w-[16%]" />
              <col className="w-[11%]" />
              <col className="w-[11%]" />
              <col className="w-[8%]" />
              <col className="w-[12%]" />
              <col className="w-[12%]" />
              <col className="w-[11%]" />
            </colgroup>
            <thead>
              <tr className="caps-label bd border-b">
                <th className="px-2 py-3">
                  <input
                    type="checkbox"
                    checked={allOnPageSelected}
                    onChange={toggleSelectAllOnPage}
                    className="h-3.5 w-3.5 align-middle"
                    aria-label="Select all"
                  />
                </th>
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
                  <td colSpan={9} className="muted px-2 py-12 text-center text-sm">
                    {tab === 'shared' ? 'Nothing shared with you yet.' : 'No pins match your filters.'}
                  </td>
                </tr>
              )}
              {pageRows.map((r) => {
                const scanned = r.used || r.status === 'Finished' || !!r.result
                return (
                <tr key={r.id} className="hoverable bd border-b align-middle text-sm">
                  <td className="px-2 py-4">
                    <input
                      type="checkbox"
                      checked={selected.includes(r.id)}
                      onChange={() => toggleSelect(r.id)}
                      className="h-3.5 w-3.5 align-middle"
                      aria-label="Select pin"
                    />
                  </td>
                  <td className="txt truncate px-2 py-4 font-mono text-xs" title={r.pin}>
                    <span className="flex items-center gap-1.5">
                      <button
                        onClick={() => dispatch({ type: 'toggle-pin-star', id: r.id })}
                        title={r.starred ? 'Unstar' : 'Star'}
                        className="shrink-0"
                      >
                        <Star
                          size={13}
                          className={r.starred ? 'fill-yellow-400 text-yellow-400' : 'muted hover:text-yellow-400'}
                        />
                      </button>
                      <span className="truncate">{r.pin}</span>
                    </span>
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
                            onClick: () => nav(`/scan/${r.id}`),
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
                            disabledHint: 'A scan was already performed with this pin — use "Delete as admin".',
                            onClick: () => {
                              setAdminMode(false)
                              setDeleting(r)
                              setDeleteInput('')
                            },
                          },
                          {
                            label: 'Delete as admin',
                            icon: <Trash2 size={15} />,
                            danger: true,
                            onClick: () => {
                              setAdminMode(true)
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
            <span className="rounded-md border border-sky-600/40 bg-sky-600/15 px-3 py-1 text-sm font-medium text-sky-500">
              {safePage} / {totalPages}
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
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
            >
              Create
            </button>
          </>
        }
      >
        <div className="space-y-4">
          {(state.pinTemplates || []).length > 0 && (
            <div>
              <label className="muted mb-1.5 block text-sm">Template</label>
              <div className="flex gap-2">
                <Select
                  className="flex-1"
                  value=""
                  onChange={(v) => {
                    const tpl = (state.pinTemplates || []).find((t) => t.id === v)
                    if (tpl) setForm({ ...form, name: tpl.name || form.name, game: tpl.game || form.game, visibility: tpl.visibility || form.visibility })
                  }}
                  options={[
                    { value: '', label: '— pick a template —' },
                    ...(state.pinTemplates || []).map((t) => ({
                      value: t.id,
                      label: `${t.label} (${t.game})`,
                    })),
                  ]}
                />
              </div>
            </div>
          )}
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
            <label className="muted mb-1.5 block text-sm">Discord ID</label>
            <input
              value={form.discordId}
              onChange={(e) => {
                const raw = e.target.value
                const m = raw.match(/(\d{17,20})/)
                setForm({ ...form, discordId: m ? m[1] : raw.replace(/[^0-9]/g, '') })
              }}
              onKeyDown={(e) => e.key === 'Enter' && submitCreate()}
              placeholder="ID or paste a Discord profile link"
              className="bd tile txt w-full rounded-lg border px-4 py-2.5 font-mono text-sm focus:outline-none"
            />
            <p className="muted mt-1 text-xs">Discord ID or a profile URL — the ID is extracted automatically.</p>
          </div>
          <div>
            <label className="muted mb-1.5 block text-sm">Game</label>
            <Select
              value={form.game}
              onChange={(v) => {
                const gp = state.settings?.gameProfiles?.[v]
                setForm({ ...form, game: v, visibility: gp?.visibility || form.visibility })
              }}
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
          <div className="bd flex items-center justify-between border-t pt-3 text-xs">
            <span className="muted">Reuse these settings as a quick template</span>
            <button
              onClick={() => {
                const label = (form.name || form.game || 'Template').trim()
                dispatch({
                  type: 'add-pin-template',
                  template: { label, game: form.game, visibility: form.visibility, name: form.name },
                })
                toast({ type: 'success', title: 'Template saved', body: label })
              }}
              className="bd txt rounded-md border px-2.5 py-1 hover:border-sky-500"
            >
              Save as template
            </button>
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
                className="bd txt flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:border-sky-500"
              >
                <Copy size={15} /> Copy
              </button>
            </div>

            <div className="tile rounded-xl border p-4">
              <p className="txt mb-3 text-sm font-semibold">Send the scanner to the player</p>

              <button
                onClick={() => downloadScannerWithPin(created)}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-3 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
              >
                <Download size={15} /> Download Scanner (PIN built in)
              </button>
              <p className="muted mt-2 text-xs">
                One archive: <span className="txt font-mono">ZeroTrace-{created.pin}.zip</span> — it contains{' '}
                <span className="txt font-mono">ZeroTrace.exe</span> and a{' '}
                <span className="txt font-mono">zerotrace.pin</span> file. The player extracts both into the same
                folder and runs <span className="txt font-mono">ZeroTrace.exe</span> — the PIN is pre-filled and
                locked. Requires the{' '}
                <a
                  href="https://dotnet.microsoft.com/download/dotnet/8.0"
                  target="_blank"
                  rel="noreferrer"
                  className="text-sky-400 underline-offset-2 hover:underline"
                >
                  .NET 8 Desktop Runtime
                </a>
                . Their result token comes back to you → paste it under{' '}
                <span className="txt">Import Result</span>.
              </p>

              <div className="mt-4">
                <p className="txt mb-1.5 text-xs font-semibold">Or copy a download link (PIN in the URL)</p>
                <div className="flex items-center gap-2">
                  <input
                    readOnly
                    value={scannerLink(created)}
                    onFocus={(e) => e.target.select()}
                    className="bd txt min-w-0 flex-1 rounded-lg border bg-transparent px-3 py-2 font-mono text-xs"
                  />
                  <button
                    onClick={() => copyText(scannerLink(created), 'Scanner link')}
                    className="bd txt flex shrink-0 items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:border-sky-500"
                  >
                    <Link2 size={15} /> Copy
                  </button>
                </div>
                <p className="muted mt-1.5 text-xs">
                  {state.settings?.scannerApiUrl?.trim()
                    ? 'One-click download via your Scanner API — the ZIP comes with the PIN already baked in.'
                    : 'Static link carrying the PIN for reference. Set a Scanner API URL in Settings to make this a one-click download with the PIN built in.'}
                </p>
              </div>

              <button
                onClick={() => downloadSession(created)}
                className="muted mt-3 text-xs underline-offset-2 hover:underline"
              >
                Or download the .zerotrace session file instead
              </button>
            </div>

            <div className="tile rounded-xl border p-4">
              <p className="txt mb-3 text-sm font-semibold">Pin Details</p>
              {[
                ['Game', created.game],
                ['Pin Name', created.name],
                ['Discord ID', created.discordId],
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
                  <div className="h-full w-0 rounded-full bg-sky-600" />
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
              disabled={!importPreview?.ok}
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-40"
            >
              Import
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="muted text-sm">
            Paste the <code className="txt">ZEROTRACE1.…</code> token produced by the scanner — or load a{' '}
            <code className="txt">.zerotrace</code> session file. It’s matched to its session code and updates
            the pin, dashboard and activity log with the real scan data.
          </p>

          <label
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); onImportFile(e.dataTransfer.files[0]) }}
            className="bd tile flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed py-3 text-xs hover:border-sky-500"
          >
            <input
              type="file"
              accept=".zerotrace,.ocean,.txt,.json,application/json,text/plain"
              className="hidden"
              onChange={(e) => e.target.files[0] && onImportFile(e.target.files[0])}
            />
            <Download size={14} className="muted" /> Drop a .zerotrace file here or click to load
          </label>

          <textarea
            autoFocus
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="ZEROTRACE1.eyJ2IjoxLCJjb2RlIjoi..."
            rows={5}
            className="bd tile txt w-full rounded-lg border p-3 font-mono text-xs focus:outline-none"
          />

          {importPreview && (
            importPreview.ok ? (
              <div className="rounded-lg border border-green-600/40 bg-green-600/10 p-3 text-xs">
                <p className="font-semibold text-green-400">Valid token ✓</p>
                <div className="muted mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5">
                  <span>Pin: <span className="txt font-mono">{importPreview.payload.code}</span></span>
                  <span>Verdict: <span className="txt">{importPreview.payload.verdict || '—'}</span></span>
                  <span>Detections: <span className="txt">{(importPreview.payload.detections || []).length}</span></span>
                  <span>Game: <span className="txt">{importPreview.payload.game || '—'}</span></span>
                  {importPreview.payload.host && <span className="col-span-2 break-all">Host: <span className="txt">{importPreview.payload.host}</span></span>}
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-red-600/40 bg-red-600/10 p-3 text-xs text-red-400">
                {importPreview.error}
              </div>
            )
          )}
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
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
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
                          ? 'border-sky-600/50 bg-sky-600/15 text-sky-400'
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
                  className="bd txt flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs hover:border-sky-500"
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
        onClose={() => { setDeleting(null); setAdminMode(false) }}
        title={adminMode ? 'Delete Pin (Admin)' : 'Delete Pin'}
        footer={
          deleting && (
            <button
              disabled={deleteInput.trim() !== deleting.pin}
              onClick={() => {
                dispatch({ type: adminMode ? 'admin-delete-pin' : 'delete-pin', id: deleting.id, pin: deleting.pin })
                toast({ type: 'success', title: 'Pin deleted', body: deleting.pin })
                setDeleting(null)
                setAdminMode(false)
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
            {adminMode && (
              <p className="rounded-lg border border-red-600/40 bg-red-600/10 px-3 py-2 text-xs text-red-400">
                Admin delete — this pin was already used for a scan. Deleting it also removes its
                scan results. This cannot be undone.
              </p>
            )}
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
                    dispatch({ type: adminMode ? 'admin-delete-pin' : 'delete-pin', id: deleting.id, pin: deleting.pin })
                    toast({ type: 'success', title: 'Pin deleted', body: deleting.pin })
                    setDeleting(null)
                    setAdminMode(false)
                  }
                }}
                placeholder={deleting.pin}
                className="bd tile txt w-full rounded-lg border px-4 py-3 font-mono text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500/40"
              />
              <p className="muted mt-2 text-xs">
                Pin Code: <span className="txt font-mono">{deleting.pin}</span>
              </p>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={!!priorScan}
        onClose={() => setPriorScan(null)}
        title="Previous Scan Found"
        footer={
          priorScan && (
            <>
              <button
                onClick={() => setPriorScan(null)}
                className="bd txt rounded-lg border px-4 py-2 text-sm"
              >
                Close
              </button>
              <button
                onClick={() => {
                  const id = priorScan.id
                  setPriorScan(null)
                  nav(`/scan/${id}`)
                }}
                className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
              >
                Open full results
              </button>
            </>
          )
        }
      >
        {priorScan &&
          (() => {
            const rep = deriveScanReport(priorScan)
            const tone =
              priorScan.result === 'Cheating'
                ? 'text-red-500'
                : priorScan.result === 'Suspicious'
                  ? 'text-yellow-500'
                  : 'text-green-500'
            return (
              <div className="space-y-4">
                <p className="muted text-sm">
                  This Discord ID was already scanned. Here are the results of the previous scan.
                </p>
                <div className="tile rounded-xl border p-4">
                  {[
                    ['Pin', <span className="font-mono">{priorScan.pin}</span>],
                    ['Name', priorScan.name],
                    ['Discord ID', <span className="font-mono">{priorScan.discordId}</span>],
                    ['Game', priorScan.game],
                    [
                      'Result',
                      <span className={`font-semibold ${tone}`}>
                        {(priorScan.result || '—').toUpperCase()}
                      </span>,
                    ],
                    ['Scanned', priorScan.scannedAt ? new Date(priorScan.scannedAt).toLocaleString() : '—'],
                  ].map(([k, v], i) => (
                    <div
                      key={i}
                      className="bd flex items-center justify-between border-b py-2.5 text-sm last:border-0"
                    >
                      <span className="muted">{k}</span>
                      <span className="txt">{v}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <p className="caps-label mb-2">
                    Detections ({rep ? rep.detects.length : 0})
                  </p>
                  {rep && rep.detects.length > 0 ? (
                    <div className="bd tile max-h-48 divide-y divide-[var(--border)] overflow-y-auto rounded-lg border">
                      {rep.detects.map((d, i) => (
                        <div key={i} className="px-3 py-2">
                          <div className="flex items-center justify-between">
                            <span className="txt text-sm font-medium">{d.name}</span>
                            <span className="text-xs font-semibold text-red-500">{d.severity}</span>
                          </div>
                          <p className="muted mt-0.5 text-xs">{d.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted text-sm">No detections in the previous scan.</p>
                  )}
                </div>
              </div>
            )
          })()}
      </Modal>

    </div>
  )
}
