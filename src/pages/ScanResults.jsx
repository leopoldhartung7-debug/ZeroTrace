import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { lookupIp } from '../lib/geo.js'
import {
  ArrowLeft, Copy, ShieldAlert, Download, Flag, Gauge, Monitor, Cpu,
  AlertTriangle, CheckCircle2, Eye, EyeOff, Sparkles, Search, ChevronLeft,
  ChevronRight, Shield, MessageSquare, Video, Gamepad2, Database, Activity,
  Clock, ImageOff, Usb, FileText, Server, RefreshCw, Image as ImageIcon,
  Trash2, Bell, Layers, ScanLine, Users, Globe, History, Terminal, Package,
  Zap, Key, Clipboard, FolderOpen,
} from 'lucide-react'
import { Card } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore, deriveScanReport, decodeScanToken } from '../store.jsx'

function ago(ts) {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `about ${Math.floor(s / 60)} min ago`
  if (s < 86400) return `about ${Math.floor(s / 3600)} hours ago`
  return `${Math.floor(s / 86400)}d ago`
}

function KV({ color, label, value }) {
  return (
    <div className="bd flex items-center justify-between border-b py-3.5 text-sm last:border-0">
      <span className="muted flex items-center gap-2.5">
        <span className="h-2 w-2 rounded-full" style={{ background: color }} />
        {label}
      </span>
      <span className="txt font-medium">{value}</span>
    </div>
  )
}

function PaginatedTable({ columns, rows, render, searchKeys, placeholder, empty }) {
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(10)
  const filtered = useMemo(() => {
    if (!q) return rows
    const l = q.toLowerCase()
    return rows.filter((r) => searchKeys.some((k) => String(r[k] ?? '').toLowerCase().includes(l)))
  }, [rows, q, searchKeys])
  const pages = Math.max(1, Math.ceil(filtered.length / size))
  const p = Math.min(page, pages)
  const slice = filtered.slice((p - 1) * size, p * size)

  if (rows.length === 0)
    return <p className="muted py-12 text-center text-sm">{empty}</p>

  return (
    <div>
      <div className="relative mb-4">
        <Search size={15} className="muted absolute left-3.5 top-1/2 -translate-y-1/2" />
        <input
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPage(1)
          }}
          placeholder={placeholder}
          className="bd tile txt w-full rounded-lg border py-2.5 pl-10 pr-4 text-sm focus:outline-none"
        />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="caps-label bd border-b">
              {columns.map((c) => (
                <th key={c} className="px-3 py-3 font-semibold">{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((r, i) => (
              <tr key={i} className="bd border-b last:border-0">
                {render(r)}
              </tr>
            ))}
            {slice.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="muted px-3 py-8 text-center">
                  No matches.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="muted mt-4 flex items-center justify-between text-sm">
        <span>
          Show <span className="txt">{filtered.length ? (p - 1) * size + 1 : 0}-{Math.min(p * size, filtered.length)}</span> of{' '}
          <span className="txt">{filtered.length}</span>
        </span>
        <div className="flex items-center gap-2">
          <button onClick={() => setPage(Math.max(1, p - 1))} disabled={p <= 1} className="bd rounded-md border p-1.5 disabled:opacity-40">
            <ChevronLeft size={14} />
          </button>
          <span className="rounded-md border border-sky-600/40 bg-sky-600/15 px-3 py-1 text-sky-500">{p} / {pages}</span>
          <button onClick={() => setPage(Math.min(pages, p + 1))} disabled={p >= pages} className="bd rounded-md border p-1.5 disabled:opacity-40">
            <ChevronRight size={14} />
          </button>
          <Select
            className="ml-2 w-28"
            value={String(size)}
            onChange={(v) => { setSize(Number(v)); setPage(1) }}
            options={[
              { value: '10', label: '10 / page' },
              { value: '25', label: '25 / page' },
              { value: '50', label: '50 / page' },
            ]}
          />
        </div>
      </div>
    </div>
  )
}


export default function ScanResults() {
  const { id } = useParams()
  const nav = useNavigate()
  const { state, dispatch } = useStore()
  const toast = useToast()
  const raw = state.pins.find((p) => p.id === id)
  const pin =
    raw && (state.role === 'admin' || raw.ownerId === state.session?.userId)
      ? raw
      : null
  const [cat, setCat] = useState(null)
  const [risk, setRisk] = useState(false)
  const [tokenInput, setTokenInput] = useState('')

  const report = useMemo(
    () => (pin && pin.status === 'Finished' ? deriveScanReport(pin) : null),
    [pin],
  )

  // Track recently viewed pins for the quick-access bar on the Pins page.
  useEffect(() => {
    if (pin) dispatch({ type: 'push-recent-pin', pinId: pin.id, ownerId: state.session?.userId || null })
  }, [pin?.id, dispatch])

  useEffect(() => {
    if (!pin || !report || !report.pc.ip || report.pc.ip === '—' || pin.geo) return
    let alive = true
    lookupIp(report.pc.ip).then((g) => {
      if (alive && g) dispatch({ type: 'set-pin-geo', id: pin.id, geo: g })
    })
    return () => {
      alive = false
    }
  }, [pin, report, dispatch])

  if (!pin) {
    return (
      <div className="py-20 text-center">
        <p className="txt text-lg font-semibold">Pin not found</p>
        <button onClick={() => nav('/pins')} className="mt-4 rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white">
          Back to Pins
        </button>
      </div>
    )
  }

  if (!report) {
    const loadToken = () => {
      try {
        const payload = decodeScanToken(tokenInput)
        if (payload.code && pin.pin && payload.code.toUpperCase() !== pin.pin.toUpperCase()) {
          toast({ type: 'error', title: 'Token belongs to another pin', body: `Token PIN: ${payload.code}` })
          return
        }
        dispatch({ type: 'import-scan', payload })
        toast({ type: 'success', title: 'Result loaded', body: pin.pin })
        setTokenInput('')
      } catch (e) {
        toast({ type: 'error', title: 'Invalid token', body: e.message })
      }
    }
    return (
      <div>
        <button onClick={() => nav('/pins')} className="muted hover:txt mb-6 flex items-center gap-2 text-sm">
          <ArrowLeft size={16} /> Back to Pins
        </button>
        <Card className="p-6 sm:p-8">
          <div className="flex flex-col items-center text-center">
            <Clock size={36} className="muted" />
            <p className="txt mt-4 text-lg font-semibold">Waiting for the scan result</p>
            <p className="muted mt-1 max-w-md text-sm">
              The player runs the ZeroTrace Checker, accepts the consent prompt and sends you their
              result token. Paste that <span className="txt font-mono">ZEROTRACE1.…</span> token here to load the report.
            </p>
          </div>
          <textarea
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="ZEROTRACE1.eyJ2IjoxLCJjb2RlIjoi..."
            rows={5}
            className="bd tile txt mt-6 w-full rounded-lg border p-3 font-mono text-xs focus:outline-none"
          />
          <div className="mt-3 flex justify-end">
            <button
              onClick={loadToken}
              disabled={!tokenInput.trim()}
              className="flex items-center gap-2 rounded-lg bg-sky-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-40"
            >
              <ScanLine size={16} /> Load result
            </button>
          </div>
        </Card>
      </div>
    )
  }

  const verdictTone =
    pin.result === 'Cheating'
      ? { box: 'border-red-900/50 bg-red-950/30', txt: 'text-red-500', word: 'cheating' }
      : pin.result === 'Suspicious'
        ? { box: 'border-yellow-900/50 bg-yellow-950/20', txt: 'text-yellow-500', word: 'suspicious' }
        : { box: 'border-green-900/50 bg-green-950/20', txt: 'text-green-500', word: 'clean' }

  const scannedLabel = report.scannedAt
    ? new Date(report.scannedAt).toLocaleString()
    : '—'
  const cats = [
    { key: 'detects', label: 'Detects Logs', n: report.counts.detects, icon: AlertTriangle, tone: 'text-red-500', badge: 'border-red-600/40 bg-red-600/15 text-red-500' },
    { key: 'integrity', label: 'Integrity Logs', n: report.counts.integrity, icon: CheckCircle2, tone: 'text-green-500', badge: 'border-green-600/40 bg-green-600/15 text-green-500' },
    { key: 'warnings', label: 'Warnings Logs', n: report.counts.warnings, icon: AlertTriangle, tone: 'text-yellow-400', badge: 'border-sky-600/40 bg-sky-600/15 text-sky-400' },
    { key: 'suspicious', label: 'Suspicious logs', n: report.counts.suspicious, icon: Eye, tone: 'text-sky-400', badge: 'bd txt' },
  ]
  const riskScore = Math.min(
    100,
    report.counts.detects * 8 + report.counts.warnings * 2 + report.counts.suspicious * 5,
  )

  const exportReport = () => {
    const blob = new Blob([JSON.stringify({ pin: pin.pin, result: pin.result, report }, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `scan-${pin.pin}.json`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Report exported' })
  }

  const watching = (state.watchlist || []).some(
    (w) => w.discordId === pin.discordId && w.ownerId === (state.session?.userId || null),
  )
  const toggleWatch = () => {
    if (!pin.discordId) {
      toast({ type: 'error', title: 'No Discord ID on this pin' })
      return
    }
    if (watching) {
      const entry = (state.watchlist || []).find(
        (w) => w.discordId === pin.discordId && w.ownerId === (state.session?.userId || null),
      )
      if (entry) dispatch({ type: 'remove-watchlist', id: entry.id })
      toast({ type: 'success', title: 'Stopped watching', body: pin.discordId })
    } else {
      dispatch({ type: 'add-watchlist', discordId: pin.discordId, ownerId: state.session?.userId || null, note: pin.name || '' })
      toast({ type: 'success', title: 'Now watching', body: pin.discordId })
    }
  }

  const reScan = () => {
    nav('/pins', { state: { prefill: { name: pin.name || '', discordId: pin.discordId || '', game: pin.game || 'HYTALE' } } })
  }

  const copyVerdict = () => {
    const emoji = pin.result === 'Cheating' ? '❌' : pin.result === 'Suspicious' ? '⚠️' : '✅'
    const cheats = (pin.cheats || []).join(', ') || '—'
    const text =
      `${emoji} ZeroTrace Scan — ${pin.result || 'Unknown'}\n` +
      `Player: ${pin.name || '—'}${pin.discordId ? ` (Discord: ${pin.discordId})` : ''}\n` +
      `Game: ${pin.game}\n` +
      (report ? `Detections: ${report.counts.detects} · Warnings: ${report.counts.warnings} · Suspicious: ${report.counts.suspicious}\n` : '') +
      `Cheats: ${cheats}\n` +
      `Risk: ${riskScore}/100`
    navigator.clipboard?.writeText(text).catch(() => {})
    toast({ type: 'success', title: 'Verdict copied', body: 'Paste it into Discord' })
  }

  // Auto-suggested verdict from raw counts (independent of stored result).
  const suggestedVerdict =
    report && report.counts.detects > 0
      ? 'Cheating'
      : report && (report.counts.warnings > 0 || report.counts.suspicious >= 3)
        ? 'Suspicious'
        : 'Clean'

  const SignedBadge = ({ ok }) => (
    <span className={`bd inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${ok ? 'text-green-500' : 'muted'}`}>
      <Shield size={11} /> {ok ? 'SIGNED' : 'UNSIGNED'}
    </span>
  )

  const SeverityBadge = ({ sev }) => {
    const cls = sev === 'Critical' || sev === 'High'
      ? 'border-red-600/40 bg-red-600/15 text-red-500'
      : sev === 'Medium'
        ? 'border-yellow-500/40 bg-yellow-500/15 text-yellow-400'
        : 'bd muted'
    return (
      <span className={`shrink-0 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${cls}`}>
        {sev}
      </span>
    )
  }

  const ModuleFindingsList = ({ findings }) =>
    findings.length === 0 ? null : (
      <div className="space-y-2">
        {findings.map((m, i) => (
          <div key={i} className="tile rounded-lg border px-4 py-3">
            <div className="flex items-center justify-between gap-2">
              <p className="txt min-w-0 truncate text-sm font-medium">{m.name}</p>
              <SeverityBadge sev={m.severity} />
            </div>
            {m.location && <p className="muted mt-1 break-all font-mono text-xs">{m.location}</p>}
            {m.detail && <p className="muted mt-1 text-xs leading-relaxed">{m.detail}</p>}
          </div>
        ))}
      </div>
    )

  return (
    <div className="space-y-6">
      <button onClick={() => nav('/pins')} className="muted hover:txt flex items-center gap-2 text-sm">
        <ArrowLeft size={16} /> Back to Pins
      </button>

      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="txt text-3xl font-bold tracking-tight">Scan Results</h1>
            <span className="rounded-md border border-sky-600/40 bg-sky-600/15 px-2.5 py-1 text-xs font-semibold text-sky-400">
              Game: {pin.game}
            </span>
            <span className="rounded-md border border-red-600/40 bg-red-600/15 px-2.5 py-1 text-xs font-semibold text-red-400">
              AI: {report.ai}
            </span>
          </div>
          <p className="muted mt-2 text-sm">Here you can see the results of the scans you have done.</p>
          <p className="muted mt-3 text-sm">
            Pin:{' '}
            <button
              onClick={() => {
                navigator.clipboard?.writeText(pin.pin)
                toast({ type: 'success', title: 'Copied', body: pin.pin })
              }}
              className="txt font-mono hover:text-sky-500"
            >
              {pin.pin} <Copy size={12} className="inline" />
            </button>
          </p>
        </div>
        <div className="flex flex-wrap gap-2 print:hidden">
          <button onClick={() => setRisk(true)} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500">
            <Gauge size={15} /> Check Risk Score
          </button>
          <button onClick={copyVerdict} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500">
            <Copy size={15} /> Copy Verdict
          </button>
          <button onClick={reScan} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500">
            <RefreshCw size={15} /> Re-scan
          </button>
          <button onClick={toggleWatch} className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-sm ${watching ? 'border-sky-500/50 bg-sky-500/10 text-sky-400' : 'bd txt hover:border-sky-500'}`}>
            <Bell size={15} /> {watching ? 'Watching' : 'Watch player'}
          </button>
          <button onClick={exportReport} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500">
            <Download size={15} /> Export
          </button>
          <button onClick={() => window.print()} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500">
            <FileText size={15} /> Print / PDF
          </button>
        </div>
      </div>

      {(() => {
        if (!pin.hwid) return null
        const alt = state.pins.find(
          (x) => x.id !== pin.id && x.hwid === pin.hwid && x.discordId && pin.discordId && x.discordId !== pin.discordId,
        )
        if (!alt) return null
        return (
          <div className="mb-6 rounded-xl border border-orange-500/40 bg-orange-500/10 p-4 text-sm">
            <p className="text-orange-300">
              <span className="font-semibold">Possible alt account detected.</span>{' '}
              The same HWID <span className="font-mono">{pin.hwid}</span> was previously scanned under
              Discord ID <span className="font-mono">{alt.discordId}</span> (pin <span className="font-mono">{alt.pin}</span>).
            </p>
          </div>
        )
      })()}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className={`flex items-center justify-center rounded-2xl border py-6 ${verdictTone.box}`}>
          <p className="txt text-lg">
            This user is <span className={`font-semibold ${verdictTone.txt}`}>{verdictTone.word}</span>
          </p>
        </div>
        <div className="panel flex items-center justify-center rounded-2xl border py-6">
          <p className="muted flex items-center gap-2 text-sm">
            <span className="h-2 w-2 rounded-full bg-sky-500" /> Scanned: {scannedLabel}
          </p>
        </div>
      </div>

      {report && suggestedVerdict !== pin.result && (
        <div className="flex items-start gap-3 rounded-xl border border-sky-500/40 bg-sky-500/10 p-4 text-sm print:hidden">
          <Sparkles size={16} className="mt-0.5 shrink-0 text-sky-400" />
          <p className="text-sky-100">
            <span className="font-semibold">Suggested verdict: {suggestedVerdict}.</span>{' '}
            Based on {report.counts.detects} detection(s), {report.counts.warnings} warning(s) and {report.counts.suspicious} suspicious log(s).
            {pin.result ? ` Current verdict is "${pin.result}".` : ''}
          </p>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <div className="mb-4 flex items-center gap-3">
            <Monitor size={20} className="text-sky-500" />
            <div>
              <h2 className="txt text-lg font-semibold">Pin Details</h2>
              <p className="muted text-xs">Information about the pin details</p>
            </div>
          </div>
          <KV color="#22c55e" label="Created" value={ago(pin.createdAt)} />
          {pin.discordId && <KV color="#6366f1" label="Discord ID" value={pin.discordId} />}
          <KV color="#a855f7" label="Visibility" value={pin.visibility} />
          <KV color="#eab308" label="Status" value={pin.status.toUpperCase()} />
          <KV color="#f97316" label="Used" value={pin.used ? 'Yes' : 'No'} />
          <SteamIdRow pin={pin} dispatch={dispatch} toast={toast} />
          <AssignmentRow pin={pin} state={state} dispatch={dispatch} toast={toast} />
        </Card>

        <Card className="p-6">
          <div className="mb-4 flex items-center gap-3">
            <Monitor size={20} className="text-sky-500" />
            <div>
              <h2 className="txt text-lg font-semibold">PC Information</h2>
              <p className="muted text-xs">Information about the users PC</p>
            </div>
          </div>
          <KV color="#848eb0" label="System" value={report.pc.system} />
          <KV
            color="#ec4899"
            label="IP Address"
            value={
              report.pc.ip && pin.geo
                ? `${report.pc.ip} · ${pin.geo.country || ''}${pin.geo.city ? ' / ' + pin.geo.city : ''}${pin.geo.isp ? ' (' + pin.geo.isp + ')' : ''}`
                : report.pc.ip
            }
          />
          <KV color="#14b8a6" label="HWID" value={pin.hwid || '—'} />
          <KV color="#22c55e" label="Boot Time" value={report.pc.bootTime} />
          <KV color="#ef4444" label="VPN" value={report.pc.vpn} />
          <KV color="#a855f7" label="Install Date" value={report.pc.installDate} />
          <KV color="#f97316" label="Country" value={report.pc.country} />
          <KV color="#22c55e" label="Game" value={report.pc.game} />
          {report.pc.hardware ? (
            <>
              <KV color="#848eb0" label="CPU" value={report.pc.hardware.cpu || '—'} />
              <KV color="#848eb0" label="RAM" value={report.pc.hardware.ram || '—'} />
              <KV color="#848eb0" label="GPU" value={report.pc.hardware.gpu || '—'} />
            </>
          ) : (
            <KV color="#848eb0" label="Hardware Stats" value="Not available" />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
        <Card className="p-6">
          <div className="mb-1 flex items-center gap-2">
            <Shield size={20} className="txt" />
            <h2 className="txt text-lg font-semibold">Detection Results</h2>
          </div>
          <p className="muted mb-4 text-sm">
            {report.counts.detects + report.counts.integrity + report.counts.warnings + report.counts.suspicious}{' '}
            total logs found across 4 categories
          </p>
          <div className="space-y-1">
            {cats.map((c) => (
              <button
                key={c.key}
                onClick={() => setCat(c.key)}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-3 text-sm ${
                  cat === c.key ? 'bg-sky-600/15' : 'hoverable'
                }`}
              >
                <span className="txt flex items-center gap-3">
                  <c.icon size={16} className={c.tone} /> {c.label}
                </span>
                <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${c.badge}`}>{c.n}</span>
              </button>
            ))}
            <div className="bd mt-1 flex items-center justify-between border-t px-3 py-3 text-sm">
              <span className="flex items-center gap-3 font-medium text-purple-400">
                <Sparkles size={16} /> AI Opinion
              </span>
              <span className="rounded-md border border-purple-600/40 bg-purple-600/15 px-2 py-0.5 text-xs font-semibold text-purple-400">AI</span>
            </div>
            <button
              onClick={() => setCat('ai')}
              className={`mt-1 w-full rounded-lg px-3 py-2 text-left text-xs ${cat === 'ai' ? 'bg-purple-600/15 text-purple-300' : 'muted hoverable'}`}
            >
              View AI opinion
            </button>
          </div>
        </Card>

        <Card className="p-6">
          {!cat ? (
            <div className="flex h-full min-h-[260px] flex-col items-center justify-center text-center">
              <Eye size={28} className="muted" />
              <p className="txt mt-4 text-lg font-semibold">Select a Detection Category</p>
              <p className="muted mt-1 text-sm">Choose a category from the sidebar to view detailed results</p>
            </div>
          ) : cat === 'ai' ? (
            <div>
              <p className="caps-label">AI Opinion</p>
              <h3 className="txt mb-3 mt-1 text-lg font-semibold">Automated assessment</h3>
              <p className="muted text-sm leading-relaxed">{report.aiOpinion}</p>
            </div>
          ) : (
            (() => {
              const CS = {
                detects: { accent: '#dc2626', Icon: AlertTriangle, title: 'Detects Logs', badge: 'Boot instance', bcls: 'border-red-600/40 bg-red-600/15 text-red-500' },
                integrity: { accent: '#22c55e', Icon: CheckCircle2, title: 'Integrity Logs', badge: 'Boot instance', bcls: 'border-green-600/40 bg-green-600/15 text-green-500' },
                warnings: { accent: '#eab308', Icon: AlertTriangle, title: 'Warnings Logs', badge: 'Warning', bcls: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500' },
                suspicious: { accent: '#848eb0', Icon: Eye, title: 'Suspicious logs', badge: 'Suspicious', bcls: 'border-sky-600/40 bg-sky-600/15 text-sky-400' },
              }
              const cs = CS[cat]
              const copyDetail = (t) => {
                navigator.clipboard?.writeText(t)
                toast({ type: 'success', title: 'Copied' })
              }
              return (
                <div>
                  <h3 className="txt flex items-center gap-3 text-2xl font-bold">
                    <cs.Icon size={24} style={{ color: cs.accent }} /> {cs.title}
                  </h3>
                  {report[cat].length === 0 ? (
                    <p className="muted py-10 text-center text-sm">Nothing found in this category.</p>
                  ) : (
                    <div className="mt-4 max-h-[560px] space-y-2 overflow-y-auto pr-1">
                      {report[cat].map((l, i) => (
                        <div
                          key={i}
                          className="rounded-xl border border-white/5 bg-white/[0.02] px-3.5 py-3"
                          style={{ borderLeft: `3px solid ${cs.accent}` }}
                        >
                          {/* Header row: icon + title + actions */}
                          <div className="flex items-center gap-2.5">
                            <span
                              className="grid h-7 w-7 shrink-0 place-items-center rounded-lg"
                              style={{ background: `${cs.accent}1f`, color: cs.accent }}
                            >
                              <cs.Icon size={14} />
                            </span>
                            <p className="txt min-w-0 flex-1 truncate text-sm font-semibold">{l.name}</p>
                            <span className={`shrink-0 rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${cs.bcls}`}>
                              {l.severity || cs.badge}
                            </span>
                            <button
                              onClick={() => copyDetail(`${l.name} — ${l.detail}`)}
                              className="bd muted hover:txt grid h-6 w-6 shrink-0 place-items-center rounded-md border"
                              title="Copy"
                            >
                              <Copy size={11} />
                            </button>
                          </div>
                          {/* Inline meta row: location + evidence on one line each */}
                          {l.location && (
                            <p className="mt-2 flex items-start gap-2 break-all font-mono text-[11px] leading-snug">
                              <span className="caps-label muted mt-0.5 shrink-0 text-[9px]">LOC</span>
                              <span style={{ color: cs.accent }}>{l.location}</span>
                            </p>
                          )}
                          <p className="muted mt-1 flex items-start gap-2 break-all font-mono text-[11px] leading-snug">
                            <span className="caps-label mt-0.5 shrink-0 text-[9px]">EVI</span>
                            <span>
                              {l.detail}
                              {l.time ? ` · ${l.time}` : ''}
                            </span>
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })()
          )}
        </Card>
      </div>

      <CaseStatusCard pin={pin} dispatch={dispatch} toast={toast} />

      <Card className="p-6">
        <p className="caps-label">Admin-Executed Applications</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Shield size={18} /> Admin-Executed Applications
        </h2>
        <p className="muted mt-1 text-sm">Applications launched with administrator privileges during the scan window</p>
        <p className="muted mb-4 mt-1 text-xs">
          {report.adminApps.filter((a) => a.verdict === 'SUSPICIOUS').length} suspicious · {report.adminApps.length} total
        </p>
        {report.adminApps.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No admin-executed applications recorded.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-3 py-3">Path</th>
                  <th className="px-3 py-3">Executed At</th>
                  <th className="px-3 py-3">Signed</th>
                  <th className="px-3 py-3">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {report.adminApps.map((a, i) => (
                  <tr key={i} className="bd border-b last:border-0">
                    <td className="txt break-all px-3 py-3 font-mono text-xs">{a.path}</td>
                    <td className="muted px-3 py-3 text-xs">{a.executedAt}</td>
                    <td className="px-3 py-3"><SignedBadge ok={a.signed} /></td>
                    <td className="px-3 py-3">
                      <span className={`bd inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${a.verdict === 'SUSPICIOUS' ? 'text-red-500' : 'muted'}`}>
                        {a.verdict}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Cpu size={18} /> Boot sequence
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Recorded boot sequence detail for this machine.</p>
        {report.boot ? (
          <>
            <div className="mb-5 grid gap-3 sm:grid-cols-2">
              {[
                ['BIOS VENDOR', report.boot.biosVendor],
                ['BIOS VERSION', report.boot.biosVersion],
                ['BOARD MANUFACTURER', report.boot.boardManufacturer],
                ['BOARD PRODUCT', report.boot.boardProduct],
                ['BOARD VERSION', report.boot.boardVersion],
              ].map(([k, v]) => (
                <div key={k} className="tile rounded-lg border p-3">
                  <p className="caps-label">{k}</p>
                  <p className="txt mt-1 font-mono text-sm">{v}</p>
                </div>
              ))}
            </div>
            <p className="caps-label mb-3">Measured Boot Chain</p>
            <PaginatedTable
              columns={['Load Position', 'Image', 'Load Address', 'Disk ID', 'Drive Type', 'Size (KB)']}
              rows={report.boot.chain}
              searchKeys={['image', 'diskId']}
              placeholder="Search chain..."
              empty="No boot chain recorded."
              render={(r) => (
                <>
                  <td className="txt px-3 py-3">{r.pos}</td>
                  <td className="txt break-all px-3 py-3 font-mono text-xs">{r.image}</td>
                  <td className="muted px-3 py-3 font-mono text-xs">{r.loadAddress}</td>
                  <td className="muted break-all px-3 py-3 font-mono text-xs">{r.diskId}</td>
                  <td className="muted px-3 py-3">{r.driveType}</td>
                  <td className="muted px-3 py-3">{r.sizeKb}</td>
                </>
              )}
            />
          </>
        ) : (
          <p className="muted py-12 text-center text-sm">No boot sequence recorded.</p>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Accounts</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Shield size={18} /> Accounts ({report.accounts.length})
          </h2>
          <p className="muted mt-1 text-sm">Alternative accounts detected</p>
          {report.accounts.length === 0 ? (
            <p className="muted py-12 text-center text-sm">No alternative accounts found</p>
          ) : null}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Discord Accounts</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <MessageSquare size={18} /> Discord Accounts ({report.discord.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">Discord accounts detected on this system</p>
          {report.discord.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No Discord accounts found</p>
          ) : (
            <div className="space-y-2">
              {report.discord.map((d) => (
                <div key={d.id} className="tile flex items-center gap-3 rounded-lg border px-4 py-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-sky-600 text-xs font-bold text-white">
                    {d.name[0].toUpperCase()}
                  </span>
                  <div>
                    <p className="txt text-sm font-medium">
                      <span className="mr-1 text-green-500">●</span>{d.name}
                    </p>
                    <p className="muted font-mono text-xs">ID: {d.id}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card className="p-6">
        <p className="caps-label">Discord Server</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Server size={18} /> Discord Server ({report.discordServers.length})
        </h2>
        <p className="muted mt-1 text-sm">
          Servers the scanned Discord account is in — reselling and cheat servers are flagged
        </p>
        <p className="muted mb-4 mt-1 text-xs">
          {report.discordServers.filter((g) => g.flag !== 'clean').length} flagged ·{' '}
          {report.discordServers.length} total
        </p>
        {report.discordServers.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No Discord servers found</p>
        ) : (
          <div className="space-y-2">
            {[...report.discordServers]
              .sort((a, b) => (a.flag === 'clean' ? 1 : 0) - (b.flag === 'clean' ? 1 : 0))
              .map((g, i) => {
                const tone =
                  g.flag === 'cheat'
                    ? 'border-red-600/40 bg-red-600/15 text-red-500'
                    : g.flag === 'reselling'
                      ? 'border-orange-500/40 bg-orange-500/15 text-orange-400'
                      : 'bd muted'
                const tag =
                  g.flag === 'cheat'
                    ? 'Cheat Discord'
                    : g.flag === 'reselling'
                      ? 'Reselling Discord'
                      : 'Member'
                return (
                  <div
                    key={i}
                    className="tile flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3"
                    style={g.flag !== 'clean' ? { borderLeft: '3px solid currentColor' } : undefined}
                  >
                    <div className="flex items-center gap-3">
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-sky-600/15 text-sky-400">
                        <Server size={15} />
                      </span>
                      <div>
                        <p className="txt text-sm font-medium">{g.name}</p>
                        <p className="muted font-mono text-xs">ID: {g.id}</p>
                      </div>
                    </div>
                    <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${tone}`}>
                      {tag}
                    </span>
                  </div>
                )
              })}
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Recording Software</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Video size={18} /> Recording Software ({report.recording.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">Screen recording or capture software detected</p>
          {report.recording.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No recording software found</p>
          ) : (
            report.recording.map((r) => (
              <div key={r.exe} className="tile flex items-center gap-3 rounded-lg border px-4 py-3">
                <Video size={16} className="muted" />
                <div>
                  <p className="txt text-sm font-medium">{r.name}</p>
                  <p className="muted font-mono text-xs">● {r.exe}</p>
                </div>
              </div>
            ))
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Mods Logs</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Gamepad2 size={18} /> Mods Logs ({report.mods.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">Mods detected in the system</p>
          {report.mods.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No mods found</p>
          ) : (
            <div className="space-y-2">
              {report.mods.map((m, i) => (
                <div key={i} className="tile rounded-lg border px-4 py-3">
                  <div className="flex items-center justify-between gap-2">
                    <p className="txt text-sm font-medium">{m.name}</p>
                    <span className={`shrink-0 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                      m.severity === 'High' || m.severity === 'Critical'
                        ? 'border-red-600/40 bg-red-600/15 text-red-500'
                        : m.severity === 'Medium'
                          ? 'border-yellow-500/40 bg-yellow-500/15 text-yellow-400'
                          : 'bd muted'
                    }`}>{m.severity}</span>
                  </div>
                  {m.location && <p className="muted mt-1 break-all font-mono text-xs">{m.location}</p>}
                  {m.detail && <p className="muted mt-1 text-xs leading-relaxed">{m.detail}</p>}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card className="p-6">
        <p className="caps-label">Steam Accounts</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Users size={18} /> Steam Accounts ({report.steamAccounts.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          Previously logged-in Steam accounts on this machine.
          {report.steamAccounts.length > 1 && (
            <span className="ml-1 text-yellow-400">Multiple accounts may indicate ban evasion.</span>
          )}
        </p>
        {report.steamAccounts.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No Steam accounts found</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-3 py-3">Account Name</th>
                  <th className="px-3 py-3">Display Name</th>
                  <th className="px-3 py-3">Steam ID</th>
                  <th className="px-3 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {report.steamAccounts.map((a, i) => (
                  <tr key={i} className="bd border-b last:border-0">
                    <td className="txt px-3 py-3 font-mono text-xs">{a.accountName || '—'}</td>
                    <td className="muted px-3 py-3 text-xs">{a.personaName || '—'}</td>
                    <td className="muted px-3 py-3 font-mono text-xs">{a.steamId}</td>
                    <td className="px-3 py-3">
                      {a.mostRecent && (
                        <span className="rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-semibold text-green-500">
                          Current
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Autostart / Persistence</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Shield size={18} /> Autostart / Persistence ({report.autostartFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Suspicious entries in Run keys, startup folders, services and scheduled tasks
          </p>
          {report.autostartFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious autostart entries found</p>
          ) : (
            <ModuleFindingsList findings={report.autostartFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Network Activity</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Globe size={18} /> Network Activity ({report.networkFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Suspicious active connections and cheat-domain DNS lookups detected
          </p>
          {report.networkFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious network activity found</p>
          ) : (
            <ModuleFindingsList findings={report.networkFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Browser Activity</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Globe size={18} /> Browser Activity ({report.browserFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Cheat or reseller sites in browser history · suspicious extensions
          </p>
          {report.browserFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious browser activity found</p>
          ) : (
            <ModuleFindingsList findings={report.browserFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Suspicious Downloads</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Download size={18} /> Suspicious Downloads ({report.downloadFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Cheat installers and archives found in the Downloads folder
          </p>
          {report.downloadFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious downloads found</p>
          ) : (
            <ModuleFindingsList findings={report.downloadFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Anti-Cheat Evasion</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Shield size={18} /> Tamper Detection ({report.tamperFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Debugger attached, junction redirects, API hooking, future-dated files, bypass tools
          </p>
          {report.tamperFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No anti-cheat tampering detected</p>
          ) : (
            <ModuleFindingsList findings={report.tamperFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Overlay / ESP</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Eye size={18} /> Overlay / ESP ({report.overlayFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Layered, click-through, always-on-top windows running from user-writable paths
          </p>
          {report.overlayFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No ESP / overlay windows detected</p>
          ) : (
            <ModuleFindingsList findings={report.overlayFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Forensic Traces</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Search size={18} /> Forensic Traces ({report.forensicFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            RecentDocs, MUICache, WER crash reports, alternate data streams — evidence of deleted cheats
          </p>
          {report.forensicFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No forensic traces found</p>
          ) : (
            <ModuleFindingsList findings={report.forensicFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Remnants &amp; Camouflage</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <EyeOff size={18} /> Remnants &amp; Camouflage ({report.remnantFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Hosts file manipulation (blocking anti-cheat domains), cheat files in the Recycle Bin
          </p>
          {report.remnantFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No remnants or camouflage detected</p>
          ) : (
            <ModuleFindingsList findings={report.remnantFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Registry</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Database size={18} /> Registry Findings ({report.registryFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Suspicious registry keys left by cheat tools, loaders, or spoofers
          </p>
          {report.registryFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious registry entries found</p>
          ) : (
            <ModuleFindingsList findings={report.registryFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Scheduled Tasks</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Clock size={18} /> Scheduled Tasks ({report.scheduledTaskFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Malicious or cheat-related scheduled tasks that survive reboots
          </p>
          {report.scheduledTaskFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious scheduled tasks found</p>
          ) : (
            <ModuleFindingsList findings={report.scheduledTaskFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">PowerShell / Commands</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Terminal size={18} /> PowerShell Activity ({report.powerShellFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            PowerShell command history and console host logs with cheat-related patterns
          </p>
          {report.powerShellFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious PowerShell activity found</p>
          ) : (
            <ModuleFindingsList findings={report.powerShellFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">WMI Persistence</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Layers size={18} /> WMI Persistence ({report.wmiFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            WMI event subscriptions used to re-launch cheats or malware after reboot
          </p>
          {report.wmiFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No WMI persistence mechanisms found</p>
          ) : (
            <ModuleFindingsList findings={report.wmiFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Hidden Drivers</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <EyeOff size={18} /> Hidden Drivers ({report.hiddenDriverFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Kernel drivers that appear in the SCM but not the kernel driver list — a rootkit indicator
          </p>
          {report.hiddenDriverFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No hidden drivers detected</p>
          ) : (
            <ModuleFindingsList findings={report.hiddenDriverFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">Root Certificates</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Key size={18} /> Root Certificates ({report.rootCertFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Untrusted or unknown root CA certificates — used to sign cheat drivers or bypass HTTPS inspection
          </p>
          {report.rootCertFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious root certificates found</p>
          ) : (
            <ModuleFindingsList findings={report.rootCertFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">DMA / Hardware Risk</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Cpu size={18} /> DMA Risk ({report.dmaFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            DMA-capable PCIe devices and IOMMU configuration — potential hardware cheat indicators
          </p>
          {report.dmaFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No DMA risk indicators found</p>
          ) : (
            <ModuleFindingsList findings={report.dmaFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">System &amp; Protection</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <ShieldAlert size={18} /> System Integrity ({report.systemIntegrityFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Security center state, Windows Defender status, and protection tampering
          </p>
          {report.systemIntegrityFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No system integrity issues detected</p>
          ) : (
            <ModuleFindingsList findings={report.systemIntegrityFindings} />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Execution History</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <History size={18} /> Execution History ({report.executionHistoryFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Prefetch, UserAssist, ShimCache, and AppCompatCache — cheat tools previously executed
          </p>
          {report.executionHistoryFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No execution history matches found</p>
          ) : (
            <ModuleFindingsList findings={report.executionHistoryFindings} />
          )}
        </Card>
        <Card className="p-6">
          <p className="caps-label">NTFS Journal</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <FileText size={18} /> NTFS Change Journal ({report.ntfsFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Recent file creation and deletion events in the NTFS USN journal — covers erased cheats
          </p>
          {report.ntfsFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious NTFS journal entries found</p>
          ) : (
            <ModuleFindingsList findings={report.ntfsFindings} />
          )}
        </Card>
      </div>

      <Card className="p-6">
        <p className="caps-label">Installed Software</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Package size={18} /> Installed Software ({report.installedSoftwareFindings.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          Programs in Add/Remove Programs matching known cheat tool, spoofer, or loader names
        </p>
        {report.installedSoftwareFindings.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No suspicious installed programs found</p>
        ) : (
          <ModuleFindingsList findings={report.installedSoftwareFindings} />
        )}
      </Card>

      <Card className="p-6">
        <p className="caps-label">Prefetch Analysis</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Zap size={18} /> Prefetch Analysis ({report.prefetchFindings.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          Windows Prefetch files (.pf) revealing cheat executables that were run and then deleted
        </p>
        {report.prefetchFindings.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No cheat-related Prefetch entries found</p>
        ) : (
          <ModuleFindingsList findings={report.prefetchFindings} />
        )}
      </Card>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Kernel Objects</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Cpu size={18} /> Named Pipes &amp; Mutexes ({report.namedResourceFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Active named pipes and known cheat mutex objects in the Windows kernel
          </p>
          {report.namedResourceFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious kernel objects found</p>
          ) : (
            <ModuleFindingsList findings={report.namedResourceFindings} />
          )}
        </Card>

        <Card className="p-6">
          <p className="caps-label">Clipboard History</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Clipboard size={18} /> Clipboard ({report.clipboardFindings.length})
          </h2>
          <p className="muted mb-4 mt-1 text-sm">
            Windows Clipboard history entries containing cheat strings or licence keys
          </p>
          {report.clipboardFindings.length === 0 ? (
            <p className="muted py-10 text-center text-sm">No suspicious clipboard entries found</p>
          ) : (
            <ModuleFindingsList findings={report.clipboardFindings} />
          )}
        </Card>
      </div>

      <Card className="p-6">
        <p className="caps-label">AppData Scan</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <FolderOpen size={18} /> AppData Directories ({report.appDataFindings.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          %APPDATA% and %LOCALAPPDATA% folders matching known cheat tool names
        </p>
        {report.appDataFindings.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No suspicious AppData directories found</p>
        ) : (
          <ModuleFindingsList findings={report.appDataFindings} />
        )}
      </Card>

      <Card className="p-6">
        <p className="caps-label">Unknown / Private Cheat Detection</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <ShieldAlert size={18} /> Unsigned Processes ({report.suspiciousExeFindings.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          Processes running from user-writable paths (Temp, Downloads, AppData) without a digital
          signature, and processes masquerading as Windows system binaries. Private / self-coded
          cheats are never code-signed and typically launch from these locations.
        </p>
        {report.suspiciousExeFindings.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No unsigned processes in suspicious locations found</p>
        ) : (
          <ModuleFindingsList findings={report.suspiciousExeFindings} />
        )}
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Activity size={18} /> Last Computer Activity
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Recent system file operations and executions</p>
        <PaginatedTable
          columns={['Filename', 'Run Time', 'Action', 'Signed']}
          rows={report.lastActivity}
          searchKeys={['filename', 'runTime']}
          placeholder="Search filename, timestamp, action..."
          empty="No activity recorded."
          render={(r) => (
            <>
              <td className="txt break-all px-3 py-3 font-mono text-xs">{r.filename}</td>
              <td className="muted px-3 py-3 text-xs">{r.runTime}</td>
              <td className="px-3 py-3">
                <span className="rounded-md border border-green-600/30 bg-green-600/10 px-2 py-0.5 text-[11px] font-semibold text-green-500">
                  {r.action}
                </span>
              </td>
              <td className="px-3 py-3">{r.signed ? <span className="text-green-500">✓</span> : <span className="text-red-500">✕</span>}</td>
            </>
          )}
        />
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Database size={18} /> Executable List
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Processes executed during the scan</p>
        <ProcessTabs report={report} pin={pin} />
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Database size={18} /> Loaded Drivers
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Kernel drivers loaded at scan time. Unsigned and known cheat drivers are highlighted.</p>
        <DriversList drivers={pin.drivers || report.drivers || []} />
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Database size={18} /> Virtual Machine Detection
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Cheaters often run scans inside a VM to hide identity. We flag VMware, VirtualBox, Hyper-V and Sandboxie.</p>
        <VmDetection vm={pin.vm || report.vm || null} />
      </Card>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Database size={18} /> VirusTotal Lookup
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Query VirusTotal for the SHA-256 of every suspicious file. Requires an API key in Account → Integrations.</p>
        <VirusTotalLookup hashes={(report.suspiciousFiles || []).map((f) => f.sha256).filter(Boolean)} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Compilation Dates</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Database size={18} /> Compilation dates
          </h2>
          <p className="muted mt-1 text-sm">Executed applications Timestamps</p>
          {report.compilationDates.length === 0 ? (
            <p className="muted py-12 text-center text-sm">No Compilation dates data found</p>
          ) : (
            <div className="mt-4 space-y-2">
              {report.compilationDates.map((c, i) => (
                <div key={i} className="tile flex items-center justify-between gap-3 rounded-lg border px-4 py-3">
                  <div className="min-w-0">
                    <p className="txt truncate text-sm font-medium">{c.name}</p>
                    <p className="muted truncate font-mono text-xs">{c.path}</p>
                  </div>
                  <span className="shrink-0 font-mono text-xs text-sky-400">{c.date}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card className="p-6">
          <h2 className="txt flex items-center gap-2 text-lg font-semibold">
            <Database size={18} /> MFT Records
          </h2>
          <p className="muted mb-4 mt-1 text-sm">Master File Table records &amp; information</p>
          <PaginatedTable
            columns={['Path', 'Last Access', 'Downloaded']}
            rows={report.mft}
            searchKeys={['path']}
            placeholder="Search path, last access, download..."
            empty="No MFT records found."
            render={(r) => (
              <>
                <td className="txt break-all px-3 py-3 font-mono text-xs">{r.path}</td>
                <td className="muted px-3 py-3 text-xs">{r.lastAccess}</td>
                <td className="muted px-3 py-3 text-xs">{r.downloaded}</td>
              </>
            )}
          />
        </Card>
      </div>

      <Card className="p-6">
        <h2 className="txt flex items-center gap-2 text-lg font-semibold">
          <Database size={18} /> Execution activity
        </h2>
        <p className="muted mb-4 mt-1 text-sm">File executions &amp; obtained data</p>
        <PaginatedTable
          columns={['Path']}
          rows={report.execution}
          searchKeys={['path']}
          placeholder="Search path, sha1, name, compilation..."
          empty="No execution activity found."
          render={(r) => (
            <td className="txt break-all px-3 py-4 font-mono text-xs">{r.path}</td>
          )}
        />
      </Card>

      <Card className="p-6">
        <p className="caps-label">USB Activity</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Usb size={18} /> USB Activity ({report.usb.length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">
          Removable / USB storage recently connected or removed, and what was on it
        </p>
        {report.usb.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No USB activity recorded.</p>
        ) : (
          <div className="space-y-3">
            {report.usb.map((u, i) => {
              const tone =
                u.action === 'Removed'
                  ? 'border-red-600/40 bg-red-600/15 text-red-500'
                  : u.action === 'Connected'
                    ? 'border-green-600/40 bg-green-600/15 text-green-500'
                    : u.action === 'Mounted'
                      ? 'border-sky-600/40 bg-sky-600/15 text-sky-400'
                      : 'bd muted'
              return (
                <div key={i} className="tile rounded-xl border p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-sky-600/15 text-sky-400">
                        <Usb size={18} />
                      </span>
                      <div>
                        <p className="txt text-sm font-semibold">{u.device}</p>
                        <p className="muted font-mono text-xs">Serial: {u.serial}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${tone}`}>
                        {u.action}
                      </span>
                      <span className="muted flex items-center gap-1.5 text-xs">
                        <Clock size={12} /> {u.time}
                      </span>
                    </div>
                  </div>
                  <div className="bd mt-3 border-t pt-3">
                    <p className="caps-label mb-2">Contents ({u.contents.length})</p>
                    {u.contents.length === 0 ? (
                      <p className="muted text-xs">Contents not recorded for this device.</p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {u.contents.map((c, k) => (
                          <span
                            key={k}
                            className="bd tile muted inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px]"
                          >
                            <FileText size={11} /> {c}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <Card className="p-6">
        <p className="caps-label">Reviewer Notes</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <FileText size={18} /> Reviewer Notes
        </h2>
        <p className="muted mt-1 text-sm">Internal notes about this scan. Saved automatically when you tap Save.</p>
        <ReviewerNotes pin={pin} dispatch={dispatch} toast={toast} />
      </Card>

      <Card className="p-6">
        <p className="caps-label">Team Comments</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <MessageSquare size={18} /> Team Comments ({(pin.comments || []).length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Discuss this scan with other analysts.</p>
        <PinComments pin={pin} state={state} dispatch={dispatch} toast={toast} />
      </Card>

      <SimilarCases pin={pin} state={state} nav={nav} />

      <Card className="p-6">
        <p className="caps-label">Evidence Screenshots</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <ImageIcon size={18} /> Evidence Screenshots ({(pin.screenshots || []).length})
        </h2>
        <p className="muted mb-4 mt-1 text-sm">Attach proof images (gameplay clips, cheat menus, logs). Stored locally with this scan.</p>
        <Screenshots pin={pin} dispatch={dispatch} toast={toast} />
      </Card>

      <Modal open={risk} onClose={() => setRisk(false)} title="Risk Score">
        <div className="text-center">
          <div className={`mx-auto flex h-28 w-28 items-center justify-center rounded-full border-4 ${riskScore >= 60 ? 'border-red-600 text-red-500' : riskScore >= 30 ? 'border-yellow-500 text-yellow-500' : 'border-green-600 text-green-500'}`}>
            <span className="text-3xl font-bold">{riskScore}</span>
          </div>
          <p className="txt mt-4 text-sm font-medium">
            {riskScore >= 60 ? 'High risk' : riskScore >= 30 ? 'Medium risk' : 'Low risk'}
          </p>
        </div>
        {(() => {
          const w = state.settings?.riskWeights || { detect: 8, warn: 2, susp: 5 }
          const rows = [
            { label: 'Detections', n: report.counts.detects, w: w.detect },
            { label: 'Warnings', n: report.counts.warnings, w: w.warn },
            { label: 'Suspicious', n: report.counts.suspicious, w: w.susp },
          ]
          const raw = rows.reduce((a, r) => a + r.n * r.w, 0)
          return (
            <div className="mt-6">
              <p className="caps-label mb-2">How this score is calculated</p>
              <div className="bd overflow-hidden rounded-lg border text-sm">
                {rows.map((r) => (
                  <div key={r.label} className="bd flex items-center justify-between border-b px-3 py-2 last:border-0">
                    <span className="muted">{r.label}</span>
                    <span className="txt font-mono">
                      {r.n} × {r.w} = <span className="font-semibold">{r.n * r.w}</span>
                    </span>
                  </div>
                ))}
                <div className="flex items-center justify-between bg-white/[0.03] px-3 py-2">
                  <span className="txt font-semibold">Total (capped at 100)</span>
                  <span className="txt font-mono font-bold">
                    {raw} → {riskScore}
                  </span>
                </div>
              </div>
              <p className="muted mt-2 text-[11px]">Weights are configurable in Settings → Risk Score.</p>
            </div>
          )
        })()}
      </Modal>
    </div>
  )
}

function ReviewerNotes({ pin, dispatch, toast }) {
  const [val, setVal] = useState(pin.note || '')
  return (
    <div className="mt-3">
      <textarea
        value={val}
        onChange={(e) => setVal(e.target.value)}
        rows={5}
        placeholder="e.g. Cheater confirmed — KillAura in memory, Vape loader on USB."
        className="bd tile txt w-full rounded-lg border p-3 text-sm focus:outline-none"
      />
      <div className="mt-2 flex justify-end">
        <button
          onClick={() => {
            dispatch({ type: 'set-pin-note', id: pin.id, note: val })
            toast({ type: 'success', title: 'Note saved' })
          }}
          className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
        >
          Save
        </button>
      </div>
    </div>
  )
}

function renderCommentBody(text, users) {
  const parts = String(text).split(/(@[\w.\-]+)/g)
  return parts.map((part, i) => {
    if (part.startsWith('@')) {
      const username = part.slice(1).toLowerCase()
      const hit = users.find((u) => (u.username || '').toLowerCase() === username)
      if (hit) {
        return (
          <span key={i} className="rounded-md bg-sky-500/15 px-1 font-semibold text-sky-400">
            {part}
          </span>
        )
      }
    }
    return <span key={i}>{part}</span>
  })
}

function PinComments({ pin, state, dispatch, toast }) {
  const [text, setText] = useState('')
  const [showSuggest, setShowSuggest] = useState(false)
  const me = state.session?.userId
    ? (state.users || []).find((u) => u.id === state.session.userId)?.username
    : state.role === 'admin'
      ? 'Admin'
      : 'Analyst'
  const lastAt = text.lastIndexOf('@')
  const suggestQuery = lastAt >= 0 && !/\s/.test(text.slice(lastAt)) ? text.slice(lastAt + 1).toLowerCase() : null
  const suggestions = suggestQuery != null
    ? (state.users || []).filter((u) => (u.username || '').toLowerCase().startsWith(suggestQuery)).slice(0, 5)
    : []
  const submit = () => {
    if (!text.trim()) return
    dispatch({ type: 'add-pin-comment', id: pin.id, author: me, text: text.trim() })
    setText('')
    setShowSuggest(false)
    toast({ type: 'success', title: 'Comment added' })
  }
  const pickSuggestion = (u) => {
    setText(text.slice(0, lastAt) + '@' + u.username + ' ')
    setShowSuggest(false)
  }
  return (
    <div>
      <div className="relative flex flex-col gap-2 sm:flex-row">
        <input
          value={text}
          onChange={(e) => { setText(e.target.value); setShowSuggest(true) }}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          onFocus={() => setShowSuggest(true)}
          placeholder="Write a comment… use @username to mention"
          className="bd tile txt w-full rounded-lg border px-3 py-2.5 text-sm focus:outline-none"
        />
        <button
          onClick={submit}
          className="rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
        >
          Add
        </button>
        {showSuggest && suggestions.length > 0 && (
          <div className="panel absolute left-0 right-0 top-full z-20 mt-1 max-h-48 overflow-auto rounded-lg border shadow-xl sm:right-auto sm:w-72">
            {suggestions.map((u) => (
              <button
                key={u.id}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pickSuggestion(u)}
                className="hoverable txt flex w-full items-center gap-2 px-3 py-2 text-left text-sm"
              >
                <span className="tile flex h-6 w-6 items-center justify-center rounded-full border text-[10px] font-semibold">
                  {(u.username || '?').charAt(0).toUpperCase()}
                </span>
                <span>@{u.username}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="mt-4 space-y-2">
        {(pin.comments || []).length === 0 ? (
          <p className="muted py-6 text-center text-xs">No comments yet.</p>
        ) : (
          (pin.comments || []).map((c) => (
            <div key={c.id} className="tile rounded-lg border p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="txt font-semibold">{c.author}</span>
                <span className="muted">{new Date(c.time).toLocaleString()}</span>
              </div>
              <p className="muted mt-1 break-words text-sm">
                {renderCommentBody(c.text, state.users || [])}
              </p>
              <div className="mt-1 flex justify-end">
                <button
                  onClick={() => dispatch({ type: 'delete-pin-comment', id: pin.id, commentId: c.id })}
                  className="text-[11px] text-red-500 hover:underline"
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

const CASE_TONE = {
  Open: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500',
  InReview: 'border-sky-600/40 bg-sky-600/15 text-sky-400',
  Resolved: 'border-green-600/40 bg-green-600/15 text-green-500',
}
const CASE_LABEL = { Open: 'Open', InReview: 'In Review', Resolved: 'Resolved' }

function SteamIdRow({ pin, dispatch, toast }) {
  const [val, setVal] = useState(pin.steamId || '')
  const save = () => {
    dispatch({ type: 'set-pin-steamid', id: pin.id, steamId: val.trim() })
    toast({ type: 'success', title: 'Steam ID saved' })
  }
  return (
    <div className="bd flex items-center justify-between gap-2 border-b py-3.5 text-sm last:border-0">
      <span className="muted flex items-center gap-2.5">
        <span className="h-2 w-2 rounded-full" style={{ background: '#848eb0' }} />
        Steam ID
      </span>
      <span className="flex items-center gap-2">
        <input
          value={val}
          onChange={(e) => setVal(e.target.value)}
          placeholder="e.g. 7656119…"
          className="bd tile txt w-44 rounded-md border px-2 py-1 text-right font-mono text-xs focus:outline-none"
        />
        <button onClick={save} className="bd txt rounded-md border px-2 py-1 text-xs hover:border-sky-500">
          Save
        </button>
      </span>
    </div>
  )
}

function CaseStatusCard({ pin, dispatch, toast }) {
  const status = pin.caseStatus || 'Open'
  const resolution = pin.caseResolution || { action: '', reason: '' }
  const [action, setAction] = useState(resolution.action || 'Banned')
  const [reason, setReason] = useState(resolution.reason || '')
  return (
    <Card className="p-6">
      <p className="caps-label">Case status</p>
      <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
        <Shield size={18} /> Case status
      </h2>
      <p className="muted mt-1 text-sm">Track how this scan moves from open → in review → resolved.</p>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${CASE_TONE[status]}`}>
          {CASE_LABEL[status] || status}
        </span>
        <div className="flex flex-wrap gap-2">
          {['Open', 'InReview', 'Resolved'].map((s) => (
            <button
              key={s}
              onClick={() => {
                dispatch({
                  type: 'set-pin-status',
                  id: pin.id,
                  status: s,
                  resolution: s === 'Resolved' ? { action, reason } : undefined,
                })
                toast({ type: 'success', title: `Status: ${CASE_LABEL[s]}` })
              }}
              className={`bd rounded-md border px-3 py-1.5 text-xs ${status === s ? 'bg-sky-500/10 text-sky-400' : 'muted hover:txt'}`}
            >
              {CASE_LABEL[s]}
            </button>
          ))}
        </div>
      </div>
      {status === 'Resolved' && (
        <div className="bd mt-4 grid gap-3 border-t pt-4 sm:grid-cols-2">
          <div>
            <p className="caps-label mb-1">Action taken</p>
            <Select
              value={action}
              onChange={setAction}
              options={[
                { value: 'Banned', label: 'Banned' },
                { value: 'Cleared', label: 'Cleared' },
                { value: 'NoAction', label: 'No action' },
              ]}
            />
          </div>
          <div>
            <p className="caps-label mb-1">Reason</p>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Short justification"
              className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none"
            />
          </div>
          <div className="sm:col-span-2 flex justify-end">
            <button
              onClick={() => {
                dispatch({ type: 'set-pin-status', id: pin.id, status: 'Resolved', resolution: { action, reason } })
                toast({ type: 'success', title: 'Resolution saved' })
              }}
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
            >
              Save resolution
            </button>
          </div>
          {pin.caseResolution && (pin.caseResolution.action || pin.caseResolution.reason) && (
            <p className="muted sm:col-span-2 text-xs">
              Current: <span className="txt">{pin.caseResolution.action}</span>
              {pin.caseResolution.reason ? ` — ${pin.caseResolution.reason}` : ''}
            </p>
          )}
        </div>
      )}
    </Card>
  )
}

function AssignmentRow({ pin, state, dispatch, toast }) {
  const [val, setVal] = useState(pin.assignedTo || '')
  const save = () => {
    dispatch({ type: 'assign-pin', pinId: pin.id, userId: val || null })
    toast({ type: 'success', title: val ? 'Pin assigned' : 'Assignment cleared' })
  }
  const assignee = (state.users || []).find((u) => u.id === pin.assignedTo)
  return (
    <div className="bd flex items-center justify-between gap-2 border-b py-3.5 text-sm last:border-0">
      <span className="muted flex items-center gap-2.5">
        <span className="h-2 w-2 rounded-full" style={{ background: '#8b5cf6' }} />
        Assigned to
      </span>
      <span className="flex flex-wrap items-center justify-end gap-2">
        {assignee && (
          <span className="bd rounded-md border px-2 py-0.5 font-mono text-[11px] text-sky-400">
            @{assignee.username}
          </span>
        )}
        <select
          value={val}
          onChange={(e) => setVal(e.target.value)}
          className="bd tile txt rounded-md border px-2 py-1 text-xs"
        >
          <option value="">— unassigned —</option>
          {(state.users || []).map((u) => (
            <option key={u.id} value={u.id}>{u.username}</option>
          ))}
        </select>
        <button
          onClick={save}
          className="bd rounded-md border px-2 py-1 text-xs hover:border-sky-500"
        >
          Save
        </button>
      </span>
    </div>
  )
}

function ProcessTabs({ report, pin }) {
  const [view, setView] = useState('flat')
  // Synthesize parent-PID relationships if the scanner didn't provide them:
  // group by name prefix, mark first occurrence of a name as root, rest as children.
  const processes = (pin.processes || report.processes || report.executables || []).map((p, i) => ({
    pid: p.pid != null ? p.pid : (1000 + i),
    parentPid: p.parentPid != null ? p.parentPid : null,
    name: p.name || (p.path ? p.path.split(/[\\/]/).pop() : '<unknown>'),
    path: p.path || '',
    elevated: !!p.elevated,
  }))
  return (
    <div>
      <div className="mb-3 inline-flex rounded-lg border border-line p-0.5 text-xs">
        <button
          onClick={() => setView('flat')}
          className={`rounded-md px-3 py-1 ${view === 'flat' ? 'bg-sky-500/15 text-sky-400' : 'muted'}`}
        >
          Flat list
        </button>
        <button
          onClick={() => setView('tree')}
          className={`rounded-md px-3 py-1 ${view === 'tree' ? 'bg-sky-500/15 text-sky-400' : 'muted'}`}
        >
          Process tree
        </button>
      </div>
      {view === 'flat' ? (
        <PaginatedTable
          columns={['Name', 'Path', 'PID', 'Signed', 'Elevated']}
          rows={report.executables}
          searchKeys={['path', 'name']}
          placeholder="Search name or path..."
          empty="No executables recorded."
          render={(r) => (
            <>
              <td className="txt px-3 py-3 font-mono text-xs">{r.name || r.path.split(/[\\/]/).pop() || '—'}</td>
              <td className="txt break-all px-3 py-3 font-mono text-xs">{r.path}</td>
              <td className="muted px-3 py-3 text-xs">{r.pid ?? '—'}</td>
              <td className="px-3 py-3">{r.verified ? <span className="text-green-500">✓</span> : <span className="text-red-500">✕</span>}</td>
              <td className="px-3 py-3">
                {r.elevated ? (
                  <span className="rounded-md border border-orange-500/40 bg-orange-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-orange-400">ELEVATED</span>
                ) : (
                  <span className="muted text-xs">—</span>
                )}
              </td>
            </>
          )}
        />
      ) : (
        <ProcessTree processes={processes} />
      )}
    </div>
  )
}

function ProcessTree({ processes }) {
  if (!processes?.length) return <p className="muted py-6 text-center text-xs">No processes captured.</p>
  // Build child map; treat any orphan as root.
  const byPid = new Map()
  processes.forEach((p) => byPid.set(p.pid, { ...p, children: [] }))
  const roots = []
  byPid.forEach((node) => {
    const parent = node.parentPid != null ? byPid.get(node.parentPid) : null
    if (parent) parent.children.push(node)
    else roots.push(node)
  })
  const Node = ({ node, depth }) => (
    <div>
      <div
        className="bd flex items-center justify-between gap-2 border-b py-1.5 text-xs last:border-0"
        style={{ paddingLeft: depth * 18 }}
      >
        <span className="txt break-all font-mono">
          {depth > 0 && <span className="muted">└─ </span>}
          {node.name || '<unknown>'}
        </span>
        <span className="flex shrink-0 items-center gap-2">
          {node.elevated && (
            <span className="rounded-md border border-orange-500/40 bg-orange-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-orange-400">ELEVATED</span>
          )}
          <span className="muted font-mono">PID {node.pid}</span>
        </span>
      </div>
      {node.children.map((c) => (
        <Node key={c.pid} node={c} depth={depth + 1} />
      ))}
    </div>
  )
  return (
    <div>
      {roots.map((r) => <Node key={r.pid} node={r} depth={0} />)}
    </div>
  )
}

function DriversList({ drivers }) {
  if (!drivers?.length) return <p className="muted py-6 text-center text-xs">No drivers reported.</p>
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="caps-label bd border-b">
            <th className="px-3 py-2">Driver</th>
            <th className="px-3 py-2">Publisher</th>
            <th className="px-3 py-2">Signature</th>
            <th className="px-3 py-2">Note</th>
          </tr>
        </thead>
        <tbody>
          {drivers.map((d, i) => (
            <tr key={i} className="bd border-b last:border-0 align-top">
              <td className="txt px-3 py-2 break-all font-mono">{d.name}</td>
              <td className="muted px-3 py-2 break-all">{d.publisher || '—'}</td>
              <td className="px-3 py-2">
                {d.signed ? (
                  <span className="rounded-md border border-green-600/40 bg-green-600/15 px-1.5 py-0.5 text-[10px] font-semibold text-green-500">signed</span>
                ) : (
                  <span className="rounded-md border border-red-600/40 bg-red-600/15 px-1.5 py-0.5 text-[10px] font-semibold text-red-500">unsigned</span>
                )}
                {d.cheatKnown && (
                  <span className="ml-1 rounded-md border border-red-600/40 bg-red-600/15 px-1.5 py-0.5 text-[10px] font-semibold text-red-500">known cheat</span>
                )}
              </td>
              <td className="muted px-3 py-2 break-words">{d.note || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function VmDetection({ vm }) {
  if (!vm) return <p className="muted py-6 text-center text-xs">No VM checks recorded.</p>
  return (
    <div className="space-y-2 text-sm">
      <div className="bd flex items-center justify-between rounded-lg border px-4 py-3">
        <span className="muted">Running inside a virtual machine?</span>
        {vm.detected ? (
          <span className="rounded-md border border-red-600/40 bg-red-600/15 px-2 py-0.5 text-xs font-semibold text-red-500">
            YES · {vm.vendor || 'Unknown'}
          </span>
        ) : (
          <span className="rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-xs font-semibold text-green-500">
            NO
          </span>
        )}
      </div>
      {vm.signals?.length > 0 && (
        <ul className="muted ml-4 list-disc space-y-1 text-xs">
          {vm.signals.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      )}
    </div>
  )
}

async function vtLookup(hash, apiKey) {
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': apiKey },
    })
    if (!r.ok) return { ok: false, status: r.status }
    const j = await r.json()
    const stats = j?.data?.attributes?.last_analysis_stats || {}
    return {
      ok: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
      permalink: `https://www.virustotal.com/gui/file/${hash}`,
    }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

function VirusTotalLookup({ hashes }) {
  const { state } = useStore()
  const apiKey = state.integrations?.virusTotalKey || ''
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState({})
  if (!hashes?.length) return <p className="muted py-6 text-center text-xs">No file hashes available.</p>
  if (!apiKey) {
    return (
      <p className="muted py-6 text-center text-xs">
        Set a VirusTotal API key in Account → Integrations to enable lookups.
      </p>
    )
  }
  const check = async (h) => {
    setBusy((b) => ({ ...b, [h]: true }))
    const r = await vtLookup(h, apiKey)
    setResults((rs) => ({ ...rs, [h]: r }))
    setBusy((b) => ({ ...b, [h]: false }))
  }
  return (
    <div className="space-y-2 text-xs">
      {hashes.map((h) => {
        const r = results[h]
        return (
          <div key={h} className="bd flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2">
            <code className="txt break-all font-mono">{h}</code>
            <div className="flex items-center gap-2">
              {r?.ok && (
                <span className={`rounded-md border px-2 py-0.5 font-semibold ${
                  r.malicious > 0 ? 'border-red-600/40 bg-red-600/15 text-red-500' :
                  r.suspicious > 0 ? 'border-yellow-500/40 bg-yellow-500/15 text-yellow-400' :
                  'border-green-600/40 bg-green-600/15 text-green-500'
                }`}>
                  {r.malicious}/{r.total} malicious
                </span>
              )}
              {r?.permalink && (
                <a href={r.permalink} target="_blank" rel="noreferrer" className="text-sky-400 underline">VT</a>
              )}
              {r && !r.ok && (
                <span className="text-red-400">err {r.status || r.error}</span>
              )}
              <button
                onClick={() => check(h)}
                disabled={busy[h]}
                className="bd rounded-md border px-2 py-0.5 text-[11px] hover:border-sky-500 disabled:opacity-50"
              >
                {busy[h] ? '…' : 'Lookup'}
              </button>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function Screenshots({ pin, dispatch, toast }) {
  const shots = pin.screenshots || []
  const [preview, setPreview] = useState(null)
  const onFiles = (files) => {
    Array.from(files).forEach((f) => {
      if (!f.type.startsWith('image/')) {
        toast({ type: 'error', title: 'Only images allowed' })
        return
      }
      if (f.size > 4 * 1024 * 1024) {
        toast({ type: 'error', title: 'Image too large', body: 'Max 4 MB each' })
        return
      }
      const reader = new FileReader()
      reader.onload = () => {
        dispatch({
          type: 'add-pin-screenshot',
          id: pin.id,
          shot: { id: 's' + Date.now() + Math.random().toString(16).slice(2, 6), name: f.name, dataUrl: reader.result, at: Date.now() },
        })
      }
      reader.readAsDataURL(f)
    })
    toast({ type: 'success', title: 'Screenshot(s) added' })
  }
  return (
    <div>
      <label
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); onFiles(e.dataTransfer.files) }}
        className="bd flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed py-10 text-center transition-colors hover:border-sky-500 print:hidden"
      >
        <input type="file" accept="image/*" multiple className="hidden" onChange={(e) => e.target.files.length && onFiles(e.target.files)} />
        <ImageIcon size={28} className="muted" />
        <p className="txt mt-3 text-sm font-medium">Drag images here or click</p>
        <p className="muted mt-1 text-xs">PNG / JPG, max 4 MB each</p>
      </label>

      {shots.length > 0 && (
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
          {shots.map((s) => (
            <div key={s.id} className="group relative overflow-hidden rounded-lg border border-line">
              <img
                src={s.dataUrl}
                alt={s.name}
                className="aspect-video w-full cursor-pointer object-cover"
                onClick={() => setPreview(s)}
              />
              <button
                onClick={() => dispatch({ type: 'delete-pin-screenshot', id: pin.id, shotId: s.id })}
                className="absolute right-1.5 top-1.5 rounded-md bg-black/60 p-1 text-white opacity-0 transition-opacity group-hover:opacity-100 print:hidden"
                title="Delete"
              >
                <Trash2 size={13} />
              </button>
              <p className="muted truncate px-2 py-1 text-[10px]">{s.name}</p>
            </div>
          ))}
        </div>
      )}

      {preview && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
          onClick={() => setPreview(null)}
        >
          <img src={preview.dataUrl} alt={preview.name} className="max-h-[90vh] max-w-full rounded-lg" />
        </div>
      )}
    </div>
  )
}

function SimilarCases({ pin, state, nav }) {
  const cheats = pin.cheats || []
  if (cheats.length === 0) return null
  const visible = state.role === 'admin'
    ? state.pins
    : state.pins.filter((p) => p.ownerId === state.session?.userId)
  const similar = visible
    .filter((p) => p.id !== pin.id && (p.cheats || []).some((c) => cheats.includes(c)))
    .map((p) => ({
      pin: p,
      shared: (p.cheats || []).filter((c) => cheats.includes(c)),
    }))
    .sort((a, b) => b.shared.length - a.shared.length)
    .slice(0, 8)
  if (similar.length === 0) return null
  return (
    <Card className="p-6">
      <p className="caps-label">Similar Cases</p>
      <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
        <Layers size={18} /> Similar Cases ({similar.length})
      </h2>
      <p className="muted mb-4 mt-1 text-sm">Other scans that share at least one detected cheat with this one.</p>
      <div className="space-y-2">
        {similar.map(({ pin: p, shared }) => (
          <button
            key={p.id}
            onClick={() => nav(`/scan/${p.id}`)}
            className="bd hoverable flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left text-sm"
          >
            <span className="min-w-0">
              <span className="txt font-mono text-xs">{p.pin}</span>
              <span className="muted ml-2">{p.name || '—'}</span>
              {p.discordId && <span className="muted ml-2 font-mono text-xs">· {p.discordId}</span>}
            </span>
            <span className="flex shrink-0 flex-wrap items-center justify-end gap-1">
              {shared.slice(0, 3).map((c) => (
                <span key={c} className="rounded-md border border-red-600/40 bg-red-600/15 px-1.5 py-0.5 text-[10px] font-semibold text-red-400">
                  {c}
                </span>
              ))}
              {shared.length > 3 && <span className="muted text-[10px]">+{shared.length - 3}</span>}
            </span>
          </button>
        ))}
      </div>
    </Card>
  )
}
