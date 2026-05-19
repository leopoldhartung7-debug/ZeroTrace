import { useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Copy, ShieldAlert, Download, Flag, Gauge, Monitor, Cpu,
  AlertTriangle, CheckCircle2, Eye, Sparkles, Search, ChevronLeft,
  ChevronRight, Shield, MessageSquare, Video, Gamepad2, Database, Activity,
  Clock, Play, ImageOff,
} from 'lucide-react'
import { Card } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

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
          <span className="rounded-md border border-blue-600/40 bg-blue-600/15 px-3 py-1 text-blue-500">{p}</span>
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
  const pin = state.pins.find((p) => p.id === id)
  const [cat, setCat] = useState(null)
  const [risk, setRisk] = useState(false)

  const report = useMemo(
    () => (pin && pin.status === 'Finished' ? deriveScanReport(pin) : null),
    [pin],
  )

  if (!pin) {
    return (
      <div className="py-20 text-center">
        <p className="txt text-lg font-semibold">Pin not found</p>
        <button onClick={() => nav('/pins')} className="mt-4 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white">
          Back to Pins
        </button>
      </div>
    )
  }

  if (!report) {
    return (
      <div>
        <button onClick={() => nav('/pins')} className="muted hover:txt mb-6 flex items-center gap-2 text-sm">
          <ArrowLeft size={16} /> Back to Pins
        </button>
        <Card className="flex flex-col items-center p-16 text-center">
          <Clock size={36} className="muted" />
          <p className="txt mt-4 text-lg font-semibold">Scan pending</p>
          <p className="muted mt-1 text-sm">No results yet — this pin has not been scanned.</p>
          <button
            onClick={() => {
              dispatch({ type: 'run-scan', id: pin.id })
              toast({ type: 'info', title: 'Scan complete', body: pin.pin })
            }}
            className="mt-6 flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
          >
            <Play size={15} /> Run scan now
          </button>
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
    { key: 'warnings', label: 'Warnings Logs', n: report.counts.warnings, icon: AlertTriangle, tone: 'text-yellow-400', badge: 'border-blue-600/40 bg-blue-600/15 text-blue-400' },
    { key: 'suspicious', label: 'Suspicious logs', n: report.counts.suspicious, icon: Eye, tone: 'text-blue-400', badge: 'bd txt' },
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

  const SignedBadge = ({ ok }) => (
    <span className={`bd inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${ok ? 'text-green-500' : 'muted'}`}>
      <Shield size={11} /> {ok ? 'SIGNED' : 'UNSIGNED'}
    </span>
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
            <span className="rounded-md border border-blue-600/40 bg-blue-600/15 px-2.5 py-1 text-xs font-semibold text-blue-400">
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
              className="txt font-mono hover:text-blue-500"
            >
              {pin.pin} <Copy size={12} className="inline" />
            </button>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setRisk(true)} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-blue-500">
            <Gauge size={15} /> Check Risk Score
          </button>
          <button onClick={exportReport} className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-blue-500">
            <Download size={15} /> Export
          </button>
          <button
            onClick={() => toast({ type: 'success', title: 'Scan reported', body: pin.pin })}
            className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-blue-500"
          >
            <Flag size={15} /> Report Scan
          </button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className={`flex items-center justify-center rounded-2xl border py-6 ${verdictTone.box}`}>
          <p className="txt text-lg">
            This user is <span className={`font-semibold ${verdictTone.txt}`}>{verdictTone.word}</span>
          </p>
        </div>
        <div className="panel flex items-center justify-center rounded-2xl border py-6">
          <p className="muted flex items-center gap-2 text-sm">
            <span className="h-2 w-2 rounded-full bg-blue-500" /> Scanned: {scannedLabel}
          </p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <div className="mb-4 flex items-center gap-3">
            <Monitor size={20} className="text-blue-500" />
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
        </Card>

        <Card className="p-6">
          <div className="mb-4 flex items-center gap-3">
            <Monitor size={20} className="text-blue-500" />
            <div>
              <h2 className="txt text-lg font-semibold">PC Information</h2>
              <p className="muted text-xs">Information about the users PC</p>
            </div>
          </div>
          <KV color="#3b82f6" label="System" value={report.pc.system} />
          <KV color="#22c55e" label="Boot Time" value={report.pc.bootTime} />
          <KV color="#ef4444" label="VPN" value={report.pc.vpn} />
          <KV color="#a855f7" label="Install Date" value={report.pc.installDate} />
          <KV color="#f97316" label="Country" value={report.pc.country} />
          <KV color="#22c55e" label="Game" value={report.pc.game} />
          <KV color="#f97316" label="Recycle" value={report.pc.recycle} />
          <KV color="#06b6d4" label="Hardware Stats" value="Not available" />
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
                  cat === c.key ? 'bg-blue-600/15' : 'hoverable'
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
                suspicious: { accent: '#3b82f6', Icon: Eye, title: 'Suspicious logs', badge: 'Suspicious', bcls: 'border-blue-600/40 bg-blue-600/15 text-blue-400' },
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
                    <div className="mt-5 max-h-[560px] space-y-4 overflow-y-auto pr-1">
                      {report[cat].map((l, i) => (
                        <div
                          key={i}
                          className="rounded-2xl border border-white/5 bg-white/[0.02] p-5"
                          style={{ borderLeft: `3px solid ${cs.accent}` }}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <span
                              className="flex h-11 w-11 items-center justify-center rounded-xl"
                              style={{ background: `${cs.accent}1f`, color: cs.accent }}
                            >
                              <cs.Icon size={20} />
                            </span>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => copyDetail(`${l.name} — ${l.detail}`)}
                                className="bd muted hover:txt rounded-md border p-1.5"
                                title="Copy"
                              >
                                <Copy size={13} />
                              </button>
                              <span className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${cs.bcls}`}>
                                {l.severity || cs.badge}
                              </span>
                            </div>
                          </div>
                          <p className="txt mt-4 text-lg font-semibold">{l.name}</p>
                          <div className="tile mt-3 rounded-lg border p-3">
                            <p className="muted break-all font-mono text-xs leading-relaxed">
                              {l.detail}
                              {l.time ? ` at ${l.time}` : ''}
                            </p>
                          </div>
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

      <Card className="p-6">
        <p className="caps-label">Admin-Executed Applications</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <Shield size={18} /> Admin-Executed Applications
        </h2>
        <p className="muted mt-1 text-sm">Applications launched with administrator privileges during the scan window</p>
        <p className="muted mb-4 mt-1 text-xs">
          {report.adminApps.filter((a) => a.verdict === 'SUSPICIOUS').length} suspicious · {report.adminApps.length} total
        </p>
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
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
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
          {report.mods.length === 0 && <p className="muted py-10 text-center text-sm">No mods found</p>}
        </Card>
      </div>

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
        <PaginatedTable
          columns={['Executable Path', 'Timestamp', 'Status', 'Verified']}
          rows={report.executables}
          searchKeys={['path', 'timestamp']}
          placeholder="Search executable path, timestamp..."
          empty="No executables recorded."
          render={(r) => (
            <>
              <td className="txt break-all px-3 py-3 font-mono text-xs">{r.path}</td>
              <td className="muted px-3 py-3 text-xs">{r.timestamp}</td>
              <td className="px-3 py-3">{r.status ? <span className="text-green-500">✓</span> : <span className="text-red-500">✕</span>}</td>
              <td className="px-3 py-3">{r.verified ? <span className="text-green-500">✓</span> : <span className="text-red-500">✕</span>}</td>
            </>
          )}
        />
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Compilation Dates</p>
          <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <Database size={18} /> Compilation dates
          </h2>
          <p className="muted mt-1 text-sm">Executed applications Timestamps</p>
          {report.compilationDates.length === 0 && (
            <p className="muted py-12 text-center text-sm">No Compilation dates data found</p>
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
        <p className="caps-label">Screenshot</p>
        <h2 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
          <ImageOff size={18} /> Screenshot
        </h2>
        <p className="muted mt-1 text-sm">No screenshot available</p>
        <div className="bd tile mt-4 flex flex-col items-center justify-center rounded-xl border py-16">
          <ImageOff size={32} className="muted" />
          <p className="muted mt-3 text-sm">No screenshot available for this scan</p>
        </div>
      </Card>

      <Modal open={risk} onClose={() => setRisk(false)} title="Risk Score">
        <div className="text-center">
          <div className={`mx-auto flex h-28 w-28 items-center justify-center rounded-full border-4 ${riskScore >= 60 ? 'border-red-600 text-red-500' : riskScore >= 30 ? 'border-yellow-500 text-yellow-500' : 'border-green-600 text-green-500'}`}>
            <span className="text-3xl font-bold">{riskScore}</span>
          </div>
          <p className="txt mt-4 text-sm font-medium">
            {riskScore >= 60 ? 'High risk' : riskScore >= 30 ? 'Medium risk' : 'Low risk'}
          </p>
          <p className="muted mt-1 text-xs">
            Computed from {report.counts.detects} detects, {report.counts.warnings} warnings and{' '}
            {report.counts.suspicious} suspicious logs.
          </p>
        </div>
      </Modal>
    </div>
  )
}
