import { useMemo, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { GitCompareArrows, ArrowLeft } from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { Select } from '../components/ui.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

function risk(r) {
  if (!r) return 0
  return Math.min(100, r.counts.detects * 8 + r.counts.warnings * 2 + r.counts.suspicious * 5)
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

function PinPicker({ value, onChange, pins, label }) {
  return (
    <div>
      <p className="caps-label mb-2">{label}</p>
      <Select
        value={value}
        onChange={onChange}
        options={[
          { value: '', label: '— select a pin —' },
          ...pins.map((p) => ({
            value: p.id,
            label: `${p.pin} · ${p.name || ''} · ${p.result || p.status}`,
          })),
        ]}
      />
    </div>
  )
}

function Side({ pin, report }) {
  if (!pin) return <Card className="p-6"><p className="muted text-sm">Pick a pin.</p></Card>
  return (
    <Card className="space-y-4 p-6">
      <div>
        <p className="caps-label">Pin</p>
        <p className="txt font-mono text-sm">{pin.pin}</p>
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Verdict</p>
          <p className="txt mt-1 font-semibold">{pin.result || '—'}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Risk</p>
          <p className="txt mt-1 font-semibold">{risk(report)}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Detects · Warn · Susp</p>
          <p className="txt mt-1">
            {report ? `${report.counts.detects} · ${report.counts.warnings} · ${report.counts.suspicious}` : '—'}
          </p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">USB</p>
          <p className="txt mt-1">{report ? report.usb.length : 0}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Discord servers</p>
          <p className="txt mt-1">{report ? report.discordServers.length : 0}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Scanned</p>
          <p className="txt mt-1 text-xs">{fmt(pin.scannedAt || pin.createdAt)}</p>
        </div>
      </div>
      <div>
        <p className="caps-label mb-2">Cheats</p>
        {pin.cheats && pin.cheats.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {pin.cheats.map((c) => (
              <span key={c} className="bd tile muted rounded-md border px-2 py-1 text-[11px]">{c}</span>
            ))}
          </div>
        ) : (
          <p className="muted text-xs">None</p>
        )}
      </div>
    </Card>
  )
}

export default function Compare() {
  const nav = useNavigate()
  const { state } = useStore()
  const loc = useLocation()
  const params = new URLSearchParams(loc.search)
  const [a, setA] = useState(params.get('a') || '')
  const [b, setB] = useState(params.get('b') || '')
  const [timelineDiscordId, setTimelineDiscordId] = useState('')

  const pins = useMemo(
    () =>
      (state.pins || [])
        .filter((p) => state.role === 'admin' || p.ownerId === state.session?.userId)
        .filter((p) => p.status === 'Finished'),
    [state.pins, state.role, state.session],
  )

  const pinA = pins.find((p) => p.id === a)
  const pinB = pins.find((p) => p.id === b)
  const reportA = useMemo(() => (pinA ? deriveScanReport(pinA) : null), [pinA])
  const reportB = useMemo(() => (pinB ? deriveScanReport(pinB) : null), [pinB])

  return (
    <div>
      <button onClick={() => nav(-1)} className="muted hover:txt mb-4 flex items-center gap-2 text-sm">
        <ArrowLeft size={16} /> Back
      </button>

      <PageHeader
        icon={GitCompareArrows}
        kicker="Side-by-side"
        title="Compare scans"
        subtitle="Pick two finished pins to see how they differ at a glance."
      />

      <Card className="mb-6 p-6">
        <div className="grid gap-4 md:grid-cols-2">
          <PinPicker value={a} onChange={setA} pins={pins} label="Pin A" />
          <PinPicker value={b} onChange={setB} pins={pins} label="Pin B" />
        </div>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Side pin={pinA} report={reportA} />
        <Side pin={pinB} report={reportB} />
      </div>

      {/* Player Timeline */}
      <div className="mt-6">
        <h3 className="txt text-lg font-semibold mb-4">Player Timeline</h3>
        <div className="mb-4">
          <input
            value={timelineDiscordId}
            onChange={e => setTimelineDiscordId(e.target.value)}
            placeholder="Enter Discord ID to view scan timeline..."
            className="bd tile txt w-full max-w-sm rounded-lg border px-3 py-2 text-sm outline-none focus:border-sky-500"
          />
        </div>
        {!timelineDiscordId.trim() ? (
          <div className="tile rounded-xl border p-8 text-center">
            <p className="muted text-sm">Select a player to view their scan timeline</p>
          </div>
        ) : (() => {
          const playerPins = (state.pins || [])
            .filter(p => p.discordId === timelineDiscordId.trim() || p.pin === timelineDiscordId.trim())
            .sort((a, b) => (a.scannedAt || a.createdAt || 0) - (b.scannedAt || b.createdAt || 0))
          if (playerPins.length === 0) {
            return (
              <div className="tile rounded-xl border p-8 text-center">
                <p className="muted text-sm">No scans found for this player</p>
              </div>
            )
          }
          return (
            <div className="relative">
              <div className="absolute left-[11px] top-0 bottom-0 w-0.5 bg-white/10" />
              <div className="space-y-4">
                {playerPins.map(p => {
                  const resultColor = p.result === 'Cheating' ? 'text-red-400 bg-red-400/10 border-red-400/20'
                    : p.result === 'Suspicious' ? 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
                    : 'text-green-400 bg-green-400/10 border-green-400/20'
                  return (
                    <div key={p.id} className="relative flex gap-4">
                      <div className={`relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border ${resultColor}`}>
                        <span className="h-2 w-2 rounded-full bg-current" />
                      </div>
                      <div className="tile flex-1 rounded-xl border p-4">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className="txt text-sm font-semibold">{p.pin}</span>
                          <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${resultColor}`}>{p.result || p.status}</span>
                          {(p.detections || 0) > 0 && (
                            <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">{p.detections} findings</span>
                          )}
                        </div>
                        <p className="muted text-xs">{fmt(p.scannedAt || p.createdAt)}</p>
                        {p.name && <p className="muted text-xs mt-0.5">{p.name}</p>}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })()}
      </div>
    </div>
  )
}
