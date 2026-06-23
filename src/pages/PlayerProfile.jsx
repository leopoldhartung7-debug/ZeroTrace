import { useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, User as UserIcon, ScanLine, ShieldAlert, Server, Usb, Activity,
  AtSign, Search, AlertTriangle,
} from 'lucide-react'
import {
  LineChart, Line, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts'
import { PageHeader, Card, StatTile } from '../components/kit.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

const VERDICT_TONE = {
  Cheating: 'border-red-600/40 bg-red-600/15 text-red-500',
  Suspicious: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500',
  Clean: 'border-green-600/40 bg-green-600/15 text-green-500',
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function PlayerProfile() {
  const { id } = useParams()
  const nav = useNavigate()
  const { state } = useStore()
  const cleanId = (id || '').trim()

  const pins = useMemo(
    () =>
      (state.pins || [])
        .filter((p) => (p.discordId || '') === cleanId)
        .sort((a, b) => (b.scannedAt || b.createdAt) - (a.scannedAt || a.createdAt)),
    [state.pins, cleanId],
  )

  const reports = useMemo(() => pins.map((p) => ({ pin: p, report: deriveScanReport(p) })), [pins])

  const all = useMemo(() => {
    const serverMap = new Map()
    const usbMap = new Map()
    const cheatSet = new Set()
    let maxRisk = 0
    const trend = []
    reports.forEach(({ pin, report }) => {
      if (!report) return
      const risk = Math.min(
        100,
        report.counts.detects * 8 + report.counts.warnings * 2 + report.counts.suspicious * 5,
      )
      maxRisk = Math.max(maxRisk, risk)
      trend.push({
        date: new Date(pin.scannedAt || pin.createdAt).toLocaleDateString(),
        risk,
        verdict: pin.result || 'Clean',
      })
      report.discordServers.forEach((s) => {
        const k = `${s.name}|${s.id}`
        if (!serverMap.has(k)) serverMap.set(k, s)
      })
      report.usb.forEach((u) => {
        const k = `${u.device}|${u.serial}`
        if (!usbMap.has(k)) usbMap.set(k, u)
      })
      ;(pin.cheats || []).forEach((c) => cheatSet.add(c))
    })
    return {
      maxRisk,
      trend: trend.reverse(),
      servers: [...serverMap.values()].sort(
        (a, b) => (a.flag === 'clean' ? 1 : 0) - (b.flag === 'clean' ? 1 : 0),
      ),
      usb: [...usbMap.values()],
      cheats: [...cheatSet],
    }
  }, [reports])

  if (!cleanId)
    return (
      <div className="py-20 text-center">
        <p className="txt text-lg font-semibold">No Discord ID</p>
      </div>
    )

  return (
    <div>
      <button onClick={() => nav(-1)} className="muted hover:txt mb-4 flex items-center gap-2 text-sm">
        <ArrowLeft size={16} /> Back
      </button>

      <PageHeader
        icon={UserIcon}
        kicker="Player profile"
        title={`Discord ID ${cleanId}`}
        subtitle="Every scan, server and finding tied to this Discord account."
      />

      {pins.length === 0 ? (
        <Card className="p-12 text-center">
          <p className="muted text-sm">No scans found for this Discord ID.</p>
        </Card>
      ) : (
        <>
          <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile icon={ScanLine} label="Total Scans" value={pins.length} />
            <StatTile icon={ShieldAlert} label="Max Risk Score" value={all.maxRisk} accent="text-red-500" />
            <StatTile icon={Server} label="Servers" value={all.servers.length} accent="text-sky-500" />
            <StatTile icon={Usb} label="USB devices" value={all.usb.length} />
          </div>

          {all.trend.length > 1 && (
            <Card className="mb-6 p-6">
              <h3 className="txt mb-1 text-lg font-semibold">Risk score history</h3>
              <p className="muted mb-4 text-sm">Risk score across every recorded scan.</p>
              <div style={{ width: '100%', height: 240 }}>
                <ResponsiveContainer>
                  <LineChart data={all.trend}>
                    <CartesianGrid stroke="#2a2c33" strokeDasharray="3 3" />
                    <XAxis dataKey="date" stroke="#8a8d93" fontSize={11} />
                    <YAxis stroke="#8a8d93" domain={[0, 100]} fontSize={11} />
                    <Tooltip
                      contentStyle={{ background: '#191b20', border: '1px solid #34363b', borderRadius: 8 }}
                      labelStyle={{ color: '#e7e8ea' }}
                    />
                    <Line type="monotone" dataKey="risk" stroke="#848eb0" strokeWidth={2} dot={{ r: 4 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>
          )}

          <Card className="mb-6 p-6">
            <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
              <Activity size={18} /> Scan timeline ({pins.length})
            </h3>
            <p className="muted mb-4 text-sm">Every scan tied to this ID, newest first.</p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="caps-label bd border-b">
                    <th className="px-3 py-3">Pin</th>
                    <th className="px-3 py-3">Game</th>
                    <th className="px-3 py-3">Verdict</th>
                    <th className="px-3 py-3">Risk</th>
                    <th className="px-3 py-3">Scanned</th>
                    <th className="px-3 py-3" />
                  </tr>
                </thead>
                <tbody>
                  {reports.map(({ pin, report }) => {
                    const risk = report
                      ? Math.min(100, report.counts.detects * 8 + report.counts.warnings * 2 + report.counts.suspicious * 5)
                      : 0
                    return (
                      <tr key={pin.id} className="bd border-b last:border-0">
                        <td className="txt px-3 py-3 font-mono text-xs">{pin.pin}</td>
                        <td className="muted px-3 py-3 text-xs">{pin.game}</td>
                        <td className="px-3 py-3">
                          {pin.result ? (
                            <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${VERDICT_TONE[pin.result] || 'bd muted'}`}>
                              {pin.result}
                            </span>
                          ) : (
                            <span className="muted">—</span>
                          )}
                        </td>
                        <td className="txt px-3 py-3 font-semibold">{risk}</td>
                        <td className="muted px-3 py-3 text-xs">{fmt(pin.scannedAt || pin.createdAt)}</td>
                        <td className="px-3 py-3 text-right">
                          <Link to={`/scan/${pin.id}`} className="bd txt inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
                            <Search size={13} /> Open
                          </Link>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>

          {all.servers.length > 0 && (
            <Card className="mb-6 p-6">
              <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
                <Server size={18} /> Discord servers ({all.servers.length})
              </h3>
              <p className="muted mb-4 text-sm">Deduplicated list across all scans.</p>
              <div className="space-y-2">
                {all.servers.map((s, i) => {
                  const tone =
                    s.flag === 'cheat'
                      ? 'border-red-600/40 bg-red-600/15 text-red-500'
                      : s.flag === 'reselling'
                        ? 'border-orange-500/40 bg-orange-500/15 text-orange-400'
                        : 'bd muted'
                  const tag = s.flag === 'cheat' ? 'Cheat Discord' : s.flag === 'reselling' ? 'Reselling Discord' : 'Member'
                  return (
                    <div key={i} className="tile flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3">
                      <div>
                        <p className="txt text-sm font-medium">{s.name}</p>
                        <p className="muted font-mono text-xs">ID: {s.id}</p>
                      </div>
                      <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${tone}`}>{tag}</span>
                    </div>
                  )
                })}
              </div>
            </Card>
          )}

          {all.cheats.length > 0 && (
            <Card className="p-6">
              <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
                <AlertTriangle size={18} /> Cheats ever found ({all.cheats.length})
              </h3>
              <div className="mt-3 flex flex-wrap gap-2">
                {all.cheats.map((c) => (
                  <span key={c} className="bd tile muted rounded-md border px-2.5 py-1 text-xs">{c}</span>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
