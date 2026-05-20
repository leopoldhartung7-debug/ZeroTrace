import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Trophy, Search, MessageSquare, ScanLine, ShieldAlert } from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

const VERDICT_TONE = {
  Cheating: 'border-red-600/40 bg-red-600/15 text-red-500',
  Suspicious: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500',
  Clean: 'border-green-600/40 bg-green-600/15 text-green-500',
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function Scoreboard() {
  const { state } = useStore()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState('all')

  const rows = useMemo(() => {
    const byId = new Map()
    ;(state.pins || []).forEach((p) => {
      if (!p.discordId) return
      if (state.role !== 'admin' && p.ownerId !== state.session?.userId) return
      const r = deriveScanReport(p)
      const risk = r
        ? Math.min(100, r.counts.detects * 8 + r.counts.warnings * 2 + r.counts.suspicious * 5)
        : 0
      const entry = byId.get(p.discordId) || {
        discordId: p.discordId,
        scans: 0,
        maxRisk: 0,
        lastVerdict: null,
        lastScanAt: 0,
        lastPinId: null,
        name: p.name || '',
      }
      entry.scans += 1
      entry.maxRisk = Math.max(entry.maxRisk, risk)
      const at = p.scannedAt || p.createdAt || 0
      if (at > entry.lastScanAt) {
        entry.lastScanAt = at
        entry.lastVerdict = p.result || null
        entry.lastPinId = p.id
        entry.name = p.name || entry.name
      }
      byId.set(p.discordId, entry)
    })
    let list = [...byId.values()]
    if (q) {
      const l = q.toLowerCase()
      list = list.filter(
        (e) => e.discordId.toLowerCase().includes(l) || (e.name || '').toLowerCase().includes(l),
      )
    }
    if (filter !== 'all') {
      list = list.filter((e) => (e.lastVerdict || '').toLowerCase() === filter)
    }
    list.sort((a, b) => b.maxRisk - a.maxRisk || b.lastScanAt - a.lastScanAt)
    return list
  }, [state.pins, state.role, state.session, q, filter])

  return (
    <div>
      <PageHeader
        icon={Trophy}
        kicker="Risk leaderboard"
        title="Scoreboard"
        subtitle="All scanned Discord IDs sorted by their highest risk score."
      />

      <Card className="p-6">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-[200px] flex-1">
            <Search size={15} className="muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by name or Discord ID…"
              className="bd tile txt w-full rounded-lg border py-2 pl-9 pr-3 text-sm focus:outline-none"
            />
          </div>
          <div className="flex gap-2 text-xs">
            {['all', 'cheating', 'suspicious', 'clean'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`bd rounded-md border px-3 py-1.5 ${
                  filter === f ? 'bg-sky-500/15 text-sky-400' : 'muted hover:txt'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {rows.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No scans yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-3 py-3">#</th>
                  <th className="px-3 py-3">Discord ID</th>
                  <th className="px-3 py-3">Name</th>
                  <th className="px-3 py-3">Risk</th>
                  <th className="px-3 py-3">Scans</th>
                  <th className="px-3 py-3">Last verdict</th>
                  <th className="px-3 py-3">Last scan</th>
                  <th className="px-3 py-3" />
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={r.discordId} className="bd border-b last:border-0">
                    <td className="muted px-3 py-3 text-xs">{i + 1}</td>
                    <td className="txt break-all px-3 py-3 font-mono text-xs">{r.discordId}</td>
                    <td className="txt px-3 py-3">{r.name || '—'}</td>
                    <td className="px-3 py-3">
                      <span className={`font-semibold ${r.maxRisk >= 60 ? 'text-red-500' : r.maxRisk >= 30 ? 'text-yellow-500' : 'text-green-500'}`}>
                        {r.maxRisk}
                      </span>
                    </td>
                    <td className="muted px-3 py-3 text-xs">{r.scans}</td>
                    <td className="px-3 py-3">
                      {r.lastVerdict ? (
                        <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${VERDICT_TONE[r.lastVerdict] || 'bd muted'}`}>
                          {r.lastVerdict}
                        </span>
                      ) : (
                        <span className="muted text-xs">—</span>
                      )}
                    </td>
                    <td className="muted px-3 py-3 text-xs">{fmt(r.lastScanAt)}</td>
                    <td className="px-3 py-3 text-right">
                      <Link to={`/players/${r.discordId}`} className="bd txt inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
                        Profile
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
