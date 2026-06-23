import { useMemo, useState } from 'react'
import { Activity, Search } from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { Select } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

const KIND_COLORS = {
  db: 'text-sky-400',
  scan: 'text-green-400',
  pin: 'text-purple-400',
  file: 'text-orange-400',
  rule: 'text-yellow-400',
  support: 'text-pink-400',
}

function timeAgo(ts) {
  const diff = Date.now() - ts
  if (diff < 60000) return 'gerade eben'
  if (diff < 3600000) return `vor ${Math.floor(diff / 60000)} Min`
  if (diff < 86400000) return `vor ${Math.floor(diff / 3600000)} Std`
  return `vor ${Math.floor(diff / 86400000)} Tagen`
}

export default function ActivityLogPage() {
  const { state } = useStore()
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('all')

  const events = useMemo(() => {
    return (state.events || []).filter(e => {
      if (kind !== 'all' && e.kind !== kind) return false
      if (q && !`${e.title} ${e.detail}`.toLowerCase().includes(q.toLowerCase())) return false
      return true
    })
  }, [state.events, q, kind])

  const kinds = [...new Set((state.events || []).map(e => e.kind))].sort()

  return (
    <div>
      <PageHeader
        icon={Activity}
        kicker="Systemereignisse"
        title="Aktivitäts-Log"
        subtitle="Chronologische Liste aller Aktionen im System."
      />

      <Card className="p-5">
        <div className="flex flex-col gap-3 sm:flex-row mb-5">
          <div className="relative flex-1">
            <Search size={16} className="muted absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder="Ereignisse suchen…"
              className="bd tile txt w-full rounded-lg border py-2.5 pl-10 pr-4 text-sm focus:outline-none"
            />
          </div>
          <Select
            className="sm:w-40"
            value={kind}
            onChange={setKind}
            options={[{ value: 'all', label: 'Alle Arten' }, ...kinds.map(k => ({ value: k, label: k }))]}
          />
        </div>

        {events.length === 0 && (
          <p className="muted text-sm text-center py-12">Keine Ereignisse gefunden.</p>
        )}

        <div className="space-y-0 divide-y divide-white/5">
          {events.map(e => (
            <div key={e.id} className="flex items-start gap-4 py-3">
              <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md tile border bd">
                <span className={`text-[9px] font-bold uppercase ${KIND_COLORS[e.kind] || 'text-sky-400'}`}>{(e.kind || '?')[0]}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium txt truncate">{e.title}</p>
                {e.detail && <p className="text-xs muted truncate">{e.detail}</p>}
              </div>
              <span className="shrink-0 text-[11px] muted">{timeAgo(e.time)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
