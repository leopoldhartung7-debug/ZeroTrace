import { useMemo, useState } from 'react'
import { History as HistoryIcon, Search, Filter, Trash2, Download } from 'lucide-react'
import { PageHeader, Card, Input } from '../components/kit.jsx'
import { Select } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function AdminAuditLog() {
  const { state, dispatch } = useStore()
  const log = state.adminAuditLog || []
  const [q, setQ] = useState('')
  const [actionFilter, setActionFilter] = useState('all')

  const actions = useMemo(
    () => Array.from(new Set(log.map((e) => e.action))).sort(),
    [log],
  )

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return log.filter((e) => {
      if (actionFilter !== 'all' && e.action !== actionFilter) return false
      if (!needle) return true
      return [e.action, e.target, e.detail, e.adminName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle))
    })
  }, [log, q, actionFilter])

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(log, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `zerotrace-audit-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <PageHeader
        icon={HistoryIcon}
        kicker="Audit Trail"
        title="Admin Audit Log"
        subtitle="Every action performed by an administrator is logged here."
        actions={
          <>
            <button
              onClick={exportJson}
              className="bd txt flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:border-sky-500"
            >
              <Download size={14} /> Export JSON
            </button>
            {log.length > 0 && (
              <button
                onClick={() => {
                  if (confirm('Clear the entire audit log? This cannot be undone.')) {
                    dispatch({ type: 'clear-audit-log' })
                  }
                }}
                className="bd flex items-center gap-2 rounded-lg border border-red-600/40 px-3 py-2 text-sm text-red-500 hover:bg-red-600/10"
              >
                <Trash2 size={14} /> Clear
              </button>
            )}
          </>
        }
      />

      <Card className="p-4">
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search size={14} className="muted absolute left-3 top-3.5" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search action, target, admin..."
              className="pl-9"
            />
          </div>
          <div className="w-full sm:w-56">
            <Select
              value={actionFilter}
              onChange={setActionFilter}
              options={[
                { value: 'all', label: 'All actions' },
                ...actions.map((a) => ({ value: a, label: a })),
              ]}
            />
          </div>
        </div>
      </Card>

      <Card className="mt-4 p-0">
        {filtered.length === 0 ? (
          <p className="muted py-16 text-center text-sm">No audit entries found.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Admin</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Detail</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => (
                  <tr key={e.id} className="bd border-b align-top last:border-0">
                    <td className="muted px-4 py-3 text-xs">{fmt(e.time)}</td>
                    <td className="txt px-4 py-3 text-xs">{e.adminName || 'Admin'}</td>
                    <td className="px-4 py-3">
                      <span className="bd txt rounded-md border px-2 py-0.5 text-[11px] font-semibold">
                        {e.action}
                      </span>
                    </td>
                    <td className="txt break-all px-4 py-3 font-mono text-xs">{e.target || '—'}</td>
                    <td className="muted break-words px-4 py-3 text-xs">{e.detail || '—'}</td>
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
