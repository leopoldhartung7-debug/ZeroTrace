import { useState } from 'react'
import { useStore } from '../store.jsx'
import { Card } from '../components/kit.jsx'
import { CheckCircle2, XCircle, RotateCcw, Download, ListChecks } from 'lucide-react'

const TYPE_LABELS = {
  FileName: 'Exact Filename',
  FileNameKeyword: 'Filename Keyword',
  ProcessName: 'Process Name',
}

const RISK_COLORS = {
  Critical: 'text-red-400 bg-red-400/10 border-red-400/20',
  High: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
  Medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
  Low: 'text-green-400 bg-green-400/10 border-green-400/20',
}

const TYPE_NUMBERS = { FileName: 1, FileNameKeyword: 2, ProcessName: 4 }
const RISK_NUMBERS = { Critical: 3, High: 2, Medium: 1, Low: 0 }

function exportAsJson(proposals) {
  const approved = proposals.filter(p => p.status === 'approved')
  const data = approved.map(p => ({
    type: TYPE_NUMBERS[p.type] ?? 2,
    pattern: p.pattern,
    risk: RISK_NUMBERS[p.risk] ?? 2,
    category: p.category,
    description: p.description || `Auto-discovered: ${p.pattern}`,
    enabled: true,
  }))
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'zerotrace.indicators.json'
  a.click()
  URL.revokeObjectURL(url)
}

export default function ProposalsPage() {
  const { state, dispatch } = useStore()
  const proposals = state.proposals || []
  const [filter, setFilter] = useState('pending')
  const [sort, setSort] = useState('seenCount')
  const [selected, setSelected] = useState([])

  const pending = proposals.filter(p => p.status === 'pending')
  const approved = proposals.filter(p => p.status === 'approved')
  const rejected = proposals.filter(p => p.status === 'rejected')

  const visible = proposals
    .filter(p => filter === 'all' ? true : p.status === filter)
    .sort((a, b) => {
      if (sort === 'seenCount') return b.seenCount - a.seenCount
      if (sort === 'risk') return RISK_NUMBERS[b.risk] - RISK_NUMBERS[a.risk]
      return b.firstSeen - a.firstSeen
    })

  const allSelectedPending = selected.length > 0 && selected.every(id =>
    proposals.find(p => p.id === id)?.status === 'pending'
  )

  const toggle = (id) => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="txt text-2xl font-bold flex items-center gap-2">
          <ListChecks size={24} /> Indicator Proposals
        </h1>
        <p className="muted mt-1 text-sm">
          Auto-collected from all imported scans. Approve to activate as indicators in the scanner.
          Export approved proposals as <code className="txt font-mono text-xs">zerotrace.indicators.json</code> and
          place it next to <code className="txt font-mono text-xs">ZeroTrace.exe</code> — the scanner loads it automatically on next startup.
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="p-4 text-center">
          <p className="text-3xl font-bold text-yellow-400">{pending.length}</p>
          <p className="muted text-sm mt-1">Pending</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-3xl font-bold text-green-400">{approved.length}</p>
          <p className="muted text-sm mt-1">Approved</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-3xl font-bold text-red-400">{rejected.length}</p>
          <p className="muted text-sm mt-1">Rejected</p>
        </Card>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg border bd overflow-hidden">
          {['pending', 'approved', 'rejected', 'all'].map(f => (
            <button
              key={f}
              onClick={() => { setFilter(f); setSelected([]) }}
              className={`px-3 py-1.5 text-sm font-medium capitalize transition-colors ${filter === f ? 'bg-sky-600 text-white' : 'muted hover:txt'}`}
            >{f}</button>
          ))}
        </div>

        <select
          value={sort}
          onChange={e => setSort(e.target.value)}
          className="bd tile txt rounded-lg border px-3 py-1.5 text-sm"
        >
          <option value="seenCount">Sort: Most Seen</option>
          <option value="risk">Sort: Highest Risk</option>
          <option value="firstSeen">Sort: Newest</option>
        </select>

        <div className="ml-auto flex gap-2">
          {selected.length > 0 && allSelectedPending && (
            <>
              <button
                onClick={() => { dispatch({ type: 'bulk-approve-proposals', ids: selected }); setSelected([]) }}
                className="flex items-center gap-1.5 rounded-lg bg-green-600/20 border border-green-600/30 px-3 py-1.5 text-sm text-green-400 hover:bg-green-600/30"
              ><CheckCircle2 size={14} /> Approve ({selected.length})</button>
              <button
                onClick={() => { dispatch({ type: 'bulk-reject-proposals', ids: selected }); setSelected([]) }}
                className="flex items-center gap-1.5 rounded-lg bg-red-600/20 border border-red-600/30 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30"
              ><XCircle size={14} /> Reject ({selected.length})</button>
            </>
          )}

          {approved.length > 0 && (
            <button
              onClick={() => exportAsJson(proposals)}
              className="flex items-center gap-1.5 rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-sky-500"
            ><Download size={14} /> Export {approved.length} approved</button>
          )}

          {rejected.length > 0 && (
            <button
              onClick={() => dispatch({ type: 'clear-rejected-proposals' })}
              className="flex items-center gap-1.5 rounded-lg border bd px-3 py-1.5 text-sm muted hover:txt"
            ><XCircle size={14} /> Clear rejected</button>
          )}
        </div>
      </div>

      {/* Table */}
      <Card>
        {visible.length === 0 ? (
          <div className="py-16 text-center">
            <ListChecks size={40} className="muted mx-auto mb-3" />
            <p className="txt font-medium">No proposals</p>
            <p className="muted text-sm mt-1">
              {filter === 'pending' ? 'Import scan results to start collecting proposals.' : `No ${filter} proposals.`}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bd border-b caps-label">
                  <th className="px-4 py-3 w-8">
                    <input type="checkbox"
                      checked={selected.length === visible.filter(p => p.status === 'pending').length && visible.some(p => p.status === 'pending')}
                      onChange={e => {
                        if (e.target.checked) setSelected(visible.filter(p => p.status === 'pending').map(p => p.id))
                        else setSelected([])
                      }}
                      className="rounded"
                    />
                  </th>
                  <th className="px-4 py-3 text-left">Pattern</th>
                  <th className="px-4 py-3 text-left">Type</th>
                  <th className="px-4 py-3 text-left">Category</th>
                  <th className="px-4 py-3 text-left">Risk</th>
                  <th className="px-4 py-3 text-center">Seen In</th>
                  <th className="px-4 py-3 text-left">Description</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(p => (
                  <tr key={p.id} className={`bd border-b last:border-0 hover:bg-white/[0.02] ${selected.includes(p.id) ? 'bg-sky-600/5' : ''}`}>
                    <td className="px-4 py-3">
                      {p.status === 'pending' && (
                        <input type="checkbox" checked={selected.includes(p.id)}
                          onChange={() => toggle(p.id)} className="rounded" />
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="txt font-mono font-medium">{p.pattern}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="muted text-xs">{TYPE_LABELS[p.type] || p.type}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded-full bg-white/5 border bd px-2 py-0.5 text-xs">{p.category}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${RISK_COLORS[p.risk]}`}>{p.risk}</span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className={`font-bold text-base ${p.seenCount >= 5 ? 'text-red-400' : p.seenCount >= 2 ? 'text-orange-400' : 'txt'}`}>
                        {p.seenCount}
                      </span>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <span className="muted text-xs line-clamp-2">{p.description}</span>
                    </td>
                    <td className="px-4 py-3">
                      {p.status === 'pending' && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-xs text-yellow-400">Pending</span>}
                      {p.status === 'approved' && <span className="rounded-full bg-green-400/10 border border-green-400/20 px-2 py-0.5 text-xs text-green-400">Approved</span>}
                      {p.status === 'rejected' && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">Rejected</span>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        {p.status === 'pending' && (
                          <>
                            <button onClick={() => dispatch({ type: 'approve-proposal', id: p.id })}
                              className="rounded-md bg-green-600/20 border border-green-600/30 p-1.5 text-green-400 hover:bg-green-600/30" title="Approve">
                              <CheckCircle2 size={14} />
                            </button>
                            <button onClick={() => dispatch({ type: 'reject-proposal', id: p.id })}
                              className="rounded-md bg-red-600/20 border border-red-600/30 p-1.5 text-red-400 hover:bg-red-600/30" title="Reject">
                              <XCircle size={14} />
                            </button>
                          </>
                        )}
                        {(p.status === 'approved' || p.status === 'rejected') && (
                          <button onClick={() => dispatch({ type: 'reset-proposal', id: p.id })}
                            className="rounded-md border bd p-1.5 muted hover:txt" title="Reset to pending">
                            <RotateCcw size={14} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Export instructions */}
      {approved.length > 0 && (
        <Card className="p-5 border-green-600/20 bg-green-600/5">
          <h3 className="txt font-semibold mb-2 flex items-center gap-2"><Download size={16} /> How to activate approved indicators</h3>
          <ol className="muted text-sm space-y-1 list-decimal list-inside">
            <li>Click <strong className="txt">Export {approved.length} approved</strong> above to download <code className="txt font-mono">zerotrace.indicators.json</code></li>
            <li>Place the file in the same folder as <code className="txt font-mono">ZeroTrace.exe</code></li>
            <li>The scanner loads it automatically on next startup — no restart needed mid-session</li>
            <li>Indicators appear as source <code className="txt font-mono">community-approved</code> in the scanner</li>
          </ol>
        </Card>
      )}
    </div>
  )
}
