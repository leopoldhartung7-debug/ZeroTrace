import { useState } from 'react'
import { useStore } from '../store.jsx'
import { Card } from '../components/kit.jsx'
import { Modal } from '../components/ui.jsx'
import { CheckCircle2, XCircle, RotateCcw, Download, ListChecks, User } from 'lucide-react'

function isSimilar(a, b) {
  const la = (a || '').toLowerCase()
  const lb = (b || '').toLowerCase()
  if (la === lb) return false // same is not "similar warning"
  if (la.includes(lb) || lb.includes(la)) return true
  // Levenshtein distance <= 2
  if (Math.abs(la.length - lb.length) > 2) return false
  const m = la.length, n = lb.length
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0))
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    dp[i][j] = la[i-1] === lb[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
  }
  return dp[m][n] <= 2
}

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
  const [commentModal, setCommentModal] = useState(null) // { id, action: 'approve' | 'reject' }
  const [commentText, setCommentText] = useState('')

  const pending = proposals.filter(p => p.status === 'pending')
  const approved = proposals.filter(p => p.status === 'approved')
  const rejected = proposals.filter(p => p.status === 'rejected')

  const visible = proposals
    .filter(p => filter === 'all' ? true : filter === 'user' ? p.source === 'user' : p.status === filter)
    .sort((a, b) => {
      if (sort === 'seenCount') return b.seenCount - a.seenCount
      if (sort === 'risk') return RISK_NUMBERS[b.risk] - RISK_NUMBERS[a.risk]
      return b.firstSeen - a.firstSeen
    })

  const thirtyDaysAgo = Date.now() - 30 * 86400000
  const stale = proposals.filter(p => p.status === 'pending' && (p.firstSeen || 0) < thirtyDaysAgo)

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
      <div className="grid grid-cols-5 gap-4">
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
        <Card className="p-4 text-center">
          <p className="text-3xl font-bold text-sky-400">{proposals.filter(p => p.source === 'user').length}</p>
          <p className="muted text-sm mt-1">User Reports</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-3xl font-bold text-orange-400">{stale.length}</p>
          <p className="muted text-sm mt-1">Stale</p>
        </Card>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg border bd overflow-hidden">
          {['pending', 'approved', 'rejected', 'user', 'all'].map(f => (
            <button
              key={f}
              onClick={() => { setFilter(f); setSelected([]) }}
              className={`px-3 py-1.5 text-sm font-medium capitalize transition-colors ${filter === f ? 'bg-sky-600 text-white' : 'muted hover:txt'}`}
            >{f === 'user' ? 'User Reports' : f}</button>
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

        {state.role === 'admin' && (
          <div className="flex items-center gap-2 text-sm">
            <span className="muted text-xs">Auto-approve if seen in ≥</span>
            <input
              type="number"
              min="1"
              value={state.settings?.autoApproveThreshold ?? 10}
              onChange={e => dispatch({ type: 'set-setting', key: 'autoApproveThreshold', value: Number(e.target.value) || 10 })}
              className="bd tile txt rounded-lg border px-2 py-1 text-sm w-16 focus:outline-none"
            />
            <span className="muted text-xs">scans</span>
          </div>
        )}

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
                  <th className="px-4 py-3 text-left">Source</th>
                  <th className="px-4 py-3 text-left">Description</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(p => {
                  const similar = p.status === 'pending'
                    ? proposals.filter(x => x.status === 'approved' && x.id !== p.id).find(x => isSimilar(p.pattern, x.pattern))
                    : null
                  return (
                  <tr key={p.id} className={`bd border-b last:border-0 hover:bg-white/[0.02] ${selected.includes(p.id) ? 'bg-sky-600/5' : ''}`}>
                    <td className="px-4 py-3">
                      {p.status === 'pending' && (
                        <input type="checkbox" checked={selected.includes(p.id)}
                          onChange={() => toggle(p.id)} className="rounded" />
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="txt font-mono font-medium">{p.pattern}</span>
                      {similar && (
                        <div className="text-xs text-orange-400 mt-0.5">⚠ Similar: {similar.pattern}</div>
                      )}
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
                    <td className="px-4 py-3">
                      {p.source === 'user'
                        ? <span className="flex items-center gap-1 rounded-full bg-sky-400/10 border border-sky-400/20 px-2 py-0.5 text-xs text-sky-400 w-fit"><User size={10} /> User</span>
                        : <span className="rounded-full bg-white/5 border bd px-2 py-0.5 text-xs muted">Auto-Scan</span>
                      }
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <span className="muted text-xs line-clamp-2">{p.description}</span>
                      {p.adminComment && (
                        <div className="text-xs text-sky-400 mt-0.5 italic">"{p.adminComment}"</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {p.status === 'pending' && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-xs text-yellow-400">Pending</span>}
                      {p.status === 'pending' && (p.firstSeen || 0) < thirtyDaysAgo && (
                        <span className="rounded-full bg-orange-400/10 border border-orange-400/20 px-2 py-0.5 text-xs text-orange-400 ml-1">Stale</span>
                      )}
                      {p.status === 'approved' && <span className="rounded-full bg-green-400/10 border border-green-400/20 px-2 py-0.5 text-xs text-green-400">Approved</span>}
                      {p.status === 'rejected' && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">Rejected</span>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        {p.status === 'pending' && (
                          <>
                            <button onClick={() => { setCommentModal({ id: p.id, action: 'approve' }); setCommentText('') }}
                              className="rounded-md bg-green-600/20 border border-green-600/30 p-1.5 text-green-400 hover:bg-green-600/30" title="Approve">
                              <CheckCircle2 size={14} />
                            </button>
                            <button onClick={() => { setCommentModal({ id: p.id, action: 'reject' }); setCommentText('') }}
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
                  )
                })}
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
      {commentModal && (
        <Modal
          open
          onClose={() => setCommentModal(null)}
          title={commentModal.action === 'approve' ? 'Approve Proposal' : 'Reject Proposal'}
          footer={
            <>
              <button onClick={() => setCommentModal(null)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
              <button
                onClick={() => {
                  dispatch({ type: commentModal.action === 'approve' ? 'approve-proposal' : 'reject-proposal', id: commentModal.id, comment: commentText })
                  setCommentModal(null)
                  setCommentText('')
                }}
                className={`rounded-lg px-4 py-2 text-sm font-semibold text-white ${commentModal.action === 'approve' ? 'bg-green-600 hover:bg-green-500' : 'bg-red-600 hover:bg-red-500'}`}
              >
                {commentModal.action === 'approve' ? 'Approve' : 'Reject'}
              </button>
            </>
          }
        >
          <div className="space-y-3">
            <p className="muted text-sm">Leave a comment (optional)</p>
            <textarea
              value={commentText}
              onChange={e => setCommentText(e.target.value)}
              rows={3}
              placeholder="Reason for this decision..."
              className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none"
            />
          </div>
        </Modal>
      )}
    </div>
  )
}
