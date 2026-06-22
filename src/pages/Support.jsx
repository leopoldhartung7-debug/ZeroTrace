import { useState, useMemo } from 'react'
import {
  LifeBuoy, Plus, MessageSquare, ShieldAlert, Clock, CheckCircle2,
  XCircle, AlertTriangle, Send, User, Shield, Search, Tag, Lock,
  Star, Trash2, UserCheck, ChevronDown, History, SortAsc, Download,
} from 'lucide-react'
import { PageHeader, Card, EmptyState, Accordion, Field, Input, Textarea } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

const FAQ = [
  { q: 'How do scan pins work?', a: 'Create a pin, share the 8-character code with the user, then run the scan to get a verdict (Clean / Suspicious / Cheating).' },
  { q: 'Is my data sent anywhere?', a: 'No. This dashboard is fully client-side — all pins, scans and files stay in your browser localStorage.' },
  { q: 'What files can the String Extractor handle?', a: 'Any binary: .exe, .jar, .dll and .sys are typical. It extracts ASCII and UTF-16LE strings.' },
  { q: 'How accurate is Suspicious Detection?', a: 'It uses a YARA-lite engine matching string and hex patterns. Treat results as indicators, not proof.' },
  { q: 'Can I suggest cheats for the database?', a: 'Yes — click "Suggest Cheat". Your suggestion goes to admin review and if approved activates in the scanner.' },
]

const STATUS_STYLES = {
  Open:          { cls: 'bg-sky-400/10 border-sky-400/20 text-sky-400',      icon: Clock },
  'In Progress': { cls: 'bg-yellow-400/10 border-yellow-400/20 text-yellow-400', icon: AlertTriangle },
  Resolved:      { cls: 'bg-green-400/10 border-green-400/20 text-green-400', icon: CheckCircle2 },
  Closed:        { cls: 'bg-white/5 border-white/10 text-white/40',           icon: XCircle },
}

const PRIORITY_STYLES = {
  Low:    'bg-white/5 border-white/10 text-white/40',
  Normal: 'bg-white/10 border-white/20 text-white/60',
  High:   'bg-orange-400/10 border-orange-400/20 text-orange-400',
  Urgent: 'bg-red-400/10 border-red-400/20 text-red-400',
}

const TAG_COLORS = [
  'bg-purple-400/10 border-purple-400/20 text-purple-400',
  'bg-cyan-400/10 border-cyan-400/20 text-cyan-400',
  'bg-pink-400/10 border-pink-400/20 text-pink-400',
  'bg-amber-400/10 border-amber-400/20 text-amber-400',
  'bg-lime-400/10 border-lime-400/20 text-lime-400',
  'bg-indigo-400/10 border-indigo-400/20 text-indigo-400',
]

const PRESET_TAGS = ['bug', 'billing', 'detection', 'feature-request', 'urgent', 'false-positive', 'cheat-related']

const CANNED_RESPONSES = [
  { label: 'Looking into it', text: 'Thanks for reaching out! We are looking into this and will update you shortly.' },
  { label: 'Need more info', text: 'Could you provide more details? Screenshots or exact steps to reproduce would help a lot.' },
  { label: 'Issue resolved', text: 'This issue has been resolved. Please let us know if you experience any further problems.' },
  { label: 'Not reproducible', text: "We were unable to reproduce this on our end. Could you check again and provide exact steps?" },
  { label: 'False positive', text: 'After reviewing, this appears to be a false positive. No action is required on your end.' },
  { label: 'Escalated', text: 'We have escalated this ticket to our senior team. You will hear back within 24 hours.' },
]

const CHEAT_TYPES = [
  { value: 'FileNameKeyword', label: 'Filename Keyword (partial match)' },
  { value: 'FileName',        label: 'Exact Filename' },
  { value: 'ProcessName',     label: 'Process Name' },
]
const CHEAT_CATEGORIES = ['Cheat', 'Spoofer', 'Injector', 'Cleaner', 'FiveM-Cheat', 'Other']
const RISK_LEVELS    = ['Medium', 'High', 'Critical']
const GAMES          = ['MINECRAFT', 'CS2', 'RUST', 'VALORANT', 'FORTNITE', 'APEX', 'FiveM', 'OTHER']
const STATUSES       = ['Open', 'In Progress', 'Resolved', 'Closed']
const emptyCheatForm = { pattern: '', type: 'FileNameKeyword', category: 'Cheat', risk: 'High', game: 'OTHER', description: '' }

function tagColor(tag) {
  let h = 0
  for (let i = 0; i < tag.length; i++) h = (h * 31 + tag.charCodeAt(i)) & 0xffff
  return TAG_COLORS[h % TAG_COLORS.length]
}

function slaLabel(createdAt) {
  const ms = Date.now() - createdAt
  const h = Math.floor(ms / 3600000)
  const d = Math.floor(h / 24)
  const rh = h % 24
  if (d > 0) return `${d}d ${rh}h`
  return `${h}h`
}

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.Open
  const Icon = s.icon
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${s.cls}`}>
      <Icon size={10} /> {status}
    </span>
  )
}

function PriorityBadge({ priority }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs ${PRIORITY_STYLES[priority] || PRIORITY_STYLES.Normal}`}>
      {priority}
    </span>
  )
}

function TagChip({ tag }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs ${tagColor(tag)}`}>{tag}</span>
  )
}

function StarRating({ value, onChange, readonly }) {
  return (
    <div className="flex gap-1">
      {[1, 2, 3, 4, 5].map(n => (
        <button
          key={n}
          onClick={() => !readonly && onChange?.(n)}
          disabled={readonly}
          className={`transition-colors ${n <= (value || 0) ? 'text-yellow-400' : 'text-white/20'} ${readonly ? '' : 'hover:text-yellow-300 cursor-pointer'}`}
        >
          <Star size={18} fill={n <= (value || 0) ? 'currentColor' : 'none'} />
        </button>
      ))}
    </div>
  )
}

function TagInput({ tags, onChange }) {
  const [input, setInput] = useState('')
  const add = (tag) => {
    const t = tag.trim().toLowerCase().replace(/\s+/g, '-')
    if (t && !tags.includes(t)) onChange([...tags, t])
    setInput('')
  }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {tags.map(t => (
          <span key={t} className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${tagColor(t)}`}>
            {t}
            <button onClick={() => onChange(tags.filter(x => x !== t))} className="hover:opacity-70">×</button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(input) } }}
          placeholder="Add tag…"
          className="bd tile txt flex-1 rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-sky-500"
        />
      </div>
      <div className="flex flex-wrap gap-1">
        {PRESET_TAGS.filter(t => !tags.includes(t)).map(t => (
          <button key={t} onClick={() => onChange([...tags, t])}
            className="rounded-full border bd px-2 py-0.5 text-xs muted hover:txt transition-colors">
            + {t}
          </button>
        ))}
      </div>
    </div>
  )
}

function TicketThread({ ticket, onClose }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [reply, setReply] = useState('')
  const [isInternal, setIsInternal] = useState(false)
  const [showCanned, setShowCanned] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [linkSearch, setLinkSearch] = useState('')
  const [showLinkPanel, setShowLinkPanel] = useState(false)
  const isAdmin = state.role === 'admin'

  const visibleReplies = (ticket.replies || []).filter(r => isAdmin || !r.internal)

  const sendReply = () => {
    if (!reply.trim()) return
    dispatch({ type: 'reply-ticket', id: ticket.id, message: reply.trim(), internal: isInternal })
    toast({ type: 'success', title: isInternal ? 'Internal note added' : 'Reply sent' })
    setReply('')
    setIsInternal(false)
  }

  const changeStatus = (status) => {
    dispatch({ type: 'update-ticket', id: ticket.id, fields: { status } })
    toast({ type: 'success', title: `Status → ${status}` })
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={
        <div className="flex flex-wrap items-center gap-2">
          <span className="txt font-semibold">{ticket.subject}</span>
          <StatusBadge status={ticket.status} />
          <PriorityBadge priority={ticket.priority} />
          {(ticket.tags || []).map(t => <TagChip key={t} tag={t} />)}
          {(ticket.relatedTo || []).map(rid => {
            const related = (state.tickets || []).find(x => x.id === rid)
            return related ? (
              <span key={rid} className="rounded-full bg-sky-400/10 border border-sky-400/20 px-2 py-0.5 text-xs text-sky-400 cursor-pointer"
                onClick={() => {/* could navigate */}}>
                ↗ {rid}
              </span>
            ) : null
          })}
        </div>
      }
      footer={
        <div className="flex gap-2 w-full flex-wrap">
          {isAdmin && (
            <>
              <select
                value={ticket.status}
                onChange={e => changeStatus(e.target.value)}
                className="bd tile txt rounded-lg border px-3 py-2 text-sm"
              >
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <button
                onClick={() => { if (confirm('Delete this ticket?')) { dispatch({ type: 'delete-ticket', id: ticket.id }); onClose() } }}
                className="flex items-center gap-1.5 rounded-lg bg-red-600/10 border border-red-600/30 px-3 py-2 text-sm text-red-400 hover:bg-red-600/20"
              >
                <Trash2 size={14} />
              </button>
              {(ticket.status === 'Open' || ticket.status === 'In Progress') && (
                <button
                  onClick={() => {
                    dispatch({ type: 'update-ticket', id: ticket.id, fields: { status: 'Closed' } })
                    dispatch({ type: 'reply-ticket', id: ticket.id, message: 'Auto-closed by admin', internal: true })
                    toast({ type: 'success', title: 'Ticket closed' })
                    onClose()
                  }}
                  className="flex items-center gap-1.5 rounded-lg border border-orange-500/30 bg-orange-500/10 px-3 py-2 text-sm text-orange-400 hover:bg-orange-500/20"
                >
                  Close Stale
                </button>
              )}
            </>
          )}
          <button
            onClick={() => setShowHistory(h => !h)}
            className="flex items-center gap-1.5 rounded-lg border bd px-3 py-2 text-sm muted hover:txt"
          >
            <History size={14} /> History
          </button>
          <button onClick={onClose} className="bd txt rounded-lg border px-4 py-2 text-sm ml-auto">Close</button>
        </div>
      }
    >
      <div className="space-y-3 max-h-[65vh] overflow-y-auto pr-1">
        {/* Assignee */}
        {isAdmin && (
          <div className="flex items-center gap-2 text-xs muted">
            <UserCheck size={13} />
            <span>Assigned to:</span>
            <select
              value={ticket.assignedTo || ''}
              onChange={e => dispatch({ type: 'assign-ticket', id: ticket.id, assignee: e.target.value || null })}
              className="bd tile txt rounded border px-2 py-0.5 text-xs"
            >
              <option value="">— unassigned —</option>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
            </select>
            {ticket.assignedTo && (
              <span className="flex items-center gap-1 text-sky-400"><UserCheck size={12} /> {ticket.assignedTo}</span>
            )}
          </div>
        )}

        {/* Linked Tickets */}
        {isAdmin && (
          <div className="rounded-lg border bd bg-white/[0.02] px-4 py-3">
            <div className="flex items-center justify-between mb-2">
              <p className="txt text-xs font-semibold">Linked Tickets</p>
              <button onClick={() => setShowLinkPanel(v => !v)} className="text-xs muted hover:txt">
                {showLinkPanel ? 'Close' : '+ Link'}
              </button>
            </div>
            {(ticket.relatedTo || []).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {(ticket.relatedTo || []).map(rid => {
                  const rel = (state.tickets || []).find(x => x.id === rid)
                  return (
                    <span key={rid} className="rounded-full bg-sky-400/10 border border-sky-400/20 px-2 py-0.5 text-xs text-sky-400">
                      {rid}{rel ? `: ${rel.subject.slice(0, 20)}` : ''}
                    </span>
                  )
                })}
              </div>
            )}
            {showLinkPanel && (
              <div className="space-y-2">
                <input
                  value={linkSearch}
                  onChange={e => setLinkSearch(e.target.value)}
                  placeholder="Search ticket ID or subject..."
                  className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-xs outline-none focus:border-sky-500"
                />
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {(state.tickets || [])
                    .filter(t => t.id !== ticket.id && t.status !== 'Closed' && !(ticket.relatedTo || []).includes(t.id))
                    .filter(t => !linkSearch || `${t.id} ${t.subject}`.toLowerCase().includes(linkSearch.toLowerCase()))
                    .slice(0, 5)
                    .map(t => (
                      <button
                        key={t.id}
                        onClick={() => {
                          dispatch({ type: 'link-ticket', id: ticket.id, relatedId: t.id })
                          setLinkSearch('')
                          setShowLinkPanel(false)
                        }}
                        className="hoverable txt w-full rounded px-2 py-1.5 text-left text-xs"
                      >
                        <span className="muted">{t.id}</span> · {t.subject.slice(0, 40)}
                      </button>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Status history */}
        {showHistory && (ticket.history || []).length > 0 && (
          <div className="rounded-lg border bd bg-white/[0.02] px-4 py-3 space-y-1">
            <p className="txt text-xs font-semibold mb-2">Status History</p>
            {(ticket.history || []).map((h, i) => (
              <div key={i} className="flex items-center gap-2 text-xs muted">
                <span className="h-1.5 w-1.5 rounded-full bg-sky-500 shrink-0" />
                <StatusBadge status={h.status} />
                <span>{new Date(h.at).toLocaleString()}</span>
                {h.by && <span>by {h.by}</span>}
              </div>
            ))}
          </div>
        )}

        {/* Original message */}
        <div className="tile rounded-xl border p-4">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-sky-600/20 border border-sky-600/30">
              <User size={13} className="text-sky-400" />
            </span>
            <span className="txt text-sm font-medium">{ticket.ownerId || 'User'}</span>
            <span className="muted text-xs">{new Date(ticket.createdAt).toLocaleString()}</span>
            <span className="muted text-xs ml-auto">{ticket.id} · {ticket.category}</span>
          </div>
          <p className="txt text-sm whitespace-pre-wrap">{ticket.message}</p>
        </div>

        {/* Replies */}
        {visibleReplies.map(r => (
          <div
            key={r.id}
            className={`rounded-xl border p-4 ${
              r.internal
                ? 'bg-yellow-400/5 border-yellow-400/20 border-dashed'
                : r.role === 'admin'
                  ? 'bg-sky-600/5 border-sky-600/20 ml-4'
                  : 'tile mr-4'
            }`}
          >
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border ${
                r.internal ? 'bg-yellow-400/10 border-yellow-400/30'
                : r.role === 'admin' ? 'bg-sky-600/20 border-sky-600/30'
                : 'bg-white/5 border-white/10'
              }`}>
                {r.internal ? <Lock size={12} className="text-yellow-400" />
                  : r.role === 'admin' ? <Shield size={13} className="text-sky-400" />
                  : <User size={13} className="muted" />}
              </span>
              <span className={`text-sm font-medium ${r.internal ? 'text-yellow-400' : r.role === 'admin' ? 'text-sky-400' : 'txt'}`}>
                {r.internal ? 'Internal Note' : r.role === 'admin' ? 'Admin' : r.author}
              </span>
              <span className="muted text-xs">{new Date(r.createdAt).toLocaleString()}</span>
              {r.internal && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/30 px-2 py-0.5 text-[10px] text-yellow-400">Only admins see this</span>}
            </div>
            <p className="txt text-sm whitespace-pre-wrap">{r.message}</p>
          </div>
        ))}

        {/* Rating (for resolved tickets, shown to user) */}
        {ticket.status === 'Resolved' && !isAdmin && (
          <div className="tile rounded-xl border p-4 text-center">
            {ticket.rating ? (
              <div>
                <p className="txt text-sm font-medium mb-2">Your rating</p>
                <StarRating value={ticket.rating} readonly />
              </div>
            ) : (
              <div>
                <p className="txt text-sm font-medium mb-2">Was this issue resolved to your satisfaction?</p>
                <div className="flex justify-center">
                  <StarRating onChange={r => { dispatch({ type: 'rate-ticket', id: ticket.id, rating: r }); toast({ type: 'success', title: 'Thanks for your feedback!' }) }} />
                </div>
              </div>
            )}
          </div>
        )}
        {ticket.status === 'Resolved' && isAdmin && ticket.rating && (
          <div className="flex items-center gap-2 px-1">
            <p className="muted text-xs">User rated:</p>
            <StarRating value={ticket.rating} readonly />
          </div>
        )}

        {/* Reply box */}
        {ticket.status !== 'Closed' && (
          <div className="space-y-2 pt-1">
            {isAdmin && (
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setIsInternal(false)}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${!isInternal ? 'bg-sky-600 border-sky-600 text-white' : 'bd muted hover:txt'}`}
                >
                  <Send size={12} /> Reply
                </button>
                <button
                  onClick={() => setIsInternal(true)}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${isInternal ? 'bg-yellow-500/20 border-yellow-500/40 text-yellow-400' : 'bd muted hover:txt'}`}
                >
                  <Lock size={12} /> Internal Note
                </button>
                <div className="relative ml-auto">
                  <button
                    onClick={() => setShowCanned(c => !c)}
                    className="flex items-center gap-1.5 rounded-lg border bd px-3 py-1.5 text-xs muted hover:txt"
                  >
                    Canned <ChevronDown size={12} />
                  </button>
                  {showCanned && (
                    <div className="absolute right-0 top-full mt-1 z-20 w-56 panel rounded-xl border shadow-2xl py-1">
                      {CANNED_RESPONSES.map(c => (
                        <button
                          key={c.label}
                          onClick={() => { setReply(c.text); setShowCanned(false) }}
                          className="hoverable txt w-full px-3 py-2 text-left text-xs"
                        >
                          {c.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
            <div className="flex gap-2">
              <Textarea
                rows={2}
                value={reply}
                onChange={e => setReply(e.target.value)}
                placeholder={isInternal ? 'Internal note (only visible to admins)…' : isAdmin ? 'Reply as admin…' : 'Add a reply… (Ctrl+Enter to send)'}
                className={`flex-1 ${isInternal ? 'border-yellow-500/40 focus:border-yellow-500' : ''}`}
                onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) sendReply() }}
              />
              <button
                onClick={sendReply}
                disabled={!reply.trim()}
                className={`flex items-center gap-1.5 self-end rounded-lg px-4 py-2 text-sm font-semibold text-white disabled:opacity-40 ${isInternal ? 'bg-yellow-600 hover:bg-yellow-500' : 'bg-sky-600 hover:bg-sky-500'}`}
              >
                <Send size={14} /> {isInternal ? 'Note' : 'Send'}
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}

function TicketCard({ ticket, selected, onSelect, onClick, isAdmin }) {
  const replyCount = (ticket.replies || []).filter(r => !r.internal).length
  const hasAdminReply = (ticket.replies || []).some(r => r.role === 'admin' && !r.internal)
  return (
    <div
      className={`tile rounded-xl border transition-colors cursor-pointer ${selected ? 'border-sky-500/50 bg-sky-600/5' : 'hover:border-sky-500/30'}`}
      onClick={onClick}
    >
      <div className="flex items-start gap-3 p-4">
        {isAdmin && (
          <input
            type="checkbox"
            checked={selected}
            onChange={e => { e.stopPropagation(); onSelect() }}
            className="mt-0.5 rounded"
            onClick={e => e.stopPropagation()}
          />
        )}
        <div className="flex-1 min-w-0 text-left">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="txt text-sm font-semibold truncate">{ticket.subject}</p>
            {hasAdminReply && !isAdmin && <span className="h-2 w-2 rounded-full bg-sky-500 shrink-0" title="Admin replied" />}
          </div>
          <p className="muted mt-0.5 text-xs">
            {ticket.id} · {ticket.category}
            {ticket.assignedTo && <span className="ml-1 text-sky-400/70">→ {ticket.assignedTo}</span>}
            {' · '}{new Date(ticket.createdAt).toLocaleDateString()}
          </p>
          {(ticket.tags || []).length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {ticket.tags.map(t => <TagChip key={t} tag={t} />)}
            </div>
          )}
          <p className="muted mt-2 text-sm line-clamp-2">{ticket.message}</p>
          <div className="mt-2 flex items-center gap-3">
            {replyCount > 0 && <p className="text-xs text-sky-400">{replyCount} {replyCount === 1 ? 'reply' : 'replies'}</p>}
            {ticket.rating && <StarRating value={ticket.rating} readonly />}
          </div>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <StatusBadge status={ticket.status} />
          <PriorityBadge priority={ticket.priority} />
          {(ticket.status === 'Open' || ticket.status === 'In Progress') && (
            <span className={`text-xs ${(Date.now() - ticket.createdAt) > 48 * 3600000 ? 'text-red-400' : 'muted'}`}>
              {slaLabel(ticket.createdAt)}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Support() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const isAdmin = state.role === 'admin'

  const [ticketOpen, setTicketOpen]   = useState(false)
  const [cheatOpen, setCheatOpen]     = useState(false)
  const [activeTicket, setActiveTicket] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch]           = useState('')
  const [sortBy, setSortBy]           = useState('updatedAt')
  const [selected, setSelected]       = useState([])
  const [form, setForm]               = useState({ subject: '', category: 'General', priority: 'Normal', message: '', tags: [] })
  const [cheatForm, setCheatForm]     = useState(emptyCheatForm)

  const myTickets = isAdmin
    ? (state.tickets || [])
    : (state.tickets || []).filter(t => !t.ownerId || t.ownerId === state.session?.userId)

  const visibleTickets = useMemo(() => {
    const q = search.toLowerCase()
    return myTickets
      .filter(t => statusFilter === 'all' ? true : t.status === statusFilter)
      .filter(t => !q || `${t.subject} ${t.message} ${t.id} ${(t.tags || []).join(' ')}`.toLowerCase().includes(q))
      .sort((a, b) => {
        if (sortBy === 'priority') {
          const pOrder = { Urgent: 3, High: 2, Normal: 1, Low: 0 }
          return (pOrder[b.priority] || 0) - (pOrder[a.priority] || 0)
        }
        if (sortBy === 'createdAt') return b.createdAt - a.createdAt
        return (b.updatedAt || b.createdAt) - (a.updatedAt || a.createdAt)
      })
  }, [myTickets, statusFilter, search, sortBy])

  const openCount    = myTickets.filter(t => t.status === 'Open').length
  const inProgCount  = myTickets.filter(t => t.status === 'In Progress').length
  const resolvedCount = myTickets.filter(t => t.status === 'Resolved').length
  const avgRating    = (() => {
    const rated = myTickets.filter(t => t.rating)
    return rated.length ? (rated.reduce((s, t) => s + t.rating, 0) / rated.length).toFixed(1) : null
  })()

  const userProposals = (state.proposals || []).filter(p =>
    p.source === 'user' && (isAdmin ? true : p.submittedBy === state.session?.userId)
  )

  const toggleSelect = (id) => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])
  const clearSelected = () => setSelected([])
  const allVisibleSelected = visibleTickets.length > 0 && visibleTickets.every(t => selected.includes(t.id))

  const bulkAction = (action) => {
    if (action === 'delete') {
      if (!confirm(`Delete ${selected.length} tickets?`)) return
      dispatch({ type: 'bulk-delete-tickets', ids: selected })
      toast({ type: 'success', title: `Deleted ${selected.length} tickets` })
    } else if (action === 'close-stale') {
      const sevenDaysAgo = Date.now() - 7 * 86400000
      const staleIds = selected.filter(id => {
        const t = (state.tickets || []).find(x => x.id === id)
        return t && t.status === 'Open' && t.createdAt < sevenDaysAgo
      })
      if (staleIds.length === 0) return toast({ type: 'error', title: 'No stale tickets selected' })
      dispatch({ type: 'bulk-update-tickets', ids: staleIds, fields: { status: 'Closed' } })
      toast({ type: 'success', title: `${staleIds.length} stale tickets closed` })
    } else {
      dispatch({ type: 'bulk-update-tickets', ids: selected, fields: { status: action } })
      toast({ type: 'success', title: `${selected.length} tickets → ${action}` })
    }
    clearSelected()
  }

  const exportCSV = () => {
    const headers = ['ID', 'Subject', 'Category', 'Priority', 'Status', 'Created', 'Updated', 'Owner', 'Replies']
    const rows = visibleTickets.map(t => [
      t.id,
      `"${(t.subject || '').replace(/"/g, '""')}"`,
      t.category || '',
      t.priority || '',
      t.status || '',
      new Date(t.createdAt).toISOString(),
      new Date(t.updatedAt || t.createdAt).toISOString(),
      t.ownerId || '',
      (t.replies || []).filter(r => !r.internal).length,
    ])
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'tickets-export.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const submit = () => {
    if (!form.subject.trim() || !form.message.trim())
      return toast({ type: 'error', title: 'Subject and message required' })
    dispatch({ type: 'add-ticket', ticket: { ...form, subject: form.subject.trim() } })
    toast({ type: 'success', title: 'Ticket submitted', body: form.subject })
    setForm({ subject: '', category: 'General', priority: 'Normal', message: '', tags: [] })
    setTicketOpen(false)
  }

  const submitCheat = () => {
    if (!cheatForm.pattern.trim()) return toast({ type: 'error', title: 'Pattern required' })
    if (cheatForm.pattern.trim().length < 3) return toast({ type: 'error', title: 'Pattern too short', body: 'At least 3 characters.' })
    dispatch({
      type: 'add-user-proposal',
      proposal: {
        pattern: cheatForm.pattern.trim().toLowerCase(),
        type: cheatForm.type, category: cheatForm.category,
        risk: cheatForm.risk, game: cheatForm.game,
        description: cheatForm.description.trim() || `User-reported ${cheatForm.category.toLowerCase()}: ${cheatForm.pattern.trim()}`,
      },
    })
    toast({ type: 'success', title: 'Cheat submitted', body: 'Pending admin review — thank you!' })
    setCheatForm(emptyCheatForm)
    setCheatOpen(false)
  }

  const openedTicket = activeTicket ? (state.tickets || []).find(t => t.id === activeTicket) : null

  return (
    <div className="space-y-6">
      <PageHeader
        icon={LifeBuoy}
        kicker="Get help & open tickets"
        title="Support"
        subtitle={isAdmin ? 'Manage all support tickets and review user cheat suggestions.' : 'Browse FAQs, open tickets, or suggest cheats for the scanner database.'}
        actions={
          <div className="flex gap-2">
            {!isAdmin && (
              <button onClick={() => setCheatOpen(true)}
                className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:border-sky-500">
                <ShieldAlert size={16} /> Suggest Cheat
              </button>
            )}
            <button onClick={() => setTicketOpen(true)}
              className="flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">
              <Plus size={18} /> New Ticket
            </button>
          </div>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        {[
          { label: 'Open',        value: openCount,     cls: 'text-sky-400' },
          { label: 'In Progress', value: inProgCount,   cls: 'text-yellow-400' },
          { label: 'Resolved',    value: resolvedCount, cls: 'text-green-400' },
          { label: 'Total',       value: myTickets.length, cls: 'txt' },
          { label: avgRating ? `Avg Rating` : (isAdmin ? 'User Reports' : 'Suggestions'),
            value: avgRating ? `${avgRating}★` : userProposals.length,
            cls: avgRating ? 'text-yellow-400' : 'text-purple-400' },
        ].map(s => (
          <Card key={s.label} className="p-4 text-center">
            <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            <p className="muted text-xs mt-1">{s.label}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_340px]">
        {/* Tickets panel */}
        <Card className="p-6">
          {/* Controls */}
          <div className="mb-4 space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <h3 className="txt text-lg font-semibold shrink-0">
                {isAdmin ? 'All Tickets' : 'My Tickets'} ({visibleTickets.length})
              </h3>
              {isAdmin && (
                <button onClick={exportCSV}
                  className="flex items-center gap-1.5 rounded-lg border bd px-3 py-2 text-xs muted hover:txt shrink-0">
                  <Download size={13} /> Export CSV
                </button>
              )}
              <div className="relative flex-1 min-w-48">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 muted" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search tickets…"
                  className="bd tile txt w-full rounded-lg border py-2 pl-8 pr-3 text-sm outline-none focus:border-sky-500"
                />
              </div>
              <select value={sortBy} onChange={e => setSortBy(e.target.value)}
                className="bd tile txt rounded-lg border px-3 py-2 text-sm">
                <option value="updatedAt">Sort: Last Updated</option>
                <option value="createdAt">Sort: Newest</option>
                <option value="priority">Sort: Priority</option>
              </select>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <div className="flex rounded-lg border bd overflow-hidden text-sm">
                {['all', 'Open', 'In Progress', 'Resolved', 'Closed'].map(s => (
                  <button key={s} onClick={() => { setStatusFilter(s); clearSelected() }}
                    className={`px-3 py-1.5 font-medium transition-colors ${statusFilter === s ? 'bg-sky-600 text-white' : 'muted hover:txt'}`}>
                    {s}
                  </button>
                ))}
              </div>

              {/* Bulk actions */}
              {isAdmin && selected.length > 0 && (
                <div className="flex items-center gap-2 ml-auto">
                  <span className="muted text-xs">{selected.length} selected</span>
                  {['Resolved', 'Closed'].map(s => (
                    <button key={s} onClick={() => bulkAction(s)}
                      className="rounded-lg border bd px-3 py-1.5 text-xs muted hover:txt">
                      → {s}
                    </button>
                  ))}
                  <button onClick={() => bulkAction('close-stale')}
                    className="rounded-lg border border-orange-500/30 px-3 py-1.5 text-xs text-orange-400 hover:bg-orange-500/10">
                    Close Stale
                  </button>
                  <button onClick={() => bulkAction('delete')}
                    className="flex items-center gap-1 rounded-lg bg-red-600/10 border border-red-600/30 px-3 py-1.5 text-xs text-red-400 hover:bg-red-600/20">
                    <Trash2 size={12} /> Delete
                  </button>
                  <button onClick={clearSelected} className="text-xs muted hover:txt">×</button>
                </div>
              )}
            </div>
          </div>

          {/* Select all (admin) */}
          {isAdmin && visibleTickets.length > 0 && (
            <div className="mb-2 flex items-center gap-2 px-1">
              <input type="checkbox" checked={allVisibleSelected}
                onChange={e => setSelected(e.target.checked ? visibleTickets.map(t => t.id) : [])}
                className="rounded" />
              <span className="muted text-xs">Select all</span>
            </div>
          )}

          {visibleTickets.length === 0 ? (
            <EmptyState icon={MessageSquare} title="No tickets"
              hint={search ? 'No tickets match your search.' : statusFilter === 'all' ? 'Click "New Ticket" to open one.' : `No ${statusFilter.toLowerCase()} tickets.`} />
          ) : (
            <div className="space-y-3">
              {visibleTickets.map(t => (
                <TicketCard
                  key={t.id}
                  ticket={t}
                  isAdmin={isAdmin}
                  selected={selected.includes(t.id)}
                  onSelect={() => toggleSelect(t.id)}
                  onClick={() => setActiveTicket(t.id)}
                />
              ))}
            </div>
          )}
        </Card>

        {/* Right column */}
        <div className="space-y-6">
          <Card className="p-6">
            <h3 className="txt mb-4 text-lg font-semibold">FAQ</h3>
            <Accordion items={FAQ} />
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="txt text-base font-semibold flex items-center gap-2">
                <ShieldAlert size={16} />
                {isAdmin ? 'User Cheat Reports' : 'My Suggestions'} ({userProposals.length})
              </h3>
              {!isAdmin && (
                <button onClick={() => setCheatOpen(true)}
                  className="flex items-center gap-1.5 rounded-lg bg-sky-600/10 border border-sky-600/30 px-3 py-1.5 text-xs text-sky-400 hover:bg-sky-600/20">
                  <Plus size={12} /> Suggest
                </button>
              )}
            </div>
            {userProposals.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="No suggestions"
                hint={isAdmin ? 'Users can submit from the Support page.' : 'Found a cheat? Click Suggest to report it.'} />
            ) : (
              <div className="space-y-2">
                {userProposals.slice(0, 5).map(p => (
                  <div key={p.id} className="tile flex items-center justify-between rounded-lg border px-3 py-2.5">
                    <div className="min-w-0">
                      <p className="txt font-mono text-sm font-medium truncate">{p.pattern}</p>
                      <p className="muted text-xs">{p.category} · {p.game || 'OTHER'}</p>
                    </div>
                    <div className="flex items-center gap-2 ml-2 shrink-0">
                      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${
                        p.risk === 'Critical' ? 'text-red-400 bg-red-400/10 border-red-400/20' :
                        p.risk === 'High' ? 'text-orange-400 bg-orange-400/10 border-orange-400/20' :
                        'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'}`}>{p.risk}</span>
                      {p.status === 'pending'  && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-xs text-yellow-400">Pending</span>}
                      {p.status === 'approved' && <span className="rounded-full bg-green-400/10 border border-green-400/20 px-2 py-0.5 text-xs text-green-400">Approved</span>}
                      {p.status === 'rejected' && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">Rejected</span>}
                    </div>
                  </div>
                ))}
                {userProposals.length > 5 && <p className="muted text-center text-xs pt-1">+{userProposals.length - 5} more</p>}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Ticket thread modal */}
      {openedTicket && <TicketThread ticket={openedTicket} onClose={() => setActiveTicket(null)} />}

      {/* New ticket modal */}
      <Modal open={ticketOpen} onClose={() => setTicketOpen(false)} title="New Support Ticket"
        footer={
          <>
            <button onClick={() => setTicketOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button onClick={submit} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">Submit</button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <p className="caps-label">Templates</p>
            <div className="flex flex-wrap gap-2">
              {[
                { label: 'Bug Report', subject: 'Bug: ', category: 'Bug', priority: 'High', message: 'Steps to reproduce:\n1. \n\nExpected:\nActual:' },
                { label: 'Detection Issue', subject: 'Detection: ', category: 'Detection', priority: 'Normal', message: 'Player:\nScan ID:\nIssue:' },
                { label: 'Billing Question', subject: 'Billing: ', category: 'Billing', priority: 'Normal', message: '' },
                { label: 'Feature Request', subject: 'Feature: ', category: 'General', priority: 'Low', message: 'I would like to suggest:' },
              ].map(tpl => (
                <button
                  key={tpl.label}
                  type="button"
                  onClick={() => setForm(f => ({ ...f, subject: tpl.subject, category: tpl.category, priority: tpl.priority, message: tpl.message }))}
                  className="rounded-lg border bd px-3 py-1.5 text-xs muted hover:txt transition-colors"
                >
                  {tpl.label}
                </button>
              ))}
            </div>
          </div>
          <Field label="Subject">
            <Input autoFocus value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} placeholder="Short summary" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Category">
              <Select value={form.category} onChange={v => setForm({ ...form, category: v })}
                options={['General', 'Bug', 'Billing', 'Detection'].map(x => ({ value: x, label: x }))} />
            </Field>
            <Field label="Priority">
              <Select value={form.priority} onChange={v => setForm({ ...form, priority: v })}
                options={['Low', 'Normal', 'High', 'Urgent'].map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <Field label="Tags (optional)">
            <TagInput tags={form.tags} onChange={tags => setForm({ ...form, tags })} />
          </Field>
          <Field label="Message">
            <Textarea rows={4} value={form.message} onChange={e => setForm({ ...form, message: e.target.value })} placeholder="Describe your issue…" />
          </Field>
        </div>
      </Modal>

      {/* Suggest cheat modal */}
      <Modal open={cheatOpen} onClose={() => setCheatOpen(false)} title="Suggest a Cheat / Spoofer / Cleaner"
        footer={
          <>
            <button onClick={() => setCheatOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button onClick={submitCheat} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">Submit for Review</button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="rounded-lg bg-sky-600/5 border border-sky-600/20 px-4 py-3 text-sm text-sky-300">
            Your suggestion goes to the admin for review. If approved, it gets added to the scanner's detection database.
          </div>
          <Field label="Pattern (filename, process name, or keyword)">
            <Input autoFocus value={cheatForm.pattern}
              onChange={e => setCheatForm({ ...cheatForm, pattern: e.target.value })}
              placeholder="e.g. cheatengine.exe or injector_x64" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Match Type">
              <Select value={cheatForm.type} onChange={v => setCheatForm({ ...cheatForm, type: v })}
                options={CHEAT_TYPES.map(t => ({ value: t.value, label: t.label }))} />
            </Field>
            <Field label="Category">
              <Select value={cheatForm.category} onChange={v => setCheatForm({ ...cheatForm, category: v })}
                options={CHEAT_CATEGORIES.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Risk Level">
              <Select value={cheatForm.risk} onChange={v => setCheatForm({ ...cheatForm, risk: v })}
                options={RISK_LEVELS.map(x => ({ value: x, label: x }))} />
            </Field>
            <Field label="Game">
              <Select value={cheatForm.game} onChange={v => setCheatForm({ ...cheatForm, game: v })}
                options={GAMES.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <Field label="Description / Evidence (optional)">
            <Textarea rows={3} value={cheatForm.description}
              onChange={e => setCheatForm({ ...cheatForm, description: e.target.value })}
              placeholder="Why do you think this is a cheat? Where did you see it?" />
          </Field>
        </div>
      </Modal>
    </div>
  )
}
