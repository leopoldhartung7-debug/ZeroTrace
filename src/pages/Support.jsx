import { useState } from 'react'
import {
  LifeBuoy, Plus, MessageSquare, ShieldAlert, Clock, CheckCircle2,
  XCircle, AlertTriangle, ChevronDown, ChevronRight, Send, User, Shield,
} from 'lucide-react'
import { PageHeader, Card, EmptyState, Accordion, Field, Input, Textarea } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

const FAQ = [
  { q: 'How do scan pins work?', a: 'Create a pin, share the 8-character code with the user, then run the scan to get a verdict (Clean / Suspicious / Cheating).' },
  { q: 'Is my data sent anywhere?', a: 'No. This dashboard is fully client-side — all pins, scans and files stay in your browser localStorage.' },
  { q: 'What files can the String Extractor handle?', a: 'Any binary: .exe, .jar, .dll and .sys are typical. It extracts ASCII and UTF-16LE strings.' },
  { q: 'How accurate is Suspicious Detection?', a: 'It uses a YARA-lite engine matching string and hex patterns. Treat results as indicators, not proof.' },
  { q: 'Can I suggest cheats for the database?', a: 'Yes — click "Suggest Cheat" in the header. Your suggestion goes to admin review and if approved it activates in the scanner.' },
]

const STATUS_STYLES = {
  Open:        { cls: 'bg-sky-400/10 border-sky-400/20 text-sky-400',      icon: Clock },
  'In Progress':{ cls: 'bg-yellow-400/10 border-yellow-400/20 text-yellow-400', icon: AlertTriangle },
  Resolved:    { cls: 'bg-green-400/10 border-green-400/20 text-green-400', icon: CheckCircle2 },
  Closed:      { cls: 'bg-white/5 border-white/10 text-white/40',           icon: XCircle },
}

const PRIORITY_STYLES = {
  Low:    'bg-white/5 border-white/10 text-white/40',
  Normal: 'bg-white/10 border-white/20 text-white/60',
  High:   'bg-orange-400/10 border-orange-400/20 text-orange-400',
  Urgent: 'bg-red-400/10 border-red-400/20 text-red-400',
}

const CHEAT_TYPES = [
  { value: 'FileNameKeyword', label: 'Filename Keyword (partial match)' },
  { value: 'FileName',        label: 'Exact Filename' },
  { value: 'ProcessName',     label: 'Process Name' },
]
const CHEAT_CATEGORIES = ['Cheat', 'Spoofer', 'Injector', 'Cleaner', 'FiveM-Cheat', 'Other']
const RISK_LEVELS = ['Medium', 'High', 'Critical']
const GAMES = ['MINECRAFT', 'CS2', 'RUST', 'VALORANT', 'FORTNITE', 'APEX', 'FiveM', 'OTHER']
const STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed']

const emptyCheatForm = { pattern: '', type: 'FileNameKeyword', category: 'Cheat', risk: 'High', game: 'OTHER', description: '' }

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

function TicketThread({ ticket, onClose }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [reply, setReply] = useState('')
  const isAdmin = state.role === 'admin'

  const sendReply = () => {
    if (!reply.trim()) return
    dispatch({ type: 'reply-ticket', id: ticket.id, message: reply.trim() })
    toast({ type: 'success', title: 'Reply sent' })
    setReply('')
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={
        <div className="flex items-center gap-3">
          <span className="txt font-semibold">{ticket.subject}</span>
          <StatusBadge status={ticket.status} />
          <PriorityBadge priority={ticket.priority} />
        </div>
      }
      footer={
        <div className="flex gap-2 w-full">
          {isAdmin && (
            <select
              value={ticket.status}
              onChange={e => dispatch({ type: 'update-ticket', id: ticket.id, fields: { status: e.target.value } })}
              className="bd tile txt rounded-lg border px-3 py-2 text-sm"
            >
              {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          )}
          <button onClick={onClose} className="bd txt rounded-lg border px-4 py-2 text-sm ml-auto">Close</button>
        </div>
      }
    >
      <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-1">
        {/* Original message */}
        <div className="tile rounded-xl border p-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-sky-600/20 border border-sky-600/30">
              <User size={13} className="text-sky-400" />
            </span>
            <span className="txt text-sm font-medium">{ticket.ownerId || 'User'}</span>
            <span className="muted text-xs">{new Date(ticket.createdAt).toLocaleString()}</span>
            <span className="muted text-xs ml-auto">{ticket.id} · {ticket.category}</span>
          </div>
          <p className="txt text-sm">{ticket.message}</p>
        </div>

        {/* Replies */}
        {(ticket.replies || []).map(r => (
          <div key={r.id} className={`rounded-xl border p-4 ${r.role === 'admin' ? 'bg-sky-600/5 border-sky-600/20 ml-4' : 'tile mr-4'}`}>
            <div className="flex items-center gap-2 mb-2">
              <span className={`flex h-7 w-7 items-center justify-center rounded-full border ${r.role === 'admin' ? 'bg-sky-600/20 border-sky-600/30' : 'bg-white/5 border-white/10'}`}>
                {r.role === 'admin' ? <Shield size={13} className="text-sky-400" /> : <User size={13} className="muted" />}
              </span>
              <span className={`text-sm font-medium ${r.role === 'admin' ? 'text-sky-400' : 'txt'}`}>
                {r.role === 'admin' ? 'Admin' : r.author}
              </span>
              <span className="muted text-xs">{new Date(r.createdAt).toLocaleString()}</span>
            </div>
            <p className="txt text-sm">{r.message}</p>
          </div>
        ))}

        {/* Reply box */}
        {ticket.status !== 'Closed' && (
          <div className="flex gap-2 pt-1">
            <Textarea
              rows={2}
              value={reply}
              onChange={e => setReply(e.target.value)}
              placeholder={isAdmin ? 'Reply as admin…' : 'Add a reply…'}
              className="flex-1"
              onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) sendReply() }}
            />
            <button
              onClick={sendReply}
              disabled={!reply.trim()}
              className="flex items-center gap-1.5 self-end rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-40"
            >
              <Send size={14} /> Send
            </button>
          </div>
        )}
      </div>
    </Modal>
  )
}

function TicketCard({ ticket, onClick }) {
  const hasUnread = (ticket.replies || []).length > 0
  return (
    <button
      onClick={onClick}
      className="tile hover:border-sky-500/40 w-full text-left rounded-xl border p-4 transition-colors"
    >
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="txt text-sm font-semibold truncate">{ticket.subject}</p>
            {hasUnread && <span className="h-2 w-2 rounded-full bg-sky-500 shrink-0" />}
          </div>
          <p className="muted mt-0.5 text-xs">
            {ticket.id} · {ticket.category} · {new Date(ticket.createdAt).toLocaleDateString()}
          </p>
          <p className="muted mt-2 text-sm line-clamp-2">{ticket.message}</p>
          {(ticket.replies || []).length > 0 && (
            <p className="mt-2 text-xs text-sky-400">{ticket.replies.length} {ticket.replies.length === 1 ? 'reply' : 'replies'}</p>
          )}
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <StatusBadge status={ticket.status} />
          <PriorityBadge priority={ticket.priority} />
        </div>
      </div>
    </button>
  )
}

export default function Support() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const isAdmin = state.role === 'admin'

  const [ticketOpen, setTicketOpen] = useState(false)
  const [cheatOpen, setCheatOpen] = useState(false)
  const [activeTicket, setActiveTicket] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [form, setForm] = useState({ subject: '', category: 'General', priority: 'Normal', message: '' })
  const [cheatForm, setCheatForm] = useState(emptyCheatForm)

  const myTickets = isAdmin
    ? state.tickets
    : (state.tickets || []).filter(t =>
        !t.ownerId || t.ownerId === state.session?.userId
      )

  const visibleTickets = myTickets
    .filter(t => statusFilter === 'all' ? true : t.status === statusFilter)
    .sort((a, b) => (b.updatedAt || b.createdAt) - (a.updatedAt || a.createdAt))

  const openCount  = myTickets.filter(t => t.status === 'Open').length
  const inProgCount = myTickets.filter(t => t.status === 'In Progress').length

  const submit = () => {
    if (!form.subject.trim() || !form.message.trim())
      return toast({ type: 'error', title: 'Subject and message required' })
    dispatch({ type: 'add-ticket', ticket: { ...form, subject: form.subject.trim() } })
    toast({ type: 'success', title: 'Ticket submitted', body: form.subject })
    setForm({ subject: '', category: 'General', priority: 'Normal', message: '' })
    setTicketOpen(false)
  }

  const submitCheat = () => {
    if (!cheatForm.pattern.trim()) return toast({ type: 'error', title: 'Pattern required' })
    if (cheatForm.pattern.trim().length < 3) return toast({ type: 'error', title: 'Pattern too short', body: 'Enter at least 3 characters.' })
    dispatch({
      type: 'add-user-proposal',
      proposal: {
        pattern: cheatForm.pattern.trim().toLowerCase(),
        type: cheatForm.type,
        category: cheatForm.category,
        risk: cheatForm.risk,
        game: cheatForm.game,
        description: cheatForm.description.trim() || `User-reported ${cheatForm.category.toLowerCase()}: ${cheatForm.pattern.trim()}`,
      },
    })
    toast({ type: 'success', title: 'Cheat submitted', body: 'Pending admin review — thank you!' })
    setCheatForm(emptyCheatForm)
    setCheatOpen(false)
  }

  const userProposals = (state.proposals || []).filter(p =>
    p.source === 'user' && (isAdmin ? true : p.submittedBy === state.session?.userId)
  )

  const openedTicket = activeTicket
    ? (state.tickets || []).find(t => t.id === activeTicket)
    : null

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
              <button
                onClick={() => setCheatOpen(true)}
                className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:border-sky-500"
              >
                <ShieldAlert size={16} /> Suggest Cheat
              </button>
            )}
            <button
              onClick={() => setTicketOpen(true)}
              className="flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
            >
              <Plus size={18} /> New Ticket
            </button>
          </div>
        }
      />

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: 'Open', value: openCount, cls: 'text-sky-400' },
          { label: 'In Progress', value: inProgCount, cls: 'text-yellow-400' },
          { label: 'Resolved', value: myTickets.filter(t => t.status === 'Resolved').length, cls: 'text-green-400' },
          { label: isAdmin ? 'User Reports' : 'My Suggestions', value: userProposals.length, cls: 'text-purple-400' },
        ].map(s => (
          <Card key={s.label} className="p-4 text-center">
            <p className={`text-3xl font-bold ${s.cls}`}>{s.value}</p>
            <p className="muted text-sm mt-1">{s.label}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
        {/* Tickets panel */}
        <Card className="p-6">
          <div className="mb-4 flex items-center justify-between gap-3 flex-wrap">
            <h3 className="txt text-lg font-semibold">
              {isAdmin ? 'All Tickets' : 'My Tickets'} ({visibleTickets.length})
            </h3>
            <div className="flex rounded-lg border bd overflow-hidden text-sm">
              {['all', 'Open', 'In Progress', 'Resolved', 'Closed'].map(s => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1.5 font-medium transition-colors capitalize ${statusFilter === s ? 'bg-sky-600 text-white' : 'muted hover:txt'}`}
                >{s}</button>
              ))}
            </div>
          </div>

          {visibleTickets.length === 0 ? (
            <EmptyState icon={MessageSquare} title="No tickets" hint={statusFilter === 'all' ? 'Click "New Ticket" to open one.' : `No ${statusFilter.toLowerCase()} tickets.`} />
          ) : (
            <div className="space-y-3">
              {visibleTickets.map(t => (
                <TicketCard key={t.id} ticket={t} onClick={() => setActiveTicket(t.id)} />
              ))}
            </div>
          )}
        </Card>

        {/* Right column */}
        <div className="space-y-6">
          {/* FAQ */}
          <Card className="p-6">
            <h3 className="txt mb-4 text-lg font-semibold">Frequently Asked Questions</h3>
            <Accordion items={FAQ} />
          </Card>

          {/* Cheat suggestions */}
          <Card className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="txt text-base font-semibold flex items-center gap-2">
                <ShieldAlert size={16} />
                {isAdmin ? 'User Cheat Reports' : 'My Cheat Suggestions'} ({userProposals.length})
              </h3>
              {!isAdmin && (
                <button
                  onClick={() => setCheatOpen(true)}
                  className="flex items-center gap-1.5 rounded-lg bg-sky-600/10 border border-sky-600/30 px-3 py-1.5 text-xs text-sky-400 hover:bg-sky-600/20"
                >
                  <Plus size={12} /> Suggest
                </button>
              )}
            </div>
            {userProposals.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="No suggestions" hint={isAdmin ? 'Users can submit cheat suggestions from the Support page.' : 'Found a cheat? Click Suggest to report it.'} />
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
                        'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
                      }`}>{p.risk}</span>
                      {p.status === 'pending'  && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-xs text-yellow-400">Pending</span>}
                      {p.status === 'approved' && <span className="rounded-full bg-green-400/10 border border-green-400/20 px-2 py-0.5 text-xs text-green-400">Approved</span>}
                      {p.status === 'rejected' && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">Rejected</span>}
                    </div>
                  </div>
                ))}
                {userProposals.length > 5 && (
                  <p className="muted text-center text-xs pt-1">+{userProposals.length - 5} more</p>
                )}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Ticket thread modal */}
      {openedTicket && (
        <TicketThread ticket={openedTicket} onClose={() => setActiveTicket(null)} />
      )}

      {/* New ticket modal */}
      <Modal
        open={ticketOpen}
        onClose={() => setTicketOpen(false)}
        title="New Support Ticket"
        footer={
          <>
            <button onClick={() => setTicketOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button onClick={submit} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">Submit</button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Subject">
            <Input autoFocus value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} placeholder="Short summary" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Category">
              <Select value={form.category} onChange={v => setForm({ ...form, category: v })} options={['General', 'Bug', 'Billing', 'Detection'].map(x => ({ value: x, label: x }))} />
            </Field>
            <Field label="Priority">
              <Select value={form.priority} onChange={v => setForm({ ...form, priority: v })} options={['Low', 'Normal', 'High', 'Urgent'].map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <Field label="Message">
            <Textarea rows={4} value={form.message} onChange={e => setForm({ ...form, message: e.target.value })} placeholder="Describe your issue…" />
          </Field>
        </div>
      </Modal>

      {/* Suggest cheat modal */}
      <Modal
        open={cheatOpen}
        onClose={() => setCheatOpen(false)}
        title="Suggest a Cheat / Spoofer / Cleaner"
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
            <Input
              autoFocus
              value={cheatForm.pattern}
              onChange={e => setCheatForm({ ...cheatForm, pattern: e.target.value })}
              placeholder="e.g. cheatengine.exe or injector_x64"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Match Type">
              <Select value={cheatForm.type} onChange={v => setCheatForm({ ...cheatForm, type: v })} options={CHEAT_TYPES.map(t => ({ value: t.value, label: t.label }))} />
            </Field>
            <Field label="Category">
              <Select value={cheatForm.category} onChange={v => setCheatForm({ ...cheatForm, category: v })} options={CHEAT_CATEGORIES.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Risk Level">
              <Select value={cheatForm.risk} onChange={v => setCheatForm({ ...cheatForm, risk: v })} options={RISK_LEVELS.map(x => ({ value: x, label: x }))} />
            </Field>
            <Field label="Game">
              <Select value={cheatForm.game} onChange={v => setCheatForm({ ...cheatForm, game: v })} options={GAMES.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>
          <Field label="Description / Evidence (optional)">
            <Textarea
              rows={3}
              value={cheatForm.description}
              onChange={e => setCheatForm({ ...cheatForm, description: e.target.value })}
              placeholder="Why do you think this is a cheat? Where did you see it?"
            />
          </Field>
        </div>
      </Modal>
    </div>
  )
}
