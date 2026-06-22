import { useState, useMemo } from 'react'
import {
  LifeBuoy, Plus, MessageSquare, ShieldAlert, Clock, CheckCircle2,
  XCircle, AlertTriangle, Send, User, Shield, Search, Tag, Lock,
  Star, Trash2, UserCheck, ChevronDown, History, SortAsc, Download,
  CreditCard, Bug, Zap,
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
  // General
  { topic: 'General', label: 'Looking into it',    text: 'Thanks for reaching out! We are looking into this and will update you shortly.' },
  { topic: 'General', label: 'Need more info',     text: 'Could you provide more details? Screenshots or exact steps to reproduce would help a lot.' },
  { topic: 'General', label: 'Issue resolved',     text: 'This issue has been resolved. Please let us know if you experience any further problems.' },
  { topic: 'General', label: 'Not reproducible',  text: 'We were unable to reproduce this on our end. Could you check again and provide exact steps?' },
  { topic: 'General', label: 'Escalated',          text: 'We have escalated this ticket to our senior team. You will hear back within 24 hours.' },
  { topic: 'General', label: 'Follow-up soon',     text: 'We haven\'t forgotten about you! We are still working on this and will follow up by end of day.' },
  { topic: 'General', label: 'Closing — no reply', text: 'We haven\'t received a response in a while, so we are closing this ticket. Feel free to reopen it if you need further help.' },
  // Billing
  { topic: 'Billing', label: 'Payment confirmed',  text: 'Your payment has been received and confirmed. Your account is fully active — thank you!' },
  { topic: 'Billing', label: 'License activated',  text: 'Your license key has been activated successfully. You now have access to all features of your plan.' },
  { topic: 'Billing', label: 'License not found',  text: 'We were unable to find a license linked to your account. Please double-check the key you entered, or contact us with your purchase receipt.' },
  { topic: 'Billing', label: 'Refund processed',   text: 'Your refund has been processed. It should appear in your account within 5–7 business days depending on your bank.' },
  { topic: 'Billing', label: 'Renewal reminder',   text: 'Your subscription is due for renewal soon. If you have any questions about pricing or upgrades, we are happy to help.' },
  { topic: 'Billing', label: 'Plan upgraded',      text: 'Your plan has been upgraded. The new limits and features are active immediately on your account.' },
  // Detection
  { topic: 'Detection', label: 'False positive',       text: 'After reviewing the scan, this appears to be a false positive. No action is required on your end — we will update the database.' },
  { topic: 'Detection', label: 'Detection confirmed',  text: 'The detection is accurate. The scanner found signatures associated with cheating software on the scanned system.' },
  { topic: 'Detection', label: 'Need scan ID',         text: 'To investigate, could you please share the Scan ID (visible in the scan result details)?' },
  { topic: 'Detection', label: 'Need file',            text: 'Could you upload or share the file that triggered the detection? This helps us verify whether it is a genuine threat.' },
  { topic: 'Detection', label: 'Pattern updated',      text: 'We have updated the detection pattern related to this case. Please re-run the scan and let us know if the issue persists.' },
  { topic: 'Detection', label: 'Inconclusive',         text: 'The scan result is inconclusive based on the available data. We recommend a deeper scan (Full profile) and sharing the file for manual review.' },
  // Cheat Report
  { topic: 'Cheat Report', label: 'Under review',       text: 'Thank you for reporting this! Our team is reviewing the signature and will update the detection database if it is confirmed.' },
  { topic: 'Cheat Report', label: 'Added to database',  text: 'The reported cheat has been verified and added to our detection database. It will be active in the next scanner update — great catch!' },
  { topic: 'Cheat Report', label: 'Already tracked',    text: 'This cheat is already tracked in our detection database. Thank you for the report — every submission helps us verify coverage!' },
  { topic: 'Cheat Report', label: 'Pattern rejected',   text: 'After review, we were unable to confirm this as a cheat indicator. If you have additional evidence (video, forum link, VT scan), please resubmit.' },
  { topic: 'Cheat Report', label: 'Need evidence',      text: 'To process this report, we need more evidence — for example a forum/Discord link, a VirusTotal scan, or a short clip showing the tool in use.' },
  { topic: 'Cheat Report', label: 'Need file sample',   text: 'Do you have access to the cheat file itself? A sample (even just the filename and hash) would allow us to add a more precise signature.' },
  // Bug
  { topic: 'Bug', label: 'Bug confirmed',           text: 'We have confirmed this bug on our end. It is now tracked internally and will be fixed in an upcoming release.' },
  { topic: 'Bug', label: 'Fixed in next update',   text: 'This bug has been fixed and the fix will go out with the next update. Thank you for reporting it!' },
  { topic: 'Bug', label: 'Workaround available',   text: 'While we work on a permanent fix, here is a workaround: [describe steps]. We will notify you once the fix is deployed.' },
  { topic: 'Bug', label: 'Need repro steps',       text: 'To reproduce this bug, we need exact steps. Could you walk us through what you did, what you expected, and what happened instead?' },
  { topic: 'Bug', label: 'Need screenshot/log',    text: 'A screenshot or the error log would help us diagnose this faster. You can attach files to your next reply.' },
]

const CHEAT_TYPES = [
  { value: 'FileNameKeyword', label: 'Filename Keyword (partial match)' },
  { value: 'FileName',        label: 'Exact Filename' },
  { value: 'ProcessName',     label: 'Process Name' },
]
const CHEAT_CATEGORIES = ['Cheat', 'Spoofer', 'Injector', 'Cleaner', 'FiveM-Cheat', 'Other']
const RISK_LEVELS    = ['Medium', 'High', 'Critical']
const GAMES          = ['MINECRAFT', 'CS2', 'RUST', 'VALORANT', 'FORTNITE', 'APEX', 'FiveM', 'OTHER']
const STATUSES        = ['Open', 'In Progress', 'Resolved', 'Closed']
const TICKET_CATEGORIES = ['General', 'Bug', 'Billing', 'Detection', 'Cheat Report']
const CANNED_TOPICS   = ['General', 'Billing', 'Detection', 'Cheat Report', 'Bug']
const emptyCheatForm = { cheatName: '', pattern: '', type: 'FileNameKeyword', category: 'Cheat', risk: 'High', game: 'OTHER', evidenceUrl: '', description: '' }

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

function CheatReportPanel({ ticket, isAdmin, dispatch, toast }) {
  const cd = ticket.cheatData
  const dbStatus = cd?.dbStatus || 'pending'
  const isDone = dbStatus === 'added' || dbStatus === 'rejected'

  const blankForm = { cheatName: '', pattern: '', type: 'FileNameKeyword', category: 'Cheat', risk: 'High', game: 'OTHER', evidenceUrl: '', description: '' }
  const [editData, setEditData] = useState(cd ? { ...cd } : blankForm)
  // No cheatData means it came in via template — open in edit mode right away
  const [showEdit, setShowEdit] = useState(!cd && isAdmin)

  const CHEAT_TYPE_LABELS = { FileNameKeyword: 'Filename Keyword', FileName: 'Exact Filename', ProcessName: 'Process Name' }

  const addToDb = () => {
    if (!editData.cheatName.trim() || !editData.pattern.trim())
      return toast({ type: 'error', title: 'Tool name and pattern are required' })
    dispatch({
      type: 'add-cheat-to-db',
      proposal: {
        cheatName: editData.cheatName.trim(),
        pattern: editData.pattern.trim().toLowerCase(),
        type: editData.type,
        category: editData.category,
        risk: editData.risk,
        game: editData.game,
        evidenceUrl: editData.evidenceUrl,
        description: editData.description,
      },
    })
    dispatch({ type: 'update-ticket', id: ticket.id, fields: { cheatData: { ...editData, dbStatus: 'added' } } })
    dispatch({ type: 'reply-ticket', id: ticket.id, message: `✅ Cheat "${editData.cheatName.trim()}" has been verified and added to the detection database. Pattern: \`${editData.pattern.trim()}\` (${CHEAT_TYPE_LABELS[editData.type] || editData.type}).`, internal: false })
    dispatch({ type: 'update-ticket', id: ticket.id, fields: { status: 'Resolved' } })
    toast({ type: 'success', title: 'Added to database', body: editData.cheatName.trim() })
    setShowEdit(false)
  }

  const reject = () => {
    dispatch({ type: 'update-ticket', id: ticket.id, fields: { cheatData: { ...(cd || editData), dbStatus: 'rejected' } } })
    dispatch({ type: 'reply-ticket', id: ticket.id, message: `❌ After review, the reported signature could not be verified as a cheat indicator. If you have additional evidence, please open a new report.`, internal: false })
    dispatch({ type: 'update-ticket', id: ticket.id, fields: { status: 'Resolved' } })
    toast({ type: 'info', title: 'Report rejected' })
  }

  return (
    <div className={`rounded-xl border p-4 space-y-3 ${
      dbStatus === 'added'    ? 'border-green-400/30 bg-green-400/5' :
      dbStatus === 'rejected' ? 'border-red-400/20 bg-red-400/5' :
      'border-purple-400/30 bg-purple-400/5'
    }`}>
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert size={15} className={dbStatus === 'added' ? 'text-green-400' : dbStatus === 'rejected' ? 'text-red-400' : 'text-purple-400'} />
          <p className="txt text-sm font-semibold">Cheat Report Data</p>
          {!cd && isAdmin && <span className="muted text-xs">(fill in to add to database)</span>}
        </div>
        <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${
          dbStatus === 'added'    ? 'border-green-400/40 bg-green-400/10 text-green-400' :
          dbStatus === 'rejected' ? 'border-red-400/40 bg-red-400/10 text-red-400' :
          'border-yellow-400/40 bg-yellow-400/10 text-yellow-400'
        }`}>
          {dbStatus === 'added' ? 'Added to DB' : dbStatus === 'rejected' ? 'Rejected' : 'Pending Review'}
        </span>
      </div>

      {/* Edit form */}
      {showEdit && isAdmin ? (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <p className="caps-label mb-1">Tool Name *</p>
              <input value={editData.cheatName} onChange={e => setEditData(d => ({ ...d, cheatName: e.target.value }))}
                placeholder="e.g. KillAura Pro"
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-purple-500" />
            </div>
            <div>
              <p className="caps-label mb-1">Pattern *</p>
              <input value={editData.pattern} onChange={e => setEditData(d => ({ ...d, pattern: e.target.value }))}
                placeholder="e.g. killaura.exe"
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm font-mono outline-none focus:border-purple-500" />
            </div>
            <div>
              <p className="caps-label mb-1">Match Type</p>
              <select value={editData.type} onChange={e => setEditData(d => ({ ...d, type: e.target.value }))}
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm">
                {CHEAT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <p className="caps-label mb-1">Category</p>
              <select value={editData.category} onChange={e => setEditData(d => ({ ...d, category: e.target.value }))}
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm">
                {CHEAT_CATEGORIES.map(x => <option key={x} value={x}>{x}</option>)}
              </select>
            </div>
            <div>
              <p className="caps-label mb-1">Risk</p>
              <select value={editData.risk} onChange={e => setEditData(d => ({ ...d, risk: e.target.value }))}
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm">
                {RISK_LEVELS.map(x => <option key={x} value={x}>{x}</option>)}
              </select>
            </div>
            <div>
              <p className="caps-label mb-1">Game</p>
              <select value={editData.game} onChange={e => setEditData(d => ({ ...d, game: e.target.value }))}
                className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm">
                {GAMES.map(x => <option key={x} value={x}>{x}</option>)}
              </select>
            </div>
          </div>
          <div>
            <p className="caps-label mb-1">Evidence URL</p>
            <input value={editData.evidenceUrl} onChange={e => setEditData(d => ({ ...d, evidenceUrl: e.target.value }))}
              placeholder="https://…"
              className="bd tile txt w-full rounded-lg border px-3 py-1.5 text-sm outline-none focus:border-purple-500" />
          </div>
          <div className="flex gap-2 pt-1">
            <button onClick={addToDb}
              className="flex-1 rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white hover:bg-green-500">
              ✓ Confirm &amp; Add to Database
            </button>
            {cd && (
              <button onClick={() => setShowEdit(false)}
                className="rounded-lg border bd px-4 py-2 text-sm muted hover:txt">
                Cancel
              </button>
            )}
          </div>
        </div>
      ) : cd ? (
        /* Read-only data view */
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
          {[
            ['Tool Name',   cd.cheatName],
            ['Pattern',     cd.pattern],
            ['Match Type',  CHEAT_TYPE_LABELS[cd.type] || cd.type],
            ['Category',    cd.category],
            ['Risk',        cd.risk],
            ['Game',        cd.game],
          ].map(([k, v]) => v ? (
            <div key={k}>
              <span className="muted">{k}: </span>
              <span className={`txt font-medium ${k === 'Pattern' ? 'font-mono' : ''}`}>{v}</span>
            </div>
          ) : null)}
          {cd.evidenceUrl && (
            <div className="col-span-2">
              <span className="muted">Evidence: </span>
              <a href={cd.evidenceUrl} target="_blank" rel="noopener noreferrer"
                className="text-sky-400 hover:underline break-all">{cd.evidenceUrl}</a>
            </div>
          )}
          {cd.description && (
            <div className="col-span-2">
              <span className="muted">Notes: </span>
              <span className="txt">{cd.description}</span>
            </div>
          )}
        </div>
      ) : null}

      {/* Admin action buttons (read-only view) */}
      {isAdmin && !isDone && !showEdit && cd && (
        <div className="flex gap-2 pt-1 border-t bd">
          <button onClick={() => setShowEdit(true)}
            className="flex-1 rounded-lg bg-purple-600/80 px-4 py-2 text-sm font-semibold text-white hover:bg-purple-600">
            Review &amp; Add to Database
          </button>
          <button onClick={reject}
            className="rounded-lg bg-red-600/10 border border-red-600/30 px-4 py-2 text-sm text-red-400 hover:bg-red-600/20">
            Reject
          </button>
        </div>
      )}
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

        {/* Cheat Report Panel (nur bei Cheat-Tickets) */}
        {ticket.category === 'Cheat Report' && (
          <CheatReportPanel
            ticket={ticket}
            isAdmin={isAdmin}
            dispatch={dispatch}
            toast={toast}
          />
        )}

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
                    <div className="absolute right-0 top-full mt-1 z-20 w-64 panel rounded-xl border shadow-2xl py-1.5 max-h-72 overflow-y-auto">
                      {/* Show ticket's own topic first, then rest */}
                      {[ticket.category, ...CANNED_TOPICS.filter(t => t !== ticket.category)]
                        .map(topic => {
                          const items = CANNED_RESPONSES.filter(c => c.topic === topic)
                          if (!items.length) return null
                          return (
                            <div key={topic}>
                              <p className="caps-label px-3 pt-2 pb-1">{topic}</p>
                              {items.map(c => (
                                <button
                                  key={c.label}
                                  onClick={() => { setReply(c.text); setShowCanned(false) }}
                                  className="hoverable txt w-full px-3 py-2 text-left text-xs"
                                >
                                  {c.label}
                                </button>
                              ))}
                            </div>
                          )
                        })}
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

  const cheatValid = cheatForm.cheatName.trim().length > 0 && cheatForm.pattern.trim().length >= 3

  const submitCheat = () => {
    if (!cheatForm.cheatName.trim()) return toast({ type: 'error', title: 'Cheat name required', body: 'Enter a recognisable name for this cheat.' })
    if (!cheatForm.pattern.trim()) return toast({ type: 'error', title: 'Detection pattern required' })
    if (cheatForm.pattern.trim().length < 3) return toast({ type: 'error', title: 'Pattern too short', body: 'At least 3 characters.' })
    const urlVal = cheatForm.evidenceUrl.trim()
    if (urlVal && !/^https?:\/\/.+/.test(urlVal))
      return toast({ type: 'error', title: 'Invalid URL', body: 'Evidence URL must start with http:// or https://' })

    const name    = cheatForm.cheatName.trim()
    const pattern = cheatForm.pattern.trim().toLowerCase()
    const notes   = cheatForm.description.trim()

    // 1. Create proposal for detection-database review (Proposals page)
    dispatch({
      type: 'add-user-proposal',
      proposal: {
        cheatName: name,
        pattern,
        type: cheatForm.type,
        category: cheatForm.category,
        risk: cheatForm.risk,
        game: cheatForm.game,
        evidenceUrl: urlVal,
        description: notes || `User-reported ${cheatForm.category.toLowerCase()}: ${name}`,
      },
    })

    // 2. Create a support ticket so admins can reply and track the report
    const ticketMsg = [
      `Cheat / Tool Name: ${name}`,
      `Category: ${cheatForm.category}`,
      `Game: ${cheatForm.game}`,
      `Risk Level: ${cheatForm.risk}`,
      '',
      `Detection Pattern: ${pattern}`,
      `Match Type: ${cheatForm.type}`,
      urlVal ? `Evidence URL: ${urlVal}` : null,
      notes ? `\nNotes:\n${notes}` : null,
    ].filter(Boolean).join('\n')

    dispatch({
      type: 'add-ticket',
      ticket: {
        subject: `Cheat Report: ${name}`,
        category: 'Cheat Report',
        priority: cheatForm.risk === 'Critical' ? 'Urgent' : cheatForm.risk === 'High' ? 'High' : 'Normal',
        message: ticketMsg,
        tags: ['cheat-related', cheatForm.game.toLowerCase()],
        cheatData: {
          cheatName: name,
          pattern,
          type: cheatForm.type,
          category: cheatForm.category,
          risk: cheatForm.risk,
          game: cheatForm.game,
          evidenceUrl: urlVal,
          description: notes,
          dbStatus: 'pending',
        },
      },
    })

    toast({ type: 'success', title: 'Report submitted', body: 'A ticket has been opened — you can track status in My Tickets.' })
    setCheatForm(emptyCheatForm)
    setCheatOpen(false)
  }

  const openedTicket = activeTicket ? myTickets.find(t => t.id === activeTicket) : null

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
                  <div key={p.id} className="tile rounded-lg border px-3 py-2.5 space-y-1">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="txt text-sm font-semibold truncate">{p.cheatName || p.pattern}</p>
                        {p.cheatName && <p className="font-mono text-xs muted truncate">{p.pattern}</p>}
                        <p className="muted text-xs">{p.category} · {p.game || 'OTHER'}</p>
                      </div>
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${
                          p.risk === 'Critical' ? 'text-red-400 bg-red-400/10 border-red-400/20' :
                          p.risk === 'High' ? 'text-orange-400 bg-orange-400/10 border-orange-400/20' :
                          'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'}`}>{p.risk}</span>
                        {p.status === 'pending'  && <span className="rounded-full bg-yellow-400/10 border border-yellow-400/20 px-2 py-0.5 text-xs text-yellow-400">Pending</span>}
                        {p.status === 'approved' && <span className="rounded-full bg-green-400/10 border border-green-400/20 px-2 py-0.5 text-xs text-green-400">Approved</span>}
                        {p.status === 'rejected' && <span className="rounded-full bg-red-400/10 border border-red-400/20 px-2 py-0.5 text-xs text-red-400">Rejected</span>}
                      </div>
                    </div>
                    {p.evidenceUrl && (
                      <a href={p.evidenceUrl} target="_blank" rel="noopener noreferrer"
                        className="text-xs text-sky-400 hover:underline truncate block" onClick={e => e.stopPropagation()}>
                        Evidence →
                      </a>
                    )}
                    {p.adminComment && (
                      <p className="text-xs muted italic">Admin: {p.adminComment}</p>
                    )}
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
                { label: 'Bug Report',       subject: 'Bug: ',      category: 'Bug',       priority: 'High',   message: 'Steps to reproduce:\n1. \n\nExpected:\nActual:' },
                { label: 'Detection Issue',  subject: 'Detection: ', category: 'Detection', priority: 'Normal', message: 'Player:\nScan ID:\nIssue:' },
                { label: 'Billing Question', subject: 'Billing: ',  category: 'Billing',   priority: 'Normal', message: '' },
                { label: 'Feature Request',  subject: 'Feature: ',  category: 'General',   priority: 'Low',    message: 'I would like to suggest:' },
              ].map(tpl => (
                <button
                  key={tpl.label}
                  type="button"
                  onClick={() => setForm(f => ({ ...f, subject: tpl.subject, category: tpl.category, priority: tpl.priority, message: tpl.message, tags: tpl.tags || f.tags }))}
                  className="rounded-lg border bd px-3 py-1.5 text-xs muted hover:txt transition-colors"
                >
                  {tpl.label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => { setTicketOpen(false); setCheatOpen(true) }}
                className="rounded-lg border border-purple-500/30 px-3 py-1.5 text-xs text-purple-400 hover:bg-purple-500/10 transition-colors"
              >
                <ShieldAlert size={11} className="inline mr-1 -mt-0.5" />
                Cheat melden
              </button>
            </div>
          </div>
          <Field label="Subject">
            <Input autoFocus value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} placeholder="Short summary" />
          </Field>
          <Field label="Category">
            <div className="grid grid-cols-5 gap-1.5">
              {[
                { value: 'General',      icon: MessageSquare, label: 'General',   idleCls: '',              selCls: 'border-white/40 bg-white/10 text-white'          },
                { value: 'Bug',          icon: Bug,           label: 'Bug',        idleCls: '',              selCls: 'border-orange-400/50 bg-orange-400/10 text-orange-400' },
                { value: 'Billing',      icon: CreditCard,    label: 'Billing',    idleCls: '',              selCls: 'border-green-400/50 bg-green-400/10 text-green-400'   },
                { value: 'Detection',    icon: Shield,        label: 'Detection',  idleCls: '',              selCls: 'border-sky-400/50 bg-sky-400/10 text-sky-400'         },
                { value: 'Cheat Report', icon: ShieldAlert,   label: 'Cheat',      idleCls: '',              selCls: 'border-purple-400/50 bg-purple-400/10 text-purple-400'},
              ].map(cat => {
                const Icon = cat.icon
                const sel = form.category === cat.value
                return (
                  <button key={cat.value} type="button"
                    onClick={() => {
                      if (cat.value === 'Cheat Report') { setTicketOpen(false); setCheatOpen(true); return }
                      setForm({ ...form, category: cat.value })
                    }}
                    className={`flex flex-col items-center gap-1.5 rounded-xl border py-3 px-1 text-center transition-all ${
                      sel ? cat.selCls : 'bd tile muted hover:txt'
                    }`}
                  >
                    <Icon size={15} />
                    <span className="text-[10px] font-semibold leading-tight">{cat.label}</span>
                  </button>
                )
              })}
            </div>
          </Field>
          <Field label="Priority">
            <div className="grid grid-cols-4 gap-1.5">
              {[
                { value: 'Low',    label: 'Low',    selCls: 'border-white/30 bg-white/5 text-white/70'           },
                { value: 'Normal', label: 'Normal', selCls: 'border-sky-400/40 bg-sky-400/10 text-sky-400'       },
                { value: 'High',   label: 'High',   selCls: 'border-orange-400/50 bg-orange-400/10 text-orange-400' },
                { value: 'Urgent', label: 'Urgent', selCls: 'border-red-400/50 bg-red-400/10 text-red-400'       },
              ].map(p => {
                const sel = form.priority === p.value
                return (
                  <button key={p.value} type="button"
                    onClick={() => setForm({ ...form, priority: p.value })}
                    className={`rounded-xl border py-2.5 text-xs font-semibold transition-all ${
                      sel ? p.selCls : 'bd tile muted hover:txt'
                    }`}
                  >
                    {p.label}
                  </button>
                )
              })}
            </div>
          </Field>
          <Field label="Tags (optional)">
            <TagInput tags={form.tags} onChange={tags => setForm({ ...form, tags })} />
          </Field>
          <Field label="Message">
            <Textarea rows={4} value={form.message} onChange={e => setForm({ ...form, message: e.target.value })} placeholder="Describe your issue…" />
          </Field>
        </div>
      </Modal>

      {/* Suggest cheat modal */}
      <Modal open={cheatOpen} onClose={() => { setCheatOpen(false); setCheatForm(emptyCheatForm) }} title="Cheat zur Datenbank melden"
        footer={
          <>
            <button onClick={() => { setCheatOpen(false); setCheatForm(emptyCheatForm) }} className="bd txt rounded-lg border px-4 py-2 text-sm">Abbrechen</button>
            <button
              onClick={submitCheat}
              disabled={!cheatValid}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
                cheatValid
                  ? 'bg-purple-600 text-white hover:bg-purple-500'
                  : 'bd tile muted cursor-not-allowed opacity-50'
              }`}
            >
              Zur Überprüfung einreichen
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="rounded-lg bg-purple-500/5 border border-purple-500/20 px-4 py-3 text-sm text-purple-300/80">
            Fülle alle Pflichtfelder <span className="text-red-400 font-bold">*</span> aus. Nach dem Absenden wird ein Support-Ticket erstellt, über das du den Status verfolgen kannst.
          </div>

          <Field label={<>Name des Cheats / Tools <span className="text-red-400">*</span></>} hint="Der Name, unter dem das Tool bekannt ist.">
            <Input
              autoFocus
              value={cheatForm.cheatName}
              onChange={e => setCheatForm({ ...cheatForm, cheatName: e.target.value })}
              placeholder="z.B. KillAura Pro, SpooferX, ESP-Master"
            />
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field label="Kategorie">
              <Select value={cheatForm.category} onChange={v => setCheatForm({ ...cheatForm, category: v })}
                options={CHEAT_CATEGORIES.map(x => ({ value: x, label: x }))} />
            </Field>
            <Field label="Spiel">
              <Select value={cheatForm.game} onChange={v => setCheatForm({ ...cheatForm, game: v })}
                options={GAMES.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>

          <Field
            label={<>Erkennungs-Pattern <span className="text-red-400">*</span></>}
            hint="Dateiname, Prozessname oder Schlüsselwort, nach dem der Scanner sucht. Mind. 3 Zeichen."
          >
            <Input
              value={cheatForm.pattern}
              onChange={e => setCheatForm({ ...cheatForm, pattern: e.target.value })}
              placeholder="z.B. killaura.exe  oder  cheat_loader"
              className="font-mono"
            />
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field label="Match-Typ">
              <Select value={cheatForm.type} onChange={v => setCheatForm({ ...cheatForm, type: v })}
                options={CHEAT_TYPES.map(t => ({ value: t.value, label: t.label }))} />
            </Field>
            <Field label="Risikostufe">
              <Select value={cheatForm.risk} onChange={v => setCheatForm({ ...cheatForm, risk: v })}
                options={RISK_LEVELS.map(x => ({ value: x, label: x }))} />
            </Field>
          </div>

          <div className="rounded-md bd border px-3 py-2 text-xs muted space-y-0.5">
            <p><span className="txt font-medium">Filename Keyword</span> — Teilübereinstimmung im Dateinamen (flexibelste Option)</p>
            <p><span className="txt font-medium">Exact Filename</span> — exakter Dateiname, z.B. <code className="font-mono txt">cheat.exe</code></p>
            <p><span className="txt font-medium">Process Name</span> — laufender Prozess wird nach Namen geprüft</p>
          </div>

          <Field label="Beweis-URL" hint="Forum-Link, Discord, YouTube oder VirusTotal-Scan — optional, aber sehr hilfreich.">
            <Input
              value={cheatForm.evidenceUrl}
              onChange={e => setCheatForm({ ...cheatForm, evidenceUrl: e.target.value })}
              placeholder="https://…"
            />
          </Field>

          <Field label="Notizen" hint="Wie und wo wurde das Tool eingesetzt? Was hast du beobachtet?">
            <Textarea
              rows={2}
              value={cheatForm.description}
              onChange={e => setCheatForm({ ...cheatForm, description: e.target.value })}
              placeholder="z.B. Auf einem FiveM-Server gesehen, Spieler flogen durch Wände…"
            />
          </Field>

          {!cheatValid && (cheatForm.cheatName || cheatForm.pattern) && (
            <p className="text-xs text-yellow-400">
              {!cheatForm.cheatName.trim()
                ? '⚠ Tool-Name fehlt.'
                : cheatForm.pattern.trim().length < 3
                  ? '⚠ Pattern muss mindestens 3 Zeichen lang sein.'
                  : ''}
            </p>
          )}
        </div>
      </Modal>
    </div>
  )
}
