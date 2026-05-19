import { useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, User as UserIcon, KeyRound, AtSign, MessageSquare,
  Clock, CheckCircle2, AlertCircle, Search, Activity, Pin as PinIcon,
  ScanLine, FileText, Code2, Database, LifeBuoy,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

const STATUS_TONE = {
  Pending: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500',
  Finished: 'border-green-600/40 bg-green-600/15 text-green-500',
  Expired: 'bd muted',
  Revoked: 'border-red-600/40 bg-red-600/15 text-red-500',
}

const VERDICT_TONE = {
  Cheating: 'border-red-600/40 bg-red-600/15 text-red-500',
  Suspicious: 'border-yellow-600/40 bg-yellow-600/15 text-yellow-500',
  Clean: 'border-green-600/40 bg-green-600/15 text-green-500',
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function UserDetails() {
  const { id } = useParams()
  const nav = useNavigate()
  const { state } = useStore()

  const user = (state.users || []).find((u) => u.id === id)
  const key = user ? (state.licenseKeys || []).find((k) => k.key === user.key) : null
  const pins = useMemo(
    () => (state.pins || []).filter((p) => p.ownerId === id),
    [state.pins, id],
  )
  const events = useMemo(
    () => (state.events || []).filter((e) => e.ownerId === id),
    [state.events, id],
  )

  if (!user) {
    return (
      <div className="py-20 text-center">
        <p className="txt text-lg font-semibold">User not found</p>
        <button onClick={() => nav('/keys')} className="mt-4 rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white">
          Back to Key Generator
        </button>
      </div>
    )
  }

  const keyStatus = !key
    ? 'No key'
    : key.status === 'Revoked'
      ? 'Revoked'
      : key.expiresAt && Date.now() > key.expiresAt
        ? 'Expired'
        : 'Active'
  const tone = STATUS_TONE[keyStatus] || 'bd muted'

  const counts = pins.reduce(
    (a, p) => {
      a.total++
      if (p.status === 'Finished') a.finished++
      else if (p.status === 'Pending') a.pending++
      else if (p.status === 'Expired') a.expired++
      if (p.result === 'Cheating') a.cheating++
      else if (p.result === 'Suspicious') a.suspicious++
      else if (p.result === 'Clean') a.clean++
      return a
    },
    { total: 0, pending: 0, finished: 0, expired: 0, cheating: 0, suspicious: 0, clean: 0 },
  )

  return (
    <div>
      <button onClick={() => nav('/keys')} className="muted hover:txt mb-4 flex items-center gap-2 text-sm">
        <ArrowLeft size={16} /> Back to Key Generator
      </button>

      <PageHeader
        icon={UserIcon}
        kicker="User account"
        title={user.username}
        subtitle="All pins and scan results bound to this analyst."
      />

      <Card className="p-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="tile rounded-lg border p-3">
            <p className="caps-label flex items-center gap-2"><AtSign size={11} /> Email</p>
            <p className="txt mt-1 break-all text-sm font-medium">{user.email}</p>
          </div>
          <div className="tile rounded-lg border p-3">
            <p className="caps-label flex items-center gap-2"><MessageSquare size={11} /> Discord ID</p>
            <p className="txt mt-1 font-mono text-sm">{user.discordId}</p>
          </div>
          <div className="tile rounded-lg border p-3">
            <p className="caps-label flex items-center gap-2"><KeyRound size={11} /> License key</p>
            <p className="txt mt-1 break-all font-mono text-sm">{user.key}</p>
          </div>
          <div className="tile rounded-lg border p-3">
            <p className="caps-label">Status</p>
            <p className="mt-1 text-sm">
              <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${tone}`}>{keyStatus}</span>
            </p>
            <p className="muted mt-2 text-[11px]">
              Created {fmt(user.createdAt)}
              {key?.expiresAt ? ` · Expires ${fmt(key.expiresAt)}` : ''}
            </p>
          </div>
        </div>
      </Card>

      <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card className="p-4">
          <p className="caps-label">Total Pins</p>
          <p className="txt mt-1 text-2xl font-bold">{counts.total}</p>
        </Card>
        <Card className="p-4">
          <p className="caps-label">Pending</p>
          <p className="txt mt-1 text-2xl font-bold">{counts.pending}</p>
        </Card>
        <Card className="p-4">
          <p className="caps-label">Finished</p>
          <p className="txt mt-1 text-2xl font-bold">{counts.finished}</p>
        </Card>
        <Card className="p-4">
          <p className="caps-label">Cheating · Susp · Clean</p>
          <p className="txt mt-1 text-2xl font-bold">
            <span className="text-red-500">{counts.cheating}</span>{' / '}
            <span className="text-yellow-500">{counts.suspicious}</span>{' / '}
            <span className="text-green-500">{counts.clean}</span>
          </p>
        </Card>
      </div>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-4 text-lg font-semibold">Pins ({pins.length})</h3>
        {pins.length === 0 ? (
          <p className="muted py-12 text-center text-sm">This user has no pins yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-3 py-3">Pin</th>
                  <th className="px-3 py-3">Name</th>
                  <th className="px-3 py-3">Game</th>
                  <th className="px-3 py-3">Status</th>
                  <th className="px-3 py-3">Verdict</th>
                  <th className="px-3 py-3">Created</th>
                  <th className="px-3 py-3">Detections</th>
                  <th className="px-3 py-3" />
                </tr>
              </thead>
              <tbody>
                {pins.map((p) => {
                  const verdict = p.result || (p.status === 'Pending' ? '—' : '—')
                  const report = p.status === 'Finished' ? deriveScanReport(p) : null
                  return (
                    <tr key={p.id} className="bd border-b last:border-0">
                      <td className="txt px-3 py-3 font-mono text-xs">{p.pin}</td>
                      <td className="txt px-3 py-3">{p.name}</td>
                      <td className="muted px-3 py-3 text-xs">{p.game}</td>
                      <td className="px-3 py-3">
                        <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${STATUS_TONE[p.status] || 'bd muted'}`}>
                          {p.status}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        {p.result ? (
                          <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${VERDICT_TONE[p.result] || 'bd muted'}`}>
                            {p.result}
                          </span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="muted px-3 py-3 text-xs">{fmt(p.createdAt)}</td>
                      <td className="muted px-3 py-3 text-xs">
                        {report
                          ? `D ${report.counts.detects} · W ${report.counts.warnings} · S ${report.counts.suspicious}`
                          : p.detections || '—'}
                      </td>
                      <td className="px-3 py-3 text-right">
                        <Link
                          to={`/scan/${p.id}`}
                          className="bd txt inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:border-sky-500"
                        >
                          <Search size={13} /> View Results
                        </Link>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
          <Activity size={18} /> Activity ({events.length})
        </h3>
        <p className="muted mb-4 text-sm">All activity-log entries this user has produced.</p>
        {events.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No activity recorded for this user.</p>
        ) : (
          <ol className="relative ml-3 border-l border-line">
            {events.map((e) => {
              const Icon =
                e.kind === 'pin' ? PinIcon :
                e.kind === 'scan' ? ScanLine :
                e.kind === 'file' ? FileText :
                e.kind === 'rule' ? Code2 :
                e.kind === 'db' ? Database :
                e.kind === 'support' ? LifeBuoy :
                Activity
              return (
                <li key={e.id} className="mb-6 ml-6">
                  <span className="panel absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full border">
                    <Icon size={12} className="muted" />
                  </span>
                  <div className="flex items-center justify-between gap-3">
                    <p className="txt text-sm font-medium">{e.title}</p>
                    <time className="muted text-xs">{fmt(e.time)}</time>
                  </div>
                  {e.detail && <p className="muted mt-0.5 text-xs">{e.detail}</p>}
                </li>
              )
            })}
          </ol>
        )}
      </Card>
    </div>
  )
}
