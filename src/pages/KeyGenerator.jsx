import { useState } from 'react'
import { KeyRound, Copy, Trash2, ShieldOff, ShieldCheck, Plus } from 'lucide-react'
import { PageHeader, Card, Field, Input } from '../components/kit.jsx'
import { Select, useToast } from '../components/ui.jsx'
import { useStore, generateLicenseKey } from '../store.jsx'

const PLANS = [
  { value: 'Trial', label: 'Trial' },
  { value: 'Personal', label: 'Personal' },
  { value: 'Enterprise', label: 'Enterprise' },
]
const DURATIONS = [
  { value: '1', label: '1 Day' },
  { value: '7', label: '7 Days' },
  { value: '30', label: '30 Days' },
  { value: '90', label: '90 Days' },
  { value: '365', label: '1 Year' },
  { value: '0', label: 'Lifetime' },
]

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function KeyGenerator() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [label, setLabel] = useState('')
  const [plan, setPlan] = useState('Personal')
  const [duration, setDuration] = useState('30')

  const keys = state.licenseKeys || []

  const create = () => {
    const key = generateLicenseKey()
    dispatch({
      type: 'create-key',
      key,
      label,
      plan,
      durationDays: Number(duration),
    })
    navigator.clipboard?.writeText(key).catch(() => {})
    toast({ type: 'success', title: 'Key created & copied', body: key })
    setLabel('')
  }

  const copyKey = (k) => {
    navigator.clipboard?.writeText(k).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: k })
  }

  const statusOf = (k) => {
    if (k.status === 'Revoked') return 'Revoked'
    if (k.expiresAt && Date.now() > k.expiresAt) return 'Expired'
    return 'Active'
  }
  const tone = {
    Active: 'border-green-600/40 bg-green-600/15 text-green-500',
    Revoked: 'border-red-600/40 bg-red-600/15 text-red-500',
    Expired: 'bd muted',
  }

  return (
    <div>
      <PageHeader
        icon={KeyRound}
        kicker="Admin only"
        title="Key Generator"
        subtitle="Create and manage license keys. Choose a plan and how long the key stays valid."
      />

      <Card className="p-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Label">
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Customer #42" />
          </Field>
          <Field label="Plan">
            <Select value={plan} onChange={setPlan} options={PLANS} />
          </Field>
          <Field label="Valid for">
            <Select value={duration} onChange={setDuration} options={DURATIONS} />
          </Field>
          <div className="flex items-end">
            <button
              onClick={create}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
            >
              <Plus size={16} /> Generate Key
            </button>
          </div>
        </div>
      </Card>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
          <KeyRound size={18} /> Generated Keys ({keys.length})
        </h3>
        <p className="muted mb-4 text-sm">
          {keys.filter((k) => statusOf(k) === 'Active').length} active ·{' '}
          {keys.length} total
        </p>
        {keys.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No keys generated yet.</p>
        ) : (
          <div className="space-y-2">
            {keys.map((k) => {
              const st = statusOf(k)
              return (
                <div key={k.id} className="tile rounded-lg border p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <code className="txt break-all font-mono text-sm font-semibold">{k.key}</code>
                        <button onClick={() => copyKey(k.key)} className="muted hover:txt" title="Copy">
                          <Copy size={14} />
                        </button>
                      </div>
                      <p className="muted mt-1 text-xs">
                        {k.label} · {k.plan} ·{' '}
                        {k.durationDays > 0 ? `${k.durationDays} day(s)` : 'Lifetime'}
                      </p>
                    </div>
                    <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${tone[st]}`}>
                      {st}
                    </span>
                  </div>
                  <div className="bd mt-3 flex flex-wrap items-center justify-between gap-3 border-t pt-3 text-xs">
                    <span className="muted">
                      Created {fmt(k.createdAt)} · Expires {k.expiresAt ? fmt(k.expiresAt) : 'Never'}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => dispatch({ type: 'revoke-key', id: k.id })}
                        className="bd txt flex items-center gap-1.5 rounded-md border px-2.5 py-1 hover:border-sky-500"
                      >
                        {k.status === 'Revoked' ? <ShieldCheck size={13} /> : <ShieldOff size={13} />}
                        {k.status === 'Revoked' ? 'Activate' : 'Revoke'}
                      </button>
                      <button
                        onClick={() => dispatch({ type: 'delete-key', id: k.id, key: k.key })}
                        className="bd flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-red-500 hover:border-red-500"
                      >
                        <Trash2 size={13} /> Delete
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </div>
  )
}
