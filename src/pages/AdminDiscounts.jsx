import { useState } from 'react'
import { Ticket, Plus, Trash2, Copy, Power } from 'lucide-react'
import { PageHeader, Card, Field, Input } from '../components/kit.jsx'
import { Select, useToast } from '../components/ui.jsx'
import { useStore, logAdminAction } from '../store.jsx'

function randCode() {
  const a = Math.random().toString(36).slice(2, 7).toUpperCase()
  const b = Math.random().toString(36).slice(2, 6).toUpperCase()
  return `ZT-${a}-${b}`
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleDateString() : '—'
}

export default function AdminDiscounts() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const codes = state.discountCodes || []

  const [code, setCode] = useState(randCode())
  const [percent, setPercent] = useState('25')
  const [maxUses, setMaxUses] = useState('0')
  const [expiryDays, setExpiryDays] = useState('0')

  const create = () => {
    const c = code.trim().toUpperCase()
    const p = Math.min(100, Math.max(1, Math.floor(Number(percent) || 0)))
    if (!c) return toast({ type: 'error', title: 'Enter a code' })
    if (!p) return toast({ type: 'error', title: 'Enter a valid percent' })
    if (codes.some((x) => x.code.toUpperCase() === c)) return toast({ type: 'error', title: 'Code already exists' })
    const days = Math.floor(Number(expiryDays) || 0)
    dispatch({
      type: 'create-discount-code',
      code: c,
      percent: p,
      maxUses: Math.floor(Number(maxUses) || 0),
      expiresAt: days > 0 ? Date.now() + days * 86400000 : null,
    })
    logAdminAction(dispatch, state, 'discount-create', c, `${p}% / maxUses ${maxUses} / ${days}d`)
    toast({ type: 'success', title: 'Discount code created', body: `${c} — ${p}%` })
    setCode(randCode())
  }

  const copy = (c) => {
    navigator.clipboard?.writeText(c).catch(() => {})
    toast({ type: 'success', title: 'Copied', body: c })
  }

  return (
    <div>
      <PageHeader
        icon={Ticket}
        kicker="Promotions"
        title="Discount Codes"
        subtitle="Create discount codes analysts can apply to license-key purchases in the shop."
      />

      <Card className="p-6">
        <p className="caps-label mb-3">Create a code</p>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Code">
            <div className="flex gap-2">
              <Input value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} className="font-mono" />
              <button onClick={() => setCode(randCode())} className="bd txt shrink-0 rounded-lg border px-3 text-xs hover:border-sky-500">
                Random
              </button>
            </div>
          </Field>
          <Field label="Discount %">
            <Input type="number" min="1" max="100" value={percent} onChange={(e) => setPercent(e.target.value)} />
          </Field>
          <Field label="Max uses (0 = ∞)">
            <Input type="number" min="0" value={maxUses} onChange={(e) => setMaxUses(e.target.value)} />
          </Field>
          <Field label="Expires in days (0 = never)">
            <Input type="number" min="0" value={expiryDays} onChange={(e) => setExpiryDays(e.target.value)} />
          </Field>
        </div>
        <div className="mt-4 flex justify-end">
          <button onClick={create} className="bg-sky-600 hover:bg-sky-700 flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold text-white">
            <Plus size={14} /> Create code
          </button>
        </div>
      </Card>

      <Card className="mt-6 p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 p-5">
          <h3 className="txt flex items-center gap-2 text-lg font-semibold">
            <Ticket size={18} /> All codes ({codes.length})
          </h3>
          {codes.length > 0 && (
            <button
              onClick={() => {
                if (!confirm(`Delete ALL ${codes.length} discount codes? This cannot be undone.`)) return
                dispatch({ type: 'clear-discount-codes' })
                logAdminAction(dispatch, state, 'discount-clear-all', '', `${codes.length} codes`)
                toast({ type: 'success', title: 'All discount codes deleted' })
              }}
              className="bd flex items-center gap-2 rounded-lg border border-red-600/40 px-3 py-2 text-sm text-red-500 hover:bg-red-600/10"
            >
              <Trash2 size={14} /> Delete all
            </button>
          )}
        </div>
        {codes.length === 0 ? (
          <p className="muted px-5 pb-12 pt-4 text-center text-sm">No discount codes yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-4 py-3">Code</th>
                  <th className="px-4 py-3">Discount</th>
                  <th className="px-4 py-3">Uses</th>
                  <th className="px-4 py-3">Expires</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {codes.map((c) => {
                  const expired = c.expiresAt && Date.now() > c.expiresAt
                  const usedUp = c.maxUses > 0 && (c.uses || 0) >= c.maxUses
                  const status = !c.active ? 'disabled' : expired ? 'expired' : usedUp ? 'used up' : 'active'
                  return (
                    <tr key={c.id} className="bd border-b last:border-0">
                      <td className="txt px-4 py-3">
                        <span className="inline-flex items-center gap-2">
                          <code className="font-mono">{c.code}</code>
                          <button onClick={() => copy(c.code)} className="muted hover:text-sky-400"><Copy size={12} /></button>
                        </span>
                      </td>
                      <td className="txt px-4 py-3 font-semibold text-sky-400">{c.percent}%</td>
                      <td className="muted px-4 py-3 text-xs">{c.uses || 0}{c.maxUses > 0 ? ` / ${c.maxUses}` : ' / ∞'}</td>
                      <td className="muted px-4 py-3 text-xs">{c.expiresAt ? fmt(c.expiresAt) : 'never'}</td>
                      <td className="muted px-4 py-3 text-xs">{c.source || 'admin'}</td>
                      <td className="px-4 py-3">
                        <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                          status === 'active' ? 'border-green-600/40 bg-green-600/15 text-green-500' :
                          status === 'disabled' ? 'border-yellow-500/40 bg-yellow-500/15 text-yellow-500' :
                          'bd muted'
                        }`}>{status}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex justify-end gap-1.5">
                          <button
                            onClick={() => dispatch({ type: 'toggle-discount-code', id: c.id })}
                            className="bd inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:border-sky-500"
                          >
                            <Power size={11} /> {c.active ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => { dispatch({ type: 'delete-discount-code', id: c.id }); logAdminAction(dispatch, state, 'discount-delete', c.code) }}
                            className="bd inline-flex items-center gap-1 rounded-md border border-red-600/40 px-2 py-1 text-xs text-red-500 hover:bg-red-600/10"
                          >
                            <Trash2 size={11} /> Delete
                          </button>
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
    </div>
  )
}
