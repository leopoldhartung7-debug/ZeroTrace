import { useState } from 'react'
import { Download } from 'lucide-react'
import { Modal, Select, useToast } from './ui.jsx'
import { Field, Input } from './kit.jsx'
import { useStore, generateLicenseKey, logAdminAction } from '../store.jsx'

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

export default function BulkKeyModal({ open, onClose }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [count, setCount] = useState('10')
  const [plan, setPlan] = useState('Personal')
  const [duration, setDuration] = useState('30')
  const [prefix, setPrefix] = useState('')

  const generate = () => {
    const n = Math.max(1, Math.min(500, Number(count) || 0))
    const days = Number(duration)
    const keys = Array.from({ length: n }, (_, i) => ({
      key: generateLicenseKey(),
      label: prefix ? `${prefix}-${String(i + 1).padStart(3, '0')}` : '',
      plan,
      durationDays: days,
    }))
    dispatch({ type: 'bulk-create-keys', keys })
    logAdminAction(dispatch, state, 'bulk-keys-created', `count=${n}`, `${plan} / ${days}d`)

    const csv = [
      'key,label,plan,duration_days',
      ...keys.map((k) => `${k.key},${k.label},${k.plan},${k.durationDays}`),
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `zerotrace-keys-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)

    toast({ type: 'success', title: `${n} keys generated`, body: 'CSV downloaded.' })
    onClose()
  }

  return (
    <Modal open={open} onClose={onClose} title="Bulk-generate license keys">
      <div className="space-y-4">
        <Field label="How many keys?">
          <Input type="number" min="1" max="500" value={count} onChange={(e) => setCount(e.target.value)} />
          <p className="muted mt-1 text-xs">Up to 500 at once.</p>
        </Field>
        <Field label="Label prefix (optional)">
          <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="e.g. reseller-x" />
          <p className="muted mt-1 text-xs">Keys get labels like prefix-001, prefix-002…</p>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Plan">
            <Select value={plan} onChange={setPlan} options={PLANS} />
          </Field>
          <Field label="Duration">
            <Select value={duration} onChange={setDuration} options={DURATIONS} />
          </Field>
        </div>
        <div className="flex flex-col gap-2 pt-2 sm:flex-row sm:justify-end">
          <button
            onClick={onClose}
            className="bd txt rounded-lg border px-4 py-2 text-sm hover:border-sky-500"
          >
            Cancel
          </button>
          <button
            onClick={generate}
            className="bg-sky-600 hover:bg-sky-700 flex items-center justify-center gap-2 rounded-lg px-5 py-2 text-sm font-semibold text-white"
          >
            <Download size={14} /> Generate & download CSV
          </button>
        </div>
      </div>
    </Modal>
  )
}
