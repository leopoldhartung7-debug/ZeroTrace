import { useState, useEffect } from 'react'
import { Wrench, Save, AlertTriangle } from 'lucide-react'
import { PageHeader, Card, Textarea } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, logAdminAction } from '../store.jsx'

export default function AdminMaintenance() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const m = state.maintenance || {}
  const [enabled, setEnabled] = useState(!!m.enabled)
  const [message, setMessage] = useState(m.message || '')

  useEffect(() => {
    setEnabled(!!m.enabled)
    setMessage(m.message || '')
  }, [m.updatedAt])

  const save = () => {
    dispatch({ type: 'set-maintenance', value: { enabled, message } })
    logAdminAction(dispatch, state, 'maintenance-update', enabled ? 'on' : 'off', message.slice(0, 80))
    toast({
      type: 'success',
      title: enabled ? 'Maintenance mode ON' : 'Maintenance mode OFF',
      body: enabled ? 'Analysts now see the maintenance screen.' : 'The site is back to normal.',
    })
  }

  return (
    <div>
      <PageHeader
        icon={Wrench}
        kicker="Operations"
        title="Maintenance Mode"
        subtitle="Block analyst access while you run upgrades, migrations or downtime. Admins are never blocked."
      />

      {enabled && (
        <div className="mb-4 flex items-start gap-3 rounded-lg border border-yellow-500/40 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-200">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <p>
            Maintenance is currently <span className="font-bold">enabled</span>. Every signed-in analyst sees the maintenance
            screen and cannot reach the dashboard. Your admin session is unaffected.
          </p>
        </div>
      )}

      <Card className="p-6">
        <label className="flex items-start gap-3">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="mt-1 h-4 w-4"
          />
          <span>
            <span className="txt text-sm font-semibold">Enable maintenance mode</span>
            <p className="muted mt-1 text-xs leading-relaxed">
              While this is on, every non-admin route returns the maintenance screen. The admin panel stays accessible.
            </p>
          </span>
        </label>

        <div className="mt-6">
          <p className="caps-label mb-2">Message shown to users</p>
          <Textarea
            rows={5}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="e.g. Scheduled maintenance until 18:00 CET. We're upgrading the scanner engine — your data is safe."
          />
          <p className="muted mt-1 text-xs">Leave empty to use the default message.</p>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={save}
            className="bg-sky-600 hover:bg-sky-700 flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold text-white"
          >
            <Save size={14} /> Save
          </button>
        </div>
      </Card>
    </div>
  )
}
