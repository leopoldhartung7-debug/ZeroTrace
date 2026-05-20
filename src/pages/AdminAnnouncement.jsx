import { useState, useEffect } from 'react'
import { Megaphone, Info, AlertTriangle, CheckCircle2, XCircle, Save } from 'lucide-react'
import { PageHeader, Card, Textarea } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, logAdminAction } from '../store.jsx'

const TONES = [
  { value: 'info', label: 'Info', icon: Info, color: 'border-sky-500/40 bg-sky-500/15 text-sky-400' },
  { value: 'success', label: 'Success', icon: CheckCircle2, color: 'border-green-600/40 bg-green-600/15 text-green-500' },
  { value: 'warning', label: 'Warning', icon: AlertTriangle, color: 'border-yellow-500/40 bg-yellow-500/15 text-yellow-400' },
  { value: 'danger', label: 'Danger', icon: XCircle, color: 'border-red-600/40 bg-red-600/15 text-red-500' },
]

export default function AdminAnnouncement() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const a = state.announcement || {}
  const [text, setText] = useState(a.text || '')
  const [tone, setTone] = useState(a.tone || 'info')
  const [enabled, setEnabled] = useState(!!a.enabled)
  const [dismissable, setDismissable] = useState(a.dismissable !== false)

  useEffect(() => {
    setText(a.text || '')
    setTone(a.tone || 'info')
    setEnabled(!!a.enabled)
    setDismissable(a.dismissable !== false)
  }, [a.updatedAt])

  const save = () => {
    dispatch({
      type: 'set-announcement',
      value: { enabled, text, tone, dismissable },
    })
    logAdminAction(dispatch, state, 'announcement-update', tone, enabled ? `enabled: ${text.slice(0, 80)}` : 'disabled')
    toast({ type: 'success', title: 'Announcement saved' })
  }

  const toneMeta = TONES.find((t) => t.value === tone) || TONES[0]
  const ToneIcon = toneMeta.icon

  return (
    <div>
      <PageHeader
        icon={Megaphone}
        kicker="Communication"
        title="Announcement Banner"
        subtitle="Display a banner at the top of the dashboard for every signed-in user."
      />

      <Card className="p-6">
        <p className="caps-label mb-3">Preview</p>
        {text.trim() ? (
          <div className={`flex items-start gap-3 rounded-lg border px-4 py-3 ${toneMeta.color}`}>
            <ToneIcon size={18} className="mt-0.5 shrink-0" />
            <p className="break-words text-sm font-medium">{text}</p>
          </div>
        ) : (
          <p className="muted py-4 text-center text-sm">Type something below to see the preview.</p>
        )}
      </Card>

      <Card className="mt-4 p-6">
        <p className="caps-label mb-2">Message</p>
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          placeholder="e.g. Scheduled maintenance tomorrow at 14:00 CET — expect 5 minutes of downtime."
        />

        <p className="caps-label mb-2 mt-5">Tone</p>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {TONES.map((t) => {
            const Icon = t.icon
            return (
              <button
                key={t.value}
                onClick={() => setTone(t.value)}
                className={`flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-sm font-medium ${
                  tone === t.value ? t.color : 'bd muted hover:border-sky-500'
                }`}
              >
                <Icon size={14} /> {t.label}
              </button>
            )
          })}
        </div>

        <div className="mt-6 space-y-3">
          <label className="flex items-center gap-3">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="h-4 w-4" />
            <span className="txt text-sm">Show banner to all users</span>
          </label>
          <label className="flex items-center gap-3">
            <input type="checkbox" checked={dismissable} onChange={(e) => setDismissable(e.target.checked)} className="h-4 w-4" />
            <span className="txt text-sm">Users can dismiss it (hides for that browser session)</span>
          </label>
        </div>

        <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <button
            onClick={save}
            className="bg-sky-600 hover:bg-sky-700 flex items-center justify-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold text-white"
          >
            <Save size={14} /> Save & apply
          </button>
        </div>

        {a.updatedAt > 0 && (
          <p className="muted mt-3 text-right text-[11px]">
            Last updated {new Date(a.updatedAt).toLocaleString()}
          </p>
        )}
      </Card>
    </div>
  )
}
