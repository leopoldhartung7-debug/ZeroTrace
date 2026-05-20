import { useState, useEffect } from 'react'
import { Info, AlertTriangle, CheckCircle2, XCircle, X, UserCog, LogOut } from 'lucide-react'
import { useStore } from '../store.jsx'

const TONE_STYLES = {
  info: 'border-sky-500/40 bg-sky-500/15 text-sky-100',
  success: 'border-green-600/40 bg-green-600/15 text-green-100',
  warning: 'border-yellow-500/40 bg-yellow-500/15 text-yellow-100',
  danger: 'border-red-600/40 bg-red-600/15 text-red-100',
}

const TONE_ICON = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  danger: XCircle,
}

export function AnnouncementBanner() {
  const { state } = useStore()
  const a = state.announcement || {}
  const [dismissed, setDismissed] = useState(false)
  useEffect(() => {
    setDismissed(false)
  }, [a.updatedAt])

  if (!a.enabled || !a.text?.trim() || dismissed) return null
  const Icon = TONE_ICON[a.tone] || Info
  return (
    <div className={`flex items-start gap-3 border-b px-4 py-2.5 text-sm ${TONE_STYLES[a.tone] || TONE_STYLES.info}`}>
      <Icon size={16} className="mt-0.5 shrink-0" />
      <p className="min-w-0 flex-1 break-words font-medium">{a.text}</p>
      {a.dismissable !== false && (
        <button onClick={() => setDismissed(true)} className="shrink-0 opacity-70 hover:opacity-100" aria-label="Dismiss">
          <X size={16} />
        </button>
      )}
    </div>
  )
}

export function ImpersonationBanner() {
  const { state, dispatch } = useStore()
  const sess = state.session
  if (!sess?.impersonatedFrom) return null
  const user = (state.users || []).find((u) => u.id === sess.userId)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-yellow-500/40 bg-yellow-500/15 px-4 py-2.5 text-sm text-yellow-100">
      <div className="flex items-center gap-2">
        <UserCog size={16} className="shrink-0" />
        <p className="font-medium">
          Viewing as <span className="font-mono">{user?.username || sess.userId || '?'}</span>
        </p>
      </div>
      <button
        onClick={() => dispatch({ type: 'stop-impersonating' })}
        className="flex items-center gap-2 rounded-md border border-yellow-500/50 px-3 py-1 text-xs font-semibold hover:bg-yellow-500/20"
      >
        <LogOut size={12} /> Return to admin
      </button>
    </div>
  )
}
