import { Wrench, LogOut } from 'lucide-react'
import Logo from '../components/Logo.jsx'
import { useStore } from '../store.jsx'

export default function MaintenanceScreen() {
  const { state, dispatch } = useStore()
  const m = state.maintenance || {}
  return (
    <div className="app-bg flex min-h-screen items-center justify-center px-4 py-10">
      <div className="panel mx-auto max-w-lg rounded-2xl border p-8 text-center shadow-2xl">
        <div className="mb-6 flex justify-center">
          <Logo size="md" />
        </div>
        <div className="tile mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border">
          <Wrench size={28} className="text-sky-400" />
        </div>
        <h1 className="txt mb-3 text-2xl font-bold tracking-tight">Maintenance in progress</h1>
        <p className="muted text-sm leading-relaxed">
          {m.message?.trim() ||
            'ZeroTrace is temporarily offline for maintenance. We will be back shortly. Thanks for your patience.'}
        </p>
        {m.updatedAt > 0 && (
          <p className="muted mt-6 text-[11px]">
            Last updated {new Date(m.updatedAt).toLocaleString()}
          </p>
        )}
        <button
          onClick={() => dispatch({ type: 'logout' })}
          className="bd muted mx-auto mt-8 inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm hover:border-sky-500"
        >
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </div>
  )
}
