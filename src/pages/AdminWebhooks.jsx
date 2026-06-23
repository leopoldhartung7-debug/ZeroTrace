import { useMemo, useState } from 'react'
import { Activity, CheckCircle2, AlertCircle, Webhook, Play, Power } from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { useStore, logAdminAction } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : 'never'
}

function ago(ts) {
  if (!ts) return '—'
  const d = Date.now() - ts
  if (d < 60_000) return `${Math.floor(d / 1000)}s ago`
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`
  if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`
  return `${Math.floor(d / 86_400_000)}d ago`
}

export default function AdminWebhooks() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [testing, setTesting] = useState({})

  const webhooks = useMemo(() => {
    const list = []
    const main = state.integrations?.discordWebhook
    if (main) list.push({ url: main, label: 'Primary webhook', enabled: true, source: 'main' })
    ;(state.integrations?.discordWebhooks || []).forEach((w) => {
      list.push({ url: w.url, label: w.label || 'Extra', enabled: w.enabled !== false, source: 'extra', id: w.id, game: w.game })
    })
    return list
  }, [state.integrations])

  const test = async (url) => {
    setTesting((s) => ({ ...s, [url]: true }))
    const t0 = performance.now()
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'ZeroTrace Health Check',
          embeds: [{
            title: 'Webhook test',
            description: 'This is a manual health check from the ZeroTrace admin panel.',
            color: 0x848eb0,
            timestamp: new Date().toISOString(),
          }],
        }),
      })
      const latency = Math.round(performance.now() - t0)
      const ok = res.ok || res.status === 204
      dispatch({
        type: 'webhook-health-record',
        url,
        success: ok,
        latencyMs: latency,
        error: ok ? '' : `HTTP ${res.status}`,
      })
      logAdminAction(dispatch, state, 'webhook-test', url, ok ? `OK (${latency}ms)` : `FAIL HTTP ${res.status}`)
      toast({ type: ok ? 'success' : 'error', title: ok ? 'Webhook OK' : 'Webhook failed', body: ok ? `${latency}ms` : `HTTP ${res.status}` })
    } catch (err) {
      const latency = Math.round(performance.now() - t0)
      dispatch({
        type: 'webhook-health-record',
        url,
        success: false,
        latencyMs: latency,
        error: String(err),
      })
      logAdminAction(dispatch, state, 'webhook-test', url, `FAIL ${err}`)
      toast({ type: 'error', title: 'Webhook failed', body: String(err) })
    } finally {
      setTesting((s) => ({ ...s, [url]: false }))
    }
  }

  const toggle = (w) => {
    if (w.source === 'extra') {
      dispatch({ type: 'update-discord-webhook', id: w.id, value: { enabled: !w.enabled } })
      logAdminAction(dispatch, state, 'webhook-toggle', w.url, w.enabled ? 'disabled' : 'enabled')
    }
  }

  return (
    <div>
      <PageHeader
        icon={Activity}
        kicker="Diagnostics"
        title="Webhook Health"
        subtitle="Monitor every Discord webhook configured in this instance."
      />

      {webhooks.length === 0 ? (
        <Card className="p-12 text-center">
          <Webhook size={32} className="muted mx-auto mb-3" />
          <p className="txt text-sm font-medium">No webhooks configured</p>
          <p className="muted mt-1 text-xs">Add one in Account → Integrations.</p>
        </Card>
      ) : (
        <div className="space-y-3">
          {webhooks.map((w) => {
            const h = state.webhookHealth?.[w.url] || { ok: 0, fail: 0 }
            const total = h.ok + h.fail
            const successRate = total > 0 ? Math.round((h.ok / total) * 100) : null
            const healthy = h.lastSuccess === true || (total === 0 && !h.lastError)
            return (
              <Card key={w.url} className="p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {healthy ? (
                        <CheckCircle2 size={16} className="text-green-500" />
                      ) : (
                        <AlertCircle size={16} className="text-red-500" />
                      )}
                      <p className="txt text-sm font-semibold">{w.label}</p>
                      {w.game && <span className="bd muted rounded-md border px-2 py-0.5 text-[10px] font-semibold">{w.game}</span>}
                      {!w.enabled && <span className="rounded-md border border-yellow-500/40 bg-yellow-500/15 px-2 py-0.5 text-[10px] font-semibold text-yellow-500">disabled</span>}
                      {h.autoDisabled && <span className="rounded-md border border-red-600/40 bg-red-600/15 px-2 py-0.5 text-[10px] font-semibold text-red-500">auto-disabled</span>}
                    </div>
                    <p className="muted mt-2 break-all font-mono text-[11px]">{w.url}</p>
                    <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                      <div>
                        <p className="caps-label">Success</p>
                        <p className="txt mt-0.5 text-sm font-semibold">{h.ok || 0}</p>
                      </div>
                      <div>
                        <p className="caps-label">Failed</p>
                        <p className="mt-0.5 text-sm font-semibold text-red-500">{h.fail || 0}</p>
                      </div>
                      <div>
                        <p className="caps-label">Rate</p>
                        <p className="txt mt-0.5 text-sm font-semibold">{successRate == null ? '—' : `${successRate}%`}</p>
                      </div>
                      <div>
                        <p className="caps-label">Last</p>
                        <p className="muted mt-0.5 text-sm font-medium">{ago(h.lastTime)}</p>
                      </div>
                    </div>
                    {h.lastError && (
                      <p className="mt-3 break-all rounded-md border border-red-600/30 bg-red-600/10 px-3 py-2 text-xs text-red-400">
                        Last error: {h.lastError}
                      </p>
                    )}
                  </div>
                  <div className="flex shrink-0 flex-col gap-2">
                    <button
                      onClick={() => test(w.url)}
                      disabled={testing[w.url]}
                      className="bd txt flex items-center gap-2 rounded-lg border px-3 py-2 text-xs hover:border-sky-500 disabled:opacity-50"
                    >
                      <Play size={12} /> {testing[w.url] ? 'Testing…' : 'Test now'}
                    </button>
                    {w.source === 'extra' && (
                      <button
                        onClick={() => toggle(w)}
                        className="bd muted flex items-center gap-2 rounded-lg border px-3 py-2 text-xs hover:border-sky-500"
                      >
                        <Power size={12} /> {w.enabled ? 'Disable' : 'Enable'}
                      </button>
                    )}
                  </div>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
