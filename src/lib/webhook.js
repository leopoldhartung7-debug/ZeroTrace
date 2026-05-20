/* Builds and sends a scan-result overview to a Discord webhook. */

import { useEffect, useRef } from 'react'
import { useStore, deriveScanReport } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

function field(name, value, inline = true) {
  return { name, value: String(value == null || value === '' ? '—' : value).slice(0, 1024), inline }
}

function hexToInt(hex) {
  const m = String(hex || '').match(/#?([0-9a-fA-F]{6})/)
  return m ? parseInt(m[1], 16) : null
}

export function buildScanEmbed(meta, report, custom = {}) {
  const c = report.counts
  const risk = Math.min(100, c.detects * 8 + c.warnings * 2 + c.suspicious * 5)
  const flagged = report.discordServers.filter((s) => s.flag !== 'clean')
  const verdictColor =
    meta.verdict === 'Cheating' ? 0xdc2626 : meta.verdict === 'Suspicious' ? 0xf59e0b : 0x22c55e
  const accent = hexToInt(custom.color)
  const color = accent != null ? accent : verdictColor
  const serverList = flagged.length
    ? flagged.map((s) => `• ${s.name} (${s.flag})`).join('\n').slice(0, 1024)
    : 'None'
  return {
    title: `Scan completed — ${meta.verdict}`,
    color,
    fields: [
      field('Pin', '`' + meta.code + '`'),
      field('Game', meta.game),
      field('Verdict', meta.verdict),
      field('Discord ID', meta.discordId ? '`' + meta.discordId + '`' : '—'),
      field('Host', report.pc.host || '—'),
      field('IP', report.pc.ip || '—'),
      field('Risk score', `${risk}/100`),
      field('Detections', `D ${c.detects} · W ${c.warnings} · S ${c.suspicious}`),
      field('USB devices', report.usb.length),
      field(`Flagged Discord servers (${flagged.length})`, serverList, false),
    ],
    footer: { text: custom.footer || 'ZeroTrace Anti-Cheat — Scan Report' },
    timestamp: new Date().toISOString(),
  }
}

export async function sendScanSummary(webhook, meta, report, custom = {}) {
  if (!webhook) return { ok: false, skipped: true }
  try {
    const resp = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: custom.username || 'ZeroTrace Anti-Cheat',
        embeds: [buildScanEmbed(meta, report, custom)],
      }),
    })
    return { ok: resp.ok || resp.status === 204, status: resp.status }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

/* Watches the store and, as soon as any pin reaches "Finished",
   automatically posts its result overview to the configured webhook —
   exactly once per pin. Pins already finished when the app starts are
   baselined (marked sent without re-posting) to avoid backfill spam. */
export function ScanWebhookNotifier() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const initialized = useRef(false)

  useEffect(() => {
    const pending = state.pins.filter(
      (p) => p.status === 'Finished' && !p.webhookNotified,
    )
    if (pending.length === 0) return

    if (!initialized.current) {
      initialized.current = true
      pending.forEach((p) => dispatch({ type: 'mark-webhook-sent', code: p.pin }))
      return
    }

    const webhook = state.integrations?.discordWebhook || ''
    pending.forEach((p) => {
      dispatch({ type: 'mark-webhook-sent', code: p.pin })
      const report = deriveScanReport(p)
      if (!report || !webhook) return
      const meta = {
        code: p.pin,
        name: p.name || p.host || 'Scan',
        game: p.game || 'FIVEM',
        discordId: p.discordId || '',
        verdict: p.result || report.verdict || 'Clean',
      }
      sendScanSummary(webhook, meta, report, state.integrations?.webhookCustom || {}).then((r) => {
        if (r.ok) toast({ type: 'success', title: 'Scan summary sent to webhook', body: p.pin })
        else if (!r.skipped)
          toast({ type: 'error', title: 'Webhook failed', body: r.error || `HTTP ${r.status}` })
      })
    })
  }, [state.pins, state.integrations, dispatch, toast])

  return null
}
