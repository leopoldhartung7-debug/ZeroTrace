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
      // Per-game preferred webhook
      const gpw = state.settings?.gameProfiles?.[p.game]?.webhookId
      const list = state.integrations?.discordWebhooks || []
      const target =
        list.find((w) => w.id === gpw && w.enabled !== false)?.url ||
        webhook
      const extras = list
        .filter((w) => w.enabled !== false && w.url !== target)
        .map((w) => w.url)
      const cfg = state.integrations?.webhookCustom || {}
      extras.forEach((u) => sendScanSummary(u, meta, report, cfg))
      sendScanSummary(target, meta, report, cfg).then((r) => {
        if (r.ok) toast({ type: 'success', title: 'Scan summary sent to webhook', body: p.pin })
        else if (!r.skipped)
          toast({ type: 'error', title: 'Webhook failed', body: r.error || `HTTP ${r.status}` })
      })
    })
  }, [state.pins, state.integrations, dispatch, toast])

  return null
}

/* Auto-weekly summary: once a week the dashboard posts a 7-day digest
   to the primary Discord webhook. Only fires when enabled in Settings. */
export function WeeklyReportNotifier() {
  const { state, dispatch } = useStore()
  useEffect(() => {
    const tick = async () => {
      const wr = state.settings?.weeklyReport
      if (!wr || !wr.enabled) return
      const webhook = state.integrations?.discordWebhook || ''
      if (!webhook) return
      const now = Date.now()
      if (wr.lastSentAt && now - wr.lastSentAt < 7 * 86400000) return
      const week = now - 7 * 86400000
      const recent = (state.pins || []).filter((p) => (p.scannedAt || p.createdAt || 0) >= week)
      const cheats = recent.filter((p) => p.result === 'Cheating').length
      const susp = recent.filter((p) => p.result === 'Suspicious').length
      const clean = recent.filter((p) => p.result === 'Clean').length
      const top = {}
      recent.forEach((p) => (p.cheats || []).forEach((c) => (top[c] = (top[c] || 0) + 1)))
      const topList = Object.entries(top).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} ×${v}`).join(', ') || '—'
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: 'ZeroTrace Weekly',
            embeds: [
              {
                title: 'ZeroTrace — Weekly summary',
                color: 0x38bdf8,
                fields: [
                  { name: 'Total scans (7d)', value: String(recent.length), inline: true },
                  { name: 'Cheating', value: String(cheats), inline: true },
                  { name: 'Suspicious', value: String(susp), inline: true },
                  { name: 'Clean', value: String(clean), inline: true },
                  { name: 'Top cheats', value: topList },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          }),
        })
        dispatch({ type: 'set-weekly-report', value: { lastSentAt: Date.now() } })
      } catch { /* ignore */ }
    }
    tick()
    const t = setInterval(tick, 60 * 60 * 1000) // hourly check
    return () => clearInterval(t)
  }, [state.settings, state.integrations, state.pins, dispatch])
  return null
}
