/* Builds and sends a scan-result overview to a Discord webhook. */

function field(name, value, inline = true) {
  return { name, value: String(value == null || value === '' ? '—' : value).slice(0, 1024), inline }
}

export function buildScanEmbed(meta, report) {
  const c = report.counts
  const risk = Math.min(100, c.detects * 8 + c.warnings * 2 + c.suspicious * 5)
  const flagged = report.discordServers.filter((s) => s.flag !== 'clean')
  const color =
    meta.verdict === 'Cheating' ? 0xdc2626 : meta.verdict === 'Suspicious' ? 0xf59e0b : 0x22c55e
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
    footer: { text: 'Ocean Anti-Cheat — Scan Report' },
    timestamp: new Date().toISOString(),
  }
}

export async function sendScanSummary(webhook, meta, report) {
  if (!webhook) return { ok: false, skipped: true }
  try {
    const resp = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'Ocean Anti-Cheat',
        embeds: [buildScanEmbed(meta, report)],
      }),
    })
    return { ok: resp.ok || resp.status === 204, status: resp.status }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}
