/* Per-user email digest watcher.
   Runs once a minute, fires when a user's chosen digest frequency
   (daily / weekly) has elapsed since their last digest. */

import { useEffect } from 'react'
import { useStore } from '../store.jsx'

const DAY = 86_400_000

async function sendDigest(user, cfg, summary, lang = 'en') {
  if (!cfg.emailJsServiceId || !cfg.emailJsTemplateId || !cfg.emailJsPublicKey) return false
  const de = lang === 'de'
  const subject = de ? 'ZeroTrace — Dein Aktivitätsbericht' : 'ZeroTrace — Your activity digest'
  const message =
    `${de ? 'Hallo' : 'Hi'} ${user.username},\n\n` +
    (de ? 'Hier ist deine Zusammenfassung:\n\n' : 'Here is your summary:\n\n') +
    `- ${de ? 'Scans' : 'Scans'}: ${summary.total}\n` +
    `- Cheating: ${summary.cheating}\n` +
    `- ${de ? 'Verdächtig' : 'Suspicious'}: ${summary.suspicious}\n` +
    `- ${de ? 'Sauber' : 'Clean'}: ${summary.clean}\n\n` +
    (de ? 'Top-Cheats: ' : 'Top cheats: ') + (summary.top || '—') + '\n\n' +
    'https://antcheat.ac\n'
  try {
    const r = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: cfg.emailJsServiceId,
        template_id: cfg.emailJsTemplateId,
        user_id: cfg.emailJsPublicKey,
        template_params: {
          to_email: user.email,
          subject,
          message,
        },
      }),
    })
    return r.ok
  } catch {
    return false
  }
}

export function DigestNotifier() {
  const { state, dispatch } = useStore()
  useEffect(() => {
    const tick = () => {
      const now = Date.now()
      const cfg = state.integrations || {}
      const lang = state.settings?.lang || 'en'
      ;(state.users || []).forEach((u) => {
        const freq = u.digestFrequency || 'off'
        if (freq === 'off' || !u.email) return
        const interval = freq === 'daily' ? DAY : freq === 'weekly' ? 7 * DAY : null
        if (!interval) return
        const last = u.lastDigestAt || 0
        if (now - last < interval) return
        const since = last || (now - interval)
        const userPins = (state.pins || []).filter(
          (p) => p.ownerId === u.id && (p.scannedAt || p.createdAt || 0) >= since,
        )
        if (userPins.length === 0) {
          dispatch({ type: 'mark-digest-sent', userId: u.id })
          return
        }
        const cheating = userPins.filter((p) => p.result === 'Cheating').length
        const suspicious = userPins.filter((p) => p.result === 'Suspicious').length
        const clean = userPins.filter((p) => p.result === 'Clean').length
        const counts = {}
        userPins.forEach((p) => (p.cheats || []).forEach((c) => (counts[c] = (counts[c] || 0) + 1)))
        const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} ×${v}`).join(', ')
        sendDigest(u, cfg, { total: userPins.length, cheating, suspicious, clean, top }, lang)
        dispatch({ type: 'mark-digest-sent', userId: u.id })
      })
    }
    tick()
    const id = setInterval(tick, 60_000)
    return () => clearInterval(id)
  }, [state.users, state.integrations, state.pins, state.settings, dispatch])
  return null
}
