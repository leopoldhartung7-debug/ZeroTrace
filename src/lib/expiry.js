/* Watches license keys and sends the analyst a notice when their key is
   about to expire (24h before) and when it has expired. Notices go to
   the in-app notifications, the configured Discord webhook, and — if
   EmailJS is configured under Account → Integrations — to the user's
   email. Real triggers only, persisted flags prevent duplicates. */

import { useEffect } from 'react'
import { useStore } from '../store.jsx'
import { expiryHtml } from './emailTemplates.js'

const DAY = 86400000

function fmtDate(ts) {
  return new Date(ts).toLocaleString()
}

async function sendWebhookNotice(webhook, { title, color, key, user, expiresAt, reason }) {
  if (!webhook) return
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'ZeroTrace Anti-Cheat',
        embeds: [
          {
            title,
            color,
            fields: [
              { name: 'Account', value: user.username + ' · ' + user.email, inline: true },
              { name: 'Discord ID', value: '`' + user.discordId + '`', inline: true },
              { name: 'Key', value: '`' + key.key + '`' },
              { name: 'Plan', value: key.plan || '—', inline: true },
              { name: 'Expires', value: expiresAt ? fmtDate(expiresAt) : '—', inline: true },
              { name: 'Reason', value: reason },
            ],
            footer: { text: 'ZeroTrace Anti-Cheat — License watcher' },
            timestamp: new Date().toISOString(),
          },
        ],
      }),
    })
  } catch { /* fire & forget */ }
}

async function sendEmail(cfg, { to, subject, message, message_html }) {
  if (!cfg.emailJsServiceId || !cfg.emailJsTemplateId || !cfg.emailJsPublicKey) return false
  try {
    const resp = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: cfg.emailJsServiceId,
        template_id: cfg.emailJsTemplateId,
        user_id: cfg.emailJsPublicKey,
        template_params: { to_email: to, subject, message, message_html: message_html || '' },
      }),
    })
    return resp.ok
  } catch {
    return false
  }
}

export function KeyExpiryWatcher() {
  const { state, dispatch } = useStore()

  useEffect(() => {
    const tick = async () => {
      const now = Date.now()
      const webhook = state.integrations?.discordWebhook || ''
      const cfg = state.integrations || {}
      for (const key of state.licenseKeys || []) {
        if (!key.usedBy || !key.expiresAt) continue
        if (key.status !== 'Active') continue
        const user = (state.users || []).find((u) => u.id === key.usedBy)
        if (!user) continue

        // 24h reminder
        const within = key.expiresAt - now
        if (!key.reminderSent && within <= DAY && within > 0) {
          dispatch({ type: 'mark-key-reminder-sent', id: key.id })
          dispatch({
            type: 'add-notification',
            title: 'License key expires in 24h',
            body: `${user.username} (${user.email}) — ${key.key}`,
            ownerId: user.id,
          })
          sendWebhookNotice(webhook, {
            title: 'License key expires in 24 hours',
            color: 0xf59e0b,
            key, user,
            expiresAt: key.expiresAt,
            reason: 'Reminder — key expires within 24 hours.',
          })
          {
            const lang = state.settings?.lang || 'en'
            sendEmail(cfg, {
              to: user.email,
              subject: lang === 'de'
                ? 'Dein ZeroTrace-Lizenz-Key läuft in 24 Std. ab'
                : 'Your ZeroTrace license key expires in 24 hours',
              message: lang === 'de'
                ? `Hallo ${user.username}, dein ZeroTrace-Lizenz-Key ${key.key} läuft am ${fmtDate(key.expiresAt)} ab. Danach kannst du dich nicht mehr im Dashboard anmelden.`
                : `Hi ${user.username}, your ZeroTrace license key ${key.key} will expire on ${fmtDate(key.expiresAt)}.`,
              message_html: expiryHtml({ username: user.username, key: key.key, expiresAt: key.expiresAt, expired: false }, lang),
            })
          }
        }

        // Expired
        if (!key.expiredNotified && now >= key.expiresAt) {
          dispatch({ type: 'mark-key-expired-notified', id: key.id })
          dispatch({
            type: 'add-notification',
            title: 'License key expired',
            body: `${user.username} (${user.email}) — ${key.key}`,
            ownerId: user.id,
          })
          sendWebhookNotice(webhook, {
            title: 'License key expired',
            color: 0xdc2626,
            key, user,
            expiresAt: key.expiresAt,
            reason: 'Key has expired — analyst can no longer sign in.',
          })
          {
            const lang = state.settings?.lang || 'en'
            sendEmail(cfg, {
              to: user.email,
              subject: lang === 'de'
                ? 'Dein ZeroTrace-Lizenz-Key ist abgelaufen'
                : 'Your ZeroTrace license key has expired',
              message: lang === 'de'
                ? `Hallo ${user.username}, dein ZeroTrace-Lizenz-Key ${key.key} ist am ${fmtDate(key.expiresAt)} abgelaufen. Du kannst dich erst wieder anmelden, sobald ein Admin einen neuen Key ausstellt.`
                : `Hi ${user.username}, your ZeroTrace license key ${key.key} expired on ${fmtDate(key.expiresAt)}.`,
              message_html: expiryHtml({ username: user.username, key: key.key, expiresAt: key.expiresAt, expired: true }, lang),
            })
          }
        }
      }
    }
    tick()
    const t = setInterval(tick, 15 * 60 * 1000) // check every 15 minutes
    return () => clearInterval(t)
  }, [state.licenseKeys, state.users, state.integrations, dispatch])

  return null
}
