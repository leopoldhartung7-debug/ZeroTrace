/* Branded HTML email templates (ZeroTrace).
   These build a self-contained HTML body so the EmailJS template only
   needs `{{{message_html}}}` in its body and `{{subject}}` in its
   subject — every other element (logo, layout, colors) is baked in. */

const ACCENT = '#848eb0'
const ACCENT_DARK = '#636c8a'
const BG = '#0e0e11'
const PANEL = '#141417'
const BORDER = '#28282e'
const TEXT = '#e7e8ea'
const MUTED = '#8a8d93'

const CROSSHAIR = `
<svg width="36" height="36" viewBox="0 0 52 52" xmlns="http://www.w3.org/2000/svg" style="display:block">
  <circle cx="26" cy="26" r="22" stroke="${ACCENT_DARK}" stroke-width="2" opacity="0.5" fill="none"/>
  <circle cx="26" cy="26" r="5" stroke="${ACCENT}" stroke-width="2" fill="none"/>
  <circle cx="26" cy="26" r="1.8" fill="${ACCENT}"/>
  <line x1="26" y1="3"  x2="26" y2="18" stroke="${ACCENT}" stroke-width="2.4" stroke-linecap="round"/>
  <line x1="26" y1="34" x2="26" y2="49" stroke="${ACCENT}" stroke-width="2.4" stroke-linecap="round"/>
  <line x1="3"  y1="26" x2="18" y2="26" stroke="${ACCENT}" stroke-width="2.4" stroke-linecap="round"/>
  <line x1="34" y1="26" x2="49" y2="26" stroke="${ACCENT}" stroke-width="2.4" stroke-linecap="round"/>
</svg>`

function shell({ title, lead, inner, footer }) {
  return `
<div style="background:${BG};padding:24px 0;font-family:'Inter',Arial,Helvetica,sans-serif;color:${TEXT};-webkit-font-smoothing:antialiased">
  <table role="presentation" align="center" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:${PANEL};border:1px solid ${BORDER};border-radius:14px;overflow:hidden">
    <tr><td style="height:3px;background:linear-gradient(90deg,${ACCENT},${ACCENT_DARK})"></td></tr>
    <tr>
      <td style="padding:28px 32px 8px">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td width="44" valign="middle">${CROSSHAIR}</td>
            <td valign="middle" style="padding-left:10px">
              <div style="font-family:'Oxanium','Inter',Arial,sans-serif;font-weight:800;font-size:22px;letter-spacing:.02em;line-height:1">
                <span style="color:${ACCENT}">Zero</span><span style="color:#b0b0c0">Trace</span>
                <span style="display:inline-block;margin-left:10px;color:${MUTED};font-family:'Rajdhani','Inter',Arial,sans-serif;font-weight:600;font-size:11px;letter-spacing:.25em;vertical-align:middle">ANTICHEAT</span>
              </div>
            </td>
            <td valign="middle" align="right">
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${ACCENT};box-shadow:0 0 8px ${ACCENT}"></span>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr><td style="padding:0 32px"><div style="height:1px;background:${BORDER};margin-top:18px"></div></td></tr>
    <tr>
      <td style="padding:24px 32px 8px">
        <h1 style="margin:0;font-family:'Oxanium','Inter',Arial,sans-serif;font-weight:800;font-size:26px;line-height:1.2">${title}</h1>
        <p style="margin:10px 0 0;color:${MUTED};font-size:15px;line-height:1.55">${lead}</p>
      </td>
    </tr>
    <tr>
      <td style="padding:24px 32px 8px">${inner}</td>
    </tr>
    <tr><td style="padding:0 32px"><div style="height:1px;background:${BORDER};margin-top:18px"></div></td></tr>
    <tr>
      <td style="padding:18px 32px 28px;color:${MUTED};font-size:12px;line-height:1.55">
        ${footer}
      </td>
    </tr>
  </table>
</div>`
}

export function verifyHtml({ username, code }, lang = 'en') {
  const de = lang === 'de'
  return shell({
    title: de ? 'Nur noch ein Schritt' : 'Just one more step',
    lead: de
      ? `Schön, dass du dabei bist${username ? `, ${username}` : ''}. Bestätige kurz deine E-Mail-Adresse — dann ist dein ZeroTrace-Konto einsatzbereit.`
      : `Great to have you${username ? `, ${username}` : ''}. Confirm your email below and your ZeroTrace account is ready to go.`,
    inner: `
      <div style="background:${BG};border:1px solid ${BORDER};border-radius:12px;padding:22px;text-align:center">
        <p style="margin:0;color:${MUTED};font-size:13px">${de ? 'Dein Bestätigungscode' : 'Your verification code'}</p>
        <p style="margin:14px 0 0;font-family:'Courier New',monospace;font-size:34px;font-weight:700;letter-spacing:.5em;color:${ACCENT}">${code}</p>
        <p style="margin:14px 0 0;color:${MUTED};font-size:12px">${de ? 'Gültig für 15 Minuten — danach einfach einen neuen anfordern.' : 'Valid for 15 minutes — request a new one anytime.'}</p>
      </div>
      <p style="margin:18px 0 0;color:${MUTED};font-size:13px">
        ${de
          ? 'Du hast diese Registrierung nicht ausgelöst? Dann kannst du diese E-Mail einfach ignorieren — es passiert nichts weiter.'
          : "Didn't ask to sign up? You can ignore this email — no further action will be taken on your address."}
      </p>`,
    footer: de
      ? 'Automatische Nachricht von ZeroTrace · keine Antwort möglich.'
      : 'Automated message from ZeroTrace · replies are not monitored.',
  })
}

export function welcomeHtml({ username }, lang = 'en') {
  const de = lang === 'de'
  return shell({
    title: de ? `Willkommen an Bord, ${username}` : `Welcome aboard, ${username}`,
    lead: de
      ? 'Schön, dass du dich für ZeroTrace entschieden hast. Wir freuen uns, dass du dabei bist.'
      : "Thanks for picking ZeroTrace — we're excited to have you on the team.",
    inner: `
      <div style="background:${BG};border:1px solid ${BORDER};border-radius:12px;padding:22px">
        <p style="margin:0;color:${TEXT};font-size:15px;line-height:1.65">
          ${de
            ? 'Dein Konto ist eingerichtet und mit deinem Lizenz-Key verknüpft. Du kannst dich direkt im Dashboard anmelden und loslegen — Pins erstellen, Scan-Ergebnisse auswerten, verdächtige Discord-Server entlarven und alle Forensik-Werkzeuge nutzen.'
            : 'Your account is set up and linked to your license key. Sign in to the dashboard whenever you like and dive straight in — generate pins, work through scan results, expose suspicious Discord servers and use the full forensic toolset.'}
        </p>
        <p style="margin:14px 0 0;color:${TEXT};font-size:15px;line-height:1.65">
          ${de
            ? 'Ein paar Tipps zum Start: lege deinen ersten Pin an, hinterlege im Webhook deine Discord-Benachrichtigungen und wirf einen Blick in die Dokumentation, wenn du mehr aus ZeroTrace herausholen möchtest.'
            : 'A couple of quick tips: create your first pin, drop a Discord webhook in to get instant alerts, and skim the documentation when you want to push ZeroTrace further.'}
        </p>
      </div>
      <p style="margin:18px 0 0;color:${MUTED};font-size:13px">
        ${de
          ? 'Brauchst du Hilfe oder hast Feedback? Wir sind über die Support-Seite im Dashboard für dich da.'
          : 'Questions or feedback? We are one ticket away on the Support page inside the dashboard.'}
      </p>`,
    footer: de
      ? 'Automatische Nachricht von ZeroTrace · keine Antwort möglich.'
      : 'Automated message from ZeroTrace · replies are not monitored.',
  })
}

export function expiryHtml({ username, key, expiresAt, expired }, lang = 'en') {
  const de = lang === 'de'
  const when = expiresAt ? new Date(expiresAt).toLocaleString() : '—'
  const title = expired
    ? (de ? 'Dein Lizenz-Key ist abgelaufen' : 'Your license key has expired')
    : (de ? 'Dein Lizenz-Key läuft bald ab' : 'Heads up — your license key expires soon')
  const lead = expired
    ? (de
        ? `Hallo ${username}, dein ZeroTrace-Lizenz-Key ist soeben abgelaufen. Damit du wieder loslegen kannst, brauchst du nur einen neuen Key von deinem Admin.`
        : `Hi ${username}, your ZeroTrace license key has just expired. To get back in you only need a fresh key from your admin.`)
    : (de
        ? `Hallo ${username}, dein ZeroTrace-Lizenz-Key läuft in weniger als 24 Stunden ab — perfekt, um rechtzeitig einen neuen einzuholen.`
        : `Hi ${username}, your ZeroTrace license key expires in less than 24 hours — a good moment to line up a renewal.`)
  return shell({
    title,
    lead,
    inner: `
      <div style="background:${BG};border:1px solid ${BORDER};border-radius:12px;padding:22px">
        <p style="margin:0;color:${MUTED};font-size:13px">${de ? 'Key' : 'Key'}</p>
        <p style="margin:6px 0 12px;font-family:'Courier New',monospace;color:${ACCENT};font-size:14px;word-break:break-all">${key}</p>
        <p style="margin:0;color:${MUTED};font-size:13px">${de ? 'Ablauf' : 'Expires'}</p>
        <p style="margin:6px 0 0;color:${TEXT};font-size:14px">${when}</p>
      </div>
      <p style="margin:18px 0 0;color:${MUTED};font-size:13px">
        ${expired
          ? (de
              ? 'Sobald dein Admin einen neuen Key ausgestellt hat, registrierst du dich einfach erneut — deine bisherigen Daten kannst du wiederverwenden.'
              : 'As soon as your admin issues a new key you can register again — feel free to reuse your existing details.')
          : (de
              ? 'Bitte melde dich rechtzeitig bei deinem Admin, damit der Zugriff nahtlos weiterläuft.'
              : 'Please reach out to your admin in time so your access keeps running smoothly.')}
      </p>`,
    footer: de
      ? 'Automatische Nachricht von ZeroTrace · keine Antwort möglich.'
      : 'Automated message from ZeroTrace · replies are not monitored.',
  })
}
