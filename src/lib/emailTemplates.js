/* Branded HTML email templates (ZeroTrace).
   These build a self-contained HTML body so the EmailJS template only
   needs `{{{message_html}}}` in its body and `{{subject}}` in its
   subject — every other element (logo, layout, colors) is baked in. */

const ACCENT = '#38bdf8'
const ACCENT_DARK = '#0284c7'
const BG = '#1a1b1e'
const PANEL = '#26272b'
const BORDER = '#34363b'
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
    title: de ? 'E-Mail bestätigen' : 'Verify your email',
    lead: de
      ? `Hallo ${username}, bitte bestätige deine E-Mail-Adresse, um dein ZeroTrace-Konto zu aktivieren.`
      : `Hi ${username}, please verify your email address to activate your ZeroTrace account.`,
    inner: `
      <div style="background:${BG};border:1px solid ${BORDER};border-radius:12px;padding:22px;text-align:center">
        <p style="margin:0;color:${MUTED};font-size:13px">${de ? 'Dein Bestätigungscode:' : 'Your verification code:'}</p>
        <p style="margin:14px 0 0;font-family:'Courier New',monospace;font-size:34px;font-weight:700;letter-spacing:.5em;color:${ACCENT}">${code}</p>
        <p style="margin:14px 0 0;color:${MUTED};font-size:12px">${de ? 'Dieser Code läuft in 15 Minuten ab.' : 'This code expires in 15 minutes.'}</p>
      </div>
      <p style="margin:18px 0 0;color:${MUTED};font-size:13px">
        ${de
          ? 'Falls du diese Registrierung nicht angefordert hast, ignoriere bitte diese Nachricht.'
          : 'If you did not request this registration, you can safely ignore this email.'}
      </p>`,
    footer: de
      ? 'Dies ist eine automatisierte Nachricht von ZeroTrace. Bitte nicht antworten.'
      : "This is an automated message from ZeroTrace. Please do not reply.",
  })
}

export function welcomeHtml({ username }, lang = 'en') {
  const de = lang === 'de'
  return shell({
    title: de ? `Willkommen, ${username}!` : `Welcome, ${username}!`,
    lead: de
      ? 'Vielen Dank, dass du dich für ZeroTrace entschieden hast — wir freuen uns, dich an Bord zu haben.'
      : 'Thank you for choosing ZeroTrace — we are glad to have you on board.',
    inner: `
      <div style="background:${BG};border:1px solid ${BORDER};border-radius:12px;padding:22px">
        <p style="margin:0;color:${TEXT};font-size:15px;line-height:1.6">
          ${de
            ? 'Dein Konto wurde erfolgreich erstellt und mit deinem Lizenz-Key verknüpft. Du kannst dich jetzt im Dashboard anmelden und sofort loslegen — Pins erstellen, Scans auswerten und verdächtige Discord-Server erkennen.'
            : 'Your account has been created and bound to your license key. You can sign in to the dashboard right away — create pins, review scans and surface suspicious Discord servers.'}
        </p>
      </div>
      <p style="margin:18px 0 0;color:${MUTED};font-size:13px">
        ${de
          ? 'Bei Fragen oder Problemen melde dich gerne über die Support-Seite im Dashboard.'
          : 'Need a hand? Reach out via the Support page inside the dashboard.'}
      </p>`,
    footer: de
      ? 'Dies ist eine automatisierte Nachricht von ZeroTrace. Bitte nicht antworten.'
      : 'This is an automated message from ZeroTrace. Please do not reply.',
  })
}

export function expiryHtml({ username, key, expiresAt, expired }, lang = 'en') {
  const de = lang === 'de'
  const when = expiresAt ? new Date(expiresAt).toLocaleString() : '—'
  const title = expired
    ? (de ? 'Dein Lizenz-Key ist abgelaufen' : 'Your license key has expired')
    : (de ? 'Dein Lizenz-Key läuft bald ab' : 'Your license key expires soon')
  const lead = expired
    ? (de
        ? `Hallo ${username}, dein ZeroTrace-Lizenz-Key ist abgelaufen.`
        : `Hi ${username}, your ZeroTrace license key has expired.`)
    : (de
        ? `Hallo ${username}, dein ZeroTrace-Lizenz-Key läuft in weniger als 24 Stunden ab.`
        : `Hi ${username}, your ZeroTrace license key expires in less than 24 hours.`)
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
          ? (de ? 'Du kannst dich erst wieder anmelden, sobald ein Admin dir einen neuen Key ausstellt.' : 'You will not be able to sign in again until an admin issues a new key.')
          : (de ? 'Wende dich rechtzeitig an einen Admin, um deinen Key zu erneuern.' : 'Please contact an admin in time to renew your key.')}
      </p>`,
    footer: de
      ? 'Dies ist eine automatisierte Nachricht von ZeroTrace. Bitte nicht antworten.'
      : 'This is an automated message from ZeroTrace. Please do not reply.',
  })
}
