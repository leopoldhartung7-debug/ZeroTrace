import { createContext, useContext, useEffect, useMemo, useReducer } from 'react'
import { checkAchievements } from './lib/casino.js'

const KEY = 'zerotrace-state-v1'
const LEGACY_KEY = 'ocean-ac-state-v2' // migrated on first load so no data is lost

// Built-in EmailJS credentials so every browser can send registration,
// welcome and expiry emails out of the box (these values are public by design).
export const DEFAULT_EMAILJS = {
  serviceId: 'service_yz2xn2b',
  templateId: 'template_1hx0b4i',
  publicKey: 'mbwGjDoImDd81sUvA',
}

function genPin() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let s = ''
  for (let i = 0; i < 8; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export function generatePinCode() {
  return genPin()
}

export function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const block = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
  return `ZT-${block()}-${block()}-${block()}-${block()}`
}

// Stable lightweight fingerprint (FNV-1a 32-bit) used for HWID matching.
export function hwidOf(host, os, ip) {
  const s = `${(host || '').trim()}|${(os || '').trim()}|${(ip || '').trim()}`.toLowerCase()
  if (!s.replace(/\|/g, '')) return ''
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0
  }
  return ('00000000' + h.toString(16)).slice(-8).toUpperCase()
}

const GAMES = ['HYTALE', 'MINECRAFT', 'CS2', 'VALORANT', 'RUST', 'FIVEM']
const CHEATS = [
  'KillAura', 'Reach', 'Velocity', 'AutoClicker', 'Aimbot', 'Wallhack',
  'FlyHack', 'SpeedHack', 'TriggerBot', 'XRay', 'NoClip',
]

// ---- Per-pin scan report (only real scan data) ---------------------
function pad(n) {
  return String(n).padStart(2, '0')
}
function fmtTs(d) {
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  )
}

export function decodeScanToken(raw) {
  let s = (raw || '').trim().replace(/^["']|["']$/g, '').trim()
  let b64 = (/^(zerotrace1|ocean1)\./i.test(s) ? s.slice(s.indexOf('.') + 1) : s).replace(/\s+/g, '')
  if (!b64) throw new Error('Empty token')
  let json
  try { json = decodeURIComponent(escape(atob(b64))) }
  catch { if (b64.startsWith('{')) json = s; else throw new Error('Token is not valid Base64') }
  let obj
  try { obj = JSON.parse(json) } catch { throw new Error('Token does not contain valid JSON') }
  if (!obj || !obj.code) throw new Error('Token is missing the session code')
  return obj
}

export function deriveScanReport(pin) {
  if (!pin || pin.status !== 'Finished') return null

  const toolDets = Array.isArray(pin.scanDetections) ? pin.scanDetections : []
  const cheats = pin.cheats || []
  const time = pin.scannedAt ? fmtTs(new Date(pin.scannedAt)) : null

  // Where the finding lives — parsed from the scanner's evidence string
  // (e.g. "Process: x.exe", "Module: y.dll", "File: C:\\...", "Window: ...").
  const loc = (detail) => {
    const m = /^\s*(Process|Module|File|Window|Path|Service)\s*:\s*(.+)$/i.exec(detail || '')
    if (m) return m[2].trim()
    if (/^\s*Signature match/i.test(detail || '')) return 'In-memory (game process)'
    return (detail || '').trim() || 'Unknown'
  }

  // Detections actually returned by the scan.
  const detects = []
  toolDets
    .filter((d) => d.severity === 'Critical' || d.severity === 'High')
    .forEach((d) =>
      detects.push({ name: d.name, severity: d.severity, detail: d.detail, location: loc(d.detail), time }),
    )
  cheats.forEach((c) => {
    if (!detects.some((x) => x.name === c))
      detects.push({
        name: c,
        severity: 'High',
        detail: `Signature match: ${c}`,
        location: 'In-memory (game process)',
        time,
      })
  })

  const warnings = toolDets
    .filter((d) => d.severity === 'Medium')
    .map((d) => ({ name: d.name, detail: d.detail, location: loc(d.detail), time }))
  const suspicious = toolDets
    .filter((d) => d.severity === 'Low')
    .map((d) => ({ name: d.name, detail: d.detail, location: loc(d.detail), time }))

  // Findings that reference a real file path → also surfaced in the
  // location tables so you can see WHERE each detection lives.
  const isPath = (s) => /\\|\.exe|\.dll|\.sys|\.bat|\.jar|\.scr/i.test(s || '')
  const allFindings = [
    ...detects.map((d) => ({ ...d, sev: d.severity })),
    ...warnings.map((d) => ({ ...d, sev: 'Medium' })),
    ...suspicious.map((d) => ({ ...d, sev: 'Low' })),
  ].filter((d) => isPath(d.location))

  const executables = (Array.isArray(pin.processes) && pin.processes.length > 0)
    ? pin.processes.map((q) => ({
        path: q.path || '—',
        name: q.name || (q.path ? q.path.split(/[\\/]/).pop() : '<unknown>'),
        pid: q.pid ?? null,
        timestamp: '—',
        status: q.signed !== false,
        verified: !!q.signed,
        elevated: !!q.elevated,
      }))
    : allFindings.map((d) => ({
        path: d.location,
        name: d.location.split(/[\\/]/).pop() || d.location,
        pid: null,
        timestamp: d.time || '—',
        status: false,
        verified: false,
        elevated: false,
      }))
  const lastActivity = allFindings.map((d) => ({
    filename: d.location,
    runTime: d.time || '—',
    action: 'DETECTED',
    signed: false,
  }))
  const execution = allFindings.map((d) => ({ path: d.location }))

  // Discord servers the scanned account is in — classify reselling / cheat
  // servers by name keywords. Only the servers the scanner actually found.
  const CHEAT_KW = ['cheat', 'hack', 'spoofer', 'loader', 'menu', 'modmenu', 'mod menu',
    'aimbot', ' esp', 'unlock', 'crack', 'leak', 'bypass', 'inject', 'exploit', 'ggez', 'rage']
  const RESELL_KW = ['resell', 'reseller', 'reselling', 'shop', 'store', 'market',
    'sellix', '.gg/buy', 'sales', 'verkauf', 'sellauth', 'plug', 'services']
  const classify = (name) => {
    const n = (name || '').toLowerCase()
    if (CHEAT_KW.some((k) => n.includes(k))) return 'cheat'
    if (RESELL_KW.some((k) => n.includes(k))) return 'reselling'
    return 'clean'
  }
  const discordServers = (Array.isArray(pin.discordServers) ? pin.discordServers : [])
    .filter((g) => g && g.name)
    .map((g) => ({
      name: String(g.name).trim(),
      id: (g.id || '').trim() || '—',
      flag: classify(g.name),
    }))

  // USB / removable storage activity — only what the scanner reported.
  const usb = (Array.isArray(pin.usb) ? pin.usb : [])
    .filter((u) => u && (u.device || u.serial))
    .map((u) => ({
      device: (u.device || '').trim() || 'Unknown device',
      serial: (u.serial || '').trim() || '—',
      action: (u.action || '').trim() || 'Seen',
      time: (u.time || '').trim() || '—',
      contents: Array.isArray(u.contents) ? u.contents.filter(Boolean) : [],
    }))

  // Compilation dates — PE compile timestamp the scanner captured per process.
  const compilationDates = (Array.isArray(pin.processes) ? pin.processes : [])
    .filter((q) => q && q.compile)
    .map((q) => ({
      name: q.name || (q.path ? q.path.split(/[\\/]/).pop() : '<unknown>'),
      path: q.path || '—',
      date: q.compile,
    }))

  // MFT-style file metadata — derived from findings that point at a real file.
  // "Downloaded" reflects a Mark-of-the-Web / internet origin noted in the detail.
  const mft = allFindings.map((d) => ({
    path: d.location,
    lastAccess: d.time || '—',
    downloaded: /internet|mark-of-the-web|herkunft|motw/i.test(d.detail || '') ? 'Yes' : '—',
  }))

  // Module-specific finding lists for dedicated panels.
  const byModule = (names) => {
    const set = Array.isArray(names) ? names : [names]
    return toolDets.filter((d) => set.includes(d.module)).map((d) => ({
      name: d.name || '',
      detail: d.detail || '',
      location: d.location || '',
      severity: d.severity || 'Low',
      module: d.module || '',
    }))
  }
  const autostartFindings = byModule('Autostart')
  const networkFindings = byModule('Netzwerk')
  const browserFindings = byModule(['Browser-Verlauf', 'Browser-Erweiterungen'])
  const downloadFindings = byModule('Downloads')
  const tamperFindings = byModule('Scan-Manipulation')
  const overlayFindings = byModule('Overlay / ESP')
  const forensicFindings = byModule('Forensische Spuren')
  const remnantFindings = byModule('Tarnung & Reste')
  const registryFindings = byModule('Registry')
  const scheduledTaskFindings = byModule('Geplante Aufgaben')
  const powerShellFindings = byModule('PowerShell / Befehle')
  const wmiFindings = byModule('WMI-Persistenz')
  const hiddenDriverFindings = byModule('Versteckte Treiber')
  const rootCertFindings = byModule('Zertifikatsspeicher')
  const dmaFindings = byModule('DMA / Hardware (Hinweis)')
  const systemIntegrityFindings = byModule('System & Schutz')
  const executionHistoryFindings = byModule('Ausfuehrungsverlauf')
  const ntfsFindings = byModule('NTFS-Aenderungsjournal')
  const installedSoftwareFindings = byModule('Installierte Software')
  const prefetchFindings = byModule('Prefetch')
  const namedResourceFindings = byModule('Kernel-Objekte')
  const clipboardFindings = byModule('Zwischenablage')
  const appDataFindings = byModule('AppData')
  const suspiciousExeFindings = byModule('Unsignierte Prozesse')

  return {
    scannedAt: pin.scannedAt || null,
    ai: 'Not Supported',
    aiOpinion: 'AI analysis is not supported for this game.',
    pc: {
      system: pin.os || 'Unknown',
      host: pin.host || null,
      ip: pin.ip || '—',
      bootTime: pin.bootTime || '—',
      vpn: pin.vpn || '—',
      installDate: pin.installDate || '—',
      country: pin.country || '—',
      game: pin.game || '—',
      recycle: '—',
      hardware: pin.hardware || null,
    },
    counts: {
      detects: detects.length,
      integrity: 0,
      warnings: warnings.length,
      suspicious: suspicious.length,
    },
    detects,
    integrity: [],
    warnings,
    suspicious,
    adminApps: Array.isArray(pin.adminExecuted) ? pin.adminExecuted : [],
    boot: pin.boot || null,
    steamAccounts: Array.isArray(pin.steamAccounts) ? pin.steamAccounts : [],
    autostartFindings,
    networkFindings,
    browserFindings,
    downloadFindings,
    tamperFindings,
    overlayFindings,
    forensicFindings,
    remnantFindings,
    registryFindings,
    scheduledTaskFindings,
    powerShellFindings,
    wmiFindings,
    hiddenDriverFindings,
    rootCertFindings,
    dmaFindings,
    systemIntegrityFindings,
    executionHistoryFindings,
    ntfsFindings,
    installedSoftwareFindings,
    prefetchFindings,
    namedResourceFindings,
    clipboardFindings,
    appDataFindings,
    suspiciousExeFindings,
    accounts: [],
    discord: [],
    recording: Array.isArray(pin.recordingSoftware)
      ? pin.recordingSoftware.map((r) => (typeof r === 'string' ? { name: r, exe: r } : r))
      : [],
    mods: toolDets
      .filter((d) => d.module === 'GTA-MP')
      .map((d) => ({
        name: d.name || '',
        detail: d.detail || '',
        location: d.location || '',
        severity: d.severity || 'Low',
      })),
    suspiciousFiles: toolDets.filter((d) => d.sha256).map((d) => ({ sha256: d.sha256, name: d.name || d.fileName || '' })),
    lastActivity,
    executables,
    compilationDates,
    mft,
    execution,
    usb,
    discordServers,
    screenshot: null,
  }
}

const CHEAT_DB = [
  { name: 'Vape Lite', type: 'Paid Client', game: 'MINECRAFT', severity: 'High', signatures: ['vape.gg', 'VapeLauncher', 'jvm_args'], notes: 'Popular paid ghost client. Check JVM args & recent files.' },
  { name: 'Vape V4', type: 'Paid Client', game: 'MINECRAFT', severity: 'Critical', signatures: ['vape.gg', 'native_payload', 'rbx'], notes: 'Native ghost client, hard to detect via strings.' },
  { name: 'LiquidBounce', type: 'Free Client', game: 'MINECRAFT', severity: 'High', signatures: ['liquidbounce.net', 'net.ccbluex'], notes: 'Open-source. Look for ccbluex packages.' },
  { name: 'Wurst Client', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: ['wurstclient.net', 'net.wurstclient'], notes: 'Forge/Fabric mod based.' },
  { name: 'Impact', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: ['impactclient.net', 'com.github.impact'], notes: 'Modular client built on Forge.' },
  { name: 'Novoline', type: 'Paid Client', game: 'MINECRAFT', severity: 'High', signatures: ['novoline', 'cn.novoline'], notes: 'Obfuscated paid client.' },
  { name: 'Rise', type: 'Paid Client', game: 'MINECRAFT', severity: 'High', signatures: ['rise.ware', 'risenetwork'], notes: 'Premium client with strong ESP.' },
  { name: 'Sigma 5.0', type: 'Free Client', game: 'MINECRAFT', severity: 'High', signatures: ['sigmaclient', 'sdk.client'], notes: 'Older but still common.' },
  { name: 'Meteor Client', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: ['meteorclient.com', 'meteordevelopment'], notes: 'Fabric utility/cheat mod.' },
  { name: 'Baritone', type: 'Utility Mod', game: 'MINECRAFT', severity: 'Low', signatures: ['baritone', 'cabaletta'], notes: 'Pathfinding bot, often paired with clients.' },
  { name: 'AutoClicker (OP)', type: 'External Tool', game: 'MINECRAFT', severity: 'Medium', signatures: ['op autoclicker', 'orphamielautoclicker'], notes: 'Standalone autoclicker.' },
  { name: 'Polargen', type: 'Spoofer', game: 'MINECRAFT', severity: 'High', signatures: ['polargen', 'hwid_spoof'], notes: 'HWID spoofer used to evade bans.' },
  { name: 'Aimware', type: 'Paid Client', game: 'CS2', severity: 'Critical', signatures: ['aimware.net', 'aw_overlay'], notes: 'CS2 paid cheat with overlay.' },
  { name: 'Fecurity', type: 'Paid Client', game: 'CS2', severity: 'Critical', signatures: ['fecurity', 'fec_loader'], notes: 'External CS2 cheat.' },
  { name: 'Cheat Engine', type: 'External Tool', game: 'RUST', severity: 'Medium', signatures: ['cheatengine', 'CE_'], notes: 'Generic memory editor.' },
].map((c, i) => ({ id: 'cdb' + i, builtin: true, ...c }))

function seed() {
  const now = Date.now()
  const day = 86400000
  const scans = []
  for (let i = 13; i >= 0; i--) {
    scans.push({
      id: 'seed-scan-' + i,
      date: new Date(now - i * day).toISOString().slice(0, 10),
      game: GAMES[i % 4],
      result: i % 3 === 0 ? 'Cheating' : i % 3 === 1 ? 'Clean' : 'Suspicious',
      detections: i % 3 === 0 ? Math.floor(Math.random() * 6) + 1 : 0,
    })
  }
  return {
    settings: {
      theme: 'dark', lang: 'en', defaultGame: 'HYTALE',
      riskWeights: { detect: 8, warn: 2, susp: 5 },
      gameProfiles: {},
      weeklyReport: { enabled: false, lastSentAt: 0 },
      approvalRequired: false,
      digestFrequency: 'off',
      lastDigestAt: 0,
      casinoSound: true,
      scannerUrl: '',
      scannerApiUrl: '',
    },
    notifications: [
      { id: 'n1', title: 'Scan finished', body: 'Pin F1T5F8C0 returned: Cheating', time: now - 3600000, read: false },
      { id: 'n2', title: 'Welcome to ZeroTrace', body: 'Your anti-cheat dashboard is ready.', time: now - 7200000, read: false },
    ],
    events: [
      { id: 'e1', kind: 'scan', title: 'Scan finished', detail: 'F1T5F8C0 — Cheating', time: now - 3600000 },
      { id: 'e2', kind: 'pin', title: 'Pin created', detail: 'F1T5F8C0 — Test', time: now - 2 * day },
    ],
    pins: [
      {
        id: 'p1', pin: 'F1T5F8C0', name: 'Test', game: 'HYTALE',
        status: 'Finished', used: true, result: 'Cheating', visibility: 'Private',
        detections: 11, cheats: ['KillAura', 'Reach', 'Velocity'], createdAt: now - 2 * day,
      },
    ],
    detectionFiles: [],
    yaraRules: [],
    suspiciousFiles: [],
    scans,
    customCheats: CHEAT_DB,
    tickets: [],
    toolStyle: defaultToolStyle(),
    auth: false,
    role: null,
    licenseKeys: [],
    users: [],
    deletedAccounts: [],
    pinTemplates: [],
    lastWeeklyReportAt: 0,
    savedStrings: [],
    connections: [],
    integrations: {
      discordWebhook: '',
      virusTotalKey: '',
      emailJsServiceId: DEFAULT_EMAILJS.serviceId,
      emailJsTemplateId: DEFAULT_EMAILJS.templateId,
      emailJsPublicKey: DEFAULT_EMAILJS.publicKey,
      webhookCustom: { username: 'ZeroTrace Anti-Cheat', color: '#38bdf8', footer: 'ZeroTrace Anti-Cheat' },
      discordWebhooks: [],
      slackWebhook: '',
      slackWebhooks: [],
    },
    security: { twoFA: false, passkeys: [], lockout: { maxAttempts: 5, lockMinutes: 15 }, attempts: {} },
    session: null,
    otherSessions: [],
    announcement: { enabled: false, text: '', tone: 'info', dismissable: true, updatedAt: 0 },
    blacklists: { hwids: [], discordIds: [], emailDomains: [] },
    adminAuditLog: [],
    webhookHealth: {},
    maintenance: { enabled: false, message: '', updatedAt: 0 },
    savedFilters: [],
    watchlist: [],
    recentlyViewed: [],
    wallets: {},
    shopPurchases: [],
    discountCodes: [],
    jackpot: 5000,
    casino: { disabledGames: [], houseProfit: 0 },
    onboardingDone: false,
  }
}

export function defaultToolStyle() {
  return {
    useDefaultLogo: true,
    logoUrl: '',
    gameBackground: true,
    version: 'v2.6',
    colors: {
      text: '#e8eaf0',
      mutedText: '#8b93a7',
      background: '#0d1326',
      mutedBackground: '#161d33',
      titlebar: '#070b16',
      accent: '#38bdf8',
    },
    text: {
      pin: 'Enter a pin below:',
      scanning: 'Scanning processes...',
      heuristic: 'Running heuristic analysis...',
      finished: 'Scan complete — generating report',
    },
  }
}

function load() {
  try {
    // Migrate data saved under the old "ocean" key to the new ZeroTrace key.
    let raw = localStorage.getItem(KEY)
    if (!raw) {
      const legacy = localStorage.getItem(LEGACY_KEY)
      if (legacy) {
        localStorage.setItem(KEY, legacy)
        raw = legacy
      }
    }
    const base = seed()
    if (!raw) return base
    const parsed = JSON.parse(raw)
    const merged = { ...base, ...parsed }
    // Deep-merge integrations and backfill the built-in EmailJS defaults so
    // existing browsers (which saved empty fields) also get working email.
    merged.integrations = { ...base.integrations, ...(parsed.integrations || {}) }
    if (!merged.integrations.emailJsServiceId) merged.integrations.emailJsServiceId = DEFAULT_EMAILJS.serviceId
    if (!merged.integrations.emailJsTemplateId) merged.integrations.emailJsTemplateId = DEFAULT_EMAILJS.templateId
    if (!merged.integrations.emailJsPublicKey) merged.integrations.emailJsPublicKey = DEFAULT_EMAILJS.publicKey
    return merged
  } catch {
    return seed()
  }
}

function ev(state, kind, title, detail, ownerId = null) {
  return [
    { id: 'e' + Date.now() + Math.random().toString(16).slice(2, 6), kind, title, detail, time: Date.now(), ownerId },
    ...state.events,
  ].slice(0, 300)
}

function note(state, title, body, ownerId = null) {
  return [
    { id: 'n' + Date.now() + Math.random().toString(16).slice(2, 6), title, body, time: Date.now(), read: false, ownerId },
    ...state.notifications,
  ].slice(0, 100)
}

function reducer(state, action) {
  switch (action.type) {
    case 'set-setting':
      return { ...state, settings: { ...state.settings, [action.key]: action.value } }

    case 'login': {
      const role = action.role === 'admin' ? 'admin' : 'analyst'
      return {
        ...state,
        auth: true,
        role,
        session: {
          id: 'sess_' + Math.random().toString(16).slice(2, 14),
          role,
          userId: action.userId || null,
          createdAt: Date.now(),
        },
      }
    }

    case 'logout':
      return { ...state, auth: false, role: null, session: null }

    case 'register-user': {
      const u = action.user
      return {
        ...state,
        users: [...(state.users || []), u],
        licenseKeys: (state.licenseKeys || []).map((k) =>
          k.key === u.key ? { ...k, usedBy: u.id } : k,
        ),
        events: ev(state, 'pin', 'Analyst registered', `${u.username} · ${u.email}`, 'admin'),
        notifications: note(state, 'Analyst registered', `${u.username} bound to key ${u.key}`, 'admin'),
      }
    }

    case 'add-notification':
      return {
        ...state,
        notifications: note(state, action.title || '', action.body || '', action.ownerId ?? null),
      }

    case 'mark-key-reminder-sent':
      return {
        ...state,
        licenseKeys: (state.licenseKeys || []).map((k) =>
          k.id === action.id ? { ...k, reminderSent: true } : k,
        ),
      }

    case 'mark-key-expired-notified':
      return {
        ...state,
        licenseKeys: (state.licenseKeys || []).map((k) =>
          k.id === action.id ? { ...k, expiredNotified: true } : k,
        ),
      }

    case 'create-key': {
      const days = Number(action.durationDays) || 0
      const key = {
        id: 'lk_' + Date.now(),
        key: action.key,
        label: (action.label || '').trim() || 'Untitled key',
        plan: action.plan || 'Personal',
        durationDays: days,
        createdAt: Date.now(),
        expiresAt: days > 0 ? Date.now() + days * 86400000 : null,
        status: 'Active',
      }
      return {
        ...state,
        licenseKeys: [key, ...(state.licenseKeys || [])],
        events: ev(state, 'pin', 'License key created', `${key.label} — ${key.plan}`, 'admin'),
      }
    }

    case 'revoke-key':
      return {
        ...state,
        licenseKeys: (state.licenseKeys || []).map((k) =>
          k.id === action.id ? { ...k, status: k.status === 'Active' ? 'Revoked' : 'Active' } : k,
        ),
      }

    case 'delete-key': {
      const key = (state.licenseKeys || []).find((k) => k.id === action.id)
      const user = key
        ? (state.users || []).find((u) => u.id === key.usedBy || u.key === key.key)
        : null
      const uid = user?.id || null
      const tombstone = user
        ? [
            { username: user.username, email: user.email, key: user.key, deletedAt: Date.now() },
            ...(state.deletedAccounts || []),
          ].slice(0, 100)
        : state.deletedAccounts || []
      return {
        ...state,
        licenseKeys: (state.licenseKeys || []).filter((k) => k.id !== action.id),
        users: uid
          ? (state.users || []).filter((u) => u.id !== uid)
          : (state.users || []),
        pins: uid ? state.pins.filter((p) => p.ownerId !== uid) : state.pins,
        events: ev(
          state.events && uid
            ? { ...state, events: state.events.filter((e) => e.ownerId !== uid) }
            : state,
          'pin',
          'License key deleted',
          user ? `${action.key || ''} · ${user.username}` : action.key || '',
          'admin',
        ),
        notifications: uid
          ? state.notifications.filter((n) => n.ownerId !== uid)
          : state.notifications,
        savedStrings: uid
          ? (state.savedStrings || []).filter((s) => {
              const e = typeof s === 'string' ? { value: s, ownerId: null } : s
              return e.ownerId !== uid
            })
          : state.savedStrings,
        detectionFiles: uid
          ? (state.detectionFiles || []).filter((f) => f.ownerId !== uid)
          : state.detectionFiles,
        suspiciousFiles: uid
          ? (state.suspiciousFiles || []).filter((f) => f.ownerId !== uid)
          : state.suspiciousFiles,
        deletedAccounts: tombstone,
      }
    }

    case 'delete-user': {
      const user = (state.users || []).find((u) => u.id === action.id)
      if (!user) return state
      const tomb = [
        { username: user.username, email: user.email, key: user.key, deletedAt: Date.now() },
        ...(state.deletedAccounts || []),
      ].slice(0, 100)
      return {
        ...state,
        users: state.users.filter((u) => u.id !== user.id),
        licenseKeys: (state.licenseKeys || []).map((k) =>
          k.key === user.key ? { ...k, usedBy: null } : k,
        ),
        pins: state.pins.filter((p) => p.ownerId !== user.id),
        events: ev(
          { ...state, events: state.events.filter((e) => e.ownerId !== user.id) },
          'pin',
          'Login deleted',
          `${user.username} · ${user.email}`,
          'admin',
        ),
        notifications: state.notifications.filter((n) => n.ownerId !== user.id),
        savedStrings: (state.savedStrings || []).filter((s) => {
          const e = typeof s === 'string' ? { value: s, ownerId: null } : s
          return e.ownerId !== user.id
        }),
        detectionFiles: (state.detectionFiles || []).filter((f) => f.ownerId !== user.id),
        suspiciousFiles: (state.suspiciousFiles || []).filter((f) => f.ownerId !== user.id),
        deletedAccounts: tomb,
      }
    }

    case 'save-strings': {
      const owner = action.ownerId ?? null
      // Normalize existing entries (legacy plain strings → {value, ownerId:null}).
      const existing = (state.savedStrings || []).map((s) =>
        typeof s === 'string' ? { value: s, ownerId: null } : s,
      )
      const have = new Set(existing.filter((e) => e.ownerId === owner).map((e) => e.value))
      const additions = []
      for (const v of action.strings || []) {
        if (v && v.length >= 3 && !have.has(v)) {
          have.add(v)
          additions.push({ value: v, ownerId: owner })
        }
      }
      return { ...state, savedStrings: [...additions, ...existing].slice(0, 5000) }
    }

    case 'remove-saved-string': {
      const owner = action.ownerId ?? null
      return {
        ...state,
        savedStrings: (state.savedStrings || []).filter((s) => {
          const e = typeof s === 'string' ? { value: s, ownerId: null } : s
          return !(e.value === action.value && e.ownerId === owner)
        }),
      }
    }

    case 'clear-saved-strings': {
      const owner = action.ownerId ?? null
      return {
        ...state,
        savedStrings: (state.savedStrings || []).filter((s) => {
          const e = typeof s === 'string' ? { value: s, ownerId: null } : s
          return e.ownerId !== owner
        }),
      }
    }

    case 'connect-account':
      return {
        ...state,
        connections: [
          { id: action.account.id, name: action.account.name, connectedAt: Date.now() },
          ...state.connections.filter((c) => c.id !== action.account.id),
        ],
      }

    case 'disconnect-account':
      return { ...state, connections: state.connections.filter((c) => c.id !== action.id) }

    case 'set-integration':
      return {
        ...state,
        integrations: { ...state.integrations, [action.key]: action.value },
      }

    case 'set-2fa':
      return { ...state, security: { ...state.security, twoFA: action.value } }

    case 'add-passkey':
      return {
        ...state,
        security: {
          ...state.security,
          passkeys: [
            { id: 'pk' + Date.now(), name: action.name || 'Passkey', createdAt: Date.now() },
            ...state.security.passkeys,
          ],
        },
      }

    case 'remove-passkey':
      return {
        ...state,
        security: {
          ...state.security,
          passkeys: state.security.passkeys.filter((p) => p.id !== action.id),
        },
      }

    case 'revoke-session':
      return { ...state, otherSessions: state.otherSessions.filter((s) => s.id !== action.id) }

    case 'revoke-all-sessions':
      return { ...state, otherSessions: [] }

    case 'set-tool-style':
      return { ...state, toolStyle: { ...state.toolStyle, ...action.patch } }

    case 'save-tool-style':
      return { ...state, toolStyle: { ...defaultToolStyle(), ...action.style } }

    case 'import-tool-style':
      return { ...state, toolStyle: { ...defaultToolStyle(), ...action.style } }

    case 'reset-tool-style':
      return { ...state, toolStyle: defaultToolStyle() }

    case 'add-pin': {
      const pin = {
        id: 'p' + Date.now(), pin: action.code || genPin(), name: action.name, game: action.game,
        status: 'Pending', used: false, result: null, visibility: action.visibility,
        discordId: action.discordId || '',
        ownerId: action.ownerId || null,
        detections: 0, cheats: [], createdAt: Date.now(),
      }
      return {
        ...state,
        pins: [pin, ...state.pins],
        events: ev(state, 'pin', 'Pin created', `${pin.pin} — ${pin.name}`, pin.ownerId),
        notifications: note(state, 'Pin created', `${pin.pin} — ${pin.name}`, pin.ownerId),
      }
    }

    case 'run-scan': {
      const roll = Math.random()
      const result = roll < 0.5 ? 'Cheating' : roll < 0.75 ? 'Suspicious' : 'Clean'
      const detections = result === 'Clean' ? 0 : Math.floor(Math.random() * 14) + 1
      const cheatCount = result === 'Clean' ? 0 : Math.floor(Math.random() * 4) + 1
      const cheats = []
      while (cheats.length < cheatCount) {
        const c = CHEATS[Math.floor(Math.random() * CHEATS.length)]
        if (!cheats.includes(c)) cheats.push(c)
      }
      const target = state.pins.find((p) => p.id === action.id)
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id ? { ...p, status: 'Finished', used: true, result, detections, cheats } : p,
        ),
        scans: [
          { id: 's' + Date.now(), date: new Date().toISOString().slice(0, 10), game: target?.game || 'HYTALE', result, detections },
          ...state.scans,
        ],
        events: ev(state, 'scan', 'Scan finished', `${target?.pin} — ${result}`, target?.ownerId ?? null),
        notifications: note(state, 'Scan finished', `${target?.pin}: ${result}`, target?.ownerId ?? null),
      }
    }

    case 'delete-pin': {
      const target = state.pins.find((p) => p.id === action.id)
      // Once a scan has been performed with a pin it is locked.
      if (target && (target.used || target.status === 'Finished' || target.result)) return state
      return {
        ...state,
        pins: state.pins.filter((p) => p.id !== action.id),
        events: ev(state, 'pin', 'Pin deleted', action.pin || '', target?.ownerId ?? null),
      }
    }

    case 'admin-delete-pin':
      // Admin override: removes a pin even if a scan was already performed.
      return {
        ...state,
        pins: state.pins.filter((p) => p.id !== action.id),
        events: ev(state, 'pin', 'Pin deleted (admin)', action.pin || '', 'admin'),
      }

    case 'update-pin': {
      const target = state.pins.find((p) => p.id === action.id)
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, ...action.patch } : p)),
        events: ev(state, 'pin', 'Pin updated', action.label || '', target?.ownerId ?? null),
      }
    }

    case 'set-visibility':
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, visibility: action.visibility } : p)),
      }

    case 'toggle-visibility':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id ? { ...p, visibility: p.visibility === 'Private' ? 'Public' : 'Private' } : p,
        ),
      }

    case 'add-detection-file':
      return {
        ...state,
        detectionFiles: [
          { id: 'd' + Date.now(), clientName: action.clientName, fileName: action.fileName, size: action.size, mode: action.mode, signatures: action.signatures, addedAt: Date.now(), ownerId: action.ownerId ?? null },
          ...state.detectionFiles,
        ],
        events: ev(state, 'file', 'Detection file added', `${action.clientName} (${action.fileName})`, action.ownerId ?? null),
      }

    case 'delete-detection-file':
      return { ...state, detectionFiles: state.detectionFiles.filter((d) => d.id !== action.id) }

    case 'save-yara': {
      const existing = state.yaraRules.find((r) => r.name === action.name)
      const rule = { id: 'y' + Date.now(), name: action.name, source: action.source, createdAt: Date.now() }
      return {
        ...state,
        yaraRules: existing
          ? state.yaraRules.map((r) => (r.name === action.name ? { ...r, source: action.source } : r))
          : [rule, ...state.yaraRules],
        events: ev(state, 'rule', 'YARA rule saved', action.name, state.session?.userId || (state.role === 'admin' ? 'admin' : null)),
      }
    }

    case 'delete-yara':
      return { ...state, yaraRules: state.yaraRules.filter((r) => r.id !== action.id) }

    case 'add-suspicious':
      return {
        ...state,
        suspiciousFiles: [
          { id: 'sf' + Date.now(), fileName: action.fileName, size: action.size, matches: action.matches, scannedAt: Date.now(), ownerId: action.ownerId ?? null },
          ...state.suspiciousFiles,
        ],
        events: ev(state, 'scan', 'File scanned', `${action.fileName} — ${action.matches.length} match(es)`, action.ownerId ?? null),
      }

    case 'import-scan': {
      const raw = action.payload
      let p
      // Detect scanner's native ScanReport JSON (PascalCase with Findings/System/Inventory).
      if (raw && Array.isArray(raw.Findings) && raw.System && raw.Inventory) {
        const sys = raw.System || {}
        const inv = raw.Inventory || {}
        const findings = raw.Findings
        const mapSev = (r) => {
          const s = String(r || '').toLowerCase()
          if (s === 'critical') return 'Critical'
          if (s === 'high') return 'High'
          if (s === 'medium') return 'Medium'
          return 'Low'
        }
        const detections = findings.map((f) => ({
          name: f.Title || '',
          severity: mapSev(f.Risk),
          detail: [f.Reason, f.Detail].filter(Boolean).join(' — '),
          location: f.Location || '',
          module: f.Module || '',
          sha256: f.Sha256 || null,
          signed: f.Signed ?? null,
        }))
        const hasCrit = findings.some((f) => String(f.Risk || '').toLowerCase() === 'critical')
        const hasHigh = findings.some((f) => String(f.Risk || '').toLowerCase() === 'high')
        const hasMed  = findings.some((f) => String(f.Risk || '').toLowerCase() === 'medium')
        const verdict = hasCrit || hasHigh ? 'Cheating' : hasMed ? 'Suspicious' : 'Clean'
        const parseHw = (s) => {
          if (!s || s === 'Not available') return null
          const o = {}
          String(s).split(/\s*[·•|]\s*/).forEach((part) => {
            const m = /^(CPU|GPU|RAM):\s*(.+)$/i.exec(part.trim())
            if (m) o[m[1].toLowerCase()] = m[2].trim()
          })
          return (o.cpu || o.gpu || o.ram) ? o : null
        }
        p = {
          code: raw.Pin || '',
          verdict,
          detections,
          game: sys.Game || 'FIVEM',
          host: raw.MachineName || '',
          os: sys.System || raw.OsVersion || '',
          ip: Array.isArray(sys.IpAddresses) && sys.IpAddresses.length > 0 ? sys.IpAddresses[0] : '',
          bootTime: sys.BootTime || '',
          installDate: sys.InstallDate || '',
          hardware: parseHw(sys.HardwareStats),
          vpn: sys.Vpn || '',
          country: sys.Country || '',
          scannerHwid: sys.Hwid || null,
          vm: inv.Vm ? {
            detected: !!(inv.Vm.Detected ?? false),
            vendor: Array.isArray(inv.Vm.Indicators) && inv.Vm.Indicators.length > 0
              ? inv.Vm.Indicators[0]
              : (inv.Vm.Detected ? 'Unknown' : null),
            signals: Array.isArray(inv.Vm.Indicators) ? inv.Vm.Indicators : [],
          } : null,
          processes: (Array.isArray(inv.Processes) ? inv.Processes : []).map((q) => ({
            pid: q.Pid ?? q.pid,
            parentPid: q.ParentPid ?? q.parentPid ?? null,
            name: q.Name || q.name || '',
            path: q.Path || q.path || '',
            signed: q.Signed ?? q.signed ?? null,
            elevated: !!(q.Elevated ?? q.elevated ?? false),
            compile: q.CompileDate || q.compile || null,
          })),
          boot: (sys.BiosVendor || sys.BoardManufacturer || sys.BiosVersion) ? {
            biosVendor: sys.BiosVendor || '—',
            biosVersion: sys.BiosVersion || '—',
            boardManufacturer: sys.BoardManufacturer || '—',
            boardProduct: sys.BoardProduct || '—',
            boardVersion: sys.BoardVersion || '—',
            chain: [],
          } : null,
          drivers: (Array.isArray(inv.Drivers) ? inv.Drivers : []).map((d) => ({
            name: d.Name || d.name || '',
            path: d.Path || d.path || null,
            publisher: null,
            signed: d.Signed ?? d.signed ?? null,
            running: !!(d.Running ?? d.running ?? false),
            cheatKnown: false,
            note: null,
          })),
          usb: (Array.isArray(inv.UsbDevices) ? inv.UsbDevices : []).map((u) => ({
            device: u.Name || u.name || 'Unknown device',
            serial: u.Serial || u.serial || '—',
            action: 'Seen',
            time: '—',
            contents: [],
          })),
          adminExecuted: (Array.isArray(inv.AdminExecuted) ? inv.AdminExecuted : []).map((a) => ({
            path: a.Path || a.path || '',
            executedAt: '—',
            signed: a.Signed ?? a.signed ?? null,
            verdict: 'ELEVATED',
          })),
          recordingSoftware: (Array.isArray(inv.RecordingSoftware) ? inv.RecordingSoftware : []).map((r) =>
            typeof r === 'string' ? { name: r, exe: r } : r,
          ),
          steamAccounts: (Array.isArray(inv.SteamAccounts) ? inv.SteamAccounts : []).map((a) => ({
            steamId: a.SteamId || a.steamId || '',
            accountName: a.AccountName || a.accountName || '',
            personaName: a.PersonaName || a.personaName || '',
            mostRecent: !!(a.MostRecent ?? a.mostRecent ?? false),
          })),
          discordServers: [],
          scannedAt: raw.FinishedUtc ? new Date(raw.FinishedUtc).getTime() : Date.now(),
        }
      } else {
        p = raw
      }
      const result =
        p.verdict === 'Cheating' ? 'Cheating' : p.verdict === 'Suspicious' ? 'Suspicious' : 'Clean'
      const dets = Array.isArray(p.detections) ? p.detections : []
      const cheats = [...new Set(dets.map((d) => d.name))]
      const game = p.game || 'FIVEM'
      const idx = state.pins.findIndex((x) => x.pin === p.code)
      const prev = idx >= 0 ? state.pins[idx] : null
      const merged = {
        pin: p.code,
        name: prev ? prev.name : p.host || 'Imported scan',
        game,
        status: 'Finished',
        used: true,
        result,
        visibility: prev ? prev.visibility : 'Private',
        detections: dets.length,
        cheats,
        scanDetections: dets,
        usb: Array.isArray(p.usb) ? p.usb : [],
        discordServers: Array.isArray(p.discordServers) ? p.discordServers : [],
        drivers: Array.isArray(p.drivers) ? p.drivers : [],
        vm: p.vm || null,
        processes: Array.isArray(p.processes) ? p.processes : [],
        host: p.host || '',
        os: p.os || '',
        ip: p.ip || '',
        bootTime: p.bootTime || '',
        installDate: p.installDate || '',
        hardware: p.hardware || null,
        adminExecuted: Array.isArray(p.adminExecuted) ? p.adminExecuted : [],
        recordingSoftware: Array.isArray(p.recordingSoftware) ? p.recordingSoftware : [],
        vpn: p.vpn || '',
        country: p.country || '',
        boot: p.boot || null,
        steamAccounts: Array.isArray(p.steamAccounts) ? p.steamAccounts : [],
        hwid: p.scannerHwid || hwidOf(p.host, p.os, p.ip),
        createdAt: prev ? prev.createdAt : Date.now(),
        scannedAt: p.scannedAt || Date.now(),
      }
      const pins =
        idx >= 0
          ? state.pins.map((x, i) => (i === idx ? { ...x, ...merged } : x))
          : [{ id: 'p' + Date.now(), ...merged }, ...state.pins]
      // Alt-account detection: same hwid seen under a different Discord ID.
      const altMatch = merged.hwid
        ? state.pins.find(
            (x) => x.hwid === merged.hwid && x.discordId && prev && x.discordId !== prev.discordId,
          )
        : null
      const extraNotes = altMatch
        ? note(
            state,
            'Possible alt account detected',
            `HWID ${merged.hwid} previously seen under ${altMatch.discordId} (pin ${altMatch.pin}).`,
            'admin',
          )
        : null
      return {
        ...state,
        pins,
        scans: [
          { id: 's' + Date.now(), date: new Date().toISOString().slice(0, 10), game, result, detections: dets.length },
          ...state.scans,
        ],
        events: ev(state, 'scan', 'Scan result imported', `${p.code} — ${result} (${dets.length} detections)`, prev?.ownerId ?? null),
        notifications: extraNotes
          ? note({ ...state, notifications: extraNotes }, 'Scan result imported', `${p.code}: ${result}`, prev?.ownerId ?? null)
          : note(state, 'Scan result imported', `${p.code}: ${result}`, prev?.ownerId ?? null),
      }
    }

    case 'set-pin-note':
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, note: action.note } : p)),
      }

    case 'add-pin-comment': {
      const mentions = Array.from(String(action.text || '').matchAll(/@([\w.\-]+)/g)).map((m) => m[1].toLowerCase())
      const mentionedUsers = (state.users || []).filter((u) => mentions.includes((u.username || '').toLowerCase()))
      let notifs = state.notifications
      mentionedUsers.forEach((u) => {
        notifs = note(
          { ...state, notifications: notifs },
          'You were mentioned',
          `${action.author} mentioned you in pin ${action.id}: ${String(action.text).slice(0, 80)}`,
          u.id,
        )
      })
      return {
        ...state,
        notifications: notifs,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? {
                ...p,
                comments: [
                  ...(p.comments || []),
                  { id: 'c' + Date.now(), author: action.author, text: action.text, time: Date.now(), mentions: mentionedUsers.map((u) => u.id) },
                ],
              }
            : p,
        ),
      }
    }

    case 'delete-pin-comment':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? { ...p, comments: (p.comments || []).filter((c) => c.id !== action.commentId) }
            : p,
        ),
      }

    case 'add-pin-template':
      return {
        ...state,
        pinTemplates: [
          { id: 't' + Date.now(), ...action.template },
          ...(state.pinTemplates || []),
        ],
      }

    case 'delete-pin-template':
      return {
        ...state,
        pinTemplates: (state.pinTemplates || []).filter((t) => t.id !== action.id),
      }

    case 'bulk-add-cheats': {
      const items = (action.cheats || []).map((c, i) => ({
        id: 'cb' + Date.now() + '_' + i,
        builtin: false,
        ...c,
      }))
      return {
        ...state,
        customCheats: [...items, ...state.customCheats],
        events: ev(state, 'db', 'Cheats bulk-imported', `${items.length} entries`, 'admin'),
      }
    }

    case 'set-last-weekly-report':
      return { ...state, lastWeeklyReportAt: action.time || Date.now() }

    case 'set-webhook-custom':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          webhookCustom: { ...(state.integrations.webhookCustom || {}), ...action.value },
        },
      }

    case 'set-totp-secret':
      return {
        ...state,
        security: { ...state.security, twoFA: !!action.secret, totpSecret: action.secret || '' },
      }

    case 'set-pin-status':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? { ...p, caseStatus: action.status, caseResolution: action.resolution || p.caseResolution }
            : p,
        ),
      }

    case 'set-pin-steamid':
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, steamId: action.steamId } : p)),
      }

    case 'set-pin-geo':
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, geo: action.geo } : p)),
      }

    case 'set-risk-weights':
      return {
        ...state,
        settings: { ...state.settings, riskWeights: { ...action.weights } },
      }

    case 'set-game-profiles':
      return {
        ...state,
        settings: { ...state.settings, gameProfiles: { ...(state.settings.gameProfiles || {}), ...action.profiles } },
      }

    case 'set-weekly-report':
      return {
        ...state,
        settings: { ...state.settings, weeklyReport: { ...(state.settings.weeklyReport || {}), ...action.value } },
      }

    case 'set-login-lockout':
      return {
        ...state,
        security: { ...state.security, lockout: { ...(state.security.lockout || {}), ...action.value } },
      }

    case 'record-login-attempt': {
      const map = { ...((state.security && state.security.attempts) || {}) }
      const cur = map[action.id] || { count: 0, first: 0, lockedUntil: 0 }
      const now = Date.now()
      if (cur.first && now - cur.first > 10 * 60000) {
        cur.count = 0
        cur.first = 0
      }
      if (action.kind === 'success') {
        delete map[action.id]
      } else {
        cur.count += 1
        if (!cur.first) cur.first = now
        const max = state.security?.lockout?.maxAttempts ?? 5
        const dur = state.security?.lockout?.lockMinutes ?? 15
        if (cur.count >= max) cur.lockedUntil = now + dur * 60000
        map[action.id] = cur
      }
      return { ...state, security: { ...state.security, attempts: map } }
    }

    case 'add-discord-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          discordWebhooks: [
            ...(state.integrations.discordWebhooks || []),
            { id: 'wh' + Date.now(), label: action.label || 'Webhook', url: action.url, enabled: true },
          ],
        },
      }

    case 'update-discord-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          discordWebhooks: (state.integrations.discordWebhooks || []).map((w) =>
            w.id === action.id ? { ...w, ...action.patch } : w,
          ),
        },
      }

    case 'delete-discord-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          discordWebhooks: (state.integrations.discordWebhooks || []).filter((w) => w.id !== action.id),
        },
      }

    case 'mark-webhook-sent':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.pin === action.code ? { ...p, webhookNotified: true } : p,
        ),
      }

    case 'add-cheat':
      return {
        ...state,
        customCheats: [{ id: 'c' + Date.now(), builtin: false, ...action.cheat }, ...state.customCheats],
        events: ev(state, 'db', 'Cheat added', action.cheat.name, 'admin'),
      }

    case 'delete-cheat':
      return { ...state, customCheats: state.customCheats.filter((c) => c.id !== action.id) }

    case 'add-ticket':
      return {
        ...state,
        tickets: [{ id: 'T-' + Date.now().toString().slice(-6), ...action.ticket, status: 'Open', createdAt: Date.now() }, ...state.tickets],
        events: ev(state, 'support', 'Ticket opened', action.ticket.subject, state.session?.userId || (state.role === 'admin' ? 'admin' : null)),
        notifications: note(state, 'Ticket opened', action.ticket.subject, state.session?.userId || (state.role === 'admin' ? 'admin' : null)),
      }

    case 'update-ticket':
      return { ...state, tickets: state.tickets.map((t) => (t.id === action.id ? { ...t, status: action.status } : t)) }

    case 'clear-events': {
      // Removes the activity-log entries the current viewer is allowed to
      // see — admins can clear everything, analysts only their own.
      const keepIfNotVisible = (e) => {
        if (action.role === 'admin') return false
        if (e.ownerId == null) return true
        return e.ownerId !== action.userId
      }
      return { ...state, events: state.events.filter(keepIfNotVisible) }
    }

    case 'mark-notifications-read': {
      const isVisible = (n) => {
        if (n.ownerId == null) return true
        if (action.role === 'admin') return n.ownerId === 'admin'
        return n.ownerId === action.userId
      }
      return {
        ...state,
        notifications: state.notifications.map((n) => (isVisible(n) ? { ...n, read: true } : n)),
      }
    }

    case 'clear-notifications':
      return { ...state, notifications: [] }

    case 'set-announcement':
      return {
        ...state,
        announcement: { ...(state.announcement || {}), ...action.value, updatedAt: Date.now() },
      }

    case 'add-blacklist': {
      const list = action.list
      const cur = (state.blacklists || {})[list] || []
      if (cur.find((e) => e.value === action.value)) return state
      return {
        ...state,
        blacklists: {
          ...(state.blacklists || {}),
          [list]: [{ value: action.value, reason: action.reason || '', addedAt: Date.now() }, ...cur],
        },
      }
    }

    case 'remove-blacklist': {
      const list = action.list
      const cur = (state.blacklists || {})[list] || []
      return {
        ...state,
        blacklists: {
          ...(state.blacklists || {}),
          [list]: cur.filter((e) => e.value !== action.value),
        },
      }
    }

    case 'clear-blacklist': {
      // Empty one blacklist (hwids / discordIds / emailDomains) in one go.
      return {
        ...state,
        blacklists: {
          ...(state.blacklists || {}),
          [action.list]: [],
        },
      }
    }

    case 'complete-onboarding':
      return { ...state, onboardingDone: true }

    case 'restart-onboarding':
      return { ...state, onboardingDone: false }

    case 'clear-audit-log':
      return { ...state, adminAuditLog: [] }

    case 'wallet-tx': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      const balance = Math.max(0, (w.balance || 0) + action.delta)
      let xp = w.xp || 0
      let wagered = w.wagered || 0
      let won = w.won || 0
      let biggestWin = w.biggestWin || 0
      let jackpot = state.jackpot || 0
      let houseProfit = state.casino?.houseProfit || 0
      if (action.txType === 'bet') {
        const amt = Math.abs(action.delta)
        wagered += amt
        xp += amt
        jackpot += Math.ceil(amt * 0.01) // 1% of every bet feeds the jackpot
        houseProfit += amt
      } else if (action.txType === 'win') {
        won += action.delta
        if (action.delta > biggestWin) biggestWin = action.delta
        houseProfit -= action.delta
      }
      const ach = checkAchievements(w.achievements || [], { balance, xp, wagered, won, biggestWin })
      let notifications = state.notifications
      ach.unlocked.forEach((a) => {
        notifications = note(
          { ...state, notifications },
          'Achievement unlocked',
          `${a.name} — ${a.desc}`,
          action.notifyOwnerId ?? null,
        )
      })
      return {
        ...state,
        jackpot,
        casino: { ...(state.casino || { disabledGames: [] }), houseProfit },
        notifications,
        wallets: {
          ...(state.wallets || {}),
          [action.key]: {
            ...w,
            balance,
            xp,
            wagered,
            won,
            biggestWin,
            achievements: ach.list,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: action.txType, amount: action.delta, detail: action.detail || '' },
              ...(w.history || []),
            ].slice(0, 200),
          },
        },
      }
    }

    case 'claim-daily-bonus': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      return {
        ...state,
        wallets: {
          ...(state.wallets || {}),
          [action.key]: {
            ...w,
            balance: (w.balance || 0) + action.amount,
            lastDailyBonus: Date.now(),
            dailyStreak: action.streak,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: 'bonus', amount: action.amount, detail: `Daily bonus (streak ${action.streak})` },
              ...(w.history || []),
            ].slice(0, 200),
          },
        },
      }
    }

    case 'mark-free-spin': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      return {
        ...state,
        wallets: { ...(state.wallets || {}), [action.key]: { ...w, lastFreeSpin: Date.now() } },
      }
    }

    case 'win-jackpot': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      const pool = state.jackpot || 0
      return {
        ...state,
        jackpot: 5000, // reset pool
        wallets: {
          ...(state.wallets || {}),
          [action.key]: {
            ...w,
            balance: (w.balance || 0) + pool,
            biggestWin: Math.max(w.biggestWin || 0, pool),
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: 'jackpot', amount: pool, detail: 'JACKPOT WIN!' },
              ...(w.history || []),
            ].slice(0, 200),
          },
        },
        notifications: note(state, 'JACKPOT!', `${action.name || 'A player'} won the ${pool.toLocaleString()} coin jackpot!`, null),
      }
    }

    case 'reset-jackpot': {
      // Admin-only: reset the jackpot pool back to its 5000 base.
      if (action.role !== 'admin') return state
      return {
        ...state,
        jackpot: 5000,
        notifications: note(state, 'Jackpot reset', 'An admin reset the jackpot pool to 5,000 coins.', null),
      }
    }

    case 'gift-coins': {
      const from = state.wallets?.[action.fromKey] || { balance: 0, history: [] }
      if ((from.balance || 0) < action.amount) return state
      const to = state.wallets?.[action.toKey] || { balance: 0, history: [] }
      return {
        ...state,
        wallets: {
          ...(state.wallets || {}),
          [action.fromKey]: {
            ...from,
            balance: from.balance - action.amount,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: 'gift-out', amount: -action.amount, detail: `Gift to ${action.toLabel || action.toKey}` },
              ...(from.history || []),
            ].slice(0, 200),
          },
          [action.toKey]: {
            ...to,
            balance: (to.balance || 0) + action.amount,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 7), time: Date.now(), type: 'gift-in', amount: action.amount, detail: `Gift from ${action.fromLabel || action.fromKey}` },
              ...(to.history || []),
            ].slice(0, 200),
          },
        },
        notifications: action.toOwnerId
          ? note(state, 'You received coins', `${action.fromLabel || 'Someone'} sent you ${action.amount.toLocaleString()} coins`, action.toOwnerId)
          : state.notifications,
      }
    }

    case 'set-casino-game': {
      const cur = state.casino || { disabledGames: [], houseProfit: 0 }
      const disabled = new Set(cur.disabledGames || [])
      if (action.enabled) disabled.delete(action.game)
      else disabled.add(action.game)
      return { ...state, casino: { ...cur, disabledGames: Array.from(disabled) } }
    }

    case 'reset-house-profit':
      return { ...state, casino: { ...(state.casino || { disabledGames: [] }), houseProfit: 0 } }

    case 'grant-coins': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      return {
        ...state,
        wallets: {
          ...(state.wallets || {}),
          [action.key]: {
            balance: Math.max(0, w.balance + action.amount),
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: action.amount >= 0 ? 'grant' : 'deduct', amount: action.amount, detail: action.detail || 'Admin adjustment' },
              ...w.history,
            ].slice(0, 200),
          },
        },
        notifications: action.notifyOwnerId
          ? note(state, action.amount >= 0 ? 'Coins granted' : 'Coins removed', `${action.amount >= 0 ? '+' : ''}${action.amount} coins by an admin`, action.notifyOwnerId)
          : state.notifications,
      }
    }

    case 'award-coins': {
      const pin = state.pins.find((p) => p.id === action.pinId)
      if (!pin || pin.coinsAwarded) return state
      const key = pin.ownerId || 'analyst'
      const w = state.wallets?.[key] || { balance: 0, history: [] }
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.pinId ? { ...p, coinsAwarded: true } : p)),
        wallets: {
          ...(state.wallets || {}),
          [key]: {
            balance: w.balance + action.amount,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: 'earn', amount: action.amount, detail: `Caught cheater (${pin.pin})` },
              ...w.history,
            ].slice(0, 200),
          },
        },
        notifications: note(state, 'Coins earned', `+${action.amount} coins for catching a cheater (${pin.pin})`, pin.ownerId),
      }
    }

    case 'shop-redeem': {
      const w = state.wallets?.[action.key] || { balance: 0, history: [] }
      if (w.balance < action.cost) return state
      const purchase = {
        id: 'sp' + Date.now() + Math.random().toString(16).slice(2, 6),
        ownerKey: action.key,
        label: action.label,
        code: action.code,
        kind: action.kind,
        cost: action.cost,
        time: Date.now(),
      }
      const extraKeys = action.licenseKey ? [action.licenseKey] : []
      // Shop-won discount codes become real, usable codes.
      const extraDiscounts = action.kind === 'discount' && action.percent
        ? [{
            id: 'dc' + Date.now() + Math.random().toString(16).slice(2, 6),
            code: action.code,
            percent: action.percent,
            maxUses: 1,
            uses: 0,
            expiresAt: null,
            active: true,
            source: 'shop',
            createdAt: Date.now(),
          }]
        : []
      return {
        ...state,
        wallets: {
          ...(state.wallets || {}),
          [action.key]: {
            balance: w.balance - action.cost,
            history: [
              { id: 'tx' + Date.now() + Math.random().toString(16).slice(2, 6), time: Date.now(), type: 'redeem', amount: -action.cost, detail: action.label },
              ...w.history,
            ].slice(0, 200),
          },
        },
        licenseKeys: [...extraKeys, ...(state.licenseKeys || [])],
        shopPurchases: [purchase, ...(state.shopPurchases || [])],
        discountCodes: [...extraDiscounts, ...(state.discountCodes || [])],
      }
    }

    case 'create-discount-code': {
      const entry = {
        id: 'dc' + Date.now() + Math.random().toString(16).slice(2, 6),
        code: action.code,
        percent: action.percent,
        maxUses: action.maxUses || 0, // 0 = unlimited
        uses: 0,
        expiresAt: action.expiresAt || null,
        active: true,
        source: 'admin',
        createdAt: Date.now(),
      }
      return { ...state, discountCodes: [entry, ...(state.discountCodes || [])] }
    }

    case 'delete-discount-code':
      return { ...state, discountCodes: (state.discountCodes || []).filter((c) => c.id !== action.id) }

    case 'clear-discount-codes':
      return { ...state, discountCodes: [] }

    case 'toggle-discount-code':
      return {
        ...state,
        discountCodes: (state.discountCodes || []).map((c) =>
          c.id === action.id ? { ...c, active: !c.active } : c,
        ),
      }

    case 'use-discount-code':
      return {
        ...state,
        discountCodes: (state.discountCodes || []).map((c) =>
          c.id === action.id ? { ...c, uses: (c.uses || 0) + 1 } : c,
        ),
      }

    case 'toggle-pin-star':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id ? { ...p, starred: !p.starred } : p,
        ),
      }

    case 'bulk-delete-pins':
      return {
        ...state,
        pins: state.pins.filter((p) => !action.ids.includes(p.id)),
      }

    case 'bulk-star-pins':
      return {
        ...state,
        pins: state.pins.map((p) =>
          action.ids.includes(p.id) ? { ...p, starred: action.value } : p,
        ),
      }

    case 'add-pin-screenshot':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? { ...p, screenshots: [...(p.screenshots || []), action.shot] }
            : p,
        ),
      }

    case 'delete-pin-screenshot':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? { ...p, screenshots: (p.screenshots || []).filter((s) => s.id !== action.shotId) }
            : p,
        ),
      }

    case 'add-saved-filter':
      return {
        ...state,
        savedFilters: [
          { id: 'sf' + Date.now() + Math.random().toString(16).slice(2, 6), ownerId: action.ownerId || null, ...action.filter },
          ...(state.savedFilters || []),
        ],
      }

    case 'delete-saved-filter':
      return {
        ...state,
        savedFilters: (state.savedFilters || []).filter((f) => f.id !== action.id),
      }

    case 'add-watchlist': {
      const cur = state.watchlist || []
      if (cur.find((w) => w.discordId === action.discordId && w.ownerId === (action.ownerId || null))) return state
      return {
        ...state,
        watchlist: [
          { id: 'wl' + Date.now() + Math.random().toString(16).slice(2, 6), discordId: action.discordId, note: action.note || '', ownerId: action.ownerId || null, addedAt: Date.now() },
          ...cur,
        ],
      }
    }

    case 'remove-watchlist':
      return {
        ...state,
        watchlist: (state.watchlist || []).filter((w) => w.id !== action.id),
      }

    case 'watchlist-notify': {
      // Mark a watched pin as notified and push a notification to the watcher.
      const entry = (state.watchlist || []).find((w) => w.id === action.watchId)
      if (!entry) return state
      return {
        ...state,
        watchlist: (state.watchlist || []).map((w) =>
          w.id === action.watchId
            ? { ...w, notifiedPins: [...(w.notifiedPins || []), action.pinId] }
            : w,
        ),
        notifications: note(
          state,
          'Watched player scanned again',
          `Discord ${entry.discordId} was scanned (pin ${action.pinCode}) — verdict: ${action.verdict || 'pending'}`,
          entry.ownerId,
        ),
      }
    }

    case 'push-recent-pin': {
      const cur = (state.recentlyViewed || []).filter((r) => r.pinId !== action.pinId || r.ownerId !== (action.ownerId || null))
      return {
        ...state,
        recentlyViewed: [
          { pinId: action.pinId, ownerId: action.ownerId || null, at: Date.now() },
          ...cur,
        ].slice(0, 40),
      }
    }

    case 'set-maintenance':
      return {
        ...state,
        maintenance: { ...(state.maintenance || {}), ...action.value, updatedAt: Date.now() },
      }

    case 'assign-pin': {
      const pin = state.pins.find((p) => p.id === action.pinId)
      let notifs = state.notifications
      if (action.userId && pin) {
        notifs = note(
          state,
          'Pin assigned to you',
          `Pin ${pin.pin || action.pinId} — ${pin.name || pin.game || 'scan'}`,
          action.userId,
        )
      }
      return {
        ...state,
        notifications: notifs,
        pins: state.pins.map((p) =>
          p.id === action.pinId ? { ...p, assignedTo: action.userId || null } : p,
        ),
      }
    }

    case 'set-pin-approval':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.pinId
            ? {
                ...p,
                approvalStatus: action.status,
                approvalBy: action.by || null,
                approvalAt: Date.now(),
                approvalReason: action.reason || '',
              }
            : p,
        ),
      }

    case 'add-slack-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          slackWebhooks: [
            { id: 'sw' + Date.now() + Math.random().toString(16).slice(2, 6), ...action.value, enabled: true, createdAt: Date.now() },
            ...(state.integrations?.slackWebhooks || []),
          ],
        },
      }

    case 'update-slack-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          slackWebhooks: (state.integrations?.slackWebhooks || []).map((w) =>
            w.id === action.id ? { ...w, ...action.value } : w,
          ),
        },
      }

    case 'delete-slack-webhook':
      return {
        ...state,
        integrations: {
          ...state.integrations,
          slackWebhooks: (state.integrations?.slackWebhooks || []).filter((w) => w.id !== action.id),
        },
      }

    case 'set-slack-webhook':
      return {
        ...state,
        integrations: { ...state.integrations, slackWebhook: action.value },
      }

    case 'set-user-digest':
      return {
        ...state,
        users: (state.users || []).map((u) =>
          u.id === action.userId ? { ...u, digestFrequency: action.value } : u,
        ),
      }

    case 'mark-digest-sent':
      return {
        ...state,
        users: (state.users || []).map((u) =>
          u.id === action.userId ? { ...u, lastDigestAt: Date.now() } : u,
        ),
      }

    case 'add-audit-log': {
      const entry = {
        id: 'a' + Date.now() + Math.random().toString(16).slice(2, 6),
        time: Date.now(),
        adminId: action.adminId || 'admin',
        adminName: action.adminName || 'Admin',
        action: action.action,
        target: action.target || '',
        detail: action.detail || '',
      }
      return {
        ...state,
        adminAuditLog: [entry, ...(state.adminAuditLog || [])].slice(0, 1000),
      }
    }

    case 'webhook-health-record': {
      const cur = (state.webhookHealth || {})[action.url] || { ok: 0, fail: 0, lastError: '', lastTime: 0, autoDisabled: false }
      const next = {
        ...cur,
        lastTime: Date.now(),
        lastLatencyMs: action.latencyMs || 0,
        lastSuccess: !!action.success,
        ok: cur.ok + (action.success ? 1 : 0),
        fail: cur.fail + (action.success ? 0 : 1),
        lastError: action.success ? '' : (action.error || cur.lastError || ''),
      }
      // Auto-disable after 5 consecutive failures
      if (!action.success && cur.fail >= 4) next.autoDisabled = true
      if (action.success) next.autoDisabled = false
      return {
        ...state,
        webhookHealth: { ...(state.webhookHealth || {}), [action.url]: next },
      }
    }

    case 'suspend-user':
      return {
        ...state,
        users: (state.users || []).map((u) =>
          u.id === action.id ? { ...u, suspended: !u.suspended } : u,
        ),
      }

    case 'set-user-force-flag':
      return {
        ...state,
        users: (state.users || []).map((u) =>
          u.id === action.id ? { ...u, [action.flag]: !!action.value } : u,
        ),
      }

    case 'clear-user-force-flag':
      return {
        ...state,
        users: (state.users || []).map((u) =>
          u.id === action.id ? { ...u, [action.flag]: false } : u,
        ),
      }

    case 'impersonate-user':
      return {
        ...state,
        role: 'analyst',
        session: {
          ...(state.session || {}),
          userId: action.userId,
          impersonatedFrom: state.role === 'admin' ? 'admin' : (state.session?.userId || null),
          impersonatedFromRole: state.role,
          createdAt: Date.now(),
          id: 's' + Date.now() + Math.random().toString(16).slice(2, 6),
        },
      }

    case 'stop-impersonating':
      return {
        ...state,
        role: state.session?.impersonatedFromRole || 'admin',
        session: state.session
          ? {
              ...state.session,
              userId: null,
              impersonatedFrom: null,
              impersonatedFromRole: null,
            }
          : null,
      }

    case 'bulk-create-keys': {
      const newKeys = (action.keys || []).map((k) => ({
        id: 'k' + Date.now() + Math.random().toString(16).slice(2, 8),
        key: k.key,
        label: k.label || '',
        plan: k.plan || 'Personal',
        durationDays: k.durationDays || 30,
        createdAt: Date.now(),
        expiresAt: k.durationDays > 0 ? Date.now() + k.durationDays * 86400000 : null,
        status: 'Active',
      }))
      return {
        ...state,
        licenseKeys: [...newKeys, ...(state.licenseKeys || [])],
      }
    }

    case 'import-state':
      return { ...seed(), ...action.state }

    case 'clear-data':
      return { ...seed(), settings: state.settings }

    case 'reset':
      return seed()

    default:
      return state
  }
}

const StoreCtx = createContext(null)

export function StoreProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, undefined, load)

  useEffect(() => {
    localStorage.setItem(KEY, JSON.stringify(state))
  }, [state])

  useEffect(() => {
    document.documentElement.classList.toggle('light', state.settings.theme === 'light')
  }, [state.settings.theme])

  const value = useMemo(() => ({ state, dispatch }), [state])
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>
}

export function useStore() {
  const ctx = useContext(StoreCtx)
  if (!ctx) throw new Error('useStore must be used within StoreProvider')
  return ctx
}

export const ALL_GAMES = GAMES

export function useStats() {
  const { state } = useStore()
  return useMemo(() => {
    // Admins see everything; analysts see only the pins they own.
    const allPins = state.pins || []
    const pins = state.role === 'admin'
      ? allPins
      : allPins.filter((p) => p.ownerId && p.ownerId === state.session?.userId)

    const finished = pins.filter((p) => p.status === 'Finished')
    const detections = pins.reduce((a, p) => a + (p.detections || 0), 0)
    const cheatSet = new Set()
    pins.forEach((p) => (p.cheats || []).forEach((c) => cheatSet.add(c)))
    const total = finished.length || 1
    const cheating = finished.filter((p) => p.result === 'Cheating').length
    const suspicious = finished.filter((p) => p.result === 'Suspicious').length
    const legit = finished.filter((p) => p.result === 'Clean').length

    const byGame = {}
    pins.forEach((p) => {
      byGame[p.game] = byGame[p.game] || { game: p.game, detections: 0, scans: 0 }
      byGame[p.game].detections += p.detections || 0
      byGame[p.game].scans += p.status === 'Finished' ? 1 : 0
    })

    // Trend is built from the user's own finished scans so analysts don't
    // see global activity here.
    const byDay = {}
    finished.forEach((p) => {
      const d = new Date(p.scannedAt || p.createdAt || Date.now()).toISOString().slice(0, 10)
      byDay[d] = byDay[d] || { date: d, scans: 0, detections: 0 }
      byDay[d].scans += 1
      byDay[d].detections += p.detections || 0
    })
    const trend = Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date)).slice(-14)

    return {
      totalPins: pins.length,
      totalScans: finished.length,
      detections,
      uniqueCheats: cheatSet.size,
      pending: pins.filter((p) => p.status === 'Pending').length,
      finished: finished.length,
      expired: pins.filter((p) => p.status === 'Expired').length,
      openTickets: state.tickets.filter((t) => t.status === 'Open').length,
      cheatDbCount: state.customCheats.length,
      rates: {
        cheating: Math.round((cheating / total) * 100),
        suspicious: Math.round((suspicious / total) * 100),
        legit: Math.round((legit / total) * 100),
      },
      distribution: [
        { name: 'Cheating', value: cheating, color: '#dc2626' },
        { name: 'Suspicious', value: suspicious, color: '#eab308' },
        { name: 'Legit', value: legit, color: '#22c55e' },
      ].filter((d) => d.value > 0),
      byGame: Object.values(byGame),
      trend,
    }
  }, [state])
}

export function usePlatformStats() {
  const { state } = useStore()
  return useMemo(() => {
    const day = 86_400_000
    const pins = state.pins || []
    const finished = pins.filter((p) => p.status === 'Finished')
    const detections = pins.reduce((a, p) => a + (p.detections || 0), 0)
    const cheatSet = new Set()
    pins.forEach((p) => (p.cheats || []).forEach((c) => cheatSet.add(c)))
    const total = finished.length || 1
    const cheating = finished.filter((p) => p.result === 'Cheating').length
    const suspicious = finished.filter((p) => p.result === 'Suspicious').length
    const legit = finished.filter((p) => p.result === 'Clean').length

    const startOfToday = new Date()
    startOfToday.setHours(0, 0, 0, 0)
    const todayMs = startOfToday.getTime()
    const scansToday = finished.filter((p) => (p.scannedAt || p.createdAt || 0) >= todayMs).length

    // Active users = registered analysts that created a pin in the last 30 days,
    // falling back to total registered users when no pin owners are tracked.
    const cutoff = Date.now() - 30 * day
    const recentOwners = new Set(
      pins.filter((p) => (p.createdAt || 0) >= cutoff && p.ownerId).map((p) => p.ownerId),
    )
    const totalUsers = (state.users || []).length
    const activeUsers = recentOwners.size || totalUsers

    const gamesCovered = new Set(pins.map((p) => p.game).filter(Boolean)).size

    const byGame = {}
    pins.forEach((p) => {
      byGame[p.game] = byGame[p.game] || { game: p.game, detections: 0, scans: 0 }
      byGame[p.game].detections += p.detections || 0
      byGame[p.game].scans += p.status === 'Finished' ? 1 : 0
    })

    const byDay = {}
    finished.forEach((p) => {
      const d = new Date(p.scannedAt || p.createdAt || Date.now()).toISOString().slice(0, 10)
      byDay[d] = byDay[d] || { date: d, scans: 0, detections: 0 }
      byDay[d].scans += 1
      byDay[d].detections += p.detections || 0
    })
    const trend = Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date)).slice(-14)

    return {
      totalUsers,
      activeUsers,
      scansToday,
      gamesCovered,
      totalPins: pins.length,
      totalScans: finished.length,
      detections,
      uniqueCheats: cheatSet.size,
      rates: {
        cheating: Math.round((cheating / total) * 100),
        suspicious: Math.round((suspicious / total) * 100),
        legit: Math.round((legit / total) * 100),
      },
      distribution: [
        { name: 'Cheating', value: cheating, color: '#dc2626' },
        { name: 'Suspicious', value: suspicious, color: '#eab308' },
        { name: 'Legit', value: legit, color: '#22c55e' },
      ].filter((d) => d.value > 0),
      byGame: Object.values(byGame),
      trend,
    }
  }, [state])
}

const DICT = {
  en: {
    'nav.dashboard': 'Dashboard', 'nav.pins': 'Pins', 'nav.strings': 'Strings',
    'nav.database': 'Cheat Database', 'nav.tools': 'Forensic Tools', 'nav.history': 'Activity Log',
    'nav.designer': 'Tool Designer', 'nav.keys': 'Key Generator',
    'nav.support': 'Support', 'nav.resources': 'Resources', 'nav.settings': 'Settings',
    'nav.scoreboard': 'Scoreboard', 'nav.compare': 'Compare', 'nav.casino': 'Coins & Casino',
    'nav.logins': 'Logins', 'nav.security': 'Security', 'nav.weeklyReport': 'Weekly Report',
    'nav.gameProfiles': 'Game Profiles',
    'nav.analytics': 'System Analytics', 'nav.blacklists': 'Blacklists',
    'nav.webhookHealth': 'Webhook Health', 'nav.announcement': 'Announcement',
    'nav.audit': 'Audit Log', 'nav.maintenance': 'Maintenance', 'nav.discounts': 'Discount Codes',
    'cat.services': 'Services', 'cat.activity': 'Activity', 'cat.support': 'Support', 'cat.others': 'Others',
    'cat.admin': 'Admin Access', 'cat.preferences': 'My Preferences',
    'dash.kicker': 'View statistics, events, and announcements on the ZeroTrace.',
    'dash.welcome': 'Welcome back, Ham.',
    'pins.kicker': 'View and manage your scan pins and results',
    'pins.title': 'My Pins', 'pins.create': 'Create Pin',
    'strings.kicker': 'Upload and analyze files for string detection.',
    'strings.title': 'String Analysis',
  },
  de: {
    'nav.dashboard': 'Übersicht', 'nav.pins': 'Pins', 'nav.strings': 'Strings',
    'nav.database': 'Cheat-Datenbank', 'nav.tools': 'Forensik-Tools', 'nav.history': 'Aktivität',
    'nav.designer': 'Tool-Designer', 'nav.keys': 'Key-Generator',
    'nav.support': 'Support', 'nav.resources': 'Ressourcen', 'nav.settings': 'Einstellungen',
    'nav.scoreboard': 'Bestenliste', 'nav.compare': 'Vergleich', 'nav.casino': 'Coins & Casino',
    'nav.logins': 'Logins', 'nav.security': 'Sicherheit', 'nav.weeklyReport': 'Wochenbericht',
    'nav.gameProfiles': 'Spielprofile',
    'nav.analytics': 'System-Analytics', 'nav.blacklists': 'Sperrlisten',
    'nav.webhookHealth': 'Webhook-Status', 'nav.announcement': 'Ankündigung',
    'nav.audit': 'Audit-Log', 'nav.maintenance': 'Wartung', 'nav.discounts': 'Rabattcodes',
    'cat.services': 'Dienste', 'cat.activity': 'Aktivität', 'cat.support': 'Hilfe', 'cat.others': 'Sonstiges',
    'cat.admin': 'Admin-Bereich', 'cat.preferences': 'Meine Einstellungen',
    'dash.kicker': 'Statistiken, Ereignisse und Ankündigungen im Überblick.',
    'dash.welcome': 'Willkommen zurück, Ham.',
    'pins.kicker': 'Scan-Pins und Ergebnisse verwalten',
    'pins.title': 'Meine Pins', 'pins.create': 'Pin erstellen',
    'strings.kicker': 'Dateien hochladen und auf Strings analysieren.',
    'strings.title': 'String-Analyse',
  },
}

export function isBlocked(state, { hwid, discordId, email } = {}) {
  const bl = state.blacklists || { hwids: [], discordIds: [], emailDomains: [] }
  if (hwid && bl.hwids?.some((e) => e.value === hwid)) return { kind: 'hwid', reason: bl.hwids.find((e) => e.value === hwid).reason }
  if (discordId && bl.discordIds?.some((e) => e.value === discordId)) return { kind: 'discord', reason: bl.discordIds.find((e) => e.value === discordId).reason }
  if (email) {
    const domain = String(email).toLowerCase().split('@')[1] || ''
    const hit = bl.emailDomains?.find((e) => {
      const v = String(e.value).toLowerCase()
      if (v.startsWith('*.')) return domain.endsWith(v.slice(2))
      return domain === v
    })
    if (hit) return { kind: 'email', reason: hit.reason }
  }
  return null
}

export function logAdminAction(dispatch, state, action, target = '', detail = '') {
  dispatch({
    type: 'add-audit-log',
    adminId: state.session?.userId || 'admin',
    adminName: state.role === 'admin' ? 'Admin' : (state.session?.userId || 'system'),
    action,
    target,
    detail,
  })
}

export function exportUserData(state, userId) {
  const user = (state.users || []).find((u) => u.id === userId)
  if (!user) return null
  const key = (state.licenseKeys || []).find((k) => k.key === user.key) || null
  const pins = (state.pins || []).filter((p) => p.ownerId === userId)
  const events = (state.events || []).filter((e) => e.ownerId === userId)
  const notifications = (state.notifications || []).filter((n) => n.ownerId === userId)
  const savedStrings = (state.savedStrings || []).filter((s) => s.ownerId === userId)
  return {
    exportedAt: new Date().toISOString(),
    schemaVersion: 1,
    user,
    licenseKey: key,
    pins,
    events,
    notifications,
    savedStrings,
  }
}

export function walletKeyOf(state) {
  return state.session?.userId || state.role || 'analyst'
}

export function validateDiscountCode(state, code) {
  const c = (state.discountCodes || []).find(
    (x) => x.code.toUpperCase() === String(code).trim().toUpperCase(),
  )
  if (!c) return { ok: false, reason: 'Unknown code' }
  if (!c.active) return { ok: false, reason: 'Code is disabled' }
  if (c.expiresAt && Date.now() > c.expiresAt) return { ok: false, reason: 'Code expired' }
  if (c.maxUses > 0 && (c.uses || 0) >= c.maxUses) return { ok: false, reason: 'Code already fully used' }
  return { ok: true, code: c }
}

export function useWallet() {
  const { state } = useStore()
  const key = walletKeyOf(state)
  const w = state.wallets?.[key] || { balance: 0, history: [] }
  return {
    key,
    balance: w.balance || 0,
    history: w.history || [],
    xp: w.xp || 0,
    wagered: w.wagered || 0,
    won: w.won || 0,
    biggestWin: w.biggestWin || 0,
    achievements: w.achievements || [],
    lastDailyBonus: w.lastDailyBonus || 0,
    dailyStreak: w.dailyStreak || 0,
    lastFreeSpin: w.lastFreeSpin || 0,
  }
}

export function useT() {
  const { state } = useStore()
  const lang = state.settings.lang || 'en'
  return (k) => (DICT[lang] && DICT[lang][k]) || DICT.en[k] || k
}
