import { createContext, useContext, useEffect, useMemo, useReducer } from 'react'

const KEY = 'ocean-ac-state-v2'

function genPin() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let s = ''
  for (let i = 0; i < 8; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

export function generatePinCode() {
  return genPin()
}

const GAMES = ['HYTALE', 'MINECRAFT', 'CS2', 'VALORANT', 'RUST', 'FIVEM']
const CHEATS = [
  'KillAura', 'Reach', 'Velocity', 'AutoClicker', 'Aimbot', 'Wallhack',
  'FlyHack', 'SpeedHack', 'TriggerBot', 'XRay', 'NoClip',
]

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
    settings: { theme: 'dark', lang: 'en', defaultGame: 'HYTALE' },
    notifications: [
      { id: 'n1', title: 'Scan finished', body: 'Pin F1T5F8C0 returned: Cheating', time: now - 3600000, read: false },
      { id: 'n2', title: 'Welcome to Ocean', body: 'Your anti-cheat dashboard is ready.', time: now - 7200000, read: false },
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
      accent: '#3b82f6',
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
    const raw = localStorage.getItem(KEY)
    if (!raw) return seed()
    return { ...seed(), ...JSON.parse(raw) }
  } catch {
    return seed()
  }
}

function ev(state, kind, title, detail) {
  return [
    { id: 'e' + Date.now() + Math.random().toString(16).slice(2, 6), kind, title, detail, time: Date.now() },
    ...state.events,
  ].slice(0, 300)
}

function note(state, title, body) {
  return [{ id: 'n' + Date.now(), title, body, time: Date.now(), read: false }, ...state.notifications].slice(0, 100)
}

function reducer(state, action) {
  switch (action.type) {
    case 'set-setting':
      return { ...state, settings: { ...state.settings, [action.key]: action.value } }

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
        detections: 0, cheats: [], createdAt: Date.now(),
      }
      return {
        ...state,
        pins: [pin, ...state.pins],
        events: ev(state, 'pin', 'Pin created', `${pin.pin} — ${pin.name}`),
        notifications: note(state, 'Pin created', `${pin.pin} — ${pin.name}`),
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
        events: ev(state, 'scan', 'Scan finished', `${target?.pin} — ${result}`),
        notifications: note(state, 'Scan finished', `${target?.pin}: ${result}`),
      }
    }

    case 'delete-pin':
      return { ...state, pins: state.pins.filter((p) => p.id !== action.id), events: ev(state, 'pin', 'Pin deleted', action.pin || '') }

    case 'update-pin':
      return {
        ...state,
        pins: state.pins.map((p) => (p.id === action.id ? { ...p, ...action.patch } : p)),
        events: ev(state, 'pin', 'Pin updated', action.label || ''),
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
          { id: 'd' + Date.now(), clientName: action.clientName, fileName: action.fileName, size: action.size, mode: action.mode, signatures: action.signatures, addedAt: Date.now() },
          ...state.detectionFiles,
        ],
        events: ev(state, 'file', 'Detection file added', `${action.clientName} (${action.fileName})`),
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
        events: ev(state, 'rule', 'YARA rule saved', action.name),
      }
    }

    case 'delete-yara':
      return { ...state, yaraRules: state.yaraRules.filter((r) => r.id !== action.id) }

    case 'add-suspicious':
      return {
        ...state,
        suspiciousFiles: [
          { id: 'sf' + Date.now(), fileName: action.fileName, size: action.size, matches: action.matches, scannedAt: Date.now() },
          ...state.suspiciousFiles,
        ],
        events: ev(state, 'scan', 'File scanned', `${action.fileName} — ${action.matches.length} match(es)`),
      }

    case 'import-scan': {
      const p = action.payload
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
        host: p.host || '',
        os: p.os || '',
        createdAt: prev ? prev.createdAt : Date.now(),
        scannedAt: p.scannedAt || Date.now(),
      }
      const pins =
        idx >= 0
          ? state.pins.map((x, i) => (i === idx ? { ...x, ...merged } : x))
          : [{ id: 'p' + Date.now(), ...merged }, ...state.pins]
      return {
        ...state,
        pins,
        scans: [
          { id: 's' + Date.now(), date: new Date().toISOString().slice(0, 10), game, result, detections: dets.length },
          ...state.scans,
        ],
        events: ev(state, 'scan', 'Scan result imported', `${p.code} — ${result} (${dets.length} detections)`),
        notifications: note(state, 'Scan result imported', `${p.code}: ${result}`),
      }
    }

    case 'add-cheat':
      return {
        ...state,
        customCheats: [{ id: 'c' + Date.now(), builtin: false, ...action.cheat }, ...state.customCheats],
        events: ev(state, 'db', 'Cheat added', action.cheat.name),
      }

    case 'delete-cheat':
      return { ...state, customCheats: state.customCheats.filter((c) => c.id !== action.id) }

    case 'add-ticket':
      return {
        ...state,
        tickets: [{ id: 'T-' + Date.now().toString().slice(-6), ...action.ticket, status: 'Open', createdAt: Date.now() }, ...state.tickets],
        events: ev(state, 'support', 'Ticket opened', action.ticket.subject),
        notifications: note(state, 'Ticket opened', action.ticket.subject),
      }

    case 'update-ticket':
      return { ...state, tickets: state.tickets.map((t) => (t.id === action.id ? { ...t, status: action.status } : t)) }

    case 'mark-notifications-read':
      return { ...state, notifications: state.notifications.map((n) => ({ ...n, read: true })) }

    case 'clear-notifications':
      return { ...state, notifications: [] }

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
    const pins = state.pins
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

    const byDay = {}
    state.scans.forEach((s) => {
      byDay[s.date] = byDay[s.date] || { date: s.date, scans: 0, detections: 0 }
      byDay[s.date].scans += 1
      byDay[s.date].detections += s.detections || 0
    })
    const trend = Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date)).slice(-14)

    return {
      totalPins: pins.length,
      totalScans: state.scans.length,
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

const DICT = {
  en: {
    'nav.dashboard': 'Dashboard', 'nav.pins': 'Pins', 'nav.strings': 'Strings',
    'nav.database': 'Cheat Database', 'nav.tools': 'Forensic Tools', 'nav.history': 'Activity Log',
    'nav.designer': 'Tool Designer',
    'nav.support': 'Support', 'nav.resources': 'Resources', 'nav.settings': 'Settings',
    'cat.services': 'Services', 'cat.activity': 'Activity', 'cat.support': 'Support', 'cat.others': 'Others',
    'dash.kicker': 'View statistics, events, and announcements on the Ocean.',
    'dash.welcome': 'Welcome back, Ham.',
    'pins.kicker': 'View and manage your scan pins and results',
    'pins.title': 'My Pins', 'pins.create': 'Create Pin',
    'strings.kicker': 'Upload and analyze files for string detection.',
    'strings.title': 'String Analysis',
  },
  de: {
    'nav.dashboard': 'Übersicht', 'nav.pins': 'Pins', 'nav.strings': 'Strings',
    'nav.database': 'Cheat-Datenbank', 'nav.tools': 'Forensik-Tools', 'nav.history': 'Aktivität',
    'nav.designer': 'Tool-Designer',
    'nav.support': 'Support', 'nav.resources': 'Ressourcen', 'nav.settings': 'Einstellungen',
    'cat.services': 'Dienste', 'cat.activity': 'Aktivität', 'cat.support': 'Hilfe', 'cat.others': 'Sonstiges',
    'dash.kicker': 'Statistiken, Ereignisse und Ankündigungen im Überblick.',
    'dash.welcome': 'Willkommen zurück, Ham.',
    'pins.kicker': 'Scan-Pins und Ergebnisse verwalten',
    'pins.title': 'Meine Pins', 'pins.create': 'Pin erstellen',
    'strings.kicker': 'Dateien hochladen und auf Strings analysieren.',
    'strings.title': 'String-Analyse',
  },
}

export function useT() {
  const { state } = useStore()
  const lang = state.settings.lang || 'en'
  return (k) => (DICT[lang] && DICT[lang][k]) || DICT.en[k] || k
}
