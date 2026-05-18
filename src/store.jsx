import { createContext, useContext, useEffect, useMemo, useReducer } from 'react'

const KEY = 'ocean-ac-state-v1'

function genPin() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let s = ''
  for (let i = 0; i < 8; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

const GAMES = ['HYTALE', 'MINECRAFT', 'CS2', 'VALORANT', 'RUST', 'FIVEM']
const CHEATS = [
  'KillAura', 'Reach', 'Velocity', 'AutoClicker', 'Aimbot', 'Wallhack',
  'FlyHack', 'SpeedHack', 'TriggerBot', 'XRay', 'NoClip',
]

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
    settings: { theme: 'dark', lang: 'en' },
    notifications: [
      { id: 'n1', title: 'Scan finished', body: 'Pin F1T5F8C0 returned: Cheating', time: now - 3600000, read: false },
      { id: 'n2', title: 'Welcome to Ocean', body: 'Your anti-cheat dashboard is ready.', time: now - 7200000, read: false },
    ],
    pins: [
      {
        id: 'p1',
        pin: 'F1T5F8C0',
        name: 'Test',
        game: 'HYTALE',
        status: 'Finished',
        used: true,
        result: 'Cheating',
        visibility: 'Private',
        detections: 11,
        cheats: ['KillAura', 'Reach', 'Velocity'],
        createdAt: now - 2 * day,
      },
    ],
    detectionFiles: [],
    yaraRules: [],
    suspiciousFiles: [],
    scans,
  }
}

function load() {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return seed()
    const parsed = JSON.parse(raw)
    return { ...seed(), ...parsed }
  } catch {
    return seed()
  }
}

function reducer(state, action) {
  switch (action.type) {
    case 'set-setting':
      return { ...state, settings: { ...state.settings, [action.key]: action.value } }

    case 'add-pin': {
      const pin = {
        id: 'p' + Date.now(),
        pin: genPin(),
        name: action.name,
        game: action.game,
        status: 'Pending',
        used: false,
        result: null,
        visibility: action.visibility,
        detections: 0,
        cheats: [],
        createdAt: Date.now(),
      }
      return {
        ...state,
        pins: [pin, ...state.pins],
        notifications: [
          { id: 'n' + Date.now(), title: 'Pin created', body: `${pin.pin} — ${pin.name}`, time: Date.now(), read: false },
          ...state.notifications,
        ],
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
      const pins = state.pins.map((p) =>
        p.id === action.id
          ? { ...p, status: 'Finished', used: true, result, detections, cheats }
          : p,
      )
      const target = state.pins.find((p) => p.id === action.id)
      return {
        ...state,
        pins,
        scans: [
          {
            id: 's' + Date.now(),
            date: new Date().toISOString().slice(0, 10),
            game: target?.game || 'HYTALE',
            result,
            detections,
          },
          ...state.scans,
        ],
        notifications: [
          { id: 'n' + Date.now(), title: 'Scan finished', body: `${target?.pin}: ${result}`, time: Date.now(), read: false },
          ...state.notifications,
        ],
      }
    }

    case 'delete-pin':
      return { ...state, pins: state.pins.filter((p) => p.id !== action.id) }

    case 'toggle-visibility':
      return {
        ...state,
        pins: state.pins.map((p) =>
          p.id === action.id
            ? { ...p, visibility: p.visibility === 'Private' ? 'Public' : 'Private' }
            : p,
        ),
      }

    case 'add-detection-file':
      return {
        ...state,
        detectionFiles: [
          {
            id: 'd' + Date.now(),
            clientName: action.clientName,
            fileName: action.fileName,
            size: action.size,
            mode: action.mode,
            signatures: action.signatures,
            addedAt: Date.now(),
          },
          ...state.detectionFiles,
        ],
      }

    case 'delete-detection-file':
      return { ...state, detectionFiles: state.detectionFiles.filter((d) => d.id !== action.id) }

    case 'save-yara': {
      const existing = state.yaraRules.find((r) => r.name === action.name)
      const rule = { id: 'y' + Date.now(), name: action.name, source: action.source, createdAt: Date.now() }
      const yaraRules = existing
        ? state.yaraRules.map((r) => (r.name === action.name ? { ...r, source: action.source } : r))
        : [rule, ...state.yaraRules]
      return { ...state, yaraRules }
    }

    case 'delete-yara':
      return { ...state, yaraRules: state.yaraRules.filter((r) => r.id !== action.id) }

    case 'add-suspicious':
      return {
        ...state,
        suspiciousFiles: [
          {
            id: 'sf' + Date.now(),
            fileName: action.fileName,
            size: action.size,
            matches: action.matches,
            scannedAt: Date.now(),
          },
          ...state.suspiciousFiles,
        ],
      }

    case 'mark-notifications-read':
      return { ...state, notifications: state.notifications.map((n) => ({ ...n, read: true })) }

    case 'clear-notifications':
      return { ...state, notifications: [] }

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
    const root = document.documentElement
    root.classList.toggle('light', state.settings.theme === 'light')
  }, [state.settings.theme])

  const value = useMemo(() => ({ state, dispatch }), [state])
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>
}

export function useStore() {
  const ctx = useContext(StoreCtx)
  if (!ctx) throw new Error('useStore must be used within StoreProvider')
  return ctx
}

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
    'nav.support': 'Support', 'nav.resources': 'Resources',
    'cat.services': 'Services', 'cat.support': 'Support', 'cat.others': 'Others',
    'dash.kicker': 'View statistics, events, and announcements on the Ocean.',
    'dash.welcome': 'Welcome back, Ham.',
    'pins.kicker': 'View and manage your scan pins and results',
    'pins.title': 'My Pins', 'pins.create': 'Create Pin',
    'strings.kicker': 'Upload and analyze files for string detection.',
    'strings.title': 'String Analysis',
  },
  de: {
    'nav.dashboard': 'Übersicht', 'nav.pins': 'Pins', 'nav.strings': 'Strings',
    'nav.support': 'Support', 'nav.resources': 'Ressourcen',
    'cat.services': 'Dienste', 'cat.support': 'Hilfe', 'cat.others': 'Sonstiges',
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
