export const currentUser = {
  name: 'Hartung',
  email: 'h.leopold@anticheat.ac',
  initial: 'H',
}

export const dashboardStats = [
  { key: 'pins', label: 'Total Pins', value: 1284, delta: '+12%', icon: 'Pin' },
  { key: 'scans', label: 'Total Scans', value: 8472, delta: '+8%', icon: 'ScanLine' },
  { key: 'detections', label: 'Detections', value: 391, delta: '+24%', icon: 'ShieldAlert' },
  { key: 'cheats', label: 'Unique Cheats', value: 57, delta: '+3%', icon: 'Bug' },
]

export const detectionRates = [
  { label: 'Cheating Rate', value: 18, color: '#dc2626' },
  { label: 'Suspicious Rate', value: 27, color: '#f59e0b' },
  { label: 'Legit Rate', value: 55, color: '#22c55e' },
]

export const resultsDistribution = [
  { name: 'Clean', value: 6810, color: '#22c55e' },
  { name: 'Flagged', value: 1662, color: '#dc2626' },
]

export const scanTrends = [
  { day: 'Mon', scans: 980, detections: 41 },
  { day: 'Tue', scans: 1240, detections: 58 },
  { day: 'Wed', scans: 1110, detections: 49 },
  { day: 'Thu', scans: 1480, detections: 72 },
  { day: 'Fri', scans: 1690, detections: 64 },
  { day: 'Sat', scans: 1320, detections: 55 },
  { day: 'Sun', scans: 652, detections: 52 },
]

export const byGame = [
  { game: 'Minecraft', scans: 3120, detections: 168 },
  { game: 'CS2', scans: 2440, detections: 121 },
  { game: 'Valorant', scans: 1580, detections: 64 },
  { game: 'Rust', scans: 880, detections: 28 },
  { game: 'Apex', scans: 452, detections: 10 },
]

export const pinStats = [
  { key: 'daily', label: 'Daily Pins', value: 34 },
  { key: 'total', label: 'Total Pins', value: 1284 },
  { key: 'pending', label: 'Pending', value: 12 },
  { key: 'finished', label: 'Finished', value: 1198 },
  { key: 'expired', label: 'Expired', value: 74 },
]

export const pins = [
  {
    pin: 'OC-9F2A',
    name: 'Tournament Finals — Alpha',
    game: 'Minecraft',
    status: 'FINISHED',
    used: '3/3',
    result: 'CHEATING',
    visibility: 'PRIVATE',
  },
  {
    pin: 'OC-7B41',
    name: 'Ranked Lobby Check',
    game: 'CS2',
    status: 'FINISHED',
    used: '1/1',
    result: 'CLEAN',
    visibility: 'SHARED',
  },
  {
    pin: 'OC-3D88',
    name: 'Scrim Block — Team Nova',
    game: 'Valorant',
    status: 'PENDING',
    used: '0/5',
    result: 'PENDING',
    visibility: 'PRIVATE',
  },
  {
    pin: 'OC-12C0',
    name: 'Server Wipe Audit',
    game: 'Rust',
    status: 'FINISHED',
    used: '8/8',
    result: 'SUSPICIOUS',
    visibility: 'PUBLIC',
  },
  {
    pin: 'OC-5E63',
    name: 'Qualifier Round 2',
    game: 'Apex',
    status: 'EXPIRED',
    used: '2/4',
    result: 'CLEAN',
    visibility: 'PRIVATE',
  },
  {
    pin: 'OC-A901',
    name: 'Community Event Sweep',
    game: 'Minecraft',
    status: 'FINISHED',
    used: '24/30',
    result: 'CHEATING',
    visibility: 'SHARED',
  },
  {
    pin: 'OC-B4F7',
    name: 'Pro League — Match 14',
    game: 'CS2',
    status: 'PENDING',
    used: '0/2',
    result: 'PENDING',
    visibility: 'PRIVATE',
  },
  {
    pin: 'OC-6622',
    name: 'Random Spot Check',
    game: 'Valorant',
    status: 'FINISHED',
    used: '1/1',
    result: 'CLEAN',
    visibility: 'PUBLIC',
  },
]
