/* Casino helpers: achievements, leveling, sound, daily bonus, confetti.
   Pure module — no store import (avoids circular deps). */

export const ACHIEVEMENTS = [
  { id: 'first_bet', name: 'Getting Started', desc: 'Place your first bet', test: (s) => s.wagered > 0 },
  { id: 'first_win', name: 'Winner', desc: 'Win a round', test: (s) => s.won > 0 },
  { id: 'big_win', name: 'Big Win', desc: 'Win 5,000+ in one round', test: (s) => s.biggestWin >= 5000 },
  { id: 'mega_win', name: 'Mega Win', desc: 'Win 50,000+ in one round', test: (s) => s.biggestWin >= 50000 },
  { id: 'high_roller', name: 'High Roller', desc: 'Wager 100,000 total', test: (s) => s.wagered >= 100000 },
  { id: 'whale', name: 'Whale', desc: 'Hold 100,000 coins at once', test: (s) => s.balance >= 100000 },
  { id: 'veteran', name: 'Veteran', desc: 'Wager 1,000,000 total', test: (s) => s.wagered >= 1000000 },
]

export function checkAchievements(have, stats) {
  const list = Array.isArray(have) ? [...have] : []
  const unlocked = []
  for (const a of ACHIEVEMENTS) {
    if (!list.includes(a.id) && a.test(stats)) {
      list.push(a.id)
      unlocked.push(a)
    }
  }
  return { list, unlocked }
}

export function levelFromXp(xp) {
  return Math.floor(Math.sqrt((xp || 0) / 500)) + 1
}
export function xpForLevel(lvl) {
  return (lvl - 1) * (lvl - 1) * 500
}
export function levelProgress(xp) {
  const lvl = levelFromXp(xp)
  const cur = xpForLevel(lvl)
  const next = xpForLevel(lvl + 1)
  const pct = next > cur ? Math.round(((xp - cur) / (next - cur)) * 100) : 0
  return { level: lvl, pct: Math.max(0, Math.min(100, pct)), cur, next }
}

export function dailyBonusAmount(streak) {
  return 200 + Math.min(Math.max(streak, 0), 7) * 100 // 200 … 900
}

const DAY = 86_400_000
export function canClaimDaily(lastAt) {
  return !lastAt || Date.now() - lastAt >= DAY
}

// ---- Sound (Web Audio, tiny beeps) ----
let _actx = null
export function playSound(type, enabled) {
  if (!enabled) return
  try {
    _actx = _actx || new (window.AudioContext || window.webkitAudioContext)()
    const ctx = _actx
    const o = ctx.createOscillator()
    const g = ctx.createGain()
    o.connect(g)
    g.connect(ctx.destination)
    const now = ctx.currentTime
    o.type = 'triangle'
    if (type === 'win') {
      o.frequency.setValueAtTime(523, now)
      o.frequency.setValueAtTime(659, now + 0.08)
      o.frequency.setValueAtTime(784, now + 0.16)
    } else if (type === 'jackpot') {
      o.frequency.setValueAtTime(523, now)
      o.frequency.setValueAtTime(784, now + 0.1)
      o.frequency.setValueAtTime(1047, now + 0.2)
    } else if (type === 'lose') {
      o.frequency.setValueAtTime(320, now)
      o.frequency.setValueAtTime(180, now + 0.14)
    } else {
      o.frequency.setValueAtTime(440, now)
    }
    g.gain.setValueAtTime(0.07, now)
    g.gain.exponentialRampToValueAtTime(0.0001, now + 0.35)
    o.start(now)
    o.stop(now + 0.36)
  } catch {
    /* ignore */
  }
}
