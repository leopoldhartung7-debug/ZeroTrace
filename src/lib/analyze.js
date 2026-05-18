// Client-side binary analysis helpers — no backend required.

const PRINTABLE_MIN = 0x20
const PRINTABLE_MAX = 0x7e

export function extractStrings(bytes, { min = 4, cap = 8000 } = {}) {
  const out = []
  const n = bytes.length

  // ASCII runs
  let start = -1
  for (let i = 0; i < n; i++) {
    const b = bytes[i]
    const printable = b >= PRINTABLE_MIN && b <= PRINTABLE_MAX
    if (printable) {
      if (start < 0) start = i
    } else if (start >= 0) {
      if (i - start >= min) {
        out.push({ value: decodeAscii(bytes, start, i), offset: start, enc: 'ascii' })
        if (out.length >= cap) return out
      }
      start = -1
    }
  }
  if (start >= 0 && n - start >= min) {
    out.push({ value: decodeAscii(bytes, start, n), offset: start, enc: 'ascii' })
  }

  // UTF-16LE runs (printable char followed by 0x00)
  let s16 = -1
  for (let i = 0; i + 1 < n; i += 2) {
    const lo = bytes[i]
    const hi = bytes[i + 1]
    const printable = hi === 0 && lo >= PRINTABLE_MIN && lo <= PRINTABLE_MAX
    if (printable) {
      if (s16 < 0) s16 = i
    } else if (s16 >= 0) {
      const len = (i - s16) / 2
      if (len >= min) {
        out.push({ value: decodeUtf16(bytes, s16, i), offset: s16, enc: 'utf16le' })
        if (out.length >= cap) return out
      }
      s16 = -1
    }
  }

  return out
}

function decodeAscii(bytes, a, b) {
  let s = ''
  for (let i = a; i < b; i++) s += String.fromCharCode(bytes[i])
  return s
}

function decodeUtf16(bytes, a, b) {
  let s = ''
  for (let i = a; i < b; i += 2) s += String.fromCharCode(bytes[i])
  return s
}

const SUSPICIOUS_KEYWORDS = [
  'aimbot', 'wallhack', 'killaura', 'kill aura', 'triggerbot', 'autoclicker',
  'autoclick', 'velocity', 'reach', 'xray', 'x-ray', 'esp', 'fly hack',
  'flyhack', 'speedhack', 'speed hack', 'noclip', 'no clip', 'bhop',
  'inject', 'injector', 'loadlibrary', 'virtualalloc', 'writeprocessmemory',
  'readprocessmemory', 'createremotethread', 'ntmapviewofsection', 'setwindowshookex',
  'getasynckeystate', 'cheat', 'bypass', 'undetected', 'spoofer', 'spoof',
  'hwid', 'memory.dll', 'd3d hook', 'opengl hook', 'overlay',
]

export function scanSuspicious(strings) {
  const hits = []
  const seen = new Set()
  for (const s of strings) {
    const low = s.value.toLowerCase()
    for (const kw of SUSPICIOUS_KEYWORDS) {
      if (low.includes(kw) && !seen.has(kw + s.offset)) {
        seen.add(kw + s.offset)
        hits.push({ keyword: kw, value: s.value.slice(0, 160), offset: s.offset })
      }
    }
  }
  return hits
}

// Minimal YARA-like parser: supports a `rule NAME { strings: $x = "lit" ... condition: ... }`.
export function parseYaraRule(src) {
  const errors = []
  const text = (src || '').trim()
  if (!text) return { ok: false, errors: ['Rule is empty'] }

  const nameMatch = text.match(/\brule\s+([A-Za-z_]\w*)/)
  if (!nameMatch) errors.push('Missing `rule <name>` declaration')

  if (!/\{[\s\S]*\}/.test(text)) errors.push('Missing rule body `{ ... }`')

  const literals = []
  const re = /\$[A-Za-z_]\w*\s*=\s*"((?:[^"\\]|\\.)*)"/g
  let m
  while ((m = re.exec(text)) !== null) literals.push(m[1].replace(/\\"/g, '"'))

  // hex strings: $h = { 4D 5A 90 }
  const reHex = /\$[A-Za-z_]\w*\s*=\s*\{([0-9A-Fa-f\s?]+)\}/g
  const hexPatterns = []
  while ((m = reHex.exec(text)) !== null) {
    hexPatterns.push(
      m[1]
        .trim()
        .split(/\s+/)
        .map((h) => h),
    )
  }

  if (!/\bcondition\s*:/.test(text)) errors.push('Missing `condition:` section')
  if (literals.length === 0 && hexPatterns.length === 0)
    errors.push('No string patterns found in `strings:` section')

  return {
    ok: errors.length === 0,
    name: nameMatch ? nameMatch[1] : null,
    literals,
    hexPatterns,
    errors,
  }
}

export function runYaraRule(parsed, bytes, strings) {
  const hits = []
  const haystack = strings.map((s) => s.value).join('\n')

  for (const lit of parsed.literals || []) {
    if (haystack.includes(lit)) hits.push({ type: 'string', pattern: lit })
  }

  for (const pat of parsed.hexPatterns || []) {
    if (matchHex(bytes, pat)) hits.push({ type: 'hex', pattern: pat.join(' ') })
  }

  return { matched: hits.length > 0, hits }
}

function matchHex(bytes, pattern) {
  const pat = pattern.map((p) => (p === '??' ? -1 : parseInt(p, 16)))
  const n = bytes.length
  const m = pat.length
  if (m === 0 || m > n) return false
  for (let i = 0; i + m <= n; i++) {
    let ok = true
    for (let j = 0; j < m; j++) {
      if (pat[j] !== -1 && bytes[i + j] !== pat[j]) {
        ok = false
        break
      }
    }
    if (ok) return true
  }
  return false
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

const CHEAT_DOMAINS = [
  'vape.gg', 'liquidbounce.net', 'wurstclient.net', 'impactclient.net',
  'novoline', 'rise.ware', 'sigmaclient', 'meteorclient.com', 'aristois.net',
  'baritone', 'inertia', 'flux', 'salhack', 'nodus', 'huzuni', 'jigsaw',
  'future-client', 'entropy', 'aimware.net', 'fecurity', 'neverlose.cc',
  'gamesense.pub', 'onetap.com', 'cheatengine', 'unknowncheats.me',
  'mpgh.net', 'nightwa.re', 'moon-client', 'prestige', 'exhibition',
]

const ARTIFACT_PATTERNS = [
  'autoclicker', 'auto clicker', 'cheat', 'hacked client', 'ghost client',
  'injector', '.dll', 'javaw.exe', 'jna', 'reflection', 'macro recorder',
  'spoofer', 'hwid', 'loader.exe', 'cleaner', 'bleachbit', 'ccleaner',
  'usn journal', 'prefetch', 'recuva', 'eraser', 'timestomp',
]

export function analyzeText(text, mode = 'history') {
  const patterns =
    mode === 'artifacts'
      ? [...CHEAT_DOMAINS, ...ARTIFACT_PATTERNS]
      : CHEAT_DOMAINS
  const lines = (text || '').split(/\r?\n/)
  const flagged = []
  let scanned = 0
  lines.forEach((line, idx) => {
    const trimmed = line.trim()
    if (!trimmed) return
    scanned++
    const low = trimmed.toLowerCase()
    const hits = patterns.filter((p) => low.includes(p))
    if (hits.length) flagged.push({ idx: idx + 1, line: trimmed.slice(0, 220), hits })
  })
  return { scanned, flagged, clean: flagged.length === 0 }
}

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(new Uint8Array(fr.result))
    fr.onerror = () => reject(fr.error)
    fr.readAsArrayBuffer(file)
  })
}
