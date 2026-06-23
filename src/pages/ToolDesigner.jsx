import { useEffect, useMemo, useRef, useState } from 'react'
import { Wand2, Save, Download, Upload, RotateCcw, Eye, Copy, FileJson, Link, AlertTriangle, Check, Play, Zap, FolderOpen, Wifi, WifiOff } from 'lucide-react'
import { PageHeader, Card, Field } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, defaultToolStyle } from '../store.jsx'

// ── colour helpers ──────────────────────────────────────────────────────────

function hexToRgb(hex) {
  const h = hex.replace('#', '')
  return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16) }
}

function rgbToHex(r, g, b) {
  return '#' + [r, g, b]
    .map((x) => Math.min(255, Math.max(0, Math.round(x))).toString(16).padStart(2, '0'))
    .join('')
}

function shiftRgb(hex, delta) {
  const { r, g, b } = hexToRgb(hex)
  return rgbToHex(r + delta, g + delta, b + delta)
}

function relativeLuminance(hex) {
  try {
    const { r, g, b } = hexToRgb(hex)
    return [r, g, b].reduce((acc, c, i) => {
      const s = c / 255
      return acc + (s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)) * [0.2126, 0.7152, 0.0722][i]
    }, 0)
  } catch { return 0 }
}

function contrastRatio(hex1, hex2) {
  const l1 = relativeLuminance(hex1)
  const l2 = relativeLuminance(hex2)
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)
}

// ── preset themes ───────────────────────────────────────────────────────────

const PRESET_THEMES = [
  {
    label: 'Dark Navy',
    colors: { background: '#0d1326', mutedBackground: '#161d33', titlebar: '#070b16', text: '#e8eaf0', mutedText: '#8b93a7', accent: '#38bdf8' },
    animations: { speed: 'normal', barStyle: 'smooth', intro: 'fade', bgEffect: 'none', glowAccent: false, glitchText: false },
  },
  {
    label: 'Midnight Purple',
    colors: { background: '#0f0b1e', mutedBackground: '#1a1430', titlebar: '#07050d', text: '#ede8f5', mutedText: '#9b90b8', accent: '#a78bfa' },
    animations: { speed: 'slow', barStyle: 'pulse', intro: 'fade', bgEffect: 'scanlines', glowAccent: true, glitchText: false },
  },
  {
    label: 'Forest',
    colors: { background: '#0a150f', mutedBackground: '#111f18', titlebar: '#050a07', text: '#dff0e5', mutedText: '#88aa95', accent: '#22c55e' },
    animations: { speed: 'normal', barStyle: 'smooth', intro: 'none', bgEffect: 'grid', glowAccent: false, glitchText: false },
  },
  {
    label: 'Sunset',
    colors: { background: '#1a0e08', mutedBackground: '#261508', titlebar: '#0d0703', text: '#f5ede5', mutedText: '#b09080', accent: '#f97316' },
    animations: { speed: 'fast', barStyle: 'smooth', intro: 'slide', bgEffect: 'glow-pulse', glowAccent: true, glitchText: false },
  },
  {
    label: 'Rose',
    colors: { background: '#1a0a12', mutedBackground: '#26101c', titlebar: '#0d0509', text: '#f5e0ea', mutedText: '#b09098', accent: '#f43f5e' },
    animations: { speed: 'slow', barStyle: 'pulse', intro: 'fade', bgEffect: 'scanlines', glowAccent: true, glitchText: true },
  },
]

const ANIMATION_PRESETS = [
  { label: 'Minimal',     speed: 'instant', barStyle: 'smooth',  intro: 'none',  bgEffect: 'none',       glowAccent: false, glitchText: false },
  { label: 'Standard',    speed: 'normal',  barStyle: 'smooth',  intro: 'fade',  bgEffect: 'none',       glowAccent: false, glitchText: false },
  { label: 'Neon',        speed: 'normal',  barStyle: 'pulse',   intro: 'fade',  bgEffect: 'scanlines',  glowAccent: true,  glitchText: false },
  { label: 'Matrix',      speed: 'normal',  barStyle: 'stepped', intro: 'fade',  bgEffect: 'grid',       glowAccent: true,  glitchText: false },
  { label: 'Cinematisch', speed: 'slow',    barStyle: 'pulse',   intro: 'fade',  bgEffect: 'glow-pulse', glowAccent: true,  glitchText: false },
  { label: 'Cyber',       speed: 'fast',    barStyle: 'smooth',  intro: 'slide', bgEffect: 'scanlines',  glowAccent: true,  glitchText: true  },
]

// ── scanner export helpers ───────────────────────────────────────────────────

function buildScannerDelta(s) {
  const def = defaultToolStyle()

  function objDelta(src, defObj) {
    const d = {}
    for (const [k, v] of Object.entries({ ...defObj, ...src })) {
      if (v !== defObj[k]) d[k] = v
    }
    return Object.keys(d).length ? d : null
  }

  const delta = {}

  const colorDelta = {}
  for (const [k, v] of Object.entries(s.colors)) {
    if (v.toLowerCase() !== (def.colors[k] ?? '').toLowerCase()) colorDelta[k] = v
  }
  if (Object.keys(colorDelta).length) delta.colors = colorDelta

  const textDelta = {}
  for (const [k, v] of Object.entries(s.text)) {
    if (v !== def.text[k]) textDelta[k] = v
  }
  if (Object.keys(textDelta).length) delta.text = textDelta
  if (s.version !== def.version) delta.version = s.version

  const d_anim = objDelta(s.animations || {}, def.animations)
  if (d_anim) delta.animations = d_anim

  const d_iv = objDelta(s.introVideo || {}, def.introVideo)
  if (d_iv) delta.introVideo = d_iv

  const d_fr = objDelta(s.frame || {}, def.frame)
  if (d_fr) delta.frame = d_fr

  const d_ty = objDelta(s.typography || {}, def.typography)
  if (d_ty) delta.typography = d_ty

  const d_pin = objDelta(s.pinField || {}, def.pinField)
  if (d_pin) delta.pinField = d_pin

  const d_bar = objDelta(s.bar || {}, def.bar)
  if (d_bar) delta.bar = d_bar

  const d_done = objDelta(s.done || {}, def.done)
  if (d_done) delta.done = d_done

  return delta
}

function downloadScannerJson(delta) {
  const blob = new Blob([JSON.stringify(delta, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'zerotrace-ui.json'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ── File System Access API ───────────────────────────────────────────────────

const SUPPORTS_FS = typeof window !== 'undefined' && 'showDirectoryPicker' in window

function _idbOpen() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('ztfs-v1', 1)
    r.onupgradeneeded = e => e.target.result.createObjectStore('h')
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}

async function idbSaveHandle(handle) {
  const db = await _idbOpen()
  return new Promise((res, rej) => {
    const t = db.transaction('h', 'readwrite')
    t.objectStore('h').put(handle, 'dir')
    t.oncomplete = res
    t.onerror = () => rej(t.error)
  })
}

async function idbLoadHandle() {
  try {
    const db = await _idbOpen()
    return new Promise(res => {
      const t = db.transaction('h', 'readonly')
      const g = t.objectStore('h').get('dir')
      g.onsuccess = () => res(g.result ?? null)
      g.onerror = () => res(null)
    })
  } catch { return null }
}

async function writeScannerJson(handle, delta) {
  const fh = await handle.getFileHandle('zerotrace-ui.json', { create: true })
  const w = await fh.createWritable()
  await w.write(JSON.stringify(delta, null, 2))
  await w.close()
}

// ── sub-components ───────────────────────────────────────────────────────────

function ColorField({ label, value, onChange }) {
  return (
    <div>
      <label className="muted mb-1.5 block text-sm">{label}</label>
      <div className="bd tile flex items-center gap-3 rounded-lg border px-3 py-2">
        <input
          type="color"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="h-7 w-9 cursor-pointer rounded border-0 bg-transparent p-0"
        />
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="txt w-full bg-transparent font-mono text-sm focus:outline-none"
        />
      </div>
    </div>
  )
}

function Toggle({ label, checked, onChange, accent }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-3 py-1.5 text-sm"
    >
      <span
        className={`flex h-5 w-5 items-center justify-center rounded border transition-colors ${
          checked
            ? accent
              ? 'border-violet-500 bg-violet-600 text-white'
              : 'border-sky-500 bg-sky-600 text-white'
            : 'bd tile'
        }`}
      >
        {checked && (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <path d="M5 13l4 4L19 7" />
          </svg>
        )}
      </span>
      <span className="txt">{label}</span>
    </button>
  )
}

function DropSelect({ value, options, onChange, color = 'sky' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return
    const close = (e) => { if (!ref.current?.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])
  const cur = options.find(o => o.value === value) ?? options[0]
  const SEL = {
    sky: 'bg-sky-600/20 text-sky-400', violet: 'bg-violet-600/20 text-violet-400',
    pink: 'bg-pink-600/20 text-pink-400', emerald: 'bg-emerald-600/20 text-emerald-400',
    amber: 'bg-amber-600/20 text-amber-400', orange: 'bg-orange-600/20 text-orange-400',
    cyan: 'bg-cyan-600/20 text-cyan-400', slate: 'bg-slate-400/10 text-slate-300',
    indigo: 'bg-indigo-600/20 text-indigo-400', fuchsia: 'bg-fuchsia-600/20 text-fuchsia-400',
    teal: 'bg-teal-600/20 text-teal-400', green: 'bg-green-600/20 text-green-400',
  }
  const selCls = SEL[color] ?? SEL.sky
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(o => !o)}
        className="bd tile txt flex w-full items-center justify-between rounded-lg border px-3 py-2.5 text-sm transition-colors hover:bg-white/5">
        <div className="flex items-center gap-2">
          {cur.icon && <span className="text-base leading-none">{cur.icon}</span>}
          <span className="font-medium">{cur.label}</span>
          {cur.desc && <span className="muted text-xs">{cur.desc}</span>}
        </div>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          className={`muted shrink-0 transition-transform ${open ? 'rotate-180' : ''}`}>
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div className="tile bd absolute left-0 right-0 z-50 mt-1 overflow-hidden rounded-xl border shadow-2xl" style={{ top: '100%' }}>
          {options.map(opt => (
            <button key={opt.value} onClick={() => { onChange(opt.value); setOpen(false) }}
              className={`flex w-full items-center justify-between px-4 py-2.5 text-sm transition-colors ${
                opt.value === value ? selCls : 'muted hover:bg-white/5 hover:txt'
              }`}>
              <div className="flex items-center gap-2">
                {opt.icon && <span className="text-base leading-none">{opt.icon}</span>}
                <span className="font-medium">{opt.label}</span>
              </div>
              {opt.desc && <span className="text-xs opacity-60">{opt.desc}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

const SPEED_MS   = { instant: 0, fast: 200, normal: 550, slow: 1400 }
const TIMING     = { smooth: 'ease-out', pulse: 'ease-in-out', stepped: 'steps(6, end)', stripe: 'linear', shine: 'linear' }
const SIM_PIN    = ['F','1','T','5','F','8']
const FONT_MAP   = { segoe: '"Segoe UI", system-ui, sans-serif', mono: '"Consolas","JetBrains Mono",monospace', inter: '"Inter",system-ui,sans-serif', roboto: '"Roboto","Segoe UI",sans-serif' }
const CORNER_MAP = { sharp: 4, rounded: 10, soft: 18, pill: 32 }
const BORDER_W   = { none: 0, thin: 1, normal: 2, thick: 3 }
const BAR_H      = { slim: 2, normal: 6, thick: 10, chunky: 16 }
const FONT_SZ    = { small: 11, normal: 13, large: 15 }
const LET_SP     = { normal: 'normal', wide: '0.06em', ultra: '0.16em' }
const PIN_CHARS  = { dot: { f: '●', e: '○' }, square: { f: '■', e: '□' }, asterisk: { f: '★', e: '☆' }, block: { f: '█', e: '░' } }
const DONE_ICONS = { check: '✓', shield: '⊛', star: '★', ring: '◉' }

const ANIM_CSS = `
@keyframes ztGlowPulse {
  0%, 100% { opacity: 0.3; }
  50%       { opacity: 0.9; }
}
@keyframes ztGlitch {
  0%, 5%, 100% { clip-path: none; transform: none; filter: none; }
  1%   { clip-path: inset(10% 0 80% 0);  transform: translate(-4px, 0); filter: hue-rotate(40deg); }
  2%   { clip-path: inset(65% 0 10% 0);  transform: translate(4px, 0);  filter: hue-rotate(-40deg); }
  3%   { clip-path: inset(35% 0 52% 0);  transform: translate(-2px, 0); filter: none; }
  4%   { clip-path: inset(50% 0 28% 0);  transform: translate(2px, 0); }
}
@keyframes ztBarGlow {
  0%, 100% { filter: brightness(1) saturate(1); }
  50%       { filter: brightness(1.45) saturate(1.5); }
}
@keyframes ztStripe {
  from { background-position: 0 0; }
  to   { background-position: 40px 0; }
}
@keyframes ztShine {
  from { background-position: -200% 0; }
  to   { background-position: 200% 0; }
}
@keyframes ztDotPop {
  0%   { transform: scale(1); }
  40%  { transform: scale(1.4); }
  100% { transform: scale(1); }
}
@keyframes ztSegSpin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
@keyframes ztVideoIcon {
  0%, 100% { opacity: 0.5; }
  50%       { opacity: 1; }
}
@keyframes ztDonePop {
  0%   { transform: scale(0.4); opacity: 0; }
  60%  { transform: scale(1.18); opacity: 1; }
  100% { transform: scale(1); }
}
@keyframes ztDoneBounce {
  0%, 100% { transform: translateY(0); }
  25%       { transform: translateY(-10px); }
  55%       { transform: translateY(-5px); }
  80%       { transform: translateY(-2px); }
}
@keyframes ztDoneSpin {
  from { transform: rotate(-30deg) scale(0.8); opacity: 0; }
  to   { transform: rotate(0deg)   scale(1);   opacity: 1; }
}
@keyframes ztWave0 { 0%,100%{height:4px} 50%{height:26px} }
@keyframes ztWave1 { 0%,100%{height:12px} 50%{height:32px} }
@keyframes ztWave2 { 0%,100%{height:6px} 50%{height:20px} }
@keyframes ztWave3 { 0%,100%{height:18px} 50%{height:10px} }
@keyframes ztWave4 { 0%,100%{height:8px} 50%{height:28px} }
@keyframes ztWave5 { 0%,100%{height:3px} 50%{height:22px} }
@keyframes ztSweep {
  0%   { top: -4px; opacity: 0.9; }
  90%  { opacity: 0.9; }
  100% { top: 100%; opacity: 0; }
}
@keyframes ztTermBlink {
  0%,100%{opacity:1} 50%{opacity:0}
}
@keyframes ztHudPing {
  0%   { transform: scale(0.8); opacity: 1; }
  100% { transform: scale(1.5); opacity: 0; }
}
@keyframes ztSpinRot {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
`

function GuiPreview({ s }) {
  const def  = defaultToolStyle()
  const c    = s.colors
  const anim = { ...def.animations, ...(s.animations || {}) }
  const fr   = { ...def.frame,      ...(s.frame      || {}) }
  const typo = { ...def.typography, ...(s.typography || {}) }
  const pin  = { ...def.pinField,   ...(s.pinField   || {}) }
  const bar  = { ...def.bar,        ...(s.bar        || {}) }
  const dn   = { ...def.done,       ...(s.done       || {}) }
  const { speed, barStyle, barShape, scanLayout, scanSweep, intro, bgEffect, glowAccent, glitchText } = anim
  const iv     = s.introVideo || { enabled: false, path: '' }
  const durMs  = SPEED_MS[speed] ?? 550
  const timing = TIMING[barStyle] ?? 'ease-out'
  const animKey = `${speed}|${barStyle}|${barShape}|${scanLayout}|${scanSweep}|${intro}|${bgEffect}|${glowAccent}|${glitchText}|${iv.enabled}|${JSON.stringify(fr)}|${JSON.stringify(typo)}|${JSON.stringify(pin)}|${JSON.stringify(bar)}|${JSON.stringify(dn)}`

  // Derived values
  const cornerR   = CORNER_MAP[fr.cornerRadius] ?? 10
  const borderW   = BORDER_W[fr.borderWidth]    ?? 0
  const borderClr = fr.borderColor || c.titlebar
  const shadowVal = { none: 'none', soft: '0 8px 32px rgba(0,0,0,0.45)', strong: '0 16px 56px rgba(0,0,0,0.75)', neon: `0 0 28px ${c.accent}55, 0 8px 40px rgba(0,0,0,0.6)` }[fr.shadow] ?? 'none'
  const fontFam   = FONT_MAP[typo.font]    ?? FONT_MAP.segoe
  const fontSzPx  = FONT_SZ[typo.size]    ?? 13
  const letSp     = LET_SP[typo.spacing]  ?? 'normal'
  const barHPx    = BAR_H[bar.height]     ?? 6
  const barCapR   = bar.caps === 'round' ? 999 : 0
  const trackClr  = bar.trackColor || c.background
  const pinCh     = PIN_CHARS[pin.char] ?? PIN_CHARS.dot
  const doneClr   = dn.color || c.accent
  const doneIcon  = DONE_ICONS[dn.icon] ?? '✓'
  const doneAnimCSS = { none: 'none', pop: 'ztDonePop 0.5s ease forwards', bounce: 'ztDoneBounce 0.6s ease 0.1s both', spin: 'ztDoneSpin 0.5s ease forwards' }[dn.anim] ?? 'none'

  const [imgErr,     setImgErr]     = useState(false)
  const [tick,       setTick]       = useState(0)
  const [visible,    setVisible]    = useState(false)
  const [stage,      setStage]      = useState('intro-video') // 'intro-video' | 'pin' | 'scanning' | 'done'
  const [pinDisplay, setPinDisplay] = useState('')
  const [bar1,       setBar1]       = useState(0)
  const [bar2,       setBar2]       = useState(0)

  useEffect(() => setImgErr(false), [s.logoUrl])

  useEffect(() => {
    setVisible(false); setStage(iv.enabled ? 'intro-video' : 'pin'); setPinDisplay(''); setBar1(0); setBar2(0)
    const ts = []
    const at = (fn, d) => ts.push(setTimeout(fn, d))

    const introDur = durMs === 0 ? 0 : Math.max(durMs, 150)

    let offset = 0
    if (iv.enabled) {
      // Simulate a ~2s intro video then fade to scanner
      at(() => setVisible(true), 50)
      at(() => { setStage('pin'); setVisible(false) }, 2000)
      offset = 2200
    }

    at(() => setVisible(true), offset + 50)
    const pinStart = offset + introDur + 350
    SIM_PIN.forEach((_, i) => at(() => setPinDisplay(SIM_PIN.slice(0, i + 1).join('')), pinStart + i * 130))

    const scanStart = pinStart + SIM_PIN.length * 130 + 550
    const step = Math.max(durMs, 200)
    at(() => setStage('scanning'), scanStart)
    at(() => setBar1(38), scanStart + 80)
    at(() => setBar1(72), scanStart + step + 200)
    at(() => setBar2(45), scanStart + step + 350)
    at(() => setBar1(100), scanStart + step * 2 + 300)
    at(() => setBar2(88), scanStart + step * 2 + 400)
    at(() => setBar2(100), scanStart + step * 2 + Math.max(step, 300) + 250)

    const doneAt = scanStart + step * 2 + Math.max(step, 300) + 700
    at(() => setStage('done'), doneAt)
    at(() => setTick(t => t + 1), doneAt + 2200)

    return () => ts.forEach(clearTimeout)
  }, [tick, animKey]) // eslint-disable-line react-hooks/exhaustive-deps

  const showCustom = !s.useDefaultLogo && !!s.logoUrl && !imgErr

  const introStyle = intro === 'fade'
    ? { opacity: visible ? 1 : 0, transition: `opacity ${Math.max(durMs, 200)}ms ease` }
    : intro === 'slide'
    ? { opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(16px)', transition: `opacity ${Math.max(durMs, 200)}ms ease, transform ${Math.max(durMs, 200)}ms ease` }
    : {}

  const accentTextStyle = glowAccent
    ? { textShadow: `0 0 10px ${c.accent}cc, 0 0 28px ${c.accent}44` }
    : {}

  const barFill = (w) => {
    const base = { width: `${w}%`, transition: durMs === 0 ? 'none' : `width ${durMs}ms ${timing}` }
    const glow = glowAccent && w > 0 ? { boxShadow: `0 0 8px 3px ${c.accent}66, 0 0 22px 6px ${c.accent}22` } : {}
    switch (barStyle) {
      case 'pulse': return { ...base, ...glow, background: `linear-gradient(90deg, ${c.accent}99, ${c.accent}, ${c.accent}99)`, animation: w > 0 ? 'ztBarGlow 1.5s ease-in-out infinite' : 'none' }
      case 'stripe': return { ...base, backgroundImage: `repeating-linear-gradient(-45deg, ${c.accent} 0, ${c.accent} 8px, ${c.accent}bb 8px, ${c.accent}bb 16px)`, backgroundSize: '40px 100%', animation: w > 0 ? 'ztStripe 0.7s linear infinite' : 'none' }
      case 'shine':  return { ...base, ...glow, background: `linear-gradient(90deg, ${c.accent}bb, ${c.accent} 40%, #ffffff99 50%, ${c.accent} 60%, ${c.accent}bb)`, backgroundSize: '200% 100%', animation: w > 0 ? 'ztShine 1.8s linear infinite' : 'none' }
      default:       return { ...base, ...glow, background: c.accent, animation: glowAccent && w > 0 ? 'ztBarGlow 2s ease-in-out infinite' : 'none' }
    }
  }

  const ringProgress = (w, size = 54, sw = 5) => {
    const r = (size - sw) / 2
    const circ = 2 * Math.PI * r
    const offset = circ * (1 - w / 100)
    const shadow = glowAccent && w > 0 ? `drop-shadow(0 0 4px ${c.accent}bb)` : 'none'
    return { r, circ, offset, size, sw, shadow }
  }

  const bodyStyle = {
    fontFamily: fontFam,
    fontSize: fontSzPx,
    letterSpacing: letSp,
  }

  // Path simulation text based on scan progress
  const scanPaths = [
    'C:\\Users\\Player\\AppData\\Local\\FiveM\\FiveM.app\\data',
    'HKCU\\Software\\FiveM\\Addons',
    'Scanning running processes…',
    'C:\\Users\\Player\\Downloads\\mods',
  ]
  const pathIdx = Math.floor((bar1 / 100) * scanPaths.length)
  const simPath = scanPaths[Math.min(pathIdx, scanPaths.length - 1)]
  const overallPct = Math.round((bar1 + bar2) / 2)

  return (
    <div>
      <style>{ANIM_CSS}</style>

      {/* ── Scanner window card ── */}
      <div style={{
        borderRadius: Math.max(cornerR, 14),
        border: borderW > 0 ? `${borderW}px solid ${borderClr}` : `1px solid ${c.accent}40`,
        boxShadow: shadowVal !== 'none' ? shadowVal : '0 16px 48px rgba(0,0,0,0.55)',
        overflow: 'hidden',
        opacity: fr.opacity / 100,
        background: c.mutedBackground,
        position: 'relative',
        ...introStyle,
      }}>
        {/* Top accent gradient line */}
        <div style={{ height: 2, background: `linear-gradient(90deg, transparent, ${c.accent}, transparent)` }} />

        {/* ── Intro video (full overlay on right column) ── */}
        {stage === 'intro-video' && (
          <div style={{ display: 'flex', minHeight: 170 }}>
            {/* Left always shown */}
            <div style={{ width: '36%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '14px 10px', position: 'relative', flexShrink: 0, background: c.mutedBackground }}>
              {showCustom ? (
                <img src={s.logoUrl} alt="logo" onError={() => setImgErr(true)} style={{ height: 46, maxWidth: 110, objectFit: 'contain', marginBottom: 4 }} />
              ) : (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                    <svg width="30" height="30" viewBox="0 0 38 38" style={{ flexShrink: 0 }}>
                      <ellipse cx="19" cy="19" rx="17.8" ry="17.8" fill="none" stroke={c.accent} strokeWidth="2.4" />
                      <ellipse cx="19" cy="19" rx="5.5" ry="5.5" fill="none" stroke={c.accent} strokeWidth="2" />
                      <ellipse cx="19" cy="19" rx="2" ry="2" fill={c.accent} />
                    </svg>
                    <span style={{ fontSize: 17, fontWeight: 'bold', lineHeight: 1 }}>
                      <span style={{ color: c.accent, animation: glitchText ? 'ztGlitch 7s step-start infinite' : 'none', ...accentTextStyle }}>Zero</span>
                      <span style={{ color: '#8A9AAA' }}>Trace</span>
                    </span>
                  </div>
                  <div style={{ color: '#5A6772', fontSize: 10 }}>Host-Scanner</div>
                  <div style={{ color: '#46505C', fontSize: 9, textAlign: 'center', marginTop: 3, lineHeight: 1.4, maxWidth: 110 }}>Lokale Cheat- &amp; Manipulations-Analyse</div>
                  <div style={{ color: '#3A444E', fontSize: 9, marginTop: 6 }}>{s.version || 'v1.3'}</div>
                </>
              )}
              {!s.useDefaultLogo && s.logoUrl && imgErr && (
                <p style={{ fontSize: 9, color: '#ef4444', marginTop: 4, textAlign: 'center' }}>Logo-Fehler</p>
              )}
              <div style={{ position: 'absolute', right: 0, top: '15%', bottom: '15%', width: 1, background: '#242A33' }} />
            </div>
            {/* Right: video */}
            <div className="flex flex-col items-center justify-center gap-2 flex-1" style={{ background: '#000' }}>
              <div style={{ animation: 'ztVideoIcon 1s ease-in-out infinite', color: c.accent, fontSize: 28 }}>▶</div>
              <p className="text-[10px] font-mono" style={{ color: c.mutedText }}>{iv.path || 'intro.mp4'}</p>
            </div>
          </div>
        )}

        {/* ── Main scanner body ── */}
        {stage !== 'intro-video' && (
          <div style={{ display: 'flex', position: 'relative', minHeight: 170 }}>
            {/* Background effects */}
            <div style={{ position: 'absolute', inset: 0, background: c.background }} />
            {bgEffect === 'scanlines' && (
              <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.13) 2px, rgba(0,0,0,0.13) 4px)' }} />
            )}
            {bgEffect === 'grid' && (
              <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', backgroundImage: `linear-gradient(${c.accent}16 1px, transparent 1px), linear-gradient(90deg, ${c.accent}16 1px, transparent 1px)`, backgroundSize: '22px 22px' }} />
            )}
            {bgEffect === 'glow-pulse' && (
              <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', background: `radial-gradient(65% 55% at 50% 30%, ${c.accent}2c, transparent)`, animation: 'ztGlowPulse 3s ease-in-out infinite' }} />
            )}

            {/* Close button */}
            <div style={{ position: 'absolute', top: 8, right: 10, color: '#5A6772', fontSize: 11, zIndex: 2 }}>✕</div>

            {/* Left branding column */}
            <div style={{ width: '36%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '14px 10px', position: 'relative', flexShrink: 0, zIndex: 1 }}>
              {showCustom ? (
                <img src={s.logoUrl} alt="logo" onError={() => setImgErr(true)} style={{ height: 46, maxWidth: 110, objectFit: 'contain', marginBottom: 4 }} />
              ) : (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                    <svg width="30" height="30" viewBox="0 0 38 38" style={{ flexShrink: 0 }}>
                      <ellipse cx="19" cy="19" rx="17.8" ry="17.8" fill="none" stroke={c.accent} strokeWidth="2.4" />
                      <ellipse cx="19" cy="19" rx="5.5" ry="5.5" fill="none" stroke={c.accent} strokeWidth="2" />
                      <ellipse cx="19" cy="19" rx="2" ry="2" fill={c.accent} />
                    </svg>
                    <span style={{ fontSize: 17, fontWeight: 'bold', lineHeight: 1 }}>
                      <span style={{ color: c.accent, animation: glitchText ? 'ztGlitch 7s step-start infinite' : 'none', ...accentTextStyle }}>Zero</span>
                      <span style={{ color: '#8A9AAA' }}>Trace</span>
                    </span>
                  </div>
                  <div style={{ color: '#5A6772', fontSize: 10 }}>Host-Scanner</div>
                  <div style={{ color: '#46505C', fontSize: 9, textAlign: 'center', marginTop: 3, lineHeight: 1.4, maxWidth: 110 }}>Lokale Cheat- &amp; Manipulations-Analyse</div>
                  <div style={{ color: '#3A444E', fontSize: 9, marginTop: 6 }}>{s.version || 'v1.3'}</div>
                </>
              )}
              {!s.useDefaultLogo && s.logoUrl && imgErr && (
                <p style={{ fontSize: 9, color: '#ef4444', marginTop: 4, textAlign: 'center' }}>Logo-Fehler</p>
              )}
              {/* Vertical divider */}
              <div style={{ position: 'absolute', right: 0, top: '15%', bottom: '15%', width: 1, background: '#242A33' }} />
            </div>

            {/* Right flow column */}
            <div style={{ flex: 1, padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1, ...bodyStyle }}>

              {/* PIN stage */}
              {stage === 'pin' && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                  <div style={{ border: '1px solid #2A3038', borderRadius: 11, padding: '12px 14px', background: 'rgba(0,0,0,0.02)' }}>
                    <p style={{ color: '#8A9AAA', fontSize: 10, textAlign: 'center', marginBottom: 10 }}>{s.text?.pin || 'Gib deinen 6-stelligen PIN ein'}</p>
                    <div style={{ display: 'flex', gap: 5, justifyContent: 'center' }}>
                      {SIM_PIN.map((_, i) => {
                        const filled = i < pinDisplay.length
                        return (
                          <div key={i} style={{
                            width: 26, height: 30, borderRadius: 5, flexShrink: 0,
                            border: `1px solid ${filled ? c.accent + '88' : '#3A4350'}`,
                            background: 'transparent',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: 13, fontWeight: 'bold', color: '#C8D2DA',
                            transition: durMs === 0 ? 'none' : `border-color ${durMs * 0.5}ms ease`,
                            boxShadow: glowAccent && filled ? `0 0 6px ${c.accent}55` : 'none',
                            ...accentTextStyle,
                          }}>
                            {filled ? pinCh.f : ''}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                  <div style={{ background: c.accent, color: '#0E1418', fontSize: 11, fontWeight: '600', borderRadius: 6, padding: '6px 20px', opacity: pinDisplay.length < 6 ? 0.4 : 1 }}>
                    Weiter
                  </div>
                </div>
              )}

              {/* Scanning stage */}
              {stage === 'scanning' && (
                <div style={{ position: 'relative', width: '100%' }}>
                  {/* Real scanner header: "X% LÄUFT" */}
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 8 }}>
                    <span style={{ color: '#C8D4DC', fontSize: 12, fontWeight: 'bold', fontFamily: 'monospace', minWidth: 34 }}>{overallPct}%</span>
                    <span style={{ color: '#5A6772', fontSize: 10, letterSpacing: '0.06em' }}>LÄUFT</span>
                  </div>
                  {/* Scan sweep line */}
                  {scanSweep && (
                    <div style={{
                      position: 'absolute', left: 0, right: 0, height: 2, zIndex: 10, pointerEvents: 'none',
                      background: `linear-gradient(90deg, transparent, ${c.accent}cc, transparent)`,
                      boxShadow: `0 0 8px 2px ${c.accent}88`,
                      animation: `ztSweep ${Math.max(durMs * 2, 1200)}ms linear infinite`,
                    }} />
                  )}

                  {/* ── Layout: Cards ── */}
                  {(scanLayout === 'cards' || !scanLayout) && (
                    <div className="space-y-4">
                      {[{ label: s.text.scanning, w: bar1 }, { label: s.text.heuristic, w: bar2 }].map((step, i) => {
                        const rp = ringProgress(step.w)
                        return (
                          <div key={i} className="rounded-lg p-4" style={{ background: c.mutedBackground }}>
                            <div className="flex items-center justify-between mb-3">
                              <p className="text-sm" style={{ color: c.text }}>{step.label}</p>
                              <p className="text-xs font-mono" style={{ color: c.mutedText }}>{Math.round(step.w)}%</p>
                            </div>
                            {barShape === 'bar' && (
                              <div className="w-full overflow-hidden" style={{ height: barHPx, borderRadius: barCapR, background: trackClr }}>
                                <div style={{ ...barFill(step.w), height: '100%', borderRadius: barCapR }} />
                              </div>
                            )}
                            {barShape === 'ring' && (
                              <div className="flex items-center gap-4">
                                <svg width={rp.size} height={rp.size} style={{ transform: 'rotate(-90deg)', flexShrink: 0, filter: rp.shadow }}>
                                  <circle cx={rp.size/2} cy={rp.size/2} r={rp.r} fill="none" stroke={trackClr || c.accent + '22'} strokeWidth={rp.sw} />
                                  <circle cx={rp.size/2} cy={rp.size/2} r={rp.r} fill="none" stroke={c.accent} strokeWidth={rp.sw}
                                    strokeDasharray={rp.circ} strokeDashoffset={rp.offset} strokeLinecap={bar.caps === 'round' ? 'round' : 'butt'}
                                    style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs}ms ${timing}` }} />
                                </svg>
                                <div className="flex-1 overflow-hidden" style={{ height: barHPx, borderRadius: barCapR, background: trackClr }}>
                                  <div style={{ ...barFill(step.w), height: '100%', borderRadius: barCapR }} />
                                </div>
                              </div>
                            )}
                            {barShape === 'dots' && (
                              <div className="flex flex-wrap gap-1.5 pt-0.5">
                                {Array.from({ length: 14 }, (_, j) => {
                                  const filled = step.w >= ((j + 1) / 14 * 100)
                                  return (
                                    <div key={j} className="rounded-full" style={{
                                      width: 9, height: 9,
                                      background: filled ? c.accent : c.accent + '22',
                                      boxShadow: glowAccent && filled ? `0 0 6px 2px ${c.accent}88` : 'none',
                                      transition: durMs === 0 ? 'none' : `background ${Math.max(durMs * 0.4, 120)}ms ease`,
                                      animation: glowAccent && filled ? 'ztDotPop 0.3s ease' : 'none',
                                    }} />
                                  )
                                })}
                              </div>
                            )}
                            {barShape === 'segments' && (
                              <div className="flex items-center gap-3">
                                <div style={{ position: 'relative', width: 50, height: 50, flexShrink: 0 }}>
                                  <svg width={50} height={50} style={{ position: 'absolute', inset: 0, animation: step.w > 0 ? 'ztSegSpin 1.4s linear infinite' : 'none' }}>
                                    {[0,1,2,3,4,5,6,7].map(seg => {
                                      const angle = (seg / 8) * 2 * Math.PI - Math.PI / 2
                                      const x = 25 + 18 * Math.cos(angle)
                                      const y = 25 + 18 * Math.sin(angle)
                                      const filled = (seg / 8 * 100) < step.w
                                      return (
                                        <circle key={seg} cx={x} cy={y} r={3.5}
                                          fill={filled ? c.accent : c.accent + '30'}
                                          style={{ filter: glowAccent && filled ? `drop-shadow(0 0 3px ${c.accent})` : 'none' }} />
                                      )
                                    })}
                                  </svg>
                                </div>
                                <div className="flex-1 h-1.5 overflow-hidden rounded-full" style={{ background: c.background }}>
                                  <div className="h-full rounded-full" style={barFill(step.w)} />
                                </div>
                              </div>
                            )}
                            {/* ── Arc (semicircle gauge) ── */}
                            {barShape === 'arc' && (() => {
                              const sw = 7, r = 36, totalW = 76
                              const circ = Math.PI * r
                              const off = circ * (1 - step.w / 100)
                              const arcD = `M ${sw / 2} ${r + sw / 2} A ${r} ${r} 0 0 0 ${totalW + sw / 2} ${r + sw / 2}`
                              const arcShadow = glowAccent && step.w > 0 ? `drop-shadow(0 0 4px ${c.accent}bb)` : 'none'
                              return (
                                <div style={{ display: 'flex', justifyContent: 'center', paddingTop: 2 }}>
                                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                                    <svg width={totalW + sw} height={r + sw + 2} style={{ overflow: 'visible' }}>
                                      <path d={arcD} fill="none" stroke={trackClr || c.accent + '22'} strokeWidth={sw}
                                        strokeLinecap={bar.caps === 'round' ? 'round' : 'butt'} />
                                      <path d={arcD} fill="none" stroke={c.accent} strokeWidth={sw}
                                        strokeLinecap={bar.caps === 'round' ? 'round' : 'butt'}
                                        strokeDasharray={circ} strokeDashoffset={off}
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs}ms ${timing}`, filter: arcShadow }} />
                                    </svg>
                                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: c.mutedText }}>{Math.round(step.w)}%</span>
                                  </div>
                                </div>
                              )
                            })()}
                            {/* ── Blocks (segmented rectangles) ── */}
                            {barShape === 'blocks' && (
                              <div style={{ display: 'flex', gap: 3 }}>
                                {Array.from({ length: 10 }, (_, j) => {
                                  const filled = step.w >= ((j + 1) / 10 * 100)
                                  return (
                                    <div key={j} style={{
                                      flex: 1, height: Math.max(barHPx, 8),
                                      background: filled ? c.accent : c.accent + '18',
                                      borderRadius: barCapR / 2,
                                      transition: durMs === 0 ? 'none' : `background ${Math.max(durMs * 0.4, 120)}ms ease`,
                                      boxShadow: glowAccent && filled ? `0 0 6px ${c.accent}88` : 'none',
                                    }} />
                                  )
                                })}
                              </div>
                            )}
                            {/* ── Steps (numbered progress circles) ── */}
                            {barShape === 'steps' && (
                              <div style={{ display: 'flex', alignItems: 'center' }}>
                                {[0, 1, 2, 3].map(j => {
                                  const done = step.w >= (j + 1) * 25
                                  return (
                                    <div key={j} style={{ display: 'flex', alignItems: 'center', flex: j < 3 ? 1 : undefined }}>
                                      <div style={{
                                        width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                                        background: done ? c.accent : 'transparent',
                                        border: `2px solid ${done ? c.accent : c.accent + '33'}`,
                                        color: done ? c.titlebar : c.mutedText,
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        fontSize: 11, fontWeight: 'bold', fontFamily: 'monospace',
                                        boxShadow: glowAccent && done ? `0 0 10px ${c.accent}88` : 'none',
                                        transition: durMs === 0 ? 'none' : `all ${durMs}ms ease`,
                                      }}>{done ? '✓' : j + 1}</div>
                                      {j < 3 && (
                                        <div style={{
                                          flex: 1, height: 2,
                                          background: step.w > (j + 1) * 25 ? c.accent : c.accent + '22',
                                          transition: durMs === 0 ? 'none' : `background ${durMs}ms ease`,
                                          boxShadow: glowAccent && step.w > (j + 1) * 25 ? `0 0 6px ${c.accent}88` : 'none',
                                        }} />
                                      )}
                                    </div>
                                  )
                                })}
                              </div>
                            )}
                            {/* ── Gauge (ring + big number) ── */}
                            {barShape === 'gauge' && (() => {
                              const rg = ringProgress(step.w, 58, 6)
                              return (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                                  <div style={{ position: 'relative', width: rg.size, height: rg.size, flexShrink: 0 }}>
                                    <svg width={rg.size} height={rg.size} style={{ transform: 'rotate(-90deg)', position: 'absolute', inset: 0, filter: rg.shadow }}>
                                      <circle cx={rg.size / 2} cy={rg.size / 2} r={rg.r} fill="none" stroke={trackClr || c.accent + '22'} strokeWidth={rg.sw} />
                                      <circle cx={rg.size / 2} cy={rg.size / 2} r={rg.r} fill="none" stroke={c.accent} strokeWidth={rg.sw}
                                        strokeDasharray={rg.circ} strokeDashoffset={rg.offset} strokeLinecap={bar.caps === 'round' ? 'round' : 'butt'}
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs}ms ${timing}` }} />
                                    </svg>
                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                                      <span style={{ color: c.accent, fontSize: 14, fontWeight: 'bold', fontFamily: 'monospace', lineHeight: 1, textShadow: glowAccent ? `0 0 10px ${c.accent}` : 'none' }}>{Math.round(step.w)}</span>
                                      <span style={{ color: c.mutedText, fontSize: 8 }}>%</span>
                                    </div>
                                  </div>
                                  <p style={{ color: c.text, fontSize: 12 }}>{step.label}</p>
                                </div>
                              )
                            })()}
                            {/* ── Comet (trailing ring) ── */}
                            {barShape === 'comet' && (() => {
                              const sz = 58, sw = 3, r = (sz - sw) / 2
                              const circ = 2 * Math.PI * r
                              const pct = step.w
                              const mainOff  = circ * (1 - pct / 100)
                              const trailOff = circ * (1 - Math.max(0, pct - 18) / 100)
                              const tailOff  = circ * (1 - Math.max(0, pct - 36) / 100)
                              const cx = sz / 2, cy = sz / 2
                              const angle  = (pct / 100) * 2 * Math.PI - Math.PI / 2
                              const dotX = cx + r * Math.cos(angle)
                              const dotY = cy + r * Math.sin(angle)
                              const glowFilter = glowAccent && pct > 0 ? `drop-shadow(0 0 5px ${c.accent}cc)` : 'none'
                              return (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                                  <div style={{ position: 'relative', width: sz, height: sz, flexShrink: 0 }}>
                                    <svg width={sz} height={sz} style={{ transform: 'rotate(-90deg)', position: 'absolute', inset: 0 }}>
                                      {/* track */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent + '14'} strokeWidth={sw} />
                                      {/* far tail — slowest */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent + '28'} strokeWidth={sw + 1}
                                        strokeDasharray={circ} strokeDashoffset={tailOff} strokeLinecap="round"
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs * 1.5}ms ${timing}` }} />
                                      {/* mid trail */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent + '55'} strokeWidth={sw}
                                        strokeDasharray={circ} strokeDashoffset={trailOff} strokeLinecap="round"
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs * 1.2}ms ${timing}` }} />
                                      {/* main arc — fastest */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent} strokeWidth={sw}
                                        strokeDasharray={circ} strokeDashoffset={mainOff} strokeLinecap="round"
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs}ms ${timing}` }} />
                                    </svg>
                                    {/* leading dot */}
                                    {pct > 1 && (
                                      <svg width={sz} height={sz} style={{ position: 'absolute', inset: 0, filter: glowFilter }}>
                                        <circle cx={dotX} cy={dotY} r={3.5} fill={c.accent}
                                          style={{ transition: durMs === 0 ? 'none' : `cx ${durMs}ms ${timing}, cy ${durMs}ms ${timing}` }} />
                                      </svg>
                                    )}
                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                      <span style={{ color: c.mutedText, fontSize: 10, fontFamily: 'monospace' }}>{Math.round(pct)}%</span>
                                    </div>
                                  </div>
                                  <p style={{ color: c.text, fontSize: 12 }}>{step.label}</p>
                                </div>
                              )
                            })()}
                            {/* ── Donut (ultra-thin clean ring) ── */}
                            {barShape === 'donut' && (() => {
                              const sz = 58, sw = 2.5, r = (sz - sw) / 2
                              const circ = 2 * Math.PI * r
                              const off = circ * (1 - step.w / 100)
                              const glowFilter = glowAccent && step.w > 0 ? `drop-shadow(0 0 3px ${c.accent}99)` : 'none'
                              return (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                                  <div style={{ position: 'relative', width: sz, height: sz, flexShrink: 0 }}>
                                    <svg width={sz} height={sz} style={{ transform: 'rotate(-90deg)', position: 'absolute', inset: 0 }}>
                                      <circle cx={sz / 2} cy={sz / 2} r={r} fill="none" stroke={c.accent + '18'} strokeWidth={sw} />
                                      <circle cx={sz / 2} cy={sz / 2} r={r} fill="none" stroke={c.accent} strokeWidth={sw}
                                        strokeDasharray={circ} strokeDashoffset={off} strokeLinecap="round"
                                        style={{ transition: durMs === 0 ? 'none' : `stroke-dashoffset ${durMs}ms ${timing}`, filter: glowFilter }} />
                                    </svg>
                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 0 }}>
                                      <span style={{ color: c.text, fontSize: 13, fontWeight: '600', lineHeight: 1 }}>{Math.round(step.w)}</span>
                                      <span style={{ color: c.mutedText, fontSize: 8, marginTop: 1 }}>%</span>
                                    </div>
                                  </div>
                                  <p style={{ color: c.text, fontSize: 12 }}>{step.label}</p>
                                </div>
                              )
                            })()}
                            {/* ── Glass (bar with label inside fill) ── */}
                            {barShape === 'glass' && (
                              <div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                                  <span style={{ color: c.mutedText, fontSize: 11 }}>{step.label}</span>
                                </div>
                                <div style={{
                                  position: 'relative', height: Math.max(barHPx, 18),
                                  borderRadius: barCapR, background: c.accent + '14',
                                  overflow: 'hidden',
                                }}>
                                  <div style={{
                                    position: 'absolute', inset: 0, right: `${100 - step.w}%`,
                                    background: `linear-gradient(90deg, ${c.accent}cc, ${c.accent})`,
                                    borderRadius: barCapR,
                                    transition: durMs === 0 ? 'none' : `right ${durMs}ms ${timing}`,
                                    boxShadow: glowAccent && step.w > 0 ? `0 0 12px ${c.accent}66` : 'none',
                                  }} />
                                  <span style={{
                                    position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                                    fontSize: 10, fontWeight: '600', fontFamily: 'monospace',
                                    color: step.w > 85 ? c.titlebar : c.accent,
                                    transition: durMs === 0 ? 'none' : `color ${durMs}ms ease`,
                                  }}>{Math.round(step.w)}%</span>
                                </div>
                              </div>
                            )}
                            {/* ── Line (thin line + glowing leading dot) ── */}
                            {barShape === 'line' && (
                              <div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                  <span style={{ color: c.mutedText, fontSize: 11 }}>{step.label}</span>
                                  <span style={{ color: c.accent, fontSize: 11, fontFamily: 'monospace' }}>{Math.round(step.w)}%</span>
                                </div>
                                <div style={{ position: 'relative', height: 12, display: 'flex', alignItems: 'center' }}>
                                  {/* track */}
                                  <div style={{ position: 'absolute', left: 0, right: 0, height: 1, background: c.accent + '20', borderRadius: 1 }} />
                                  {/* filled line */}
                                  <div style={{
                                    position: 'absolute', left: 0, height: 1,
                                    width: `${step.w}%`, background: c.accent,
                                    borderRadius: 1,
                                    transition: durMs === 0 ? 'none' : `width ${durMs}ms ${timing}`,
                                  }} />
                                  {/* leading dot */}
                                  {step.w > 0 && (
                                    <div style={{
                                      position: 'absolute', width: 8, height: 8, borderRadius: '50%',
                                      background: c.accent,
                                      left: `calc(${step.w}% - 4px)`,
                                      boxShadow: glowAccent ? `0 0 8px ${c.accent}, 0 0 16px ${c.accent}88` : `0 0 4px ${c.accent}99`,
                                      transition: durMs === 0 ? 'none' : `left ${durMs}ms ${timing}`,
                                    }} />
                                  )}
                                </div>
                              </div>
                            )}
                            {/* ── Spinner (endlos drehender Schweif-Ring) ── */}
                            {barShape === 'spinner' && (() => {
                              const sz = 58, sw = 3, r = (sz - sw) / 2
                              const circ = 2 * Math.PI * r
                              const cx = sz / 2, cy = sz / 2
                              const spinDur = Math.max(1000, durMs === 0 ? 1000 : durMs * 1.8)
                              const arc = (pct) => `${circ * pct} ${circ * (1 - pct)}`
                              const rotStyle = (multiplier) => ({
                                transformOrigin: `${cx}px ${cy}px`,
                                animation: `ztSpinRot ${spinDur * multiplier}ms linear infinite`,
                              })
                              return (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                                  <div style={{ position: 'relative', width: sz, height: sz, flexShrink: 0 }}>
                                    <svg width={sz} height={sz} style={{ position: 'absolute', inset: 0 }}>
                                      {/* track */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent + '14'} strokeWidth={sw} />
                                      {/* far tail — slowest, shortest, most transparent */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent}
                                        strokeWidth={sw + 1} strokeLinecap="round"
                                        strokeDasharray={arc(0.28)} opacity={0.18}
                                        style={rotStyle(1.22)} />
                                      {/* mid trail */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent}
                                        strokeWidth={sw} strokeLinecap="round"
                                        strokeDasharray={arc(0.48)} opacity={0.42}
                                        style={rotStyle(1.1)} />
                                      {/* main arc — fastest, brightest */}
                                      <circle cx={cx} cy={cy} r={r} fill="none" stroke={c.accent}
                                        strokeWidth={sw} strokeLinecap="round"
                                        strokeDasharray={arc(0.68)}
                                        style={{
                                          ...rotStyle(1),
                                          filter: glowAccent ? `drop-shadow(0 0 5px ${c.accent}cc)` : 'none',
                                        }} />
                                    </svg>
                                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                      <span style={{ color: c.mutedText, fontSize: 10, fontFamily: 'monospace' }}>{Math.round(step.w)}%</span>
                                    </div>
                                  </div>
                                  <p style={{ color: c.text, fontSize: 12 }}>{step.label}</p>
                                </div>
                              )
                            })()}
                          </div>
                        )
                      })}
                    </div>
                  )}

                  {/* ── Layout: Minimal ── */}
                  {scanLayout === 'minimal' && (
                    <div className="space-y-5 py-2">
                      {[{ label: s.text.scanning, w: bar1 }, { label: s.text.heuristic, w: bar2 }].map((step, i) => (
                        <div key={i}>
                          <div className="flex justify-between mb-1.5">
                            <span style={{ color: c.mutedText, fontSize: 11 }}>{step.label}</span>
                            <span style={{ color: c.accent, fontSize: 11, fontFamily: 'monospace' }}>{Math.round(step.w)}%</span>
                          </div>
                          <div style={{ height: barHPx, borderRadius: barCapR, background: trackClr, overflow: 'hidden' }}>
                            <div style={{ ...barFill(step.w), height: '100%', borderRadius: barCapR }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* ── Layout: Terminal ── */}
                  {scanLayout === 'terminal' && (
                    <div style={{
                      background: '#050810', border: `1px solid ${c.accent}33`, borderRadius: 6,
                      padding: '12px 16px', fontFamily: '"Consolas","JetBrains Mono",monospace', fontSize: 11,
                    }}>
                      <div className="flex items-center gap-2 mb-3 pb-2" style={{ borderBottom: `1px solid ${c.accent}22` }}>
                        <span style={{ color: c.accent, opacity: 0.6 }}>●</span>
                        <span style={{ color: c.accent, fontSize: 10, letterSpacing: '0.12em' }}>ZEROTRACE SCAN ENGINE — ACTIVE</span>
                      </div>
                      {[{ w: bar1, cmd: 'proc_scan()' }, { w: bar2, cmd: 'heur_check()' }].map((step, i) => (
                        <div key={i} style={{ marginBottom: i < 1 ? 10 : 0 }}>
                          <div style={{ color: c.mutedText, marginBottom: 3 }}>
                            <span style={{ color: c.accent + 'aa' }}>{'> '}</span>
                            <span>{step.cmd}</span>
                            {step.w < 100 && <span style={{ animation: 'ztTermBlink 0.8s step-start infinite', marginLeft: 4, color: c.accent }}>█</span>}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 14 }}>
                            <div style={{ flex: 1, height: barHPx, background: c.accent + '15', borderRadius: barCapR, overflow: 'hidden' }}>
                              <div style={{ ...barFill(step.w), height: '100%', borderRadius: barCapR }} />
                            </div>
                            <span style={{ color: c.accent, minWidth: 34, textAlign: 'right', fontSize: 11 }}>{Math.round(step.w)}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* ── Layout: HUD ── */}
                  {scanLayout === 'hud' && (
                    <div className="space-y-3">
                      {[{ w: bar1, id: 'PROC' }, { w: bar2, id: 'HEUR' }].map((step, i) => (
                        <div key={i} style={{ position: 'relative', padding: '10px 18px' }}>
                          <div style={{ position: 'absolute', top: 0, left: 0, width: 10, height: 10, borderTop: `2px solid ${c.accent}`, borderLeft: `2px solid ${c.accent}` }} />
                          <div style={{ position: 'absolute', top: 0, right: 0, width: 10, height: 10, borderTop: `2px solid ${c.accent}`, borderRight: `2px solid ${c.accent}` }} />
                          <div style={{ position: 'absolute', bottom: 0, left: 0, width: 10, height: 10, borderBottom: `2px solid ${c.accent}`, borderLeft: `2px solid ${c.accent}` }} />
                          <div style={{ position: 'absolute', bottom: 0, right: 0, width: 10, height: 10, borderBottom: `2px solid ${c.accent}`, borderRight: `2px solid ${c.accent}` }} />
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ position: 'relative', width: 8, height: 8, flexShrink: 0 }}>
                              <div style={{ width: 8, height: 8, borderRadius: '50%', background: c.accent, boxShadow: glowAccent ? `0 0 8px ${c.accent}` : 'none' }} />
                              {step.w < 100 && <div style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: c.accent + '44', animation: 'ztHudPing 1.4s ease-out infinite' }} />}
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                                <span style={{ color: c.mutedText, fontSize: 9, fontFamily: 'monospace', letterSpacing: '0.12em' }}>SYS.{step.id}</span>
                                <span style={{ color: c.accent, fontSize: 15, fontWeight: 'bold', fontFamily: 'monospace' }}>{Math.round(step.w).toString().padStart(3, '0')}</span>
                              </div>
                              <div style={{ height: barHPx, borderRadius: barCapR, background: c.accent + '15', overflow: 'hidden' }}>
                                <div style={{ ...barFill(step.w), height: '100%', borderRadius: barCapR }} />
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* ── Layout: Wave ── */}
                  {scanLayout === 'wave' && (
                    <div className="space-y-5 py-1">
                      {[{ label: s.text.scanning, w: bar1 }, { label: s.text.heuristic, w: bar2 }].map((step, i) => (
                        <div key={i}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                            <span style={{ color: c.text, fontSize: 12 }}>{step.label}</span>
                            <span style={{ color: c.accent, fontSize: 11, fontFamily: 'monospace' }}>{Math.round(step.w)}%</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', height: 36, gap: 2 }}>
                            {Array.from({ length: 20 }, (_, j) => {
                              const filled = step.w >= ((j + 1) / 20 * 100)
                              return (
                                <div key={j} style={{
                                  width: 3,
                                  height: filled && step.w < 100 ? undefined : 4,
                                  alignSelf: 'center',
                                  background: filled ? c.accent : c.accent + '1a',
                                  borderRadius: 2,
                                  animation: filled && step.w < 100 ? `ztWave${j % 6} ${(0.6 + (j % 5) * 0.15).toFixed(2)}s ease-in-out infinite` : 'none',
                                  boxShadow: glowAccent && filled ? `0 0 6px ${c.accent}88` : 'none',
                                  transition: `background ${Math.max(durMs * 0.3, 100)}ms ease`,
                                }} />
                              )
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Current path text (real scanner style) */}
                  <div style={{ marginTop: 10 }}>
                    <div style={{ color: '#5A6772', fontSize: 9, marginBottom: 3 }}>{s.text?.scanning || 'Scanne gerade'}</div>
                    <div style={{ color: '#C8D4DC', fontSize: 10, fontWeight: '600', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 220 }}>{simPath}</div>
                  </div>
                </div>
              )}

              {/* Done stage — SVG checkmark like real scanner */}
              {stage === 'done' && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                  <div style={{ animation: doneAnimCSS }}>
                    <svg width="72" height="72" viewBox="0 0 140 140">
                      <ellipse cx="70" cy="70" rx="55" ry="55" stroke={doneClr} strokeWidth="1.5" fill="none" opacity="0.15" />
                      <path stroke={doneClr} strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" fill="none"
                        d="M 38 70 L 58 90 L 102 48"
                        style={{ filter: glowAccent ? `drop-shadow(0 0 6px ${doneClr}cc)` : 'none' }} />
                    </svg>
                  </div>
                  <p style={{ color: '#C8D2DA', fontSize: 13, fontWeight: 'bold', textAlign: 'center' }}>{s.text?.finished || 'Scan abgeschlossen'}</p>
                  <p style={{ color: '#5A6772', fontSize: 9 }}>3 Funde · Bericht wird generiert…</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="mt-2 flex items-center justify-between px-0.5">
        <span className="muted text-[11px]">
          {stage === 'intro-video' ? 'Intro-Video' : stage === 'pin' ? 'PIN-Eingabe' : stage === 'scanning' ? 'Wird gescannt…' : 'Scan abgeschlossen'}
        </span>
        <button
          onClick={() => { setVisible(false); setStage(iv.enabled ? 'intro-video' : 'pin'); setPinDisplay(''); setBar1(0); setBar2(0); setTick(t => t + 1) }}
          className="muted flex items-center gap-1 text-[11px] hover:txt"
        >
          <Play size={10} /> Neu
        </button>
      </div>
    </div>
  )
}

const PREFIX = 'ZEROTRACEUI1.'
const LEGACY_PREFIX = 'OCEANUI1.'

// ── main component ───────────────────────────────────────────────────────────

export default function ToolDesigner({ embedded = false }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const saved = state.toolStyle || defaultToolStyle()

  const [s, setS] = useState(saved)
  const [importText, setImportText] = useState('')
  const [importUrl, setImportUrl] = useState('')
  const [urlLoading, setUrlLoading] = useState(false)
  const [harmonyMode, setHarmonyMode] = useState(false)
  const [dirHandle, setDirHandle] = useState(null)
  const [syncStatus, setSyncStatus] = useState('idle') // idle | syncing | synced | error | needs-permission

  const savedKey = useMemo(() => JSON.stringify(saved), [saved])
  useEffect(() => {
    setS((cur) => (JSON.stringify(cur) === savedKey ? cur : JSON.parse(savedKey)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedKey])

  // Restore persisted directory handle on mount
  useEffect(() => {
    if (!SUPPORTS_FS) return
    idbLoadHandle().then(async h => {
      if (!h) return
      try {
        const perm = await h.queryPermission({ mode: 'readwrite' })
        if (perm === 'granted') { setDirHandle(h); setSyncStatus('idle') }
        else setSyncStatus('needs-permission')
      } catch { /* stale handle, ignore */ }
    })
  }, [])

  // Auto-sync: write zerotrace-ui.json whenever settings change (debounced 700ms)
  useEffect(() => {
    if (!dirHandle) return
    setSyncStatus('syncing')
    const t = setTimeout(async () => {
      try {
        const perm = await dirHandle.queryPermission({ mode: 'readwrite' })
        if (perm !== 'granted') { setSyncStatus('needs-permission'); return }
        const delta = buildScannerDelta(s)
        await writeScannerJson(dirHandle, delta)
        setSyncStatus('synced')
      } catch {
        setSyncStatus('error')
      }
    }, 700)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s, dirHandle])

  const dirty = useMemo(() => JSON.stringify(s) !== savedKey, [s, savedKey])

  const set = (patch) => setS((cur) => ({ ...cur, ...patch }))

  const def   = defaultToolStyle()
  const anim  = { ...def.animations, ...(s.animations || {}) }
  const fr    = { ...def.frame,      ...(s.frame      || {}) }
  const typo  = { ...def.typography, ...(s.typography || {}) }
  const pinF  = { ...def.pinField,   ...(s.pinField   || {}) }
  const barD  = { ...def.bar,        ...(s.bar        || {}) }
  const doneD = { ...def.done,       ...(s.done       || {}) }
  const iv    = s.introVideo || def.introVideo

  const setAnim  = (p) => setS(c => ({ ...c, animations: { ...def.animations, ...(c.animations || {}), ...p } }))
  const setFr    = (p) => setS(c => ({ ...c, frame:      { ...def.frame,      ...(c.frame      || {}), ...p } }))
  const setTypo  = (p) => setS(c => ({ ...c, typography: { ...def.typography, ...(c.typography || {}), ...p } }))
  const setPinF  = (p) => setS(c => ({ ...c, pinField:   { ...def.pinField,   ...(c.pinField   || {}), ...p } }))
  const setBarD  = (p) => setS(c => ({ ...c, bar:        { ...def.bar,        ...(c.bar        || {}), ...p } }))
  const setDoneD = (p) => setS(c => ({ ...c, done:       { ...def.done,       ...(c.done       || {}), ...p } }))
  const setIv    = (p) => setS(c => ({ ...c, introVideo: { ...def.introVideo, ...(c.introVideo || {}), ...p } }))

  const setColor = (k, v) => {
    if (harmonyMode && k === 'background') {
      setS((cur) => ({
        ...cur,
        colors: {
          ...cur.colors,
          background: v,
          mutedBackground: shiftRgb(v, 15),
          titlebar: shiftRgb(v, -5),
        },
      }))
    } else {
      setS((cur) => ({ ...cur, colors: { ...cur.colors, [k]: v } }))
    }
  }

  const setText = (k, v) => setS((cur) => ({ ...cur, text: { ...cur.text, [k]: v } }))

  const exportCode = useMemo(
    () => PREFIX + btoa(unescape(encodeURIComponent(JSON.stringify(s)))),
    [s],
  )

  const linkDir = async () => {
    try {
      const h = await window.showDirectoryPicker({ mode: 'readwrite' })
      await idbSaveHandle(h)
      setDirHandle(h)
      const delta = buildScannerDelta(s)
      await writeScannerJson(h, delta)
      setSyncStatus('synced')
      toast({ type: 'success', title: 'Verzeichnis verknüpft', body: 'Änderungen werden ab jetzt automatisch übertragen.' })
    } catch (e) {
      if (e.name !== 'AbortError') toast({ type: 'error', title: 'Fehler beim Verknüpfen', body: e.message })
    }
  }

  const relinkDir = async () => {
    const h = await idbLoadHandle()
    if (!h) { setSyncStatus('idle'); return }
    try {
      const perm = await h.requestPermission({ mode: 'readwrite' })
      if (perm === 'granted') { setDirHandle(h); setSyncStatus('idle') }
    } catch { setSyncStatus('error') }
  }

  const unlinkDir = async () => {
    setDirHandle(null)
    setSyncStatus('idle')
    try { await idbSaveHandle(null) } catch {}
    toast({ type: 'info', title: 'Verknüpfung getrennt' })
  }

  const saveAll = async () => {
    dispatch({ type: 'save-tool-style', style: s })
    const delta = buildScannerDelta(s)
    const hasDelta = Object.keys(delta).length > 0
    if (dirHandle) {
      try {
        const perm = await dirHandle.queryPermission({ mode: 'readwrite' })
        if (perm === 'granted' && hasDelta) {
          await writeScannerJson(dirHandle, delta)
          setSyncStatus('synced')
        }
      } catch { /* sync will retry via effect */ }
      toast({ type: 'success', title: 'Gespeichert', body: 'Stil gespeichert und direkt zum Scanner übertragen.' })
    } else {
      if (hasDelta) downloadScannerJson(delta)
      toast({
        type: 'success',
        title: 'Gespeichert',
        body: hasDelta
          ? 'Stil gespeichert — zerotrace-ui.json heruntergeladen. Neben ZeroTrace.exe ablegen.'
          : 'Stil gespeichert (keine Abweichung von den Standardwerten)',
      })
    }
  }

  const parseStyleCode = (raw) => {
    const b64 = raw.startsWith(PREFIX)
      ? raw.slice(PREFIX.length)
      : raw.startsWith(LEGACY_PREFIX)
        ? raw.slice(LEGACY_PREFIX.length)
        : raw
    return JSON.parse(decodeURIComponent(escape(atob(b64))))
  }

  const doImport = () => {
    try {
      const obj = parseStyleCode(importText.trim())
      setS({ ...defaultToolStyle(), ...obj })
      toast({ type: 'success', title: 'Stil geladen', body: 'Alles speichern zum Übernehmen' })
      setImportText('')
    } catch (e) {
      toast({ type: 'error', title: 'Ungültiger Stil-Code', body: e.message })
    }
  }

  const doImportUrl = async () => {
    setUrlLoading(true)
    try {
      const res = await fetch(importUrl.trim())
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = (await res.text()).trim()
      let obj
      try {
        obj = parseStyleCode(text)
      } catch {
        obj = JSON.parse(text)
      }
      setS({ ...defaultToolStyle(), ...obj })
      toast({ type: 'success', title: 'Stil geladen', body: 'Alles speichern zum Übernehmen' })
      setImportUrl('')
    } catch (e) {
      toast({ type: 'error', title: 'Import fehlgeschlagen', body: e.message })
    } finally {
      setUrlLoading(false)
    }
  }

  // Contrast checks for the three most important pairs
  const contrastChecks = useMemo(() => [
    { label: 'Text / Hintergrund',     fg: s.colors.text,      bg: s.colors.background },
    { label: 'Gedämpft / Hintergrund', fg: s.colors.mutedText, bg: s.colors.background },
    { label: 'Text / Karten-BG',       fg: s.colors.text,      bg: s.colors.mutedBackground },
  ].map(({ label, fg, bg }) => ({ label, ratio: contrastRatio(fg, bg) })), [s.colors])

  const anyContrastFail = contrastChecks.some((c) => c.ratio < 4.5)

  return (
    <div>
      {!embedded && (
        <PageHeader
          icon={Wand2}
          kicker="Dashboard / Tool Designer"
          title="Tool Designer"
          subtitle="Passe das Aussehen des FiveM-Scanner-GUIs an. Änderungen werden gespeichert und erzeugen eine zerotrace-ui.json, die der Scanner automatisch lädt."
        />
      )}

      <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(340px,420px)]">
        {/* Options */}
        <Card className="p-6 md:p-8">
          <h3 className="txt mb-6 text-lg font-semibold">Alle Optionen</h3>

          {/* ── Preset themes ── */}
          <p className="caps-label mb-4">Vorgefertigte Themes</p>
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
            {PRESET_THEMES.map((theme) => (
              <button
                key={theme.label}
                onClick={() => set({ colors: theme.colors, ...(theme.animations ? { animations: theme.animations } : {}) })}
                title={theme.label}
                className="bd hoverable group flex flex-col items-center gap-2 rounded-xl border px-2 py-3 text-center transition-colors hover:border-sky-500"
              >
                <div className="flex gap-1">
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.background }} />
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.accent }} />
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.text }} />
                </div>
                <span className="txt text-[11px] font-medium leading-tight">{theme.label}</span>
              </button>
            ))}
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Logo ── */}
          <p className="caps-label mb-4">Logo</p>
          <div className="space-y-4">
            <Toggle label="ZeroTrace-Logo verwenden" checked={s.useDefaultLogo} onChange={(v) => set({ useDefaultLogo: v })} />
            <Field label="Eigene Logo-URL (gestreckt auf 600×300)">
              <input
                value={s.logoUrl}
                onChange={(e) => {
                  const url = e.target.value
                  set({ logoUrl: url, useDefaultLogo: url.trim() ? false : s.useDefaultLogo })
                }}
                placeholder="https://cdn.example.com/logo.png"
                className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none"
              />
              {s.logoUrl && !s.useDefaultLogo && (
                <p className="muted mt-1.5 text-xs">Eigenes Logo ist in der Vorschau aktiv.</p>
              )}
            </Field>
            <Toggle label="Spiel-Hintergrund" checked={s.gameBackground} onChange={(v) => set({ gameBackground: v })} />
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Colours ── */}
          <div className="mb-4 flex items-center justify-between">
            <p className="caps-label">Farben</p>
            <Toggle
              label="Harmonie-Modus"
              checked={harmonyMode}
              onChange={setHarmonyMode}
              accent
            />
          </div>
          {harmonyMode && (
            <p className="muted mb-4 rounded-lg bg-violet-500/10 px-3 py-2 text-xs text-violet-400">
              Harmonie-Modus aktiv — Karten-BG und Titelleiste werden automatisch aus der Hauptfarbe abgeleitet.
            </p>
          )}
          <div className="grid gap-5 sm:grid-cols-2">
            <ColorField label="Textfarbe" value={s.colors.text} onChange={(v) => setColor('text', v)} />
            <ColorField label="Gedämpfte Textfarbe" value={s.colors.mutedText} onChange={(v) => setColor('mutedText', v)} />
            <ColorField label="Hintergrundfarbe" value={s.colors.background} onChange={(v) => setColor('background', v)} />
            <ColorField
              label={harmonyMode ? 'Karten-BG (automatisch)' : 'Karten-Hintergrundfarbe'}
              value={s.colors.mutedBackground}
              onChange={(v) => setColor('mutedBackground', v)}
            />
            <ColorField
              label={harmonyMode ? 'Titelleiste (automatisch)' : 'Titelleistenfarbe'}
              value={s.colors.titlebar}
              onChange={(v) => setColor('titlebar', v)}
            />
            <ColorField label="Akzentfarbe" value={s.colors.accent} onChange={(v) => setColor('accent', v)} />
          </div>

          {/* Contrast check */}
          <div className={`bd mt-5 rounded-lg border p-4 ${anyContrastFail ? 'border-yellow-500/30 bg-yellow-500/5' : ''}`}>
            <p className="caps-label mb-3">Kontrast-Check (WCAG AA ≥ 4,5:1)</p>
            <div className="space-y-2">
              {contrastChecks.map(({ label, ratio }) => {
                const pass = ratio >= 4.5
                return (
                  <div key={label} className="flex items-center justify-between text-xs">
                    <span className="muted">{label}</span>
                    <span className={`flex items-center gap-1.5 font-mono font-semibold ${pass ? 'text-green-500' : 'text-yellow-400'}`}>
                      {ratio.toFixed(1)}:1
                      {pass ? <Check size={11} /> : <AlertTriangle size={11} />}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Text ── */}
          <p className="caps-label mb-4">Texte</p>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="PIN-Eingabe-Beschriftung">
              <input value={s.text.pin} onChange={(e) => setText('pin', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Scan-Text">
              <input value={s.text.scanning} onChange={(e) => setText('scanning', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Heuristik-Text">
              <input value={s.text.heuristic} onChange={(e) => setText('heuristic', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Abschluss-Text">
              <input value={s.text.finished} onChange={(e) => setText('finished', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Versionsbezeichnung">
              <input value={s.version} onChange={(e) => set({ version: e.target.value })} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Animationen & Effekte ── */}
          <p className="caps-label mb-4 flex items-center gap-2"><Zap size={12} /> Animationen & Effekte</p>

          {/* Animation quick-presets */}
          <p className="muted mb-2 text-xs">Schnell-Vorlagen</p>
          <div className="mb-5 flex flex-wrap gap-2">
            {ANIMATION_PRESETS.map(p => {
              const { label: _l, ...fields } = p
              const active = Object.entries(fields).every(([k, v]) => anim[k] === v)
              return (
                <button key={p.label} onClick={() => setAnim(p)}
                  className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                    active ? 'border-sky-500 bg-sky-600/20 text-sky-400' : 'bd tile muted hover:txt'
                  }`}>
                  {p.label}
                </button>
              )
            })}
          </div>

          {/* Speed */}
          <Field label="Animationsgeschwindigkeit">
            <DropSelect value={anim.speed} onChange={v => setAnim({ speed: v })} color="sky" options={[
              { value: 'instant', label: 'Keine',   desc: '0 ms',   icon: '⚡' },
              { value: 'fast',    label: 'Schnell', desc: '200 ms', icon: '▶' },
              { value: 'normal',  label: 'Normal',  desc: '550 ms', icon: '▷' },
              { value: 'slow',    label: 'Langsam', desc: '1,4 s',  icon: '◁' },
            ]} />
          </Field>

          {/* Bar style */}
          <Field label="Balken-Animation" className="mt-4">
            <DropSelect value={anim.barStyle} onChange={v => setAnim({ barStyle: v })} color="violet" options={[
              { value: 'smooth',  label: 'Flüssig',  desc: 'Klassisch',  icon: '▬' },
              { value: 'pulse',   label: 'Puls',     desc: 'Glühend',    icon: '◈' },
              { value: 'stripe',  label: 'Streifen', desc: 'Diagonal',   icon: '▧' },
              { value: 'shine',   label: 'Glanz',    desc: 'Lichtblitz', icon: '✦' },
              { value: 'stepped', label: 'Stufen',   desc: 'Diskret',    icon: '▮' },
            ]} />
          </Field>

          {/* Bar shape */}
          <Field label="Fortschritts-Form" className="mt-4">
            <DropSelect value={anim.barShape ?? 'bar'} onChange={v => setAnim({ barShape: v })} color="pink" options={[
              { value: 'bar',      label: 'Balken',   desc: 'Klassisch',    icon: '▬' },
              { value: 'glass',    label: 'Glass',    desc: 'Label innen',  icon: '▰' },
              { value: 'line',     label: 'Linie',    desc: 'Dot am Ende',  icon: '—•' },
              { value: 'spinner',  label: 'Spinner',  desc: 'Dreht immer',  icon: '↻' },
              { value: 'donut',    label: 'Donut',    desc: 'Dünner Ring',  icon: '◯' },
              { value: 'comet',    label: 'Komet',    desc: 'Zieht nach',   icon: '🌑' },
              { value: 'ring',     label: 'Ring',     desc: 'Kreis + Bar',  icon: '○' },
              { value: 'gauge',    label: 'Gauge',    desc: 'Ring + Zahl',  icon: '⊕' },
              { value: 'arc',      label: 'Bogen',    desc: 'Halbkreis',    icon: '◜' },
              { value: 'dots',     label: 'Punkte',   desc: 'Dot-Reihe',   icon: '⠿' },
              { value: 'blocks',   label: 'Blöcke',   desc: 'Segmentiert', icon: '▪▪▪' },
              { value: 'segments', label: 'Segmente', desc: 'Spinner',      icon: '◎' },
              { value: 'steps',    label: 'Schritte', desc: '1→2→3→4',     icon: '①' },
            ]} />
          </Field>

          {/* Scan layout */}
          <Field label="Scan-Layout" className="mt-4">
            <DropSelect value={anim.scanLayout ?? 'cards'} onChange={v => setAnim({ scanLayout: v })} color="orange" options={[
              { value: 'cards',    label: 'Karten',   desc: 'Standard', icon: '▣' },
              { value: 'minimal',  label: 'Minimal',  desc: 'Sauber',   icon: '—' },
              { value: 'terminal', label: 'Terminal', desc: 'CLI',      icon: '>' },
              { value: 'hud',      label: 'HUD',      desc: 'Cyber',    icon: '◧' },
              { value: 'wave',     label: 'Wave',      desc: 'Audio',   icon: '≋' },
            ]} />
          </Field>

          {/* Scan sweep */}
          <div className="bd mt-4 rounded-xl border p-4">
            <Toggle
              label="Scan-Sweep — leuchtende Linie, die während des Scans abwärts läuft"
              checked={anim.scanSweep ?? false}
              onChange={v => setAnim({ scanSweep: v })}
            />
          </div>

          {/* Intro effect */}
          <Field label="Intro-Effekt (Fenster-Einblendung)" className="mt-4">
            <DropSelect value={anim.intro} onChange={v => setAnim({ intro: v })} color="emerald" options={[
              { value: 'none',  label: 'Keiner',     desc: 'Sofort', icon: '·' },
              { value: 'fade',  label: 'Einblenden', desc: 'Fade',   icon: '◌' },
              { value: 'slide', label: 'Einfahren',  desc: 'Slide',  icon: '↑' },
            ]} />
          </Field>

          {/* Background effect */}
          <Field label="Hintergrund-Effekt" className="mt-4">
            <DropSelect value={anim.bgEffect} onChange={v => setAnim({ bgEffect: v })} color="amber" options={[
              { value: 'none',       label: 'Keiner',    desc: 'Standard',   icon: '□' },
              { value: 'scanlines',  label: 'Scanlines', desc: 'Retro',      icon: '≡' },
              { value: 'grid',       label: 'Gitter',    desc: 'Cyber',      icon: '⊞' },
              { value: 'glow-pulse', label: 'Glühen',    desc: 'Pulsierend', icon: '◉' },
            ]} />
          </Field>

          {/* Visual effect toggles */}
          <div className="bd mt-4 space-y-1 rounded-xl border p-4">
            <p className="muted mb-3 text-[11px] font-semibold uppercase tracking-widest">Visuelle Effekte</p>
            <Toggle label="Akzent-Glow — Neon-Leuchten auf Titel & Balken" checked={anim.glowAccent ?? false} onChange={v => setAnim({ glowAccent: v })} />
            <Toggle label="Glitch-Titel — gelegentlicher Störeffekt auf dem Titel" checked={anim.glitchText ?? false} onChange={v => setAnim({ glitchText: v })} />
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Fenster-Rahmen ── */}
          <p className="caps-label mb-4 flex items-center gap-2">◻ Fenster-Rahmen</p>

          <Field label="Eckenradius">
            <DropSelect value={fr.cornerRadius} onChange={v => setFr({ cornerRadius: v })} color="sky" options={[
              { value: 'sharp',   label: 'Eckig',      desc: '4 px',  icon: '⬜' },
              { value: 'rounded', label: 'Abgerundet', desc: '10 px', icon: '▢' },
              { value: 'soft',    label: 'Weich',      desc: '18 px', icon: '◻' },
              { value: 'pill',    label: 'Pill',       desc: '32 px', icon: '⬭' },
            ]} />
          </Field>

          <Field label="Fenster-Schatten" className="mt-4">
            <DropSelect value={fr.shadow} onChange={v => setFr({ shadow: v })} color="cyan" options={[
              { value: 'none',   label: 'Keiner', desc: 'Flach',    icon: '□' },
              { value: 'soft',   label: 'Weich',  desc: 'Subtil',   icon: '▧' },
              { value: 'strong', label: 'Stark',  desc: 'Tief',     icon: '■' },
              { value: 'neon',   label: 'Neon',   desc: 'Leuchten', icon: '◈' },
            ]} />
          </Field>

          <Field label="Rahmenbreite" className="mt-4">
            <DropSelect value={fr.borderWidth} onChange={v => setFr({ borderWidth: v })} color="slate" options={[
              { value: 'none',   label: 'Kein',   desc: '0 px', icon: '·' },
              { value: 'thin',   label: 'Dünn',   desc: '1 px', icon: '─' },
              { value: 'normal', label: 'Normal', desc: '2 px', icon: '━' },
              { value: 'thick',  label: 'Dick',   desc: '3 px', icon: '▬' },
            ]} />
          </Field>

          {fr.borderWidth !== 'none' && (
            <div className="mt-3">
              <ColorField label="Rahmenfarbe (Standard = Titelleiste)" value={fr.borderColor || s.colors.titlebar} onChange={v => setFr({ borderColor: v })} />
            </div>
          )}

          <Field label="Transparenz" className="mt-4">
            <div className="flex items-center gap-3">
              <input type="range" min={60} max={100} value={fr.opacity}
                onChange={e => setFr({ opacity: Number(e.target.value) })}
                className="flex-1 accent-sky-500" />
              <span className="txt w-10 text-right text-sm font-mono">{fr.opacity}%</span>
            </div>
          </Field>

          <div className="bd my-7 border-t" />

          {/* ── Typografie ── */}
          <p className="caps-label mb-4 flex items-center gap-2">Aa Typografie</p>

          <Field label="Schriftart">
            <DropSelect value={typo.font} onChange={v => setTypo({ font: v })} color="indigo" options={[
              { value: 'segoe',  label: 'Segoe UI', desc: 'Standard', icon: 'S' },
              { value: 'mono',   label: 'Mono',     desc: 'Terminal', icon: 'M' },
              { value: 'inter',  label: 'Inter',    desc: 'Modern',   icon: 'I' },
              { value: 'roboto', label: 'Roboto',   desc: 'Clean',    icon: 'R' },
            ]} />
          </Field>

          <Field label="Schriftgröße" className="mt-4">
            <DropSelect value={typo.size} onChange={v => setTypo({ size: v })} color="indigo" options={[
              { value: 'small',  label: 'Klein',  desc: '11 px', icon: 'a' },
              { value: 'normal', label: 'Normal', desc: '13 px', icon: 'A' },
              { value: 'large',  label: 'Groß',   desc: '15 px', icon: 'Ａ' },
            ]} />
          </Field>

          <Field label="Zeichenabstand" className="mt-4">
            <DropSelect value={typo.spacing} onChange={v => setTypo({ spacing: v })} color="indigo" options={[
              { value: 'normal', label: 'Normal', desc: 'Standard', icon: 'ab' },
              { value: 'wide',   label: 'Weit',   desc: '0.06 em',  icon: 'a b' },
              { value: 'ultra',  label: 'Ultra',  desc: '0.16 em',  icon: 'a  b' },
            ]} />
          </Field>

          <div className="bd my-7 border-t" />

          {/* ── PIN-Feld ── */}
          <p className="caps-label mb-4 flex items-center gap-2">⬤ PIN-Feld</p>

          <Field label="Zeichen-Stil">
            <DropSelect value={pinF.char} onChange={v => setPinF({ char: v })} color="fuchsia" options={[
              { value: 'dot',      label: 'Punkte',   desc: '● ○', icon: '●' },
              { value: 'square',   label: 'Quadrate', desc: '■ □', icon: '■' },
              { value: 'asterisk', label: 'Sterne',   desc: '★ ☆', icon: '★' },
              { value: 'block',    label: 'Blöcke',   desc: '█ ░', icon: '█' },
            ]} />
          </Field>

          <Field label="Rahmen-Stil" className="mt-4">
            <DropSelect value={pinF.border} onChange={v => setPinF({ border: v })} color="fuchsia" options={[
              { value: 'none',    label: 'Keiner',        desc: 'Transparent', icon: '·' },
              { value: 'bottom',  label: 'Unterstrichen', desc: 'Linie',       icon: '_' },
              { value: 'rounded', label: 'Abgerundet',    desc: 'Box',         icon: '▢' },
              { value: 'square',  label: 'Eckig',         desc: 'Box',         icon: '▪' },
            ]} />
          </Field>

          <div className="bd my-7 border-t" />

          {/* ── Balken-Details ── */}
          <p className="caps-label mb-4 flex items-center gap-2">▬ Balken-Details</p>

          <Field label="Balkenhöhe">
            <DropSelect value={barD.height} onChange={v => setBarD({ height: v })} color="teal" options={[
              { value: 'slim',   label: 'Slim',   desc: '2 px',  icon: '─' },
              { value: 'normal', label: 'Normal', desc: '6 px',  icon: '━' },
              { value: 'thick',  label: 'Dick',   desc: '10 px', icon: '▬' },
              { value: 'chunky', label: 'Massiv', desc: '16 px', icon: '█' },
            ]} />
          </Field>

          <Field label="Balken-Enden" className="mt-4">
            <DropSelect value={barD.caps} onChange={v => setBarD({ caps: v })} color="teal" options={[
              { value: 'round', label: 'Rund',  desc: 'Abgerundet', icon: '⌢' },
              { value: 'sharp', label: 'Eckig', desc: '90°',        icon: '⌐' },
            ]} />
          </Field>

          <div className="mt-4">
            <ColorField
              label="Track-Farbe (Standard = Hintergrundfarbe)"
              value={barD.trackColor || s.colors.background}
              onChange={v => setBarD({ trackColor: v })}
            />
            {barD.trackColor && (
              <button onClick={() => setBarD({ trackColor: '' })} className="muted mt-1.5 text-[11px] hover:txt">
                × Zurücksetzen auf Standard
              </button>
            )}
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Abschluss-Bildschirm ── */}
          <p className="caps-label mb-4 flex items-center gap-2">✓ Abschluss-Bildschirm</p>

          <Field label="Icon-Stil">
            <DropSelect value={doneD.icon} onChange={v => setDoneD({ icon: v })} color="green" options={[
              { value: 'check',  label: 'Check',  desc: 'Klassisch', icon: '✓' },
              { value: 'shield', label: 'Schild', desc: 'Sicher',    icon: '⊛' },
              { value: 'star',   label: 'Stern',  desc: 'Belohnung', icon: '★' },
              { value: 'ring',   label: 'Ring',   desc: 'Minimal',   icon: '◉' },
            ]} />
          </Field>

          <div className="mt-4">
            <ColorField
              label="Erfolgsfarbe (Standard = Akzentfarbe)"
              value={doneD.color || s.colors.accent}
              onChange={v => setDoneD({ color: v })}
            />
            {doneD.color && (
              <button onClick={() => setDoneD({ color: '' })} className="muted mt-1.5 text-[11px] hover:txt">
                × Zurücksetzen auf Akzentfarbe
              </button>
            )}
          </div>

          <Field label="Icon-Animation" className="mt-4">
            <DropSelect value={doneD.anim} onChange={v => setDoneD({ anim: v })} color="green" options={[
              { value: 'none',   label: 'Keine',  desc: 'Sofort',    icon: '·' },
              { value: 'pop',    label: 'Pop',    desc: 'Aufpoppen', icon: '⊕' },
              { value: 'bounce', label: 'Bounce', desc: 'Hüpfen',    icon: '↕' },
              { value: 'spin',   label: 'Spin',   desc: 'Eindrehen', icon: '↻' },
            ]} />
          </Field>

          <div className="bd my-7 border-t" />

          {/* ── Intro-Video ── */}
          <p className="caps-label mb-4 flex items-center gap-2">▶ Intro-Video</p>
          <div className="space-y-4">
            <Toggle
              label="Intro-Video beim Start abspielen"
              checked={iv.enabled}
              onChange={v => setIv({ enabled: v })}
            />
            {iv.enabled && (
              <Field label="Videodatei (relativ zu ZeroTrace.exe, z.B. intro.mp4)">
                <input
                  value={iv.path}
                  onChange={e => setIv({ path: e.target.value })}
                  placeholder="intro.mp4"
                  className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none font-mono"
                />
                <p className="muted mt-1.5 text-xs">
                  Lege die Videodatei neben <span className="txt font-mono">ZeroTrace.exe</span>. Unterstützte Formate: mp4, wmv, avi.
                </p>
              </Field>
            )}
          </div>
        </Card>

        {/* Right column — sticky, scrollable so preview is always visible */}
        <div className="space-y-6 lg:sticky lg:top-6 lg:self-start lg:max-h-[calc(100vh-3rem)] lg:overflow-y-auto lg:pr-1 lg:pb-6">
          <div>
            <button
              onClick={saveAll}
              disabled={!dirty}
              className={`flex w-full items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold transition-colors ${
                dirty ? 'bg-sky-600 text-white hover:bg-sky-500' : 'bd tile muted cursor-default'
              }`}
            >
              <Save size={17} /> {dirty ? 'Alles speichern' : 'Gespeichert'}
            </button>
            {dirty ? (
              <p className="mt-2 flex items-center justify-center gap-1.5 text-xs text-yellow-500">
                <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
                Ungespeicherte Änderungen — Alles speichern drücken
              </p>
            ) : (
              <p className="muted mt-2 text-center text-xs">Alle Änderungen gespeichert</p>
            )}
          </div>

          {/* ── Live-Sync ── */}
          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              {dirHandle && syncStatus !== 'error' && syncStatus !== 'needs-permission'
                ? <Wifi size={15} className="text-green-400" />
                : <WifiOff size={15} className="text-red-400/70" />}
              Live-Sync mit Scanner
            </h4>

            {!SUPPORTS_FS ? (
              <p className="muted text-xs">Nur in Chrome oder Edge verfügbar. Im Firefox bitte <span className="txt">zerotrace-ui.json</span> manuell herunterladen.</p>
            ) : dirHandle && syncStatus !== 'needs-permission' ? (
              <div className="space-y-2.5">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${
                    syncStatus === 'synced'  ? 'bg-green-400' :
                    syncStatus === 'syncing' ? 'bg-yellow-400 animate-pulse' :
                    syncStatus === 'error'   ? 'bg-red-400' : 'bg-sky-400'
                  }`} />
                  <span className={`text-xs font-medium ${
                    syncStatus === 'synced'  ? 'text-green-400' :
                    syncStatus === 'syncing' ? 'text-yellow-400' :
                    syncStatus === 'error'   ? 'text-red-400' : 'txt'
                  }`}>
                    {syncStatus === 'synced'  ? 'Live-Sync aktiv' :
                     syncStatus === 'syncing' ? 'Wird übertragen…' :
                     syncStatus === 'error'   ? 'Übertragungsfehler' : 'Verbunden'}
                  </span>
                </div>
                <p className="muted truncate text-xs" title={dirHandle.name}>📁 {dirHandle.name}</p>
                <p className="muted text-[11px]">Jede Änderung wird automatisch an den Scanner geschickt.</p>
                <button onClick={unlinkDir} className="muted text-[11px] hover:txt">Verknüpfung trennen</button>
              </div>
            ) : syncStatus === 'needs-permission' ? (
              <div className="space-y-2.5">
                <p className="text-xs text-yellow-400">Berechtigung abgelaufen — Neu verbinden um fortzufahren.</p>
                <button onClick={relinkDir}
                  className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500">
                  Neu verbinden
                </button>
                <button onClick={unlinkDir} className="muted text-[11px] hover:txt">Trennen</button>
              </div>
            ) : (
              <div className="space-y-2.5">
                <p className="muted text-xs">
                  Wähle das Verzeichnis in dem <span className="txt font-mono">ZeroTrace.exe</span> liegt.
                  Danach werden alle Design-Änderungen sofort an den Scanner übertragen — kein Neustart nötig.
                </p>
                <button onClick={linkDir}
                  className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500">
                  <FolderOpen size={14} /> Verzeichnis wählen
                </button>
              </div>
            )}
          </Card>

          <Card className="p-6">
            <h3 className="txt mb-5 flex items-center gap-2 text-lg font-semibold">
              <Eye size={18} /> Vorschau GUI
            </h3>
            <GuiPreview s={s} />
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Upload size={15} /> Stil importieren
            </h4>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder="Stil-Code einfügen…"
              rows={3}
              className="bd tile txt w-full rounded-lg border p-3 font-mono text-[11px] focus:outline-none"
            />
            <button
              onClick={doImport}
              className="bd txt mt-2 w-full rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              Stil-Code importieren
            </button>

            <div className="bd my-3 border-t" />

            <p className="muted mb-2 flex items-center gap-1.5 text-xs font-medium">
              <Link size={11} /> Per URL importieren
            </p>
            <div className="flex gap-2">
              <input
                value={importUrl}
                onChange={(e) => setImportUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && importUrl.trim() && doImportUrl()}
                placeholder="https://example.com/style.txt"
                className="bd tile txt min-w-0 flex-1 rounded-lg border px-3 py-2 text-xs focus:outline-none"
              />
              <button
                onClick={doImportUrl}
                disabled={!importUrl.trim() || urlLoading}
                className="bd txt rounded-lg border px-3 py-2 text-xs font-medium hover:border-sky-500 disabled:opacity-40"
              >
                {urlLoading ? '…' : 'Laden'}
              </button>
            </div>
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Download size={15} /> Stil exportieren
            </h4>
            <div className="bd tile max-h-40 overflow-y-auto break-all rounded-lg border p-3 font-mono text-[11px]">
              <span className="muted">{exportCode}</span>
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(exportCode)
                toast({ type: 'success', title: 'Stil-Code kopiert' })
              }}
              className="bd txt mt-3 flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              <Copy size={14} /> Code kopieren
            </button>
            <button
              onClick={() => {
                setS(defaultToolStyle())
                toast({ type: 'info', title: 'Standardwerte geladen', body: 'Alles speichern zum Übernehmen' })
              }}
              className="muted hover:txt mt-2 flex w-full items-center justify-center gap-2 py-1.5 text-xs"
            >
              <RotateCcw size={13} /> Auf Standard zurücksetzen
            </button>
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-1 flex items-center gap-2 text-sm font-semibold">
              <FileJson size={15} /> Für Scanner exportieren
            </h4>
            <p className="muted mb-3 text-xs">
              Lädt <code className="txt">zerotrace-ui.json</code> herunter — nur Felder, die vom Standard abweichen.
              Datei neben <code className="txt">ZeroTrace.exe</code> ablegen, Scanner neu starten.
            </p>
            <button
              onClick={() => {
                const delta = buildScannerDelta(s)
                if (!Object.keys(delta).length) {
                  toast({ type: 'info', title: 'Keine Änderungen', body: 'Alle Werte entsprechen den Standardwerten' })
                  return
                }
                downloadScannerJson(delta)
                toast({ type: 'success', title: 'Heruntergeladen', body: 'zerotrace-ui.json neben ZeroTrace.exe ablegen' })
              }}
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              <Download size={14} /> zerotrace-ui.json herunterladen
            </button>
          </Card>
        </div>
      </div>
    </div>
  )
}
