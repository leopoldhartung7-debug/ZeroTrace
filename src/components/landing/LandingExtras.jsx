/* ============================================================
   Landing extras — every new design feature in one file.
   Imported and dropped into the Landing page where needed.

    1 Terminal hero      4 Typewriter        9 Step-through
    2 Before/After       5 Detection ticker 10 Live counter
    3 Tilt card          6 Trust marquee
                         7 Demo video mock
                         8 Pricing teaser

   Plus shared micro-interactions:
   15 MagneticCTA  16 SectionIndex  17 ScrollProgress
   18 MouseGlow    19 SkeletonBlock

   Pure CSS classes used by these live in src/index.css under the
   "DESIGN UPLIFT" comment block.
   ============================================================ */

import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Check, Play, Shield, ShieldAlert, ShieldCheck, Cpu } from 'lucide-react'
import ztLogoForScannerMock from '../../assets/zt-logo.png'

/* ------------------------------------------------------------ */
/* 17 — Scroll progress bar (top of viewport)                   */
/* ------------------------------------------------------------ */
export function ScrollProgress() {
  const ref = useRef(null)
  useEffect(() => {
    const update = () => {
      const doc = document.documentElement
      const h = doc.scrollHeight - doc.clientHeight
      const pct = h > 0 ? (window.scrollY / h) * 100 : 0
      if (ref.current) ref.current.style.width = `${pct}%`
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update, { passive: true })
    return () => {
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
    }
  }, [])
  return <div ref={ref} className="zt-scroll-progress" aria-hidden="true" />
}

/* ------------------------------------------------------------ */
/* 18 — Mouse glow (big radial follow)                          */
/* ------------------------------------------------------------ */
export function MouseGlow() {
  const ref = useRef(null)
  useEffect(() => {
    const onMove = (e) => {
      if (!ref.current) return
      ref.current.style.setProperty('--cgx', `${e.clientX}px`)
      ref.current.style.setProperty('--cgy', `${e.clientY}px`)
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    return () => window.removeEventListener('mousemove', onMove)
  }, [])
  return <div ref={ref} className="zt-cursor-glow" aria-hidden="true" />
}

/* ------------------------------------------------------------ */
/* 14 — Subtle film grain (mounted once)                        */
/* ------------------------------------------------------------ */
export function NoiseLayer() {
  return <div className="zt-noise fixed inset-0 z-[2]" aria-hidden="true" />
}

/* ------------------------------------------------------------ */
/* 15 — Magnetic CTA (button drifts toward cursor on hover)     */
/* ------------------------------------------------------------ */
export function MagneticCTA({ children, className = '', strength = 18, ...props }) {
  const ref = useRef(null)
  const onMove = (e) => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const x = ((e.clientX - r.left) / r.width - 0.5) * strength
    const y = ((e.clientY - r.top) / r.height - 0.5) * strength
    el.style.transform = `translate(${x}px, ${y}px)`
  }
  const onLeave = () => {
    const el = ref.current
    if (el) el.style.transform = 'translate(0, 0)'
  }
  return (
    <button
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      className={`transition-transform duration-200 ease-out will-change-transform ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}

/* ------------------------------------------------------------ */
/* 16 — Section index dots (right edge, vertical)               */
/* ------------------------------------------------------------ */
export function SectionIndex({ sections }) {
  const [active, setActive] = useState(0)
  useEffect(() => {
    const els = sections.map(({ id }) => document.getElementById(id)).filter(Boolean)
    if (els.length === 0) return undefined
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            const i = els.indexOf(e.target)
            if (i >= 0) setActive(i)
          }
        })
      },
      { rootMargin: '-40% 0px -50% 0px', threshold: 0 },
    )
    els.forEach((el) => obs.observe(el))
    return () => obs.disconnect()
  }, [sections])

  const go = (id) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' })

  return (
    <div className="pointer-events-auto fixed right-4 top-1/2 z-40 hidden -translate-y-1/2 flex-col gap-3 md:flex">
      {sections.map((s, i) => (
        <button
          key={s.id}
          onClick={() => go(s.id)}
          aria-label={s.label}
          title={s.label}
          className={`zt-section-dot ${i === active ? 'is-active' : ''}`}
        />
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 19 — Loading skeleton block                                  */
/* ------------------------------------------------------------ */
export function SkeletonBlock({ className = 'h-24 w-full' }) {
  return <div className={`zt-skeleton ${className}`} aria-hidden="true" />
}

/* ------------------------------------------------------------ */
/* 4 — Typewriter (cycles between phrases)                       */
/* ------------------------------------------------------------ */
export function Typewriter({ phrases, className = '', speed = 55, pause = 1400 }) {
  const [out, setOut] = useState('')
  const [phaseIdx, setPhaseIdx] = useState(0)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    const current = phrases[phaseIdx]
    let timeout
    if (!deleting && out.length < current.length) {
      timeout = setTimeout(() => setOut(current.slice(0, out.length + 1)), speed)
    } else if (!deleting && out.length === current.length) {
      timeout = setTimeout(() => setDeleting(true), pause)
    } else if (deleting && out.length > 0) {
      timeout = setTimeout(() => setOut(current.slice(0, out.length - 1)), Math.max(20, speed / 2))
    } else {
      timeout = setTimeout(() => {
        setDeleting(false)
        setPhaseIdx((i) => (i + 1) % phrases.length)
      }, 220)
    }
    return () => clearTimeout(timeout)
  }, [out, deleting, phaseIdx, phrases, speed, pause])

  return (
    <span className={className}>
      {out}
      <span className="zt-caret" />
    </span>
  )
}

/* ------------------------------------------------------------ */
/* 1 — Terminal hero (animated scan-style log)                   */
/* ------------------------------------------------------------ */
/*  Looks like the real WPF scanner cycling through its steps:    */
/*  Game → PIN → Consent → Scanning → Result                       */
/* ------------------------------------------------------------ */

const SCANNER_STEPS = [
  { id: 'game',    durationMs: 2200 },
  { id: 'pin',     durationMs: 2400 },
  { id: 'consent', durationMs: 2000 },
  { id: 'scan',    durationMs: 4200 },
  { id: 'result',  durationMs: 3500 },
]

/* Palette mirrors scanner/src/ZeroTrace.App/Themes/DarkTheme.xaml */
const ZT = {
  panel: '#161d33',
  accent: '#38bdf8',
  text: '#e8eaf0',
  muted: '#8b93a7',
  trace: '#8A9AAA',
  border: '#2A3038',
  tileBg: 'rgba(25, 29, 36, 0.38)',
  tileBorder: 'rgba(46, 130, 150, 0.63)',
}

function GameStep() {
  const games = ['FiveM', 'alt:V', 'RageMP']
  return (
    <div className="flex h-full flex-col items-center justify-center">
      <p className="text-[11px] font-semibold" style={{ color: ZT.trace }}>Spiel auswählen</p>
      <div className="mt-3 flex gap-2">
        {games.map((g, i) => (
          <div
            key={g}
            className="grid h-[58px] w-[88px] place-items-center rounded-[10px] border text-[12px] font-bold transition-all"
            style={{
              borderColor: i === 0 ? ZT.accent : ZT.tileBorder,
              background: i === 0 ? 'rgba(56,189,248,0.10)' : ZT.tileBg,
              color: '#C8D4DC',
              boxShadow: i === 0 ? '0 0 14px rgba(56,189,248,0.25)' : 'none',
            }}
          >
            {g}
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-2 text-[10px]" style={{ color: '#5A6772' }}>
        <span>Scan-Profil:</span>
        <span
          className="rounded border px-2 py-[2px]"
          style={{ borderColor: ZT.border, background: '#1A2028', color: '#C8D4DC' }}
        >
          Standard ▾
        </span>
      </div>
    </div>
  )
}

function PinStep({ progress }) {
  const filled = Math.min(6, Math.round(progress * 7))
  const digits = ['4', '8', '2', '9', '1', '6']
  return (
    <div className="flex h-full flex-col items-center justify-center">
      <div
        className="rounded-[11px] border px-[14px] py-[12px]"
        style={{ borderColor: ZT.border, background: 'rgba(255,255,255,0.012)' }}
      >
        <p className="text-center text-[10px]" style={{ color: ZT.trace }}>
          Gib deinen 6-stelligen PIN ein
        </p>
        <div className="mt-2 flex justify-center gap-[6px]">
          {digits.map((d, i) => {
            const done = i < filled
            const active = i === filled
            return (
              <div
                key={i}
                className="grid h-[33px] w-[28px] place-items-center rounded-[5px] border font-mono text-[15px] font-bold"
                style={{
                  borderColor: active ? ZT.accent : ZT.border,
                  background: done ? 'rgba(56,189,248,0.08)' : '#0E141B',
                  color: '#C8D2DA',
                  boxShadow: active ? `0 0 10px rgba(56,189,248,0.45)` : 'none',
                }}
              >
                {done ? d : active ? <span className="zt-caret" /> : ''}
              </div>
            )
          })}
        </div>
      </div>
      <span
        className="mt-[10px] rounded-[6px] px-[22px] py-[8px] text-[12.5px] font-semibold"
        style={{
          background: filled >= 6 ? ZT.accent : '#2A3038',
          color: filled >= 6 ? '#0E1418' : '#3A4450',
        }}
      >
        Weiter
      </span>
    </div>
  )
}

function ConsentStep() {
  return (
    <div className="flex h-full flex-col justify-center">
      <p className="text-center text-[13px] font-bold" style={{ color: '#E6EDF2' }}>
        Lizenzvereinbarung &amp; Datenschutz
      </p>
      <p className="mt-[2px] text-center text-[10px]" style={{ color: '#5A6772' }}>
        Bitte lies die Bedingungen, bevor du fortfährst.
      </p>
      <div
        className="mt-2 h-[120px] overflow-hidden rounded-[7px] border px-[13px] py-[10px]"
        style={{ background: '#191D24', borderColor: ZT.border }}
      >
        <p className="text-[11px] font-semibold" style={{ color: '#C8D4DC' }}>
          ENDBENUTZER-LIZENZ- UND DATENSCHUTZVEREINBARUNG
        </p>
        <p className="mt-1 text-[10px] leading-[14px]" style={{ color: '#9AAAB4' }}>
          ZeroTrace ist ein lokales Analysewerkzeug, das diesen PC auf Hinweise für Cheats und
          Manipulationen untersucht. Mit „Akzeptieren" stimmst du der nachfolgend beschriebenen
          Prüfung zu.
        </p>
        <p className="mt-2 text-[10px] font-semibold" style={{ color: ZT.accent }}>
          1. Was geprüft wird
        </p>
        <p className="mt-[2px] text-[10px] leading-[14px]" style={{ color: '#9AAAB4' }}>
          Laufende Prozesse samt geladener Module, Autostart, ausgewählte Registry-Schlüssel…
        </p>
      </div>
      <div className="mt-2 flex justify-end gap-2">
        <span
          className="rounded-[6px] px-[18px] py-[6px] text-[11px] font-semibold"
          style={{ background: '#2A313A', color: '#C2CCD4' }}
        >
          Ablehnen
        </span>
        <span
          className="rounded-[6px] px-[18px] py-[6px] text-[11px] font-semibold"
          style={{ background: ZT.accent, color: '#0E1418' }}
        >
          Akzeptieren
        </span>
      </div>
    </div>
  )
}

function ScanStep({ progress }) {
  const pct = Math.round(progress * 100)
  const modules = [
    'Prozesse',
    'Module',
    'Kernel-Treiber',
    'Registry',
    'ETW-Tamper',
    'Speicher',
    'Hypervisor',
    'Browser-Verlauf',
  ]
  const stage = Math.min(modules.length - 1, Math.floor(progress * modules.length))
  return (
    <div className="flex h-full flex-col justify-center">
      <p className="text-center text-[11px] font-semibold" style={{ color: ZT.trace }}>
        Scanne gerade
      </p>
      <p className="mt-1 text-center text-[13px] font-bold" style={{ color: '#E6EDF2' }}>
        {modules[stage]}…
      </p>
      <div className="mt-3 h-[6px] w-full overflow-hidden rounded-[3px]" style={{ background: '#0E141B' }}>
        <div
          className="h-full rounded-[3px] transition-all duration-150"
          style={{
            width: `${pct}%`,
            background: ZT.accent,
            boxShadow: `0 0 10px rgba(56,189,248,0.55)`,
          }}
        />
      </div>
      <div className="mt-1 flex items-center justify-between font-mono text-[10px]" style={{ color: '#5A6772' }}>
        <span>Modul {stage + 1}/{modules.length}</span>
        <span>{pct}%</span>
      </div>
      <div className="mt-3 grid grid-cols-4 gap-[6px]">
        {modules.map((m, i) => (
          <div
            key={m}
            className="rounded-[4px] border px-[6px] py-[4px] text-center text-[9.5px] transition-all"
            style={{
              borderColor: i < stage ? '#22c55e66' : i === stage ? ZT.accent : ZT.border,
              background: i < stage ? 'rgba(34,197,94,0.10)' : i === stage ? 'rgba(56,189,248,0.10)' : '#0E141B',
              color: i < stage ? '#86efac' : i === stage ? '#E6EDF2' : '#46505C',
            }}
          >
            {m}
          </div>
        ))}
      </div>
    </div>
  )
}

function ResultStep() {
  return (
    <div className="flex h-full flex-col items-center justify-center">
      <p className="text-[11px] font-semibold" style={{ color: ZT.trace }}>
        Scan abgeschlossen
      </p>
      <div
        className="mt-3 grid h-[64px] w-[64px] place-items-center rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(34,197,94,0.28), rgba(34,197,94,0.04) 70%, transparent)',
          boxShadow: '0 0 36px rgba(34,197,94,0.40)',
        }}
      >
        <svg viewBox="0 0 52 52" className="h-10 w-10">
          <circle cx="26" cy="26" r="22" fill="none" stroke="#22c55e" strokeWidth="3" opacity="0.7">
            <animate attributeName="stroke-dasharray" from="0 200" to="138 200" dur="0.7s" fill="freeze" />
          </circle>
          <path
            d="M14 27 l9 8 l16 -18"
            fill="none"
            stroke="#22c55e"
            strokeWidth="3.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <animate attributeName="stroke-dasharray" from="0 60" to="60 60" dur="0.45s" begin="0.5s" fill="freeze" />
            <animate attributeName="stroke-dashoffset" from="60" to="0" dur="0.45s" begin="0.5s" fill="freeze" />
          </path>
        </svg>
      </div>
      <p className="mt-3 text-[15px] font-bold" style={{ color: '#86efac' }}>
        Kein Befund
      </p>
      <p className="mt-1 text-[10.5px]" style={{ color: '#5A6772' }}>
        Bericht an den Analysten gesendet.
      </p>
    </div>
  )
}

export function TerminalCard() {
  // Compatibility alias — kept the export name to avoid touching imports.
  return <ScannerMock />
}

export function ScannerMock() {
  const ref = useRef(null)
  const [idx, setIdx] = useState(0)
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    let cancelled = false
    let timer = null
    let rafId = null

    const runStep = (i) => {
      if (cancelled) return
      const step = SCANNER_STEPS[i]
      const start = performance.now()
      const tick = (t) => {
        if (cancelled) return
        const p = Math.min(1, (t - start) / step.durationMs)
        setProgress(p)
        if (p < 1) rafId = requestAnimationFrame(tick)
        else {
          timer = setTimeout(() => {
            const next = (i + 1) % SCANNER_STEPS.length
            setIdx(next)
            setProgress(0)
            runStep(next)
          }, 250)
        }
      }
      rafId = requestAnimationFrame(tick)
    }

    const io = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        runStep(0)
        io.disconnect()
      }
    }, { threshold: 0.2 })
    if (ref.current) io.observe(ref.current)

    return () => {
      cancelled = true
      io.disconnect()
      if (rafId) cancelAnimationFrame(rafId)
      if (timer) clearTimeout(timer)
    }
  }, [])

  const current = SCANNER_STEPS[idx].id

  return (
    <div
      ref={ref}
      className="relative mx-auto overflow-hidden rounded-[14px] border shadow-[0_30px_80px_-20px_rgba(0,0,0,0.75)]"
      style={{
        aspectRatio: '2 / 1',
        maxWidth: 800,
        background: ZT.panel,
        borderColor: '#264EBCD2',
      }}
    >
      {/* top accent line (gradient → accent → gradient), matches WPF top accent */}
      <div
        className="absolute inset-x-0 top-0 h-[2px]"
        style={{
          background: `linear-gradient(90deg, rgba(56,189,248,0) 0%, ${ZT.accent} 50%, rgba(56,189,248,0) 100%)`,
        }}
      />

      {/* close button (top-right) */}
      <div
        className="absolute right-[10px] top-[8px] z-10 grid h-6 w-6 place-items-center rounded-[6px] text-[12px]"
        style={{ color: '#5A6772' }}
      >
        ✕
      </div>

      {/* two columns: left branding, right step flow */}
      <div className="grid h-full" style={{ gridTemplateColumns: '290px 1fr' }}>
        {/* LEFT — branding */}
        <div className="relative flex flex-col items-center justify-center px-5">
          <div className="flex items-center gap-3">
            <img
              src={ztLogoForScannerMock}
              alt=""
              className="h-[40px] w-[52px] object-contain"
              draggable="false"
            />
            <span className="text-[26px] font-bold leading-none">
              <span style={{ color: ZT.accent }}>Zero</span>
              <span style={{ color: ZT.trace }}>Trace</span>
            </span>
          </div>
          <p className="mt-[10px] text-[13px]" style={{ color: '#5A6772' }}>Host-Scanner</p>
          <p className="mt-[6px] max-w-[200px] text-center text-[11px] leading-tight" style={{ color: '#46505C' }}>
            Lokale Cheat- &amp; Manipulations-Analyse
          </p>
          <p className="mt-[10px] text-[11px]" style={{ color: '#3A444E' }}>v1.3</p>

          {/* vertical divider on the right of the left column */}
          <div
            className="absolute bottom-[40px] right-0 top-[40px] w-px"
            style={{ background: '#242A33' }}
          />
        </div>

        {/* RIGHT — step flow (margin 34,16 in WPF) */}
        <div key={current} className="relative px-[28px] py-[18px] zt-fade-in">
          {current === 'game'    && <GameStep />}
          {current === 'pin'     && <PinStep progress={progress} />}
          {current === 'consent' && <ConsentStep />}
          {current === 'scan'    && <ScanStep progress={progress} />}
          {current === 'result'  && <ResultStep />}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 3 — 3D tilt card wrapper                                      */
/* ------------------------------------------------------------ */
export function TiltCard({ children, className = '', max = 8 }) {
  const ref = useRef(null)
  const onMove = (e) => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const x = (e.clientX - r.left) / r.width  // 0..1
    const y = (e.clientY - r.top)  / r.height // 0..1
    const rx = (0.5 - y) * 2 * max
    const ry = (x - 0.5) * 2 * max
    el.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg) scale(1.015)`
  }
  const onLeave = () => {
    const el = ref.current
    if (el) el.style.transform = 'perspective(900px) rotateX(0) rotateY(0) scale(1)'
  }
  return (
    <div
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      className={`transition-transform duration-200 ease-out will-change-transform ${className}`}
      style={{ transformStyle: 'preserve-3d' }}
    >
      {children}
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 5 — Live detection ticker                                     */
/* ------------------------------------------------------------ */
const TICKER = [
  { v: 'cheat', s: 'eu-mc-04',    p: 'd1scord#5523' },
  { v: 'clean', s: 'us-cs2-12',   p: 'shadowfox' },
  { v: 'susp',  s: 'eu-fivem-22', p: 'kohlrabi' },
  { v: 'clean', s: 'eu-rust-07',  p: 'jonas#9912' },
  { v: 'cheat', s: 'na-val-31',   p: 'phantom_77' },
  { v: 'clean', s: 'eu-sea-09',   p: 'wave-runner' },
  { v: 'susp',  s: 'as-cs2-44',   p: 'kuro' },
  { v: 'clean', s: 'eu-mc-18',    p: 'tomate' },
  { v: 'cheat', s: 'eu-fivem-03', p: 'nightowl' },
  { v: 'clean', s: 'na-apex-21',  p: 'corecut' },
]

export function DetectionTicker() {
  const items = [...TICKER, ...TICKER]
  return (
    <div className="zt-marquee-mask py-4">
      <div className="zt-marquee">
        {items.map((row, i) => {
          const tone =
            row.v === 'cheat' ? 'zt-verdict-cheat zt-verdict-dot-cheat' :
            row.v === 'susp'  ? 'zt-verdict-susp zt-verdict-dot-susp' :
                                'zt-verdict-clean zt-verdict-dot-clean'
          const label =
            row.v === 'cheat' ? 'cheating' :
            row.v === 'susp'  ? 'suspicious' : 'clean'
          const [colorCls, dotCls] = tone.split(' ')
          return (
            <span
              key={i}
              className="mx-6 inline-flex items-center gap-2 text-sm whitespace-nowrap"
            >
              <span className={`h-2 w-2 rounded-full ${dotCls}`} />
              <span className="text-neutral-300">{row.s}</span>
              <span className="text-neutral-600">·</span>
              <span className="font-mono text-xs text-neutral-500">{row.p}</span>
              <span className="text-neutral-600">·</span>
              <span className={`font-semibold uppercase tracking-widest text-[10.5px] ${colorCls}`}>
                {label}
              </span>
            </span>
          )
        })}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 6 — Trusted-by marquee                                        */
/* ------------------------------------------------------------ */
const TRUST = [
  'Hytale Hub',   'CS2 Pro League', 'Valorant Open',  'Sea of Veterans',
  'FiveM Network','RP Hauptquartier','Apex EU Coup',  'Rust Wipe Wars',
  'Tournament BE','EU Casual',      'NA Forge',       'AsiaPac Sentinel',
]
export function TrustedByMarquee() {
  const items = [...TRUST, ...TRUST]
  return (
    <div className="zt-marquee-mask py-2 opacity-70">
      <div className="zt-marquee zt-marquee-fast">
        {items.map((name, i) => (
          <span
            key={i}
            className="mx-8 inline-flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.18em] text-neutral-500"
          >
            <Shield size={14} className="opacity-60" /> {name}
          </span>
        ))}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 10 — Live counter (climbs slowly, "x cheaters caught")        */
/* ------------------------------------------------------------ */
export function LiveCounter({ label = 'Cheaters caught this week', base = 1247 }) {
  const [v, setV] = useState(base)
  useEffect(() => {
    const t = setInterval(() => setV((x) => x + Math.floor(1 + Math.random() * 2)), 2500)
    return () => clearInterval(t)
  }, [])
  return (
    <div className="zt-glass zt-gradient-border flex items-center gap-4 rounded-2xl px-5 py-4">
      <div className="grid h-11 w-11 place-items-center rounded-xl bg-red-500/15 text-red-400">
        <ShieldAlert size={20} />
      </div>
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-500">{label}</p>
        <p className="mt-0.5 text-2xl font-extrabold tabular-nums text-white">{v.toLocaleString()}</p>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 7 — Demo video card (animated SVG mock)                       */
/* ------------------------------------------------------------ */
export function DemoVideoMock() {
  return (
    <div className="zt-glass zt-gradient-border is-always-on relative aspect-video overflow-hidden rounded-3xl">
      <div className="absolute inset-0 bg-gradient-to-br from-violet-900/40 via-slate-900/20 to-black/40" />
      <svg viewBox="0 0 800 450" className="absolute inset-0 h-full w-full">
        <defs>
          <linearGradient id="zt-vbar" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#a78bfa" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#a78bfa" stopOpacity="0.05" />
          </linearGradient>
        </defs>
        {/* animated bars */}
        {Array.from({ length: 26 }, (_, i) => (
          <rect
            key={i}
            x={40 + i * 28}
            y={120}
            width="14"
            height="200"
            rx="3"
            fill="url(#zt-vbar)"
          >
            <animate
              attributeName="height"
              values={`${40 + (i * 17) % 180}; ${120 + (i * 23) % 180}; ${40 + (i * 17) % 180}`}
              dur={`${2.4 + (i % 5) * 0.3}s`}
              repeatCount="indefinite"
            />
            <animate
              attributeName="y"
              values={`${320 - (40 + (i * 17) % 180)}; ${320 - (120 + (i * 23) % 180)}; ${320 - (40 + (i * 17) % 180)}`}
              dur={`${2.4 + (i % 5) * 0.3}s`}
              repeatCount="indefinite"
            />
          </rect>
        ))}
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <button
          type="button"
          className="zt-glass flex h-20 w-20 items-center justify-center rounded-full text-white transition-transform duration-200 hover:scale-110"
        >
          <Play size={28} className="ml-1 fill-white" />
        </button>
      </div>
      <div className="absolute bottom-4 left-4 right-4 flex items-end justify-between text-xs text-neutral-400">
        <span>ZeroTrace · Live Scan Replay</span>
        <span className="font-mono">00:58 / 01:00</span>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 8 — Pricing teaser (3 cards)                                  */
/* ------------------------------------------------------------ */
const PLANS = [
  {
    name: 'Free',
    price: '€0',
    period: '/forever',
    blurb: 'Try ZeroTrace with limited monthly scans.',
    bullets: ['25 scans / month', 'Standard profile', 'Community support'],
    cta: 'Get Started',
  },
  {
    name: 'Pro',
    price: '€19',
    period: '/month',
    blurb: 'For active moderation teams and small leagues.',
    bullets: ['Unlimited scans', 'Deep profile + custom rules', 'Discord webhook', 'Priority support'],
    cta: 'Choose Pro',
    highlight: true,
  },
  {
    name: 'Tournament',
    price: '€79',
    period: '/month',
    blurb: 'For tournament organisers running high-stakes matches.',
    bullets: ['Multi-admin dashboard', 'API access', '24/7 response team', 'Custom signatures'],
    cta: 'Talk to us',
  },
]

export function PricingTeaser() {
  const nav = useNavigate()
  return (
    <div className="grid gap-6 md:grid-cols-3">
      {PLANS.map((p) => (
        <div
          key={p.name}
          className={`zt-glass relative flex flex-col rounded-3xl p-7 transition-transform duration-300 hover:-translate-y-1 ${
            p.highlight ? 'zt-gradient-border is-always-on' : ''
          }`}
        >
          {p.highlight && (
            <span className="absolute -top-3 left-7 rounded-full bg-violet-500 px-3 py-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-white shadow-lg">
              Most popular
            </span>
          )}
          <p className="text-sm font-semibold uppercase tracking-[0.14em] text-neutral-400">{p.name}</p>
          <div className="mt-4 flex items-baseline gap-1">
            <span className="text-5xl font-extrabold text-white">{p.price}</span>
            <span className="text-sm text-neutral-500">{p.period}</span>
          </div>
          <p className="mt-3 text-sm text-neutral-400">{p.blurb}</p>
          <ul className="my-6 flex-1 space-y-2.5 text-sm">
            {p.bullets.map((b) => (
              <li key={b} className="flex items-start gap-2 text-neutral-300">
                <Check size={15} className="mt-0.5 shrink-0 text-violet-400" />
                {b}
              </li>
            ))}
          </ul>
          <button
            onClick={() => nav('/pricing')}
            className={`mt-auto rounded-full px-5 py-2.5 text-sm font-semibold transition-all ${
              p.highlight
                ? 'bg-violet-500 text-white hover:bg-violet-400'
                : 'border border-white/15 text-white hover:bg-white/[0.05]'
            }`}
          >
            {p.cta}
          </button>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 9 — Interactive step-through                                   */
/* ------------------------------------------------------------ */
const STEPS = [
  {
    n: '01',
    title: 'Create a PIN',
    text: 'In the dashboard tap Create Pin. A 6-digit code is generated and tied to one player.',
  },
  {
    n: '02',
    title: 'Send the scanner',
    text: 'Download the single-file ZeroTrace.exe with the PIN baked in. The player opens it — no install.',
  },
  {
    n: '03',
    title: 'They tap Accept',
    text: 'The player sees the consent screen, the scan profile, and accepts. They can decline at any time.',
  },
  {
    n: '04',
    title: 'You get the verdict',
    text: 'Around 58 seconds later the verdict, risk score and every artifact land in your Discord webhook.',
  },
]

export function StepThrough() {
  const [i, setI] = useState(0)
  return (
    <div className="grid items-start gap-8 lg:grid-cols-[1fr_1.4fr]">
      <div className="space-y-2">
        {STEPS.map((s, idx) => {
          const active = idx === i
          return (
            <button
              key={s.n}
              onClick={() => setI(idx)}
              className={`w-full rounded-2xl border px-5 py-4 text-left transition-all duration-300 ${
                active
                  ? 'border-violet-500/50 bg-violet-500/10 shadow-[0_10px_40px_-12px_rgba(139,110,245,0.5)]'
                  : 'border-white/10 bg-white/[0.02] hover:border-white/20'
              }`}
            >
              <p className={`text-xs font-bold tracking-[0.18em] ${active ? 'text-violet-300' : 'text-neutral-500'}`}>
                STEP {s.n}
              </p>
              <p className={`mt-1 text-lg font-semibold ${active ? 'text-white' : 'text-neutral-200'}`}>
                {s.title}
              </p>
            </button>
          )
        })}
      </div>
      <div
        key={i}
        className="zt-glass zt-gradient-border is-always-on min-h-[280px] rounded-3xl p-8 animate-fade-up"
      >
        <p className="text-xs font-bold uppercase tracking-[0.18em] text-violet-300">STEP {STEPS[i].n}</p>
        <h3 className="mt-3 text-2xl font-bold text-white md:text-3xl">{STEPS[i].title}</h3>
        <p className="mt-4 text-base leading-relaxed text-neutral-300">{STEPS[i].text}</p>
        <div className="mt-8 flex items-center gap-3 text-sm">
          {STEPS.map((_, idx) => (
            <span
              key={idx}
              className={`h-1.5 rounded-full transition-all duration-300 ${
                idx === i ? 'w-10 bg-violet-400' : 'w-5 bg-white/15'
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/* 2 — Before/After slider                                        */
/* ------------------------------------------------------------ */
export function BeforeAfter() {
  const [pct, setPct] = useState(50)
  const containerRef = useRef(null)
  const dragRef = useRef(false)

  const setFromX = (clientX) => {
    const el = containerRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const p = ((clientX - r.left) / r.width) * 100
    setPct(Math.max(2, Math.min(98, p)))
  }

  useEffect(() => {
    const move = (e) => {
      if (!dragRef.current) return
      setFromX(e.touches ? e.touches[0].clientX : e.clientX)
    }
    const up = () => { dragRef.current = false }
    window.addEventListener('mousemove', move)
    window.addEventListener('touchmove', move, { passive: true })
    window.addEventListener('mouseup', up)
    window.addEventListener('touchend', up)
    return () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('touchmove', move)
      window.removeEventListener('mouseup', up)
      window.removeEventListener('touchend', up)
    }
  }, [])

  const startDrag = (e) => {
    dragRef.current = true
    setFromX(e.touches ? e.touches[0].clientX : e.clientX)
  }

  return (
    <div
      ref={containerRef}
      onMouseDown={startDrag}
      onTouchStart={startDrag}
      className="zt-glass zt-gradient-border is-always-on relative h-[320px] select-none overflow-hidden rounded-3xl md:h-[400px]"
    >
      {/* BEFORE — live anti-cheat passes it */}
      <div className="absolute inset-0 flex items-center justify-center bg-gradient-to-br from-emerald-900/30 via-slate-900 to-black p-10 text-center">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-emerald-300">Live anti-cheat</p>
          <h3 className="mt-3 text-3xl font-extrabold text-white md:text-4xl">No alerts.</h3>
          <p className="mt-3 max-w-md text-sm text-neutral-400">
            Real-time engine sees nothing suspicious — the cheat hid its hook before the watchdog could scan.
          </p>
          <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-4 py-1.5 text-sm font-semibold text-emerald-200">
            <ShieldCheck size={14} /> player: clean
          </div>
        </div>
      </div>
      {/* AFTER — ZeroTrace finds it */}
      <div
        className="absolute inset-y-0 left-0 overflow-hidden bg-gradient-to-br from-rose-900/30 via-slate-900 to-black"
        style={{ width: `${pct}%` }}
      >
        <div className="flex h-full w-screen max-w-full items-center justify-center p-10 text-center">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-rose-300">ZeroTrace forensic scan</p>
            <h3 className="mt-3 text-3xl font-extrabold text-white md:text-4xl">RWX page in csgo.exe.</h3>
            <p className="mt-3 max-w-md text-sm text-neutral-400">
              On-disk artifacts + a runtime memory sweep reveal the loader the live engine never saw.
            </p>
            <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-rose-500/40 bg-rose-500/10 px-4 py-1.5 text-sm font-semibold text-rose-200">
              <ShieldAlert size={14} /> verdict: cheating
            </div>
          </div>
        </div>
      </div>
      <div className="zt-ba-handle" style={{ left: `${pct}%`, transform: 'translateX(-1px)' }} />
      <p className="absolute bottom-3 left-1/2 -translate-x-1/2 text-[11px] uppercase tracking-[0.18em] text-neutral-500">
        ⟷ drag to compare
      </p>
    </div>
  )
}
