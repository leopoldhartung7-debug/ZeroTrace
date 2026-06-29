import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play, Globe, ChevronDown, Check, ArrowRight, Link2, MoreVertical, FileText,
  Users, ShieldCheck, Zap, CheckCircle2, Clock, ScanFace, Webhook, BellRing,
  SlidersHorizontal, Cpu, LifeBuoy, BookOpen, Lock, AlertTriangle, FastForward,
  Activity,
} from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'
import Logo from '../components/Logo.jsx'
import LanguageToggle from '../components/LanguageToggle.jsx'
import {
  ScrollProgress, MouseGlow, NoiseLayer, MagneticCTA, SectionIndex,
  Typewriter, TerminalCard, TiltCard, DetectionTicker,
  LiveCounter, DemoVideoMock, PricingTeaser, StepThrough, BeforeAfter,
} from '../components/landing/LandingExtras.jsx'

const NAV = ['Features', 'Pricing', 'Docs', 'Branding', 'FAQ', 'Download', 'Discord']

const GLOW = 'rgba(154,164,198,'

/* ── Deterministic pseudo-random for particle positions ── */
function makePRNG(seed) {
  let s = seed >>> 0
  return () => {
    s ^= s << 13; s ^= s >> 17; s ^= s << 5
    return (s >>> 0) / 0x100000000
  }
}
const _rng = makePRNG(0x9e3779b9)
const PARTICLES = Array.from({ length: 32 }, () => ({
  x: _rng() * 96 + 2,
  y: _rng() * 96 + 2,
  size: _rng() * 2.8 + 1,
  duration: _rng() * 14 + 8,
  delay: _rng() * 12,
  opacity: _rng() * 0.22 + 0.05,
}))

/* ── Scroll-reveal hook — fires once when element enters viewport ── */
function useScrollReveal(threshold = 0.12) {
  const ref = useRef(null)
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect() } },
      { threshold },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [threshold])
  return [ref, visible]
}

/* ── Generic fly-in wrapper for any element on scroll ── */
function Reveal({ children, dir = 'up', delay = 0, distance = 32, className = '', as: As = 'div' }) {
  const [ref, visible] = useScrollReveal(0.1)
  const offMap = {
    up:    `translate3d(0, ${distance}px, 0)`,
    down:  `translate3d(0, -${distance}px, 0)`,
    left:  `translate3d(${distance}px, 0, 0)`,   // enters FROM the right
    right: `translate3d(-${distance}px, 0, 0)`,  // enters FROM the left
    pop:   'scale(0.92)',
    blur:  'translate3d(0, 12px, 0)',
  }
  const off = offMap[dir] || offMap.up
  const extraFilter = dir === 'blur' ? (visible ? 'blur(0)' : 'blur(6px)') : 'none'
  return (
    <As
      ref={ref}
      className={className}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translate3d(0,0,0) scale(1)' : off,
        filter: extraFilter,
        transition: `opacity 0.7s ${delay}s cubic-bezier(0.22,1,0.36,1), transform 0.7s ${delay}s cubic-bezier(0.22,1,0.36,1), filter 0.7s ${delay}s ease`,
        willChange: 'opacity, transform',
      }}
    >
      {children}
    </As>
  )
}

/* ── Count-up hook ── */
function useCountUp(target, duration, active) {
  const [val, setVal] = useState(0)
  useEffect(() => {
    if (!active || !target) return
    let start = null
    const tick = (ts) => {
      if (!start) start = ts
      const p = Math.min((ts - start) / duration, 1)
      setVal(Math.round((1 - Math.pow(1 - p, 3)) * target))
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [active, target, duration])
  return val
}

/* ── Floating asteroid-style rocks for the hero (decorative) ── */
const ROCKS = [
  { x: 3,  y: 55, size: 150, dur: 9,  delay: 0,   rot: -15 },
  { x: 14, y: 78, size: 95,  dur: 11, delay: 2.2, rot: 12 },
  { x: 24, y: 64, size: 60,  dur: 13, delay: 4,   rot: -25 },
  { x: 82, y: 50, size: 160, dur: 10, delay: 1,   rot: 8 },
  { x: 74, y: 78, size: 90,  dur: 12, delay: 3,   rot: -8 },
  { x: 65, y: 92, size: 55,  dur: 14, delay: 2,   rot: 20 },
  { x: 50, y: 95, size: 70,  dur: 11, delay: 0.5, rot: 35 },
]

function FloatingRocks() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      {ROCKS.map((r, i) => (
        <div
          key={i}
          className="absolute"
          style={{
            left: `${r.x}%`,
            top: `${r.y}%`,
            width: `${r.size}px`,
            height: `${r.size * 0.86}px`,
            animation: `zt-float ${r.dur}s ease-in-out ${r.delay}s infinite`,
          }}
        >
          <div
            className="h-full w-full"
            style={{
              transform: `rotate(${r.rot}deg)`,
              background:
                'radial-gradient(circle at 30% 25%, #5a5a64 0%, #2a2a34 55%, #0e0e16 100%)',
              borderRadius: '60% 40% 55% 45% / 50% 60% 40% 50%',
              boxShadow:
                'inset -12px -18px 32px rgba(0,0,0,0.7), 0 24px 48px rgba(0,0,0,0.55), 0 0 36px rgba(139,110,245,0.08)',
            }}
          />
        </div>
      ))}
    </div>
  )
}

/* ── Floating particle field ── */
function ParticleField() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      {PARTICLES.map((p, i) => (
        <div
          key={i}
          className="absolute rounded-full"
          style={{
            left: `${p.x}%`,
            top: `${p.y}%`,
            width: `${p.size}px`,
            height: `${p.size}px`,
            opacity: p.opacity,
            background: i % 3 === 0 ? 'rgba(14,165,233,0.8)' : i % 3 === 1 ? 'rgba(154,164,198,0.8)' : 'rgba(167,139,250,0.8)',
            animation: `zt-float ${p.duration}s ease-in-out ${p.delay}s infinite`,
          }}
        />
      ))}
    </div>
  )
}

/* ── Hero verdict graphic with animated ring + count-up score ── */
function VerdictGraphic() {
  const score = 78
  const r = 46
  const circ = 2 * Math.PI * r
  const [progress, setProgress] = useState(0)
  const ref = useRef(null)
  const [seen, setSeen] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setSeen(true); obs.disconnect() } },
      { threshold: 0.2 },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  useEffect(() => {
    if (!seen) return
    let start = null
    const tick = (ts) => {
      if (!start) start = ts
      const p = Math.min((ts - start) / 1300, 1)
      setProgress(Math.round((1 - Math.pow(1 - p, 3)) * score))
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [seen])

  const arc = (circ * progress) / 100

  return (
    <div ref={ref} className="zt-float-slow relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6">
      <div
        className="pointer-events-none absolute inset-0 zt-orb-pulse"
        style={{ background: `radial-gradient(50% 50% at 50% 35%, ${GLOW}0.16), transparent 70%)` }}
      />
      <div className="relative flex items-center justify-between text-sm">
        <span className="text-neutral-300">Results <span className="text-neutral-600">›</span> 238FS64</span>
        <span className="flex items-center gap-2 text-neutral-600"><Link2 size={14} /> <MoreVertical size={14} /></span>
      </div>

      <div className="relative mt-4 flex flex-col items-center">
        <div className="relative h-32 w-32">
          <svg width="128" height="128" className="-rotate-90">
            <circle cx="64" cy="64" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="9" />
            <circle
              cx="64" cy="64" r={r} fill="none" stroke="#9aa4c6" strokeWidth="9" strokeLinecap="round"
              strokeDasharray={`${arc} ${circ}`}
              className="zt-ring-glow"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-extrabold text-white">{progress}</span>
            <span className="text-[10px] uppercase tracking-[0.15em] text-neutral-500">Risk</span>
          </div>
        </div>
        <span className="zt-verdict-badge mt-4 flex items-center gap-2 rounded-full border border-sky-500/40 bg-sky-500/10 px-4 py-1.5 text-sm font-semibold text-sky-200">
          <AlertTriangle size={14} /> Cheating · detected
        </span>
      </div>

      <div className="relative mt-5 grid grid-cols-3 gap-2.5">
        {['Memory', 'Modules', 'Registry'].map((t, i) => (
          <div
            key={t}
            className="zt-flagged-tile rounded-lg border px-3 py-2 text-center"
            style={{ animationDelay: `${i * 0.4}s` }}
          >
            <p className="text-[11px] text-neutral-500">{t}</p>
            <p className="text-xs font-semibold text-sky-300">flagged</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Animated numeric value — counts up when it enters the viewport.
   Parses "500+", "99.9%", "<1 min" gracefully. ── */
function AnimatedNumber({ value, duration = 1400, className = '' }) {
  const [ref, visible] = useScrollReveal(0.3)
  const match = String(value).match(/^([<>]?)([\d.]+)(.*)$/)
  const hasNumber = !!match
  const prefix = match?.[1] ?? ''
  const num    = hasNumber ? parseFloat(match[2]) : 0
  const suffix = match?.[3] ?? ''
  const isInt  = hasNumber && Number.isInteger(num)
  const target = isInt ? num : Math.round(num * 10)
  const animated = useCountUp(target, duration, visible)
  const display = !hasNumber
    ? value
    : prefix + (isInt ? animated : (animated / 10).toFixed(1)) + suffix
  return <span ref={ref} className={`tabular-nums ${className}`}>{display}</span>
}

/* ── Hero stat card with entrance + animated count-up ── */
function StatCard({ icon: Icon, label, value }) {
  return (
    <div className="group flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-4 backdrop-blur transition-all duration-300 hover:-translate-y-1 hover:border-sky-500/30 hover:bg-white/[0.05] hover:shadow-[0_0_28px_rgba(14,165,233,0.2)]">
      <span
        className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-500/15 text-sky-300 transition-all duration-300 group-hover:scale-110 group-hover:rotate-3 group-hover:bg-sky-500/25"
        style={{ boxShadow: `0 0 22px ${GLOW}0.25)` }}
      >
        <Icon size={20} />
      </span>
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-500">{label}</p>
        <p className="text-2xl font-extrabold tracking-tight text-white">
          <AnimatedNumber value={value} />
        </p>
      </div>
    </div>
  )
}

/* ── Bento mocks ── */
function FlowMock() {
  return (
    <div className="relative h-full min-h-[210px] w-full">
      <div className="absolute left-3 top-3 rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2 transition-all duration-300 hover:border-sky-500/30">
        <p className="text-sm font-medium">Scanning</p>
        <p className="text-xs text-neutral-500">User PC</p>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path
          d="M70 50 C 70 130, 220 80, 220 160"
          stroke="#9aa4c6" strokeWidth="2" strokeDasharray="5 5"
          style={{ animation: 'zt-dash-flow 1.4s linear infinite' }}
        />
      </svg>
      <span className="absolute left-1/2 top-1/2 flex h-8 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-sky-500/50 bg-sky-500/15 text-sky-300 zt-neon-pulse">
        <Clock size={14} />
      </span>
      <div className="absolute bottom-3 right-3 rounded-lg border border-sky-500/30 bg-white/[0.04] px-4 py-2">
        <p className="text-sm font-medium">Verdict</p>
        <p className="text-xs text-neutral-500">~58 seconds</p>
      </div>
    </div>
  )
}

function ResultsMock() {
  const rows = [
    { c: 'bg-green-500', t: 'Clean' },
    { c: 'bg-yellow-500', t: 'Suspicious' },
    { c: 'bg-red-500', t: 'Cheating' },
  ]
  return (
    <div className="flex h-full min-h-[210px] flex-col justify-center gap-2.5">
      {rows.map((r, i) => (
        <div
          key={r.t}
          className={`flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.03] px-4 py-3 transition-all duration-300 hover:-translate-x-1 hover:border-white/20 ${i === 2 ? 'ring-1 ring-sky-500/20' : ''}`}
          style={{ animationDelay: `${i * 0.1}s` }}
        >
          <div className="flex items-center gap-3">
            <span className={`h-4 w-4 rounded-full ${r.c} transition-transform duration-300 hover:scale-125`} />
            <div>
              <p className="text-sm font-medium">{r.t}</p>
              <p className="text-xs text-neutral-500">Verdict tier</p>
            </div>
          </div>
          <MoreVertical size={15} className="text-neutral-600" />
        </div>
      ))}
    </div>
  )
}

function WebhookMock() {
  return (
    <div className="relative h-full min-h-[210px] w-full">
      <div className="absolute left-3 top-3 flex items-center gap-3 rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2 transition-all duration-300 hover:border-sky-500/30">
        <ScanFace size={18} className="text-sky-300" />
        <div>
          <p className="text-sm font-medium">Scan finished</p>
          <p className="text-xs text-neutral-500">Pin · A1B2C3D4</p>
        </div>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path
          d="M80 50 C 150 50, 180 110, 230 150"
          stroke="#9aa4c6" strokeWidth="2" strokeDasharray="4 4"
          style={{ animation: 'zt-dash-flow 1.1s linear infinite' }}
        />
      </svg>
      <span className="absolute left-1/2 top-1/2 flex h-8 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-sky-500/50 bg-sky-500/15 text-sky-300 zt-neon-pulse">
        <Webhook size={14} />
      </span>
      <div className="absolute bottom-3 right-3 w-52 rounded-lg border border-sky-500/30 bg-white/[0.04] p-3 transition-all duration-300 hover:border-sky-500/60">
        <div className="flex items-center gap-2 text-sky-300">
          <BellRing size={14} />
          <span className="text-xs font-semibold">Cheating · risk 78</span>
        </div>
        <p className="mt-1 text-[11px] text-neutral-500">Discord webhook delivered · 1.2 s</p>
      </div>
    </div>
  )
}

const BENTO = [
  { icon: FastForward, title: 'A verdict in\nunder a minute', text: 'ZeroTrace is built around a strict time budget — most scans wrap up in about 58 seconds, so checks never stall a tournament.', mock: <FlowMock /> },
  { icon: Activity, title: 'Three clear\nverdict tiers', text: 'Every scan resolves to a clean, suspicious or cheating verdict, backed by the exact artifacts that drove the call.', mock: <ResultsMock />, reverse: true },
  { icon: BellRing, title: 'Pushed straight\nto your team', text: 'The moment a scan finishes, the full verdict, risk score and flagged servers land in your Discord webhook — no polling, no waiting.', mock: <WebhookMock />, wide: true },
]

/* ── Feature card: scroll-reveal + cursor spotlight that follows the mouse ── */
function GlowCard({ icon: Icon, title, text, delay = 0 }) {
  const [revealRef, visible] = useScrollReveal(0.1)
  const cardRef = useRef(null)
  const onMove = (e) => {
    const el = cardRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    el.style.setProperty('--mx', `${e.clientX - rect.left}px`)
    el.style.setProperty('--my', `${e.clientY - rect.top}px`)
  }
  const setRef = (node) => {
    cardRef.current = node
    revealRef.current = node
  }
  return (
    <div
      ref={setRef}
      onMouseMove={onMove}
      className="zt-spotlight group relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-7 transition-all duration-300 hover:-translate-y-2 hover:border-sky-500/30 hover:bg-white/[0.04] hover:shadow-[0_0_40px_rgba(14,165,233,0.12)]"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(28px)',
        transition: `opacity 0.55s ${delay}s ease, transform 0.55s ${delay}s ease, border-color 0.3s, background 0.3s, box-shadow 0.3s`,
      }}
    >
      <span
        className="relative z-10 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300 transition-all duration-300 group-hover:scale-110 group-hover:rotate-6 group-hover:bg-sky-500/25 group-hover:shadow-[0_0_20px_rgba(14,165,233,0.4)]"
        style={{ boxShadow: `0 0 26px ${GLOW}0.3)` }}
      >
        <Icon size={24} />
      </span>
      <h3 className="relative z-10 mt-6 text-xl font-bold text-white">{title}</h3>
      <p className="relative z-10 mt-3 text-sm leading-relaxed text-neutral-400">{text}</p>
    </div>
  )
}

const FEATURES = [
  { icon: SlidersHorizontal, title: 'Three scan profiles', text: 'Pick Quick, Standard or Deep — same engine, different time budget. Quick for spot checks, Deep for tournament-grade evidence.' },
  { icon: Cpu, title: 'Windows-deep forensics', text: '30+ modules covering processes, kernel drivers, ETW tampering, registry persistence, memory protections, hypervisor traces and on-disk remnants.' },
  { icon: ShieldCheck, title: 'Game-aware detection', text: 'Dedicated modules for FiveM, CS2, Valorant, Sea of Thieves, RageMP and AltV — beyond generic process and signature checks.' },
  { icon: Webhook, title: 'Discord webhook delivery', text: 'The full verdict, risk score and flagged artifacts post straight to your moderation channel the moment the scan finishes.' },
  { icon: Lock, title: 'Consent-first by design', text: 'A 6-digit PIN ties every scan to a single user. They see the consent screen, can decline, and the artifacts never leave their machine without their tap.' },
  { icon: LifeBuoy, title: 'Support that shows up', text: 'A response team that actually answers, around the clock, so you are never stuck mid-screenshare.' },
]

/* ── Metric card with scroll-reveal ── */
function MetricCard({ value, label, delay = 0 }) {
  const [ref, visible] = useScrollReveal(0.15)
  return (
    <div
      ref={ref}
      className="rounded-3xl border border-white/10 bg-white/[0.02] p-8 text-center transition-all duration-300 hover:border-sky-500/30 hover:shadow-[0_0_30px_rgba(14,165,233,0.1)]"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0) scale(1)' : 'translateY(20px) scale(0.97)',
        transition: `opacity 0.5s ${delay}s ease, transform 0.5s ${delay}s ease`,
      }}
    >
      <p className="text-4xl font-extrabold tracking-tight text-sky-300">
        <AnimatedNumber value={value} />
      </p>
      <p className="mt-1 text-sm text-neutral-400">{label}</p>
    </div>
  )
}

const METRICS = [
  { value: '~58s', label: 'Standard scan time' },
  { value: '30+', label: 'Detection modules' },
  { value: '500+', label: 'Active servers' },
]

const COMPARE = [
  { feature: 'Approach', live: 'Watches the game in real time', zt: 'Investigates the PC after the fact' },
  { feature: 'Timing', live: 'Always running in the background', zt: 'One deep scan, around a minute' },
  { feature: 'Outcome', live: 'Blocks cheats while they run', zt: 'Surfaces what was hidden or wiped' },
  { feature: 'Performance', live: 'Constant CPU overhead', zt: 'No impact on game performance' },
]

/* ── How-it-works step mocks ── */
function DownloadMock() {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 transition-all duration-300 hover:border-white/20">
      <p className="text-sm font-medium">Download</p>
      <div className="mt-4 space-y-3">
        {[1, 0.6, 0.35].map((o, i) => (
          <div
            key={i}
            className={`flex items-center gap-3 rounded-lg border border-white/10 px-4 py-3 transition-all duration-200 hover:bg-white/[0.04] ${i === 0 ? 'bg-white/[0.05]' : 'bg-white/[0.02]'}`}
            style={{ opacity: o }}
          >
            <FileText size={18} className={i === 0 ? 'text-sky-400' : 'text-neutral-500'} />
            <div>
              <p className="text-sm">ZeroTrace-238fS64.exe</p>
              <p className="text-xs text-neutral-500">ZeroTrace File - exe</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ScanningMock() {
  const [pct, setPct] = useState(0)
  const [done, setDone] = useState(false)
  const ref = useRef(null)
  const [seen, setSeen] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setSeen(true); obs.disconnect() } },
      { threshold: 0.2 },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  useEffect(() => {
    if (!seen) return
    const DURATION = 2800
    let start = null
    const tick = (ts) => {
      if (!start) start = ts
      const p = Math.min((ts - start) / DURATION, 1)
      setPct(Math.round(p * 100))
      if (p < 1) requestAnimationFrame(tick)
      else setDone(true)
    }
    requestAnimationFrame(tick)
  }, [seen])

  return (
    <div ref={ref} className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 transition-all duration-300 hover:border-white/20">
      <div className="flex justify-end gap-2 text-neutral-600">
        <span>—</span>
        <span>×</span>
      </div>
      <pre className="mt-1 font-mono text-[11px] leading-relaxed text-neutral-500">{`"KeyAuth": {
  Var1 => String::Keyauth::Nocase;
  Var2 => String::Keyauth::Wide;`}</pre>
      <div className="mt-6 flex justify-center"><Logo size="md" asLink={false} /></div>
      <p className="mt-3 text-center text-sm text-neutral-500 transition-colors duration-500">
        {done ? 'Scan complete' : 'Scanning...'}
      </p>
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div
          className="h-full rounded-full transition-all duration-75"
          style={{
            width: `${pct}%`,
            background: done ? 'linear-gradient(90deg, #22c55e, #4ade80)' : 'linear-gradient(90deg, #0ea5e9, #38bdf8)',
            boxShadow: pct > 0 ? `0 0 ${done ? 10 : 8}px ${done ? 'rgba(34,197,94,0.7)' : 'rgba(14,165,233,0.6)'}` : 'none',
          }}
        />
      </div>
      <p className="mt-1 text-right font-mono text-xs text-neutral-500">{pct}%</p>
    </div>
  )
}

function ReviewMock() {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 transition-all duration-300 hover:border-white/20">
      <div className="flex items-center justify-between text-sm">
        <span className="text-neutral-300">Results <span className="text-neutral-600">›</span> 238FS64</span>
        <span className="flex items-center gap-2 text-neutral-600"><Link2 size={14} /> <MoreVertical size={14} /></span>
      </div>
      <div className="mt-4 flex items-center justify-center rounded-xl border border-red-600/30 bg-red-600/[0.06] py-10 transition-all duration-300 hover:bg-red-600/[0.1]">
        <span className="relative rounded-md border border-red-500 px-4 py-1.5 text-lg font-semibold text-white" style={{ boxShadow: '0 0 20px rgba(239,68,68,0.3)' }}>
          Cheating
          <span className="absolute -right-3 -top-3 rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">
            Detected
          </span>
        </span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        {[0, 1].map((i) => (
          <div key={i} className="rounded-lg border border-white/10 bg-white/[0.02] p-4 transition-all duration-200 hover:bg-white/[0.05]">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-neutral-600" />
              <span className="h-1.5 w-20 rounded bg-white/10" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const STEPS = [
  { n: '1.', title: 'Downloading', text: 'Two clicks and the scanner handles the rest — no setup, no config files, no friction.', mock: <DownloadMock /> },
  { n: '2.', title: 'Scanning', text: 'Sit back while ZeroTrace works through memory, modules, drivers and disk, then assembles the evidence.', mock: <ScanningMock />, reverse: true },
  { n: '3.', title: 'Data Review', text: 'Read the verdict on the dashboard, open the underlying artifacts, and make the call with confidence.', mock: <ReviewMock /> },
]

const QA = [
  { q: 'Why should you use ZeroTrace?', a: 'ZeroTrace delivers fast, consent-based forensic screenshare scans with precise, trustworthy results — a clear verdict in around a minute, backed by every artifact that drove the call.' },
  { q: 'Which games does the scanner cover?', a: 'Dedicated modules ship for FiveM, CS2, Valorant, Sea of Thieves, RageMP and AltV — on top of generic process, driver, registry and memory checks that apply to every title.' },
  { q: 'What operating system does the scanner support?', a: 'The scanner is Windows-only (a single-file .exe on .NET 8 — no install). The dashboard works in any modern browser.' },
  { q: 'What type of data does ZeroTrace collect?', a: 'Only anti-cheat artifacts (processes, modules, drivers, registry persistence, on-disk traces) gathered with explicit PIN-based consent. Dashboard data stays in your browser; nothing is sold or shared.' },
  { q: 'How does the consent flow work?', a: 'You create a pin in the dashboard, the player downloads a one-file scanner with the PIN baked in, taps Accept on the consent screen, and the verdict lands in your Discord webhook when the scan finishes.' },
  { q: 'What payment methods do you accept?', a: 'Payments are handled by our Merchant of Record (card and common online methods). See the Pricing page for plans.' },
]

/* ── FAQ with smooth height transition ── */
function FaqRow({ q, a }) {
  const [open, setOpen] = useState(false)
  const contentRef = useRef(null)
  return (
    <div className="border-b border-white/10">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between py-6 text-left transition-colors duration-200 hover:text-sky-200"
      >
        <span className="text-lg text-white">{q}</span>
        <ChevronDown
          size={20}
          className="shrink-0 text-neutral-500 transition-all duration-300"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', color: open ? '#7dd3fc' : undefined }}
        />
      </button>
      <div
        ref={contentRef}
        style={{
          maxHeight: open ? (contentRef.current?.scrollHeight ?? 300) + 'px' : '0px',
          overflow: 'hidden',
          transition: 'max-height 0.38s cubic-bezier(0.16,1,0.3,1)',
        }}
      >
        <p className="pb-6 pr-8 leading-relaxed text-neutral-400">{a}</p>
      </div>
    </div>
  )
}

/* ── Step row with scroll-reveal ── */
function StepRow({ s, idx }) {
  const [ref, visible] = useScrollReveal(0.12)
  return (
    <div
      ref={ref}
      className="grid items-center gap-10 md:grid-cols-2"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(32px)',
        transition: 'opacity 0.6s ease, transform 0.6s ease',
      }}
    >
      <div className={s.reverse ? 'md:order-2' : ''}>
        <p className="text-lg text-neutral-500">{s.n}</p>
        <h3 className="mt-4 text-4xl font-extrabold tracking-tight text-sky-300 md:text-5xl">{s.title}</h3>
        <p className="mt-6 max-w-md text-lg leading-relaxed text-neutral-400">{s.text}</p>
      </div>
      <div className={s.reverse ? 'md:order-1' : ''}>{s.mock}</div>
    </div>
  )
}

/* ── Bento card with scroll-reveal ── */
function BentoCard({ p, delay = 0 }) {
  const [ref, visible] = useScrollReveal(0.1)
  return (
    <div
      ref={ref}
      className={`rounded-3xl border border-white/10 bg-white/[0.02] p-7 transition-all duration-300 hover:border-white/15 hover:bg-white/[0.03] ${p.wide ? 'lg:col-span-2' : ''}`}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(24px)',
        transition: `opacity 0.55s ${delay}s ease, transform 0.55s ${delay}s ease`,
      }}
    >
      <div className={`grid items-start gap-6 ${p.wide ? 'md:grid-cols-2' : ''}`}>
        <div className={p.reverse ? 'md:order-2' : ''}>
          <span
            className="inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300 transition-transform duration-300 hover:scale-110"
            style={{ boxShadow: `0 0 24px ${GLOW}0.3)` }}
          >
            <p.icon size={22} />
          </span>
          <h3 className="mt-8 whitespace-pre-line text-2xl font-bold md:text-3xl">{p.title}</h3>
          <p className="mt-4 max-w-md leading-relaxed text-neutral-400">{p.text}</p>
        </div>
        <div className={`rounded-2xl border border-white/10 bg-white/[0.03] p-5 ${p.reverse ? 'md:order-1' : ''}`}>
          {p.mock}
        </div>
      </div>
    </div>
  )
}

export default function Landing() {
  const nav = useNavigate()
  const { state } = useStore()
  const toast = useToast()
  const enter = () => nav(state.auth ? '/dashboard' : '/login')

  // Shrink the header into a floating rounded pill once the user scrolls.
  // Uses an IntersectionObserver on a top-of-page sentinel — fires reliably
  // on iPad Safari where window 'scroll' events can be inconsistent when
  // ancestors set overflow / 100% heights.
  const [scrolled, setScrolled] = useState(false)
  const sentinelRef = useRef(null)
  useEffect(() => {
    const el = sentinelRef.current
    if (!el || typeof IntersectionObserver === 'undefined') return undefined
    const obs = new IntersectionObserver(
      ([entry]) => setScrolled(!entry.isIntersecting),
      { threshold: 0, rootMargin: '0px' },
    )
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  const ROUTES = {
    Pricing: '/pricing',
    Docs: '/docs',
    Download: '/download',
    Branding: '/branding',
    Changelog: '/changelog',
    'Terms of Service': '/terms',
    'Privacy Policy': '/privacy',
    Legal: '/legal',
  }
  const onNav = (item) => {
    if (item === 'Features') document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })
    else if (item === 'FAQ') document.getElementById('faq')?.scrollIntoView({ behavior: 'smooth' })
    else if (item === 'Discord') window.open('https://discord.gg/r4hJzh4pcW', '_blank', 'noopener,noreferrer')
    else if (ROUTES[item]) nav(ROUTES[item])
    else nav('/')
  }

  return (
    <div className="landing-font force-dark app-bg relative min-h-screen overflow-x-hidden text-white">
      <ScrollProgress />
      <MouseGlow />
      <NoiseLayer />
      <SectionIndex
        sections={[
          { id: 'hero', label: 'Top' },
          { id: 'sample-verdict', label: 'Verdict' },
          { id: 'bento', label: 'Why ZeroTrace' },
          { id: 'features', label: 'Features' },
          { id: 'how', label: 'How it works' },
          { id: 'demo', label: 'Demo' },
          { id: 'pricing', label: 'Pricing' },
          { id: 'faq', label: 'FAQ' },
          { id: 'cta', label: 'Get started' },
        ]}
      />

      {/* Top sentinel — sits in normal flow so it scrolls off naturally. */}
      <div ref={sentinelRef} className="h-px w-full" aria-hidden="true" />

      {/* ── Header (shrinks into a floating rounded pill on scroll) ── */}
      <header
        className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ease-out ${
          scrolled ? 'px-3 md:px-6' : 'px-0'
        }`}
        style={{
          paddingTop: scrolled
            ? 'calc(env(safe-area-inset-top, 0px) + 14px)'
            : 'env(safe-area-inset-top, 0px)',
          transform: 'translateZ(0)',
          WebkitTransform: 'translateZ(0)',
        }}
      >
        <div
          className={`mx-auto flex items-center justify-between transition-all duration-300 ease-out ${
            scrolled
              ? 'max-w-3xl rounded-full border border-white/15 bg-[#0a0a12]/90 px-4 py-2 shadow-[0_18px_48px_-12px_rgba(0,0,0,0.65)] backdrop-blur-xl md:px-5'
              : 'max-w-full border-b border-white/10 bg-[#0a0a12]/85 px-6 py-4 backdrop-blur-xl md:px-12'
          }`}
        >
        <Logo size="md" iconOnly={scrolled} />
        <nav className="hidden items-center gap-4 lg:flex">
          {NAV.map((n) => (
            <button
              key={n}
              onClick={() => onNav(n)}
              className="relative text-sm text-neutral-400 transition-colors hover:text-white after:absolute after:-bottom-1 after:left-0 after:h-px after:w-0 after:bg-sky-400 after:transition-all after:duration-300 hover:after:w-full"
            >
              {n}
            </button>
          ))}
        </nav>
        <div className="flex shrink-0 items-center gap-3">
          <LanguageToggle size={scrolled ? 'sm' : 'md'} />
          {state.auth ? (
            <button onClick={() => nav('/dashboard')} className="flex items-center gap-3">
              <span className="text-sm text-neutral-300 hover:text-white">Dashboard</span>
              <span className="flex h-9 w-9 items-center justify-center rounded-full border border-white/15 bg-white/[0.05] text-sm font-semibold">H</span>
            </button>
          ) : (
            <>
              <button
                onClick={() => nav('/login')}
                className="rounded-full border border-sky-500/50 px-5 py-2 text-sm font-semibold text-sky-300 transition-all hover:bg-sky-500/10 hover:border-sky-400 hover:shadow-[0_0_16px_rgba(14,165,233,0.2)]"
              >
                Login
              </button>
              <button
                onClick={() => nav('/login?register=1')}
                className="zt-sweep rounded-full bg-sky-500 px-5 py-2 text-sm font-semibold text-[#0b0c0e] transition-all duration-200 hover:bg-sky-400 hover:-translate-y-0.5 hover:shadow-[0_0_24px_rgba(14,165,233,0.45)]"
              >
                Sign Up
              </button>
            </>
          )}
        </div>
        </div>
      </header>

      {/* ── Hero (giant wordmark + typewriter + terminal + live counter) ── */}
      <section id="hero" className="relative overflow-hidden">
        {/* Violet wash background */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(75% 65% at 50% 0%, rgba(139,110,245,0.45), transparent 72%), radial-gradient(55% 45% at 50% 28%, rgba(109,40,217,0.35), transparent 75%)',
          }}
        />
        <div className="zt-grid-overlay pointer-events-none absolute inset-0" />

        <div className="relative mx-auto max-w-7xl px-6 pb-20 pt-32 text-center md:px-12 md:pt-40">
          {/* Massive headline — Oxanium display font, violet shimmer gradient.
              data-no-i18n: brand wordmark, never translate. */}
          <h1
            data-no-i18n
            className="zt-hero-line-1 mx-auto leading-[0.95]"
            style={{
              fontFamily: "'Oxanium', 'Inter', system-ui, sans-serif",
              fontSize: 'clamp(4rem, 14vw, 13rem)',
              fontWeight: 800,
              letterSpacing: '0.01em',
            }}
          >
            <span
              className="uppercase"
              style={{
                background: 'linear-gradient(180deg, #c4b5fd 0%, #a78bfa 35%, #8b6ef5 60%, #6d28d9 100%)',
                WebkitBackgroundClip: 'text',
                backgroundClip: 'text',
                color: 'transparent',
                filter: 'drop-shadow(0 0 36px rgba(139,110,245,0.45))',
              }}
            >
              ZeroTrace
            </span>
          </h1>

          {/* Typewriter sub-line — minHeight locks the box so different
              phrase lengths can't re-wrap the line and shift the page below. */}
          <p
            className="zt-hero-line-3 mx-auto mt-6 max-w-2xl text-base leading-relaxed text-neutral-300 md:text-lg"
            style={{ minHeight: '7em' }}
          >
            ZeroTrace runs a deep, consent-based forensic scan that{' '}
            <span className="font-semibold text-violet-200">
              <Typewriter
                phrases={{
                  en: [
                    'surfaces what live anti-cheats overlook.',
                    'unmasks unsigned kernel drivers.',
                    'catches RWX pages live cheats hide.',
                    'hands you a verdict in about a minute.',
                  ],
                  de: [
                    'entdeckt, was Live-Anticheats übersehen.',
                    'enttarnt unsignierte Kernel-Treiber.',
                    'erkennt RWX-Speicher, den Cheats verstecken.',
                    'liefert ein Verdict in etwa einer Minute.',
                  ],
                }}
              />
            </span>
          </p>

          {/* Pill CTA (magnetic) */}
          <div className="zt-hero-line-4 mt-8 flex justify-center">
            <MagneticCTA
              onClick={enter}
              className="zt-sweep group inline-flex items-center gap-3 rounded-full border border-white/15 bg-white/[0.06] py-2.5 pl-6 pr-2.5 text-sm font-medium text-white backdrop-blur duration-200 hover:border-white/30 hover:bg-white/[0.1]"
            >
              <span className="relative z-10">Start Scanning Today</span>
              <span className="relative z-10 grid h-8 w-8 place-items-center rounded-full bg-white/15 transition-all duration-300 group-hover:translate-x-1 group-hover:bg-white/25">
                <ArrowRight size={14} />
              </span>
            </MagneticCTA>
          </div>

          {/* Scanner preview — matches the real Windows scanner 1:1 */}
          <div className="mx-auto mt-16 max-w-4xl text-left">
            <TiltCard className="rounded-2xl">
              <TerminalCard />
            </TiltCard>
          </div>
        </div>
      </section>

      {/* ── Sample verdict (moved out of the hero, keeps all original info) ── */}
      <section id="sample-verdict" className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="grid items-start gap-10 lg:grid-cols-[1fr_1fr]">
          <div>
            <Reveal dir="right">
              <span className="inline-flex items-center gap-2 rounded-full border border-sky-500/40 bg-sky-500/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.18em] text-sky-300">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-75" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-sky-300" />
                </span>
                Forensic Screenshare
              </span>
            </Reveal>
            <Reveal dir="right" delay={0.1}>
              <h2 className="mt-5 text-3xl font-extrabold tracking-tight md:text-4xl">
                <span className="zt-shimmer-text">A scan you can act on.</span>
              </h2>
              <p className="mt-4 max-w-md leading-relaxed text-neutral-400">
                One clear number, one decision — with the artifacts attached. We surface what live
                anti-cheats overlook and hand you a verdict in about a minute.
              </p>
            </Reveal>
            <Reveal dir="up" delay={0.2}>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <button
                  onClick={() => onNav('Docs')}
                  className="zt-sweep group flex items-center gap-2 rounded-full border border-white/15 bg-white/[0.04] px-5 py-2.5 text-sm font-semibold text-white backdrop-blur transition-all hover:border-white/30 hover:bg-white/[0.08]"
                >
                  <span className="relative z-10 flex items-center gap-2">
                    <Play size={14} className="fill-white" /> See how it works
                  </span>
                </button>
              </div>
            </Reveal>
            <Reveal dir="up" delay={0.3}>
              <div className="mt-8 grid max-w-md grid-cols-2 gap-4">
                <div className="zt-hover-glow rounded-2xl">
                  <StatCard icon={Users} label="Servers" value="500+" />
                </div>
                <div className="zt-hover-glow rounded-2xl">
                  <StatCard icon={CheckCircle2} label="Accuracy" value="99.9%" />
                </div>
              </div>
            </Reveal>
          </div>
          <Reveal dir="left" delay={0.15}>
            <VerdictGraphic />
          </Reveal>
        </div>
      </section>

      {/* ── See why ── */}
      <section id="bento" className="mx-auto max-w-6xl px-6 py-16 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <Reveal dir="right">
            <h2 className="text-4xl font-extrabold tracking-tight md:text-6xl">See why teams switch</h2>
          </Reveal>
          <Reveal dir="left" delay={0.1}>
            <p className="text-lg text-neutral-400">What makes ZeroTrace different</p>
          </Reveal>
        </div>
        <div className="mt-12 grid gap-6 lg:grid-cols-2">
          {BENTO.map((p, i) => (
            <BentoCard key={p.title} p={p} delay={i * 0.1} />
          ))}
        </div>
      </section>

      {/* ── Feature grid + metrics ── */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-16 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <Reveal dir="right">
            <h2 className="max-w-2xl text-4xl font-extrabold leading-[1.05] tracking-tight md:text-6xl">
              Everything you need to ban with confidence
            </h2>
          </Reveal>
          <Reveal dir="left" delay={0.15}>
            <p className="max-w-sm text-lg text-neutral-400">
              The core features and options that ship with every ZeroTrace plan.
            </p>
          </Reveal>
        </div>
        <div className="mt-12 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f, i) => (
            <GlowCard key={f.title} {...f} delay={i * 0.07} />
          ))}
        </div>
        <div className="mt-6 grid gap-6 sm:grid-cols-3">
          {METRICS.map((m, i) => (
            <MetricCard key={m.label} {...m} delay={i * 0.1} />
          ))}
        </div>
      </section>

      {/* ── Comparison ── */}
      <section className="mx-auto max-w-5xl px-6 py-20 md:px-12">
        <div className="text-center">
          <Reveal dir="pop">
            <h2 className="inline-block text-4xl font-extrabold tracking-tight md:text-5xl">
              Where ZeroTrace fits
              <span className="mx-auto mt-3 block h-1 w-28 rounded-full bg-sky-500" style={{ boxShadow: '0 0 12px rgba(14,165,233,0.6)' }} />
            </h2>
          </Reveal>
          <Reveal dir="up" delay={0.15}>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-neutral-400">
              Live anti-cheats are great at stopping "loud" cheats as they run. ZeroTrace takes over where
              they stop — proving what slipped past, after the fact.
            </p>
          </Reveal>
        </div>

        <Reveal dir="up" delay={0.1} className="mt-10 overflow-hidden rounded-2xl border border-white/10">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-5 py-4 text-xs font-bold uppercase tracking-[0.12em] text-neutral-500"> </th>
                <th className="px-5 py-4 text-xs font-bold uppercase tracking-[0.12em] text-neutral-500">Live Anti-Cheat</th>
                <th className="px-5 py-4 text-xs font-bold uppercase tracking-[0.12em] text-sky-300">ZeroTrace</th>
              </tr>
            </thead>
            <tbody>
              {COMPARE.map((row, i) => (
                <tr
                  key={row.feature}
                  className={`transition-colors duration-150 hover:bg-white/[0.02] ${i < COMPARE.length - 1 ? 'border-b border-white/10' : ''}`}
                >
                  <td className="px-5 py-4 font-semibold text-white">{row.feature}</td>
                  <td className="px-5 py-4 text-neutral-400">{row.live}</td>
                  <td className="px-5 py-4 font-medium text-sky-300">{row.zt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Reveal>
        <Reveal dir="up" delay={0.15}>
          <p className="mt-8 text-center text-neutral-400">
            Run them together — live protection up front, ZeroTrace for the proof.
          </p>
        </Reveal>
      </section>

      {/* ── How ZeroTrace works — interactive step-through ── */}
      <section id="how" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="text-center">
          <Reveal dir="pop">
            <h2 className="text-4xl font-extrabold tracking-tight md:text-6xl">From download to verdict</h2>
          </Reveal>
          <Reveal dir="up" delay={0.15}>
            <p className="mx-auto mt-6 max-w-3xl text-lg text-neutral-400">
              Four short steps. Tap one on the left to see what happens.
            </p>
          </Reveal>
        </div>
        <div className="mt-12">
          <StepThrough />
        </div>
      </section>

      {/* ── Demo video card ── */}
      <section id="demo" className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="grid items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <Reveal dir="right">
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-violet-300">Watch it run</p>
              <h2 className="mt-3 text-4xl font-extrabold tracking-tight md:text-5xl">
                <span className="zt-shimmer-text">~58 seconds, end to end.</span>
              </h2>
              <p className="mt-4 max-w-md text-lg text-neutral-400">
                A real scan replay — from consent to verdict — with the same artifact ladder
                you'll see in your own dashboard.
              </p>
            </Reveal>
          </div>
          <Reveal dir="left" delay={0.15}>
            <TiltCard>
              <DemoVideoMock />
            </TiltCard>
          </Reveal>
        </div>
      </section>

      {/* ── Pricing teaser ── */}
      <section id="pricing" className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="mb-10 text-center">
          <Reveal dir="pop">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-violet-300">Pricing</p>
            <h2 className="mt-3 text-4xl font-extrabold tracking-tight md:text-5xl">
              Pick the plan that fits.
            </h2>
            <p className="mx-auto mt-3 max-w-2xl text-neutral-400">
              Start free. Move up when your community grows.
            </p>
          </Reveal>
        </div>
        <PricingTeaser />
      </section>

      {/* ── FAQ ── */}
      <section id="faq" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="grid gap-10 lg:grid-cols-2">
          <Reveal dir="right">
            <h2 className="text-4xl font-extrabold leading-[1.05] tracking-tight md:text-6xl">
              Answer your <span className="text-sky-300">questions</span>
            </h2>
            <p className="mt-6 text-lg text-neutral-400">
              You've got <span className="text-white">answers</span>
            </p>
          </Reveal>
          <div>
            {QA.map((x, i) => (
              <Reveal key={x.q} dir="left" delay={i * 0.08}>
                <FaqRow q={x.q} a={x.a} />
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section id="cta" className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0 zt-orb-pulse"
          style={{ background: `radial-gradient(60% 80% at 50% 100%, ${GLOW}0.18), transparent 70%)` }}
        />
        {/* Mini particles in CTA section */}
        <div className="pointer-events-none absolute inset-0 overflow-hidden">
          {PARTICLES.slice(0, 12).map((p, i) => (
            <div
              key={i}
              className="absolute rounded-full bg-sky-400/40"
              style={{
                left: `${p.x}%`, top: `${p.y}%`,
                width: `${p.size * 0.7}px`, height: `${p.size * 0.7}px`,
                animation: `zt-float ${p.duration * 1.3}s ease-in-out ${p.delay * 1.5}s infinite`,
              }}
            />
          ))}
        </div>
        <div className="relative mx-auto max-w-6xl px-6 py-28 md:px-12">
          <div className="flex flex-col gap-10 lg:flex-row lg:items-center lg:justify-between">
            <Reveal dir="right">
              <h2 className="text-5xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
                Two clicks
                <br />
                <span className="text-sky-300">to certainty</span>
              </h2>
            </Reveal>
            <Reveal dir="left" delay={0.2} className="flex items-center gap-6">
              <MagneticCTA
                onClick={enter}
                className="zt-sweep group rounded-full bg-sky-500 px-10 py-5 text-lg font-bold text-[#0b0c0e] shadow-[0_0_28px_rgba(14,165,233,0.4)] duration-200 hover:bg-sky-400 hover:scale-105 hover:shadow-[0_0_44px_rgba(14,165,233,0.6)] active:scale-100"
              >
                <span className="relative z-10">Get Started</span>
              </MagneticCTA>
              <p className="text-neutral-400">
                Trusted by
                <br />
                <span className="text-white">500+ communities</span>
              </p>
            </Reveal>
          </div>
          <Reveal dir="up" delay={0.3} className="mt-10 flex flex-wrap gap-8">
            <span className="flex items-center gap-2 text-neutral-300 transition-colors duration-200 hover:text-white">
              <Check size={18} className="text-sky-300" /> Download ZeroTrace
            </span>
            <span className="flex items-center gap-2 text-neutral-300 transition-colors duration-200 hover:text-white">
              <Check size={18} className="text-sky-300" /> Join our Community
            </span>
          </Reveal>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-white/10 px-6 py-14 md:px-12">
        <div className="mx-auto grid max-w-6xl gap-10 md:grid-cols-[1.5fr_1fr_1fr_1fr_1fr]">
          <div>
            <div className="flex items-center gap-2">
              <Logo size="sm" />
              <span className="text-neutral-500">- anticheat.ac</span>
            </div>
            <p className="mt-3 max-w-xs text-sm text-neutral-500">
              The most powerful screenshare tool — detect cheaters in 60 seconds.
            </p>
            <div className="mt-5 flex items-center gap-3">
              <a
                href="https://discord.gg/r4hJzh4pcW"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Join the ZeroTrace Discord"
                className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04] text-neutral-300 transition-all hover:border-violet-400/40 hover:bg-violet-500/10 hover:text-violet-200"
              >
                {/* Discord glyph */}
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M20.317 4.369A19.79 19.79 0 0 0 16.558 3.2c-.18.323-.385.76-.526 1.108a18.4 18.4 0 0 0-4.069 0c-.14-.348-.354-.785-.534-1.108A19.7 19.7 0 0 0 7.677 4.37C4.155 9.633 3.195 14.766 3.675 19.82a19.94 19.94 0 0 0 6.099 3.087c.487-.664.92-1.37 1.292-2.116a13.04 13.04 0 0 1-2.034-.974c.171-.126.339-.257.5-.392 3.927 1.795 8.18 1.795 12.057 0 .163.135.331.266.5.392-.65.387-1.331.714-2.036.974.373.745.805 1.45 1.292 2.115a19.93 19.93 0 0 0 6.1-3.086c.562-5.886-.96-10.97-4.128-15.451ZM10.04 16.85c-1.215 0-2.21-1.116-2.21-2.486 0-1.37.977-2.486 2.21-2.486 1.234 0 2.23 1.116 2.21 2.486 0 1.37-.976 2.486-2.21 2.486Zm6.92 0c-1.214 0-2.21-1.116-2.21-2.486 0-1.37.977-2.486 2.21-2.486 1.234 0 2.23 1.116 2.21 2.486 0 1.37-.976 2.486-2.21 2.486Z" />
                </svg>
              </a>
            </div>
          </div>
          {[
            { h: 'Product',   items: ['Features', 'Pricing', 'Download', 'Changelog'] },
            { h: 'Legal',     items: ['Terms of Service', 'Privacy Policy', 'Legal'] },
            { h: 'Community', items: ['Discord', 'Branding'] },
            { h: 'Support',   items: ['Docs', 'FAQ'] },
          ].map((col) => (
            <div key={col.h}>
              <p className="text-sm font-semibold text-white">{col.h}</p>
              <ul className="mt-3 space-y-2">
                {col.items.map((it) => (
                  <li key={it}>
                    {it === 'Discord' ? (
                      <a
                        href="https://discord.gg/r4hJzh4pcW"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-neutral-500 transition-colors duration-150 hover:text-sky-300"
                      >
                        Discord
                      </a>
                    ) : (
                      <button
                        onClick={() => onNav(it)}
                        className="text-sm text-neutral-500 transition-colors duration-150 hover:text-sky-300"
                      >
                        {it}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <p className="mx-auto mt-12 max-w-6xl border-t border-white/10 pt-8 text-sm text-neutral-600">
          © 2026 ZeroTrace Anti-Cheat — anticheat.ac
        </p>
      </footer>
    </div>
  )
}
