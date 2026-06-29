import { useEffect, useRef, useState } from 'react'
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
import {
  ScrollProgress, MouseGlow, NoiseLayer, MagneticCTA, SectionIndex,
  Typewriter, TerminalCard, TiltCard, DetectionTicker, TrustedByMarquee,
  LiveCounter, DemoVideoMock, PricingTeaser, StepThrough, BeforeAfter,
} from '../components/landing/LandingExtras.jsx'

const NAV = ['Features', 'Pricing', 'Docs', 'Branding', 'FAQ', 'Download', 'Discord']

/* Steel accent in rgba form for glow effects (matches --accent #9aa4c6). */
const GLOW = 'rgba(154,164,198,'

/* ---- hero verdict graphic (ZeroTrace's own scan-result motif) ---- */
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

function VerdictGraphic() {
  const score = 78
  const r = 46
  const circ = 2 * Math.PI * r
  return (
    <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6">
      <div
        className="pointer-events-none absolute inset-0"
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
              strokeDasharray={`${(circ * score) / 100} ${circ}`}
              style={{
                filter: `drop-shadow(0 0 6px ${GLOW}0.8))`,
                strokeDashoffset: circ,
                animation: 'zt-ring-draw 1.6s cubic-bezier(0.22, 1, 0.36, 1) 0.2s forwards',
              }}
            />
            <style>{`
              @keyframes zt-ring-draw {
                from { stroke-dashoffset: ${circ}; }
                to   { stroke-dashoffset: 0; }
              }
            `}</style>
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="zt-shimmer text-3xl font-extrabold">{score}</span>
            <span className="text-[10px] uppercase tracking-[0.15em] text-neutral-500">Risk</span>
          </div>
        </div>
        <span className="zt-pulse-glow mt-4 flex items-center gap-2 rounded-full border border-sky-500/40 bg-sky-500/10 px-4 py-1.5 text-sm font-semibold text-sky-200">
          <AlertTriangle size={14} className="zt-pulse-soft" /> Cheating · detected
        </span>
      </div>

      <div className="zt-stagger relative mt-5 grid grid-cols-3 gap-2.5">
        {['Memory', 'Modules', 'Registry'].map((t) => (
          <div key={t} className="zt-hover-lift rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-center">
            <p className="text-[11px] text-neutral-500">{t}</p>
            <p className="text-xs font-semibold text-sky-300">flagged</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ---- hero floating stat card ---- */
function StatCard({ icon: Icon, label, value }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-4 backdrop-blur">
      <span
        className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-500/15 text-sky-300"
        style={{ boxShadow: `0 0 22px ${GLOW}0.25)` }}
      >
        <Icon size={20} />
      </span>
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-500">{label}</p>
        <p className="text-2xl font-extrabold tracking-tight text-white">{value}</p>
      </div>
    </div>
  )
}

/* ---- bento "see why" mocks (original ZeroTrace, restyled steel) ---- */
function FlowMock() {
  return (
    <div className="relative h-full min-h-[210px] w-full">
      <div className="absolute left-3 top-3 rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2">
        <p className="text-sm font-medium">Scanning</p>
        <p className="text-xs text-neutral-500">User PC</p>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path d="M70 50 C 70 130, 220 80, 220 160" stroke="#9aa4c6" strokeWidth="2" strokeDasharray="5 5" />
      </svg>
      <span className="absolute left-1/2 top-1/2 flex h-8 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-sky-500/50 bg-sky-500/15 text-sky-300">
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
          className={`flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.03] px-4 py-3 ${i === 2 ? 'ring-1 ring-sky-500/20' : ''}`}
        >
          <div className="flex items-center gap-3">
            <span className={`h-4 w-4 rounded-full ${r.c}`} />
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
      <div className="absolute left-3 top-3 flex items-center gap-3 rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2">
        <ScanFace size={18} className="text-sky-300" />
        <div>
          <p className="text-sm font-medium">Scan finished</p>
          <p className="text-xs text-neutral-500">Pin · A1B2C3D4</p>
        </div>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path d="M80 50 C 150 50, 180 110, 230 150" stroke="#9aa4c6" strokeWidth="2" strokeDasharray="4 4" />
      </svg>
      <span className="absolute left-1/2 top-1/2 flex h-8 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-sky-500/50 bg-sky-500/15 text-sky-300">
        <Webhook size={14} />
      </span>
      <div className="absolute bottom-3 right-3 w-52 rounded-lg border border-sky-500/30 bg-white/[0.04] p-3">
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

/* ---- glow feature grid (ZeroTrace's own features, reworded) ---- */
function GlowCard({ icon: Icon, title, text }) {
  return (
    <div className="group rounded-3xl border border-white/10 bg-white/[0.02] p-7 transition-all duration-300 hover:-translate-y-1 hover:border-white/20">
      <span
        className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300 transition-transform duration-300 group-hover:scale-110"
        style={{ boxShadow: `0 0 26px ${GLOW}0.3)` }}
      >
        <Icon size={24} />
      </span>
      <h3 className="mt-6 text-xl font-bold text-white">{title}</h3>
      <p className="mt-3 text-sm leading-relaxed text-neutral-400">{text}</p>
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

const METRICS = [
  { value: '~58s', label: 'Standard scan time' },
  { value: '30+', label: 'Detection modules' },
  { value: '500+', label: 'Active servers' },
]

/* ---- "where it fits" comparison (reworded, ZeroTrace voice) ---- */
const COMPARE = [
  { feature: 'Approach', live: 'Watches the game in real time', zt: 'Investigates the PC after the fact' },
  { feature: 'Timing', live: 'Always running in the background', zt: 'One deep scan, around a minute' },
  { feature: 'Outcome', live: 'Blocks cheats while they run', zt: 'Surfaces what was hidden or wiped' },
  { feature: 'Performance', live: 'Constant CPU overhead', zt: 'No impact on game performance' },
]

/* ---- "How ZeroTrace works" step mocks ---- */
function DownloadMock() {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
      <p className="text-sm font-medium">Download</p>
      <div className="mt-4 space-y-3">
        {[1, 0.6, 0.35].map((o, i) => (
          <div
            key={i}
            className={`flex items-center gap-3 rounded-lg border border-white/10 px-4 py-3 ${i === 0 ? 'bg-white/[0.05]' : 'bg-white/[0.02]'}`}
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
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
      <div className="flex justify-end gap-2 text-neutral-600">
        <span>—</span>
        <span>×</span>
      </div>
      <pre className="mt-1 font-mono text-[11px] leading-relaxed text-neutral-500">{`"KeyAuth": {
  Var1 => String::Keyauth::Nocase;
  Var2 => String::Keyauth::Wide;`}</pre>
      <div className="mt-6 flex justify-center"><Logo size="md" /></div>
      <p className="mt-3 text-center text-sm text-neutral-500">Scanning...</p>
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div className="h-full w-3/4 rounded-full bg-sky-500" />
      </div>
    </div>
  )
}
function ReviewMock() {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
      <div className="flex items-center justify-between text-sm">
        <span className="text-neutral-300">Results <span className="text-neutral-600">›</span> 238FS64</span>
        <span className="flex items-center gap-2 text-neutral-600"><Link2 size={14} /> <MoreVertical size={14} /></span>
      </div>
      <div className="mt-4 flex items-center justify-center rounded-xl border border-red-600/30 bg-red-600/[0.06] py-10">
        <span className="relative rounded-md border border-red-500 px-4 py-1.5 text-lg font-semibold text-white">
          Cheating
          <span className="absolute -right-3 -top-3 rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">
            Detected
          </span>
        </span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        {[0, 1].map((i) => (
          <div key={i} className="rounded-lg border border-white/10 bg-white/[0.02] p-4">
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

function FaqRow({ q, a }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-b border-white/10">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between py-6 text-left">
        <span className="text-lg text-white">{q}</span>
        <ChevronDown size={20} className={`text-neutral-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <p className="-mt-2 pb-6 pr-8 text-neutral-400">{a}</p>}
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
    else if (item === 'Discord') toast({ type: 'info', title: 'Discord', body: 'Community link is not configured in this demo.' })
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
        <button onClick={() => nav('/')} className="flex items-center gap-3">
          <Logo size="md" iconOnly={scrolled} />
        </button>
        <nav className="hidden items-center gap-7 lg:flex">
          {NAV.map((n) => (
            <button key={n} onClick={() => onNav(n)} className="text-sm text-neutral-400 transition-colors hover:text-white">
              {n}
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-3">
          <Globe size={18} className="hidden text-neutral-500 sm:block" />
          {state.auth ? (
            <button onClick={() => nav('/dashboard')} className="flex items-center gap-3">
              <span className="text-sm text-neutral-300 hover:text-white">Dashboard</span>
              <span className="flex h-9 w-9 items-center justify-center rounded-full border border-white/15 bg-white/[0.05] text-sm font-semibold">
                H
              </span>
            </button>
          ) : (
            <>
              <button
                onClick={() => nav('/login')}
                className="rounded-full border border-sky-500/50 px-5 py-2 text-sm font-semibold text-sky-300 transition-colors hover:bg-sky-500/10"
              >
                Login
              </button>
              <button
                onClick={() => nav('/login?register=1')}
                className="rounded-full bg-sky-500 px-5 py-2 text-sm font-semibold text-[#0b0c0e] transition-all hover:bg-sky-400"
                style={{ boxShadow: `0 0 24px ${GLOW}0.4)` }}
              >
                Sign Up
              </button>
            </>
          )}
        </div>
        </div>
      </header>

      {/* ── Hero ── */}
      <section id="hero" className="relative overflow-hidden">
        {/* Solid violet wash background (no sphere) */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(75% 65% at 50% 0%, rgba(139,110,245,0.45), transparent 72%), radial-gradient(55% 45% at 50% 28%, rgba(109,40,217,0.35), transparent 75%)',
          }}
        />
        {/* Faint dot grid for texture */}
        <div className="zt-grid-overlay pointer-events-none absolute inset-0" />

        <div className="relative mx-auto max-w-7xl px-6 pb-24 pt-32 text-center md:px-12 md:pt-40">
          {/* Massive headline — wordmark, thin uppercase, shimmer gradient */}
          <h1
            className="zt-fade-up mx-auto leading-[0.95] tracking-[0.04em]"
            style={{
              fontSize: 'clamp(4rem, 14vw, 13rem)',
              fontWeight: 200,
            }}
          >
            <span
              className="uppercase"
              style={{
                background:
                  'linear-gradient(180deg, #c4b5fd 0%, #a78bfa 35%, #8b6ef5 60%, #6d28d9 100%)',
                WebkitBackgroundClip: 'text',
                backgroundClip: 'text',
                color: 'transparent',
                filter: 'drop-shadow(0 0 36px rgba(139,110,245,0.45))',
              }}
            >
              ZeroTrace
            </span>
          </h1>

          {/* Subtitle with typewriter — minHeight locks the box so different
              phrase lengths can't re-wrap the line and shift the page below. */}
          <p
            className="zt-fade-up mx-auto mt-6 max-w-2xl text-base leading-relaxed text-neutral-300 md:text-lg"
            style={{ animationDelay: '120ms', minHeight: '7em' }}
          >
            ZeroTrace runs a deep, consent-based forensic scan that{' '}
            <span className="font-semibold text-violet-200">
              <Typewriter
                phrases={[
                  'surfaces what live anti-cheats overlook.',
                  'unmasks unsigned kernel drivers.',
                  'catches RWX pages live cheats hide.',
                  'hands you a verdict in about a minute.',
                ]}
              />
            </span>
          </p>

          {/* Pill CTA with circle arrow */}
          <div className="zt-fade-up mt-8 flex justify-center" style={{ animationDelay: '220ms' }}>
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
      <section className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="grid items-start gap-10 lg:grid-cols-[1fr_1fr]">
          <div className="zt-fade-up">
            <span className="zt-pulse-glow inline-flex items-center gap-2 rounded-full border border-sky-500/40 bg-sky-500/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.18em] text-sky-300">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-sky-300" />
              </span>
              Forensic Screenshare
            </span>
            <h2 className="mt-5 text-3xl font-extrabold tracking-tight md:text-4xl">
              <span className="zt-shimmer">A scan you can act on.</span>
            </h2>
            <p className="mt-4 max-w-md leading-relaxed text-neutral-400">
              One clear number, one decision — with the artifacts attached. We surface what live
              anti-cheats overlook and hand you a verdict in about a minute.
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                onClick={() => onNav('Docs')}
                className="zt-sweep flex items-center gap-2 rounded-full border border-white/15 bg-white/[0.04] px-5 py-2.5 text-sm font-semibold text-white backdrop-blur transition-all hover:border-white/30 hover:bg-white/[0.08]"
              >
                <Play size={14} className="fill-white" /> See how it works
              </button>
            </div>
            <div className="zt-stagger mt-8 grid max-w-md grid-cols-2 gap-4">
              <div className="zt-hover-lift rounded-2xl">
                <StatCard icon={Users} label="Servers" value="500+" />
              </div>
              <div className="zt-hover-lift rounded-2xl">
                <StatCard icon={CheckCircle2} label="Accuracy" value="99.9%" />
              </div>
            </div>
          </div>
          <div className="zt-float-slow zt-hover-glow rounded-3xl">
            <VerdictGraphic />
          </div>
        </div>
      </section>

      {/* ── Trusted-by marquee ── */}
      <section id="trusted-by" className="relative mx-auto max-w-6xl px-6 pb-12 md:px-12">
        <p className="mb-3 text-center text-[11px] font-bold uppercase tracking-[0.22em] text-neutral-500">
          Trusted by 500+ communities
        </p>
        <TrustedByMarquee />
      </section>

      {/* ── See why (bento, original ZeroTrace) ── */}
      <section id="bento" className="mx-auto max-w-6xl px-6 py-16 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <h2 className="text-4xl font-extrabold tracking-tight md:text-6xl">See why teams switch</h2>
          <p className="text-lg text-neutral-400">What makes ZeroTrace different</p>
        </div>
        <div className="mt-12 grid gap-6 lg:grid-cols-2">
          {BENTO.map((p) => (
            <div key={p.title} className={`rounded-3xl border border-white/10 bg-white/[0.02] p-7 ${p.wide ? 'lg:col-span-2' : ''}`}>
              <div className={`grid items-start gap-6 ${p.wide ? 'md:grid-cols-2' : ''}`}>
                <div className={p.reverse ? 'md:order-2' : ''}>
                  <span
                    className="inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300"
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
          ))}
        </div>
      </section>

      {/* ── Feature grid + metrics ── */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-16 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <h2 className="max-w-2xl text-4xl font-extrabold leading-[1.05] tracking-tight md:text-6xl">
            Everything you need to ban with confidence
          </h2>
          <p className="max-w-sm text-lg text-neutral-400">
            The core features and options that ship with every ZeroTrace plan.
          </p>
        </div>
        <div className="mt-12 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <GlowCard key={f.title} {...f} />
          ))}
        </div>
        <div className="mt-6 grid gap-6 sm:grid-cols-3">
          {METRICS.map((m) => (
            <div key={m.label} className="rounded-3xl border border-white/10 bg-white/[0.02] p-8 text-center">
              <p className="text-4xl font-extrabold tracking-tight text-sky-300">{m.value}</p>
              <p className="mt-1 text-sm text-neutral-400">{m.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Where ZeroTrace fits (comparison) ── */}
      <section className="mx-auto max-w-5xl px-6 py-20 md:px-12">
        <div className="text-center">
          <h2 className="inline-block text-4xl font-extrabold tracking-tight md:text-5xl">
            Where ZeroTrace fits
            <span className="mx-auto mt-3 block h-1 w-28 rounded-full bg-sky-500" />
          </h2>
          <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-neutral-400">
            Live anti-cheats are great at stopping "loud" cheats as they run. ZeroTrace takes over where
            they stop — proving what slipped past, after the fact.
          </p>
        </div>

        <div className="mt-10 overflow-hidden rounded-2xl border border-white/10">
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
                <tr key={row.feature} className={i < COMPARE.length - 1 ? 'border-b border-white/10' : ''}>
                  <td className="px-5 py-4 font-semibold text-white">{row.feature}</td>
                  <td className="px-5 py-4 text-neutral-400">{row.live}</td>
                  <td className="px-5 py-4 font-medium text-sky-300">{row.zt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-8 text-center text-neutral-400">
          Run them together — live protection up front, ZeroTrace for the proof.
        </p>
      </section>

      {/* ── How ZeroTrace works — interactive step-through ── */}
      <section id="how" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="text-center">
          <h2 className="text-4xl font-extrabold tracking-tight md:text-6xl">From download to verdict</h2>
          <p className="mx-auto mt-6 max-w-3xl text-lg text-neutral-400">
            Four short steps. Tap one on the left to see what happens.
          </p>
        </div>
        <div className="mt-12">
          <StepThrough />
        </div>
      </section>

      {/* ── Demo video card ── */}
      <section id="demo" className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="grid items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-violet-300">Watch it run</p>
            <h2 className="mt-3 text-4xl font-extrabold tracking-tight md:text-5xl">
              <span className="zt-shimmer-text">~58 seconds, end to end.</span>
            </h2>
            <p className="mt-4 max-w-md text-lg text-neutral-400">
              A real scan replay — from consent to verdict — with the same artifact ladder
              you'll see in your own dashboard.
            </p>
          </div>
          <TiltCard>
            <DemoVideoMock />
          </TiltCard>
        </div>
      </section>

      {/* ── Pricing teaser ── */}
      <section id="pricing" className="relative mx-auto max-w-6xl px-6 py-16 md:px-12 md:py-20">
        <div className="mb-10 text-center">
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-violet-300">Pricing</p>
          <h2 className="mt-3 text-4xl font-extrabold tracking-tight md:text-5xl">
            Pick the plan that fits.
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-neutral-400">
            Start free. Move up when your community grows.
          </p>
        </div>
        <PricingTeaser />
      </section>

      {/* ── FAQ ── */}
      <section id="faq" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="grid gap-10 lg:grid-cols-2">
          <div>
            <h2 className="text-4xl font-extrabold leading-[1.05] tracking-tight md:text-6xl">
              Answer your <span className="text-sky-300">questions</span>
            </h2>
            <p className="mt-6 text-lg text-neutral-400">
              You've got <span className="text-white">answers</span>
            </p>
          </div>
          <div>
            {QA.map((x) => (
              <FaqRow key={x.q} q={x.q} a={x.a} />
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section id="cta" className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: `radial-gradient(60% 80% at 50% 100%, ${GLOW}0.18), transparent 70%)` }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-28 md:px-12">
          <div className="flex flex-col gap-10 lg:flex-row lg:items-center lg:justify-between">
            <h2 className="text-5xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
              Two clicks
              <br />
              to certainty
            </h2>
            <div className="flex items-center gap-6">
              <MagneticCTA
                onClick={enter}
                className="rounded-full bg-sky-500 px-10 py-5 text-lg font-bold text-[#0b0c0e] hover:bg-sky-400"
                style={{ boxShadow: `0 0 40px ${GLOW}0.5)` }}
              >
                Get Started
              </MagneticCTA>
              <p className="text-neutral-400">
                Trusted by
                <br />
                <span className="text-white">500+ communities</span>
              </p>
            </div>
          </div>
          <div className="mt-10 flex flex-wrap gap-8">
            <span className="flex items-center gap-2 text-neutral-300">
              <Check size={18} className="text-sky-300" /> Download ZeroTrace
            </span>
            <span className="flex items-center gap-2 text-neutral-300">
              <Check size={18} className="text-sky-300" /> Join our Community
            </span>
          </div>
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
          </div>
          {[
            { h: 'Product', items: ['Features', 'Pricing', 'Download', 'Changelog'] },
            { h: 'Legal', items: ['Terms of Service', 'Privacy Policy', 'Legal'] },
            { h: 'Community', items: ['Discord', 'Branding'] },
            { h: 'Support', items: ['Docs', 'Contact Us', 'FAQ'] },
          ].map((col) => (
            <div key={col.h}>
              <p className="text-sm font-semibold text-white">{col.h}</p>
              <ul className="mt-3 space-y-2">
                {col.items.map((it) => (
                  <li key={it}>
                    <button
                      onClick={() => onNav(it === 'Contact Us' ? 'Discord' : it)}
                      className="text-sm text-neutral-500 hover:text-white"
                    >
                      {it}
                    </button>
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
