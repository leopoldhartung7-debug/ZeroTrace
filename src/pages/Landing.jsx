import { useNavigate } from 'react-router-dom'
import {
  Play, Globe, FastForward, Activity, Lock, RotateCw, AppWindow,
  Clock, Smile, FileCheck, ShieldCheck, Server, ScanFace, MoreVertical,
} from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

const NAV = ['Features', 'Pricing', 'Docs', 'Branding', 'FAQ', 'Download', 'Discord']

/* ---- decorative mockups ---- */
function FlowMock() {
  return (
    <div className="relative h-full min-h-[200px] w-full">
      <div className="absolute left-3 top-3 rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2">
        <p className="text-sm font-medium">Scanning</p>
        <p className="text-xs text-neutral-500">User PC</p>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path d="M70 50 C 70 130, 220 80, 220 160" stroke="#22c55e" strokeWidth="2" />
      </svg>
      <span className="absolute left-1/2 top-1/2 flex h-7 w-7 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full bg-neutral-700 text-neutral-300">
        <Clock size={14} />
      </span>
      <div className="absolute bottom-3 right-3 rounded-lg border border-green-500/30 bg-white/[0.04] px-4 py-2">
        <p className="text-sm font-medium">Results</p>
        <p className="text-xs text-neutral-500">Dashboard page</p>
      </div>
    </div>
  )
}
function ResultsMock() {
  const rows = [
    { c: 'bg-green-500', t: 'Legit Result' },
    { c: 'bg-yellow-500', t: 'Warning Result' },
    { c: 'bg-red-500', t: 'Cheater Result' },
  ]
  return (
    <div className="flex h-full min-h-[200px] flex-col justify-center gap-2.5">
      {rows.map((r, i) => (
        <div
          key={r.t}
          className={`flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.03] px-4 py-3 ${
            i === 1 ? 'ring-1 ring-white/10' : ''
          }`}
        >
          <div className="flex items-center gap-3">
            <span className={`h-4 w-4 rounded-full ${r.c}`} />
            <div>
              <p className="text-sm font-medium">{r.t}</p>
              <p className="text-xs text-neutral-500">Look Results</p>
            </div>
          </div>
          <MoreVertical size={15} className="text-neutral-600" />
        </div>
      ))}
    </div>
  )
}
function SecurityMock() {
  return (
    <div className="relative h-full min-h-[200px] w-full">
      <div className="absolute right-3 top-3 w-44 rounded-lg border border-white/10 bg-white/[0.04] p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Server</p>
            <p className="text-xs text-neutral-500">Results</p>
          </div>
          <ShieldCheck size={15} className="text-neutral-500" />
        </div>
        <div className="mt-4 flex justify-center"><Server size={26} className="text-neutral-500" /></div>
      </div>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 300 200" fill="none" preserveAspectRatio="none">
        <path d="M120 150 C 200 150, 230 110, 230 70" stroke="#3b82f6" strokeWidth="2" />
      </svg>
      <div className="absolute bottom-3 left-3 w-44 rounded-lg border border-white/10 bg-white/[0.06] p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">User</p>
            <p className="text-xs text-neutral-500">Scan</p>
          </div>
          <ScanFace size={15} className="text-neutral-500" />
        </div>
        <div className="mt-4 flex justify-center"><Lock size={24} className="text-blue-500" /></div>
      </div>
    </div>
  )
}

const PANELS = [
  { icon: FastForward, color: 'text-green-500', title: 'Lightning Fast\nSpeed', text: 'Ocean prioritizes completing scans within a strict time frame, averaging around 60 seconds for comprehensive cheat detection.', mock: <FlowMock /> },
  { icon: Activity, color: 'text-yellow-500', title: 'Detection\nQuality', text: 'Powered by cutting-edge AI and expert digital forensics, we provide precise, trustworthy cheat detection results.', mock: <ResultsMock />, reverse: true },
  { icon: Lock, color: 'text-blue-500', title: 'Military-Grade\nSecurity', text: "Ocean is secured with military-grade encryption — because security comes first, and it's built into every part of our product.", mock: <SecurityMock /> },
]

const FEATURES = [
  { icon: RotateCw, color: 'text-red-500', title: 'Custom Detection Rules', text: 'Ocean offers customizations ranging from simple design tweaks to real-time threat detection — all as part of our service.' },
  { icon: AppWindow, color: 'text-yellow-500', title: 'Forensic Detections', text: 'Our detections are powered by deep expertise in digital forensics and an advanced understanding of operating systems.' },
  { icon: Clock, color: 'text-green-500', title: '24/7 Active Support', text: "Ocean's support team sets us apart — delivering excellence and unmatched comfort to ensure the best service experience." },
  { icon: Smile, color: 'text-blue-500', title: 'Growing Community', text: 'Our community is constantly growing, with 500+ active servers and dedicated members ready to help you!' },
  { icon: FileCheck, color: 'text-purple-500', title: 'Complete Documentation', text: 'We provide documentation tailored for both new users and experts in the field of screensharing and cheat detection.' },
  { icon: ShieldCheck, color: 'text-teal-500', title: 'Privacy Focused', text: 'With future-focused security, we ensure every trace of information remains completely protected and encrypted.' },
]

export default function Landing() {
  const nav = useNavigate()
  const { state } = useStore()
  const toast = useToast()
  const enter = () => nav(state.auth ? '/dashboard' : '/login')

  const onNav = (item) => {
    if (item === 'Features') document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })
    else if (item === 'FAQ') document.getElementById('faq')?.scrollIntoView({ behavior: 'smooth' })
    else if (item === 'Discord') toast({ type: 'info', title: 'Discord', body: 'Community link is not configured in this demo.' })
    else nav('/login')
  }

  return (
    <div className="min-h-screen overflow-x-hidden bg-black text-white">
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-white/5 bg-black/80 px-6 py-5 backdrop-blur md:px-12">
        <button onClick={() => nav('/')} className="flex items-center gap-3">
          <span className="font-mono text-2xl font-bold">{'(*>'}</span>
          <span className="text-xl font-semibold">ocean</span>
        </button>
        <nav className="hidden items-center gap-7 lg:flex">
          {NAV.map((n) => (
            <button key={n} onClick={() => onNav(n)} className="text-sm text-neutral-400 transition-colors hover:text-white">
              {n}
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-4">
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
              <button onClick={() => nav('/login')} className="text-sm text-neutral-300 transition-colors hover:text-white">
                Login
              </button>
              <button onClick={() => nav('/login')} className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-500">
                Sign Up
              </button>
            </>
          )}
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: 'radial-gradient(70% 60% at 70% 10%, rgba(37,99,235,0.35), transparent 60%), linear-gradient(120deg, transparent 40%, rgba(59,130,246,0.18) 55%, transparent 70%)' }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-24 md:px-12 md:py-32">
          <span className="inline-block rounded-md bg-blue-600 px-4 py-1.5 text-sm font-bold tracking-wide text-white">UPDATE</span>
          <h1 className="mt-8 max-w-4xl text-6xl font-extrabold leading-[1.05] tracking-tight md:text-8xl">
            Most <span className="text-blue-500">powerful</span> Screenshare Tool
          </h1>
          <p className="mt-8 max-w-2xl text-lg leading-relaxed text-neutral-400 md:text-xl">
            Experience an unparalleled service designed with quality, safety, and speed in mind.
            Detect cheaters in 60 seconds with advanced forensic analysis.
          </p>
          <button
            onClick={enter}
            className="mt-10 flex items-center gap-3 rounded-full border border-white/15 bg-white/[0.04] py-4 pl-5 pr-7 text-lg font-medium backdrop-blur transition-colors hover:bg-white/[0.08]"
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10">
              <Play size={16} className="fill-white" />
            </span>
            Start Ocean
          </button>
        </div>
      </section>

      {/* See why */}
      <section className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <h2 className="text-5xl font-extrabold tracking-tight md:text-7xl">See why</h2>
          <p className="text-lg text-neutral-400 md:text-xl">Discover the key features of Ocean</p>
        </div>
        <div className="mt-12 grid gap-6 lg:grid-cols-2">
          {PANELS.map((p, i) => (
            <div
              key={p.title}
              className={`rounded-3xl border border-white/10 bg-white/[0.02] p-7 ${
                i === 2 ? 'lg:col-span-2' : ''
              }`}
            >
              <div className={`grid items-start gap-6 ${i === 2 ? 'md:grid-cols-2' : ''}`}>
                <div className={p.reverse ? 'md:order-2' : ''}>
                  <p.icon size={30} className={p.color} />
                  <h3 className="mt-12 whitespace-pre-line text-3xl font-bold">{p.title}</h3>
                  <p className="mt-4 max-w-md leading-relaxed text-neutral-400">{p.text}</p>
                </div>
                <div className={`rounded-2xl border border-white/10 bg-black/40 p-5 ${p.reverse ? 'md:order-1' : ''}`}>
                  {p.mock}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* A reliable solution */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <h2 className="max-w-2xl text-5xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
            A reliable solution against cheaters
          </h2>
          <p className="max-w-sm text-lg text-neutral-400 md:text-xl">
            An introduction to the basic features and customizable options available with Ocean.
          </p>
        </div>
        <div className="mt-14 grid gap-6 md:grid-cols-2">
          {FEATURES.map((f) => (
            <div key={f.title} className="rounded-3xl border border-white/10 bg-white/[0.02] p-8 md:p-10">
              <f.icon size={28} className={f.color} />
              <h3 className="mt-10 text-2xl font-bold">{f.title}</h3>
              <p className="mt-4 leading-relaxed text-neutral-400">{f.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="mx-auto max-w-3xl px-6 py-20 md:px-12">
        <h2 className="text-4xl font-extrabold tracking-tight md:text-5xl">FAQ</h2>
        <div className="mt-8 space-y-4">
          {[
            { q: 'How fast is a scan?', a: 'Most scans complete in around 60 seconds depending on the system.' },
            { q: 'Can it detect every cheat?', a: 'No usermode tool can. Ocean detects signature, heuristic and artifact-based indicators; kernel/DMA/external cheats are out of scope.' },
            { q: 'Is consent required?', a: 'Yes. The scanner only runs after the user accepts the consent prompt tied to a pin.' },
          ].map((f) => (
            <div key={f.q} className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
              <p className="font-medium">{f.q}</p>
              <p className="mt-1.5 text-sm text-neutral-400">{f.a}</p>
            </div>
          ))}
        </div>
        <div className="mt-14 flex flex-col items-center gap-4 rounded-2xl border border-white/10 bg-white/[0.03] p-10 text-center">
          <h3 className="text-2xl font-bold">Ready to start detecting?</h3>
          <button onClick={enter} className="rounded-lg bg-blue-600 px-6 py-3 text-sm font-semibold text-white hover:bg-blue-500">
            Start Ocean
          </button>
        </div>
      </section>

      <footer className="border-t border-white/10 px-6 py-8 text-center text-sm text-neutral-500">
        © 2026 Ocean Anti-Cheat — anticheat.ac
      </footer>
    </div>
  )
}
