import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play, Globe, FastForward, Activity, Lock, RotateCw, AppWindow,
  Clock, Smile, FileCheck, ShieldCheck, Server, ScanFace, MoreVertical,
  FileText, ChevronDown, Check, Link2,
} from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'
import Logo from '../components/Logo.jsx'

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
        <path d="M120 150 C 200 150, 230 110, 230 70" stroke="#38bdf8" strokeWidth="2" />
      </svg>
      <div className="absolute bottom-3 left-3 w-44 rounded-lg border border-white/10 bg-white/[0.06] p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">User</p>
            <p className="text-xs text-neutral-500">Scan</p>
          </div>
          <ScanFace size={15} className="text-neutral-500" />
        </div>
        <div className="mt-4 flex justify-center"><Lock size={24} className="text-sky-500" /></div>
      </div>
    </div>
  )
}

const PANELS = [
  { icon: FastForward, color: 'text-green-500', title: 'Lightning Fast\nSpeed', text: 'ZeroTrace prioritizes completing scans within a strict time frame, averaging around 60 seconds for comprehensive cheat detection.', mock: <FlowMock /> },
  { icon: Activity, color: 'text-yellow-500', title: 'Detection\nQuality', text: 'Powered by cutting-edge AI and expert digital forensics, we provide precise, trustworthy cheat detection results.', mock: <ResultsMock />, reverse: true },
  { icon: Lock, color: 'text-sky-500', title: 'Military-Grade\nSecurity', text: "ZeroTrace is secured with military-grade encryption — because security comes first, and it's built into every part of our product.", mock: <SecurityMock /> },
]

const FEATURES = [
  { icon: RotateCw, color: 'text-red-500', title: 'Custom Detection Rules', text: 'ZeroTrace offers customizations ranging from simple design tweaks to real-time threat detection — all as part of our service.' },
  { icon: AppWindow, color: 'text-yellow-500', title: 'Forensic Detections', text: 'Our detections are powered by deep expertise in digital forensics and an advanced understanding of operating systems.' },
  { icon: Clock, color: 'text-green-500', title: '24/7 Active Support', text: "ZeroTrace's support team sets us apart — delivering excellence and unmatched comfort to ensure the best service experience." },
  { icon: Smile, color: 'text-sky-500', title: 'Growing Community', text: 'Our community is constantly growing, with 500+ active servers and dedicated members ready to help you!' },
  { icon: FileCheck, color: 'text-purple-500', title: 'Complete Documentation', text: 'We provide documentation tailored for both new users and experts in the field of screensharing and cheat detection.' },
  { icon: ShieldCheck, color: 'text-sky-500', title: 'Privacy Focused', text: 'With future-focused security, we ensure every trace of information remains completely protected and encrypted.' },
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
            <FileText size={18} className={i === 0 ? 'text-sky-500' : 'text-neutral-500'} />
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
      <pre className="mt-1 font-mono text-[11px] leading-relaxed text-yellow-600/70">{`"KeyAuth": {
  Var1 => String::Keyauth::Nocase;
  Var2 => String::Keyauth::Wide;`}</pre>
      <div className="mt-6 flex justify-center"><Logo size="md" /></div>
      <p className="mt-3 text-center text-sm text-neutral-500">Scanning...</p>
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div className="h-full w-3/4 rounded-full bg-yellow-500" />
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
  { n: '1.', title: 'Downloading', color: 'text-sky-500', text: 'Effortlessly scan suspects in seconds with two simple clicks that handle everything automatically.', mock: <DownloadMock /> },
  { n: '2.', title: 'Scanning', color: 'text-yellow-500', text: 'Let ZeroTrace take care of all the hard work for you. Simply wait a few seconds while our advanced technology processes everything and delivers accurate results quickly and effortlessly.', mock: <ScanningMock />, reverse: true },
  { n: '3.', title: 'Data Review', color: 'text-red-500', text: 'Analyze the results on our dashboard and reach a final verdict on the suspect with confidence!', mock: <ReviewMock /> },
]

const QA = [
  { q: 'Why should you use ZeroTrace?', a: 'ZeroTrace delivers fast, consent-based forensic screenshare scans with precise, trustworthy results — detecting cheaters in around 60 seconds.' },
  { q: 'What operating systems do you support?', a: 'The scanner runs on Windows and Linux. The dashboard works in any modern browser.' },
  { q: 'What type of data does ZeroTrace collect?', a: 'Only anti-cheat artifacts (processes, modules, files, system traces) gathered with consent. Dashboard data stays in your browser; nothing is sold or shared.' },
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
    <div className="force-dark app-bg min-h-screen overflow-x-hidden text-white">
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-white/5 bg-[#1a1b1e]/80 px-6 py-5 backdrop-blur md:px-12">
        <button onClick={() => nav('/')} className="flex items-center gap-3">
          <Logo size="md" />
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
              <button onClick={() => nav('/login')} className="rounded-lg bg-sky-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-sky-500">
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
          style={{ background: 'radial-gradient(70% 60% at 70% 10%, rgba(56,189,248,0.35), transparent 60%), linear-gradient(120deg, transparent 40%, rgba(56,189,248,0.18) 55%, transparent 70%)' }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-24 md:px-12 md:py-32">
          <span className="inline-block rounded-md bg-sky-600 px-4 py-1.5 text-sm font-bold tracking-wide text-white">UPDATE</span>
          <h1 className="mt-8 max-w-4xl text-6xl font-extrabold leading-[1.05] tracking-tight md:text-8xl">
            Most <span className="text-sky-500">powerful</span> Screenshare Tool
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
            Start ZeroTrace
          </button>
        </div>
      </section>

      {/* See why */}
      <section className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <h2 className="text-5xl font-extrabold tracking-tight md:text-7xl">See why</h2>
          <p className="text-lg text-neutral-400 md:text-xl">Discover the key features of ZeroTrace</p>
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
                <div className={`rounded-2xl border border-white/10 bg-white/[0.03] p-5 ${p.reverse ? 'md:order-1' : ''}`}>
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
            An introduction to the basic features and customizable options available with ZeroTrace.
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

      {/* How ZeroTrace works */}
      <section className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="text-center">
          <h2 className="text-5xl font-extrabold tracking-tight md:text-7xl">How ZeroTrace works</h2>
          <p className="mx-auto mt-6 max-w-3xl text-lg text-neutral-400 md:text-xl">
            We show you how easy it is to use ZeroTrace: in just a few steps, you can download, scan,
            and get secure results—no complications or lengthy processes.
          </p>
        </div>
        <div className="mt-16 space-y-20">
          {STEPS.map((s) => (
            <div key={s.title} className="grid items-center gap-10 md:grid-cols-2">
              <div className={s.reverse ? 'md:order-2' : ''}>
                <p className="text-lg text-neutral-500">{s.n}</p>
                <h3 className={`mt-4 text-5xl font-extrabold tracking-tight md:text-6xl ${s.color}`}>
                  {s.title}
                </h3>
                <p className="mt-6 max-w-md text-lg leading-relaxed text-neutral-400">{s.text}</p>
              </div>
              <div className={s.reverse ? 'md:order-1' : ''}>{s.mock}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Answer your questions */}
      <section id="faq" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="grid gap-10 lg:grid-cols-2">
          <div>
            <h2 className="text-5xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
              Answer your <span className="text-sky-500">questions</span>
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

      {/* Start Swimming Now */}
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: 'radial-gradient(60% 80% at 50% 100%, rgba(56,189,248,0.18), transparent 70%)' }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-28 md:px-12">
          <div className="flex flex-col gap-10 lg:flex-row lg:items-center lg:justify-between">
            <h2 className="text-6xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
              Start Swimming
              <br />
              Now
            </h2>
            <div className="flex items-center gap-6">
              <button
                onClick={enter}
                className="rounded-full bg-sky-600 px-10 py-5 text-lg font-semibold text-black hover:bg-sky-500"
              >
                Get Started
              </button>
              <p className="text-neutral-400">
                More than
                <br />
                <span className="text-white">500+ frequent buyers</span>
              </p>
            </div>
          </div>
          <div className="mt-10 flex flex-wrap gap-8">
            <span className="flex items-center gap-2 text-neutral-300">
              <Check size={18} className="text-sky-500" /> Download ZeroTrace
            </span>
            <span className="flex items-center gap-2 text-neutral-300">
              <Check size={18} className="text-sky-500" /> Join our Community
            </span>
          </div>
        </div>
      </section>

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
