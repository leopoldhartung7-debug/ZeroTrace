import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play, Globe, Clock, ChevronDown, Check, Link2, MoreVertical, FileText,
  Search, Users, ShieldCheck, Zap, ScanSearch, CheckCircle2, Workflow,
  Folder, ArrowRight,
} from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'
import Logo from '../components/Logo.jsx'

const NAV = ['Features', 'Pricing', 'Docs', 'Branding', 'FAQ', 'Download', 'Discord']

/* Steel accent in rgba form for glow effects (matches --accent #9aa4c6). */
const GLOW = 'rgba(154,164,198,'

/* ---- hero scan graphic (detect.ac-style folder grid + magnifier) ---- */
function ScanGraphic() {
  return (
    <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6">
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: `radial-gradient(45% 45% at 60% 45%, ${GLOW}0.18), transparent 70%)` }}
      />
      <div className="relative grid grid-cols-5 gap-4">
        {Array.from({ length: 20 }).map((_, i) => (
          <Folder
            key={i}
            size={34}
            className="text-sky-400"
            style={{ opacity: [0.25, 0.5, 0.8, 1][i % 4] }}
          />
        ))}
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <div
          className="flex h-20 w-20 items-center justify-center rounded-full bg-sky-500"
          style={{ boxShadow: `0 0 44px ${GLOW}0.6), 0 0 0 10px ${GLOW}0.08)` }}
        >
          <Search size={32} className="text-[#0b0c0e]" strokeWidth={2.5} />
        </div>
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

/* ---- feature card with centred glowing icon ---- */
function GlowCard({ icon: Icon, title, text }) {
  return (
    <div className="group rounded-3xl border border-white/10 bg-white/[0.02] p-8 text-center transition-all duration-300 hover:-translate-y-1 hover:border-white/20">
      <div className="flex justify-center">
        <span
          className="flex h-14 w-14 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300 transition-transform duration-300 group-hover:scale-110"
          style={{ boxShadow: `0 0 28px ${GLOW}0.35)` }}
        >
          <Icon size={26} />
        </span>
      </div>
      <h3 className="mt-6 text-xl font-bold text-white">{title}</h3>
      <p className="mt-3 text-sm leading-relaxed text-neutral-400">{text}</p>
    </div>
  )
}

const GLOW_CARDS = [
  { icon: ScanSearch, title: 'Deep Forensic Scans', text: 'Advanced memory analysis and process investigation that reaches far beyond surface checks.' },
  { icon: ShieldCheck, title: 'Anti-Forensic Detection', text: 'Uncover sophisticated hiding techniques, cleaners and bypasses built to fool live anti-cheats.' },
  { icon: Zap, title: 'Lightning Fast', text: 'Complete a comprehensive, consent-based scan in under 60 seconds — no hour-long manual checks.' },
]

const METRICS = [
  { icon: CheckCircle2, value: '<0.1%', label: 'False Positives' },
  { icon: Clock, value: '60s', label: 'Average Scan' },
  { icon: Users, value: '500+', label: 'Active Servers' },
]

const KEY_POINTS = [
  { icon: Zap, title: 'Fast Forensics', text: 'Conduct a comprehensive investigation in under 60 seconds. No more hour-long manual PC checks that stall tournaments or cost server time.' },
  { icon: CheckCircle2, title: 'Great Accuracy', text: 'With a false-positive rate of less than 0.1%, you can issue bans with confidence that you are not hitting innocent players.' },
  { icon: ShieldCheck, title: 'Anti-Forensic Detection', text: 'Specifically designed to uncover traces of "cleaners" and bypasses meant to defeat traditional scanners and live anti-cheats.' },
  { icon: Workflow, title: 'Simplified Workflow', text: 'Removes the risk of needing trained "PC checkers". If the scan says they are cheating, the forensic evidence is right there.' },
]

const COMPARE = [
  { feature: 'Focus', live: 'Real-time memory and code injection', zt: 'Residual traces and forensic artifacts' },
  { feature: 'Speed', live: 'Continuous monitoring', zt: 'Deep-dive scan in under 60 seconds' },
  { feature: 'Goal', live: 'Prevent the cheat from running', zt: 'Prove the cheat was ever there' },
  { feature: 'Efficiency', live: 'High CPU overhead', zt: 'Zero impact on game performance' },
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
  { n: '1.', title: 'Downloading', text: 'Effortlessly scan suspects in seconds with two simple clicks that handle everything automatically.', mock: <DownloadMock /> },
  { n: '2.', title: 'Scanning', text: 'Let ZeroTrace take care of all the hard work for you. Simply wait a few seconds while our advanced technology processes everything and delivers accurate results.', mock: <ScanningMock />, reverse: true },
  { n: '3.', title: 'Data Review', text: 'Analyze the results on our dashboard and reach a final verdict on the suspect with confidence!', mock: <ReviewMock /> },
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
    <div className="landing-font force-dark app-bg min-h-screen overflow-x-hidden text-white">
      {/* ── Header ── */}
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-white/5 bg-black/50 px-6 py-4 backdrop-blur md:px-12">
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
      </header>

      {/* ── Hero ── */}
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: `radial-gradient(60% 55% at 75% 5%, ${GLOW}0.22), transparent 60%), radial-gradient(40% 50% at 0% 60%, ${GLOW}0.10), transparent 70%)` }}
        />
        <div className="relative mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 md:px-12 md:py-28 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <span
              className="inline-block rounded-full border border-sky-500/40 bg-sky-500/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.18em] text-sky-300"
            >
              Forensic Anti-Cheat
            </span>
            <h1 className="mt-7 text-5xl font-extrabold leading-[1.02] tracking-tight md:text-7xl">
              <span className="bg-gradient-to-br from-white to-[#9aa4c6] bg-clip-text text-transparent">
                Catch Cheaters Like Never Before
              </span>
            </h1>
            <p className="mt-7 max-w-xl text-lg leading-relaxed text-neutral-400">
              A brand-new forensic anti-cheat method that catches what live anti-cheats miss.
              Detect cheaters in 60 seconds with deep, consent-based analysis.
            </p>
            <div className="mt-9 flex flex-wrap items-center gap-4">
              <button
                onClick={enter}
                className="flex items-center gap-2 rounded-full bg-sky-500 px-7 py-3.5 text-base font-bold text-[#0b0c0e] transition-all hover:bg-sky-400"
                style={{ boxShadow: `0 0 34px ${GLOW}0.5)` }}
              >
                Get Started <ArrowRight size={18} />
              </button>
              <button
                onClick={() => onNav('Docs')}
                className="flex items-center gap-2 rounded-full border border-white/15 bg-white/[0.04] px-7 py-3.5 text-base font-semibold text-white backdrop-blur transition-colors hover:bg-white/[0.08]"
              >
                <Play size={15} className="fill-white" /> Learn More
              </button>
            </div>
          </div>

          <div className="space-y-5">
            <ScanGraphic />
            <div className="grid grid-cols-2 gap-4">
              <StatCard icon={Search} label="Scans" value="1M+" />
              <StatCard icon={Users} label="Servers" value="500+" />
            </div>
          </div>
        </div>
      </section>

      {/* ── Feature cards ── */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-16 md:px-12">
        <div className="grid gap-6 md:grid-cols-3">
          {GLOW_CARDS.map((c) => (
            <GlowCard key={c.title} {...c} />
          ))}
        </div>
        <div className="mt-6 grid gap-6 sm:grid-cols-3">
          {METRICS.map((m) => (
            <div key={m.label} className="rounded-3xl border border-white/10 bg-white/[0.02] p-8 text-center">
              <div className="flex justify-center">
                <span
                  className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-500/15 text-sky-300"
                  style={{ boxShadow: `0 0 24px ${GLOW}0.3)` }}
                >
                  <m.icon size={22} />
                </span>
              </div>
              <p className="mt-5 text-4xl font-extrabold tracking-tight text-sky-300">{m.value}</p>
              <p className="mt-1 text-sm text-neutral-400">{m.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── What is ZeroTrace ── */}
      <section className="mx-auto max-w-5xl px-6 py-20 md:px-12">
        <div className="text-center">
          <h2 className="inline-block text-4xl font-extrabold tracking-tight md:text-5xl">
            What Is ZeroTrace?
            <span className="mx-auto mt-3 block h-1 w-28 rounded-full bg-sky-500" />
          </h2>
        </div>
        <p className="mx-auto mt-8 max-w-3xl text-center text-lg leading-relaxed text-neutral-400">
          Standard anti-cheats are great at catching "loud" software, but they often struggle with
          sophisticated bypasses and anti-forensic tools designed to hide the cheats. ZeroTrace fills
          that gap by providing a deep-dive scan that most live systems simply are not built to perform.
        </p>

        <h3 className="mt-14 text-2xl font-bold">Key Points</h3>
        <div className="mt-6 grid gap-5 md:grid-cols-2">
          {KEY_POINTS.map((k) => (
            <div key={k.title} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6">
              <div className="flex items-center gap-2.5">
                <k.icon size={18} className="text-sky-300" />
                <h4 className="text-base font-bold text-white">{k.title}</h4>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-neutral-400">{k.text}</p>
            </div>
          ))}
        </div>

        {/* Comparison table */}
        <div className="mt-12 overflow-hidden rounded-2xl border border-white/10">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02]">
                <th className="px-5 py-4 text-xs font-bold uppercase tracking-[0.12em] text-neutral-500">Feature</th>
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
          Think of ZeroTrace not as a replacement, but as the best complement to your existing security.
        </p>
      </section>

      {/* ── How ZeroTrace works ── */}
      <section className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <div className="text-center">
          <h2 className="text-4xl font-extrabold tracking-tight md:text-6xl">How ZeroTrace works</h2>
          <p className="mx-auto mt-6 max-w-3xl text-lg text-neutral-400">
            In just a few steps you download, scan, and get secure results — no complications or
            lengthy processes.
          </p>
        </div>
        <div className="mt-16 space-y-20">
          {STEPS.map((s) => (
            <div key={s.title} className="grid items-center gap-10 md:grid-cols-2">
              <div className={s.reverse ? 'md:order-2' : ''}>
                <p className="text-lg text-neutral-500">{s.n}</p>
                <h3 className="mt-4 text-4xl font-extrabold tracking-tight text-sky-300 md:text-5xl">
                  {s.title}
                </h3>
                <p className="mt-6 max-w-md text-lg leading-relaxed text-neutral-400">{s.text}</p>
              </div>
              <div className={s.reverse ? 'md:order-1' : ''}>{s.mock}</div>
            </div>
          ))}
        </div>
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
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: `radial-gradient(60% 80% at 50% 100%, ${GLOW}0.18), transparent 70%)` }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-28 md:px-12">
          <div className="flex flex-col gap-10 lg:flex-row lg:items-center lg:justify-between">
            <h2 className="text-5xl font-extrabold leading-[1.05] tracking-tight md:text-7xl">
              Start Detecting
              <br />
              Now
            </h2>
            <div className="flex items-center gap-6">
              <button
                onClick={enter}
                className="rounded-full bg-sky-500 px-10 py-5 text-lg font-bold text-[#0b0c0e] transition-all hover:bg-sky-400"
                style={{ boxShadow: `0 0 40px ${GLOW}0.5)` }}
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
