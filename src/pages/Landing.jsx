import { useNavigate } from 'react-router-dom'
import { Play, Globe } from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

const NAV = ['Features', 'Pricing', 'Docs', 'Branding', 'FAQ', 'Download', 'Discord']

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
      {/* Top navigation */}
      <header className="relative z-20 flex items-center justify-between px-6 py-5 md:px-12">
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
          <button onClick={() => nav('/login')} className="text-sm text-neutral-300 transition-colors hover:text-white">
            Login
          </button>
          <button
            onClick={() => nav('/login')}
            className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-500"
          >
            Sign Up
          </button>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(70% 60% at 70% 10%, rgba(37,99,235,0.35), transparent 60%), linear-gradient(120deg, transparent 40%, rgba(59,130,246,0.18) 55%, transparent 70%)',
          }}
        />
        <div className="relative mx-auto max-w-6xl px-6 py-24 md:px-12 md:py-32">
          <span className="inline-block rounded-md bg-blue-600 px-4 py-1.5 text-sm font-bold tracking-wide text-white">
            UPDATE
          </span>
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

      {/* Features */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-20 md:px-12">
        <h2 className="text-3xl font-bold md:text-4xl">Why Ocean</h2>
        <div className="mt-10 grid gap-6 md:grid-cols-3">
          {[
            { t: '60-second detection', d: 'Advanced forensic analysis flags known clients, injectors and artifacts in under a minute.' },
            { t: 'Consent-based', d: 'A pin-bound scanner runs only with the user’s consent — fully auditable.' },
            { t: 'Deep forensics', d: 'Processes, modules, browser history, DNS cache, prefetch and MFT — correlated into one verdict.' },
          ].map((f) => (
            <div key={f.t} className="rounded-2xl border border-white/10 bg-white/[0.03] p-7">
              <h3 className="text-lg font-semibold">{f.t}</h3>
              <p className="mt-2 text-sm leading-relaxed text-neutral-400">{f.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="mx-auto max-w-3xl px-6 py-20 md:px-12">
        <h2 className="text-3xl font-bold md:text-4xl">FAQ</h2>
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
          <button
            onClick={enter}
            className="rounded-lg bg-blue-600 px-6 py-3 text-sm font-semibold text-white hover:bg-blue-500"
          >
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
