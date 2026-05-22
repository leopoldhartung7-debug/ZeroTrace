import { useMemo, useRef, useState } from 'react'
import {
  Trophy, BookOpen, Download, FileText, Scale, History,
  Check, ScanLine, Eye, ShieldAlert, Terminal, Search,
  ChevronDown, ChevronRight, Monitor, Shield, Ticket, ExternalLink,
  AlertCircle, CheckCircle2, Activity, Code2,
} from 'lucide-react'
import { Card, StatTile } from '../components/kit.jsx'
import { useStats, useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

/* ----------------------------- Leaderboard ----------------------------- */
export function Leaderboard() {
  const stats = useStats()
  const ranked = useMemo(
    () => [...stats.byGame].sort((a, b) => b.detections - a.detections),
    [stats.byGame],
  )
  const medal = ['#facc15', '#cbd5e1', '#f59e0b']
  return (
    <div>
      <HeroBanner
        title="Leaderboard"
        subtitle="Ranking is computed live from your own scan data."
        meta={`${stats.totalScans} scans · ${stats.detections} detections`}
      />
      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile icon={ScanLine} label="Total Scans" value={stats.totalScans} />
        <StatTile icon={Eye} label="Detections" value={stats.detections} accent="text-red-500" />
        <StatTile icon={ShieldAlert} label="Unique Cheats" value={stats.uniqueCheats} accent="text-yellow-500" />
        <StatTile icon={Trophy} label="Games Tracked" value={ranked.length} accent="text-sky-500" />
      </div>
      <Card className="p-6">
        <h3 className="txt mb-4 text-lg font-semibold">Games by Detections</h3>
        {ranked.length === 0 ? (
          <p className="muted py-10 text-center text-sm">No scan data yet.</p>
        ) : (
          <div className="space-y-2">
            {ranked.map((g, i) => (
              <div key={g.game} className="tile flex items-center gap-4 rounded-lg border px-4 py-3">
                <span
                  className="flex h-8 w-8 items-center justify-center rounded-full text-sm font-bold"
                  style={{ background: medal[i] || 'var(--border)', color: i < 3 ? '#000' : 'var(--text)' }}
                >
                  {i + 1}
                </span>
                <span className="txt flex-1 font-medium">{g.game}</span>
                <span className="muted text-sm">{g.scans} scans</span>
                <span className="text-sm font-semibold text-red-500">{g.detections} detections</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

/* ---------------------------- Documentation ---------------------------- */
const DOC_NAV = [
  { type: 'item', id: 'overview', label: 'Overview', icon: BookOpen },
  {
    type: 'group',
    id: 'detections',
    label: 'Detections',
    icon: Activity,
    children: [
      { id: 'detects-logs', label: 'Detects Logs' },
      { id: 'warning-logs', label: 'Warning Logs' },
      { id: 'suspicious-logs', label: 'Suspicious Logs' },
      { id: 'detection-systems', label: 'Detection Systems' },
      { id: 'integrity-checks', label: 'Integrity Checks' },
    ],
  },
  {
    type: 'group',
    id: 'api',
    label: 'API',
    icon: Code2,
    children: [
      { id: 'api-overview', label: 'Overview' },
      { id: 'scanned-users', label: 'Scanned Users' },
      { id: 'user-risk-score', label: 'User Risk Score' },
      { id: 'api-pins', label: 'Pins' },
      { id: 'pin-status', label: 'Pin Status' },
      { id: 'create-pins', label: 'Create Pins' },
    ],
  },
]

const DOC_CONTENT = {
  overview: {
    title: 'Documentation',
    blocks: [
      { h: null, p: 'Welcome to the official documentation of ZeroTrace Anticheat Solutions, a post-mortem detection framework designed to identify and analyze cheating activity across multiple game environments including FiveM, Minecraft, and other supported platforms.' },
      { h: null, p: "This portal provides a complete reference for developers, partners, and server administrators who work with ZeroTrace's detection systems. Here you will find detailed explanations of detection categories, integrity modules, logging schemas, and implementation details for the ZeroTrace Dashboard and ZeroTrace+ APIs." },
      { h: 'Getting Started', list: [
        'Use the navigation sidebar to explore categories such as Detections, Logs, and Integrity Systems.',
        'Read each section to understand how ZeroTrace classifies detections, processes memory and file artifacts, and communicates results through the dashboard.',
        'Use the search bar to quickly locate specific detection signatures or log entries by name.',
        'Generate a pin from the Pins page, run the scanner, and review the results on the Scan Results page.',
      ] },
    ],
  },
  'detects-logs': {
    title: 'Detects Logs',
    blocks: [
      { p: 'Detects Logs are high-confidence findings produced when ZeroTrace matches a known cheat signature in memory, on disk, or in the loaded module list of the game process. Each entry includes the matched signature, severity (High/Critical), and the evidence (process, module or file path).' },
      { h: 'Severity', list: ['Critical — paid/native cheat clients and injectors', 'High — known free clients, loaders and tooling'] },
      { p: 'Detects Logs alone are sufficient grounds for a moderation decision when corroborated by execution evidence.' },
    ],
  },
  'warning-logs': {
    title: 'Warning Logs',
    blocks: [
      { p: 'Warning Logs are medium-severity indicators. They do not prove cheating on their own but raise the risk score and warrant manual review — e.g. analysis/debug tools, unsigned modules in unusual locations, or anti-forensic utilities.' },
      { h: 'Typical sources', list: ['Cheat Engine, x64dbg, ReClass', 'Unsigned non-system DLLs', 'File cleaners (BleachBit, CCleaner) run shortly before the scan'] },
    ],
  },
  'suspicious-logs': {
    title: 'Suspicious Logs',
    blocks: [
      { p: 'Suspicious Logs are low-severity, contextual findings used for timeline correlation. They become meaningful when combined with Detects or Warning logs.' },
      { p: 'Examples: short-lived processes from temp directories, renamed binaries, or gaps in the prefetch/USN journal.' },
    ],
  },
  'detection-systems': {
    title: 'Detection Systems',
    blocks: [
      { p: 'ZeroTrace combines several engines to reach a verdict:' },
      { h: 'Engines', list: [
        'Signature matching — strings & module names against the cheat database',
        'Hashing — SHA-256 of files compared to known-bad sets',
        'YARA-lite — string & hex pattern rules',
        'Heuristics — suspicious JVM args, reflection, injection patterns',
        'Correlation — artifacts merged into a single timeline',
      ] },
      { p: 'Usermode scanning cannot detect kernel, DMA or external (second-PC) cheats — results are indicators, not absolute proof.' },
    ],
  },
  'integrity-checks': {
    title: 'Integrity Checks',
    blocks: [
      { p: 'Integrity Checks validate that the system and the scanner itself were not tampered with: module signature verification, driver integrity, handle/hook table inspection and memory region scanning.' },
      { p: 'Passing integrity checks are logged as Integrity Logs and increase confidence in a Clean verdict.' },
    ],
  },
  'api-overview': {
    title: 'API — Overview',
    blocks: [
      { p: 'The ZeroTrace+ API exposes scan sessions and results. All endpoints require a Bearer API key. Base URL: https://api.anticheat.ac/v1.' },
      { code: 'GET /v1/pins\nAuthorization: Bearer <API_KEY>' },
      { p: 'This dashboard is client-side; the API reference here describes the schema the ZEROTRACE1 token / .zerotrace session files follow.' },
    ],
  },
  'scanned-users': {
    title: 'API — Scanned Users',
    blocks: [
      { p: 'Returns users that have been scanned, keyed by Discord ID. Repeat scans of the same Discord ID are grouped so previous results can be retrieved.' },
      { code: 'GET /v1/users/{discordId}\n→ { discordId, scans: [ { pin, result, scannedAt } ] }' },
    ],
  },
  'user-risk-score': {
    title: 'API — User Risk Score',
    blocks: [
      { p: 'The risk score is computed from the scan result: detects × 8 + warnings × 2 + suspicious × 5, capped at 100.' },
      { list: ['0–29 — Low risk', '30–59 — Medium risk', '60–100 — High risk'] },
    ],
  },
  'api-pins': {
    title: 'API — Pins',
    blocks: [
      { p: 'List and inspect scan pins. A pin is an 8-character code bound to a scanned user (Discord ID) and game.' },
      { code: 'GET /v1/pins → [ { pin, name, discordId, game, status, result } ]' },
    ],
  },
  'pin-status': {
    title: 'API — Pin Status',
    blocks: [
      { p: 'Pin lifecycle: Pending → Finished (or Expired after 24h).' },
      { list: ['Pending — created, waiting to be scanned', 'Finished — scan completed, result available', 'Expired — not used within 24 hours'] },
    ],
  },
  'create-pins': {
    title: 'API — Create Pins',
    blocks: [
      { p: 'Create a pin for a scan. The scanned user’s Discord ID is required and stored with the result.' },
      { code: 'POST /v1/pins\n{ "name": "Suspect", "discordId": "1454…", "game": "FIVEM" }\n→ { "pin": "N0V7M3M7", "status": "Pending" }' },
    ],
  },
}

export function Documentation() {
  const [active, setActive] = useState('overview')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState({ detections: true, api: true })
  const doc = DOC_CONTENT[active] || DOC_CONTENT.overview

  const matches = (label) => !q || label.toLowerCase().includes(q.toLowerCase())

  return (
    <div>
      <HeroBanner
        title="Documentation"
        subtitle="Guides, references and API details for ZeroTrace Anti-Cheat"
      />
      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
      <Card className="h-fit p-4 lg:sticky lg:top-6">
        <div className="relative mb-4">
          <Search size={15} className="muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search..."
            className="bd tile txt w-full rounded-lg border py-2 pl-9 pr-3 text-sm focus:outline-none"
          />
        </div>
        <p className="caps-label mb-2 px-2">Documentation</p>
        <nav className="space-y-1">
          {DOC_NAV.map((n) => {
            if (n.type === 'item') {
              if (!matches(n.label)) return null
              return (
                <button
                  key={n.id}
                  onClick={() => setActive(n.id)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium ${
                    active === n.id ? 'bg-sky-600/15 text-sky-500' : 'txt hoverable'
                  }`}
                >
                  <n.icon size={16} /> {n.label}
                </button>
              )
            }
            const kids = n.children.filter((c) => matches(c.label))
            if (kids.length === 0 && !matches(n.label)) return null
            return (
              <div key={n.id}>
                <button
                  onClick={() => setOpen((o) => ({ ...o, [n.id]: !o[n.id] }))}
                  className="txt hoverable flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium"
                >
                  <n.icon size={16} className="muted" />
                  <span className="flex-1 text-left">{n.label}</span>
                  {open[n.id] ? <ChevronDown size={15} className="muted" /> : <ChevronRight size={15} className="muted" />}
                </button>
                {open[n.id] && (
                  <div className="bd ml-4 mt-1 space-y-1 border-l pl-3">
                    {kids.map((c) => (
                      <button
                        key={c.id}
                        onClick={() => setActive(c.id)}
                        className={`block w-full rounded-lg px-3 py-1.5 text-left text-sm ${
                          active === c.id ? 'bg-sky-600/15 text-sky-500' : 'muted hoverable'
                        }`}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </nav>
      </Card>

      <div>
        <h2 className="txt text-3xl font-bold tracking-tight">{doc.title}</h2>
        <div className="mt-6 space-y-6">
          {doc.blocks.map((b, i) => (
            <div key={i}>
              {b.h && <h2 className="txt mb-3 text-2xl font-bold">{b.h}</h2>}
              {b.p && <p className="muted text-[15px] leading-relaxed">{b.p}</p>}
              {b.list && (
                <ol className="mt-2 space-y-2">
                  {b.list.map((li, j) => (
                    <li key={j} className="muted flex gap-3 text-[15px] leading-relaxed">
                      <span className="text-sky-500">{j + 1}.</span> {li}
                    </li>
                  ))}
                </ol>
              )}
              {b.code && (
                <pre className="bd tile txt mt-2 overflow-x-auto rounded-lg border p-4 font-mono text-xs">
                  {b.code}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>
      </div>
    </div>
  )
}

/* ------------------------------- Pricing ------------------------------- */
function PriceCard({ title, desc, price, period, features, onBuy }) {
  return (
    <Card className="flex flex-col p-6">
      <h3 className="txt text-lg font-semibold">{title}</h3>
      <p className="muted mt-2 text-sm leading-relaxed">{desc}</p>
      <p className="txt mt-5 text-4xl font-bold">
        {price}
        <span className="muted text-sm font-normal"> {period}</span>
      </p>
      <ul className="mt-5 flex-1 space-y-2.5">
        {features.map((f) => (
          <li key={f} className="muted flex items-center gap-2.5 text-sm">
            <span className="text-sky-500">•</span> {f}
          </li>
        ))}
      </ul>
      <button
        onClick={onBuy}
        className="mt-6 w-full rounded-xl bg-white px-4 py-3 text-sm font-semibold text-black transition-opacity hover:opacity-90"
      >
        Purchase
      </button>
    </Card>
  )
}

export function Pricing() {
  const toast = useToast()
  const buy = (n) => toast({ type: 'info', title: 'Checkout', body: `${n} — payment is not wired up in this demo.` })
  const personalFeatures = ['1 slot', 'Personal use', 'FIVEM access', 'Unlimited pin generation', 'Basic support']

  return (
    <div>
      <HeroBanner
        title="Pricing"
        subtitle="Plans & limits — pick the plan that fits your community"
      />
      <button
        onClick={() => toast({ type: 'info', title: 'Claim license', body: 'No pending licenses on this account.' })}
        className="muted hover:txt mx-auto mb-8 flex items-center gap-2 text-sm"
      >
        <Ticket size={16} /> Have a pending license? <span className="text-sky-500">Claim it here</span>
      </button>

      <div className="mb-4 flex items-center gap-4">
        <span className="bd h-px flex-1 border-t" />
        <span className="caps-label">Personal Plans</span>
        <span className="bd h-px flex-1 border-t" />
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <PriceCard
          title="ZeroTrace FiveM - Yearly Personal"
          desc="Specific license that supports scans for the game FiveM, including its respective detection modules."
          price="$79.99"
          period="/year"
          features={personalFeatures}
          onBuy={() => buy('Yearly Personal')}
        />
        <PriceCard
          title="ZeroTrace FiveM - 6 Month Personal"
          desc="Specific license that supports scans for the game FiveM, including its respective detection modules."
          price="$44.99"
          period="/6 months"
          features={personalFeatures}
          onBuy={() => buy('6 Month Personal')}
        />
        <PriceCard
          title="ZeroTrace FiveM - Monthly Personal"
          desc="Specific license that supports scans for the game FiveM, including its respective detection modules."
          price="$10"
          period="/month"
          features={personalFeatures}
          onBuy={() => buy('Monthly Personal')}
        />
      </div>

      <div className="mb-4 mt-12 flex items-center gap-4">
        <span className="bd h-px flex-1 border-t" />
        <span className="caps-label">Enterprise Plans</span>
        <span className="bd h-px flex-1 border-t" />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <PriceCard
          title="ZeroTrace FiveM - Enterprise+ (6 months) 20 Slots"
          desc="Team license for organisations. Supports FiveM scans across multiple operators."
          price="$249.99"
          period="/6 months"
          features={['20 slots', 'Team / organisation use', 'FIVEM access', 'Unlimited pin generation', 'Shared pins & access', 'Priority support']}
          onBuy={() => buy('Enterprise+ 20 Slots')}
        />
        <PriceCard
          title="ZeroTrace FiveM - Enterprise (6 months) 10 Slots"
          desc="Team license for organisations. Supports FiveM scans across multiple operators."
          price="$149.99"
          period="/6 months"
          features={['10 slots', 'Team / organisation use', 'FIVEM access', 'Unlimited pin generation', 'Shared pins & access', 'Priority support']}
          onBuy={() => buy('Enterprise 10 Slots')}
        />
      </div>
      <p className="muted mt-8 text-center text-xs">Demo pricing — no payment processing is wired up.</p>
    </div>
  )
}

/* ------------------------------ Download ------------------------------- */
function DownloadCard({ icon: Icon, name, tagTone, desc, hint, accent, pins, toast }) {
  const [pin, setPin] = useState('')
  const go = () => {
    const code = pin.trim().toUpperCase()
    const match = pins.find((p) => p.pin === code)
    if (code.length !== 8 || !match) {
      toast({ type: 'error', title: 'Invalid PIN', body: 'Enter a valid 8-character pin from your Pins.' })
      return
    }
    const session = {
      v: 1,
      product: `ZeroTrace Scanner (${name})`,
      pin: match.pin,
      game: match.game,
      name: match.name,
      discordId: match.discordId || '',
      createdAt: match.createdAt,
      expiresAt: match.createdAt + 24 * 3600 * 1000,
    }
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' }))
    a.download = `ZeroTraceScan-${match.pin}.zerotrace`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Session downloaded', body: `ZeroTraceScan-${match.pin}.zerotrace` })
  }
  return (
    <Card className="p-6">
      <div className="bd flex items-center gap-3 border-b pb-4">
        <span className="flex h-11 w-11 items-center justify-center rounded-xl border" style={{ borderColor: accent, color: accent, background: `${accent}1a` }}>
          <Icon size={20} />
        </span>
        <div>
          <p className="txt flex items-center gap-2 font-semibold">
            {name}
            <span className="rounded-md border px-2 py-0.5 text-[10px] font-bold" style={{ color: tagTone, borderColor: `${tagTone}55`, background: `${tagTone}1a` }}>
              PIN Required
            </span>
          </p>
          <p className="muted text-xs">{desc}</p>
        </div>
      </div>
      <p className="muted mt-4 text-sm">{hint}</p>
      <label className="txt mb-1.5 mt-4 block text-sm font-medium">Enter your PIN code</label>
      <div className="flex gap-2">
        <input
          value={pin}
          onChange={(e) => setPin(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, ''))}
          maxLength={8}
          placeholder="A1B2C3D4"
          className="bd tile txt w-full rounded-lg border px-3 py-2.5 font-mono text-sm focus:outline-none"
        />
        <button
          onClick={go}
          className="flex shrink-0 items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold text-white"
          style={{ background: accent }}
        >
          <Download size={15} /> Download
        </button>
      </div>
    </Card>
  )
}

export function DownloadPage() {
  const { state } = useStore()
  const toast = useToast()
  return (
    <div>
      <HeroBanner title="Start Detecting" subtitle="Download ZeroTrace for your platform — available for Windows & Linux" />

      <div className="grid gap-5 lg:grid-cols-3">
        <DownloadCard icon={Monitor} name="Windows" tagTone="#ef4444" accent="#dc2626"
          desc="Advanced cheat detection" hint="Enter your 8-character PIN."
          pins={state.pins} toast={toast} />
        <DownloadCard icon={Monitor} name="Linux" tagTone="#f59e0b" accent="#d97706"
          desc="Cheat detection for Linux systems" hint="Enter your 8-character PIN."
          pins={state.pins} toast={toast} />
        <DownloadCard icon={Shield} name="Anti SS Tool" tagTone="#38bdf8" accent="#0ea5e9"
          desc="Bypass blocks preventing ZeroTrace from running"
          hint="Enter your 8-character PIN to download the Anti SS Tool."
          pins={state.pins} toast={toast} />
      </div>

      <div className="mt-14 text-center">
        <h2 className="txt text-3xl font-bold">Can't run ZeroTrace?</h2>
        <p className="muted mt-2">Let's solve that.</p>
      </div>
      <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Troubleshooting</p>
          <h3 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <AlertCircle size={18} className="text-yellow-500" /> VC++ Runtime Error
          </h3>
          <ol className="mt-4 space-y-3">
            {['Download and install vcredist (x64)', 'Restart your computer.', 'Try running ZeroTrace again.', 'Contact support if persists.'].map((s, i) => (
              <li key={i} className="muted flex items-start gap-3 text-sm">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-yellow-600/40 bg-yellow-600/15 text-[11px] font-bold text-yellow-500">
                  {i + 1}
                </span>
                {s}
              </li>
            ))}
          </ol>
        </Card>
        <Card className="p-6">
          <p className="caps-label">Support</p>
          <h3 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <CheckCircle2 size={18} className="text-green-500" /> Need More Help?
          </h3>
          <p className="muted mt-3 text-sm">Join our Discord for support.</p>
          <button
            onClick={() => toast({ type: 'info', title: 'Discord', body: 'Community Discord link is not configured in this demo.' })}
            className="bd txt mt-5 flex w-full items-center justify-center gap-2 rounded-lg border py-2.5 text-sm font-medium hover:border-sky-500"
          >
            <ExternalLink size={15} /> Discord
          </button>
        </Card>
      </div>
    </div>
  )
}


/* ----------------------- Shared doc primitives ------------------------- */
function HeroBanner({ title, subtitle, meta }) {
  return (
    <div className="bd relative mb-10 overflow-hidden rounded-xl border">
      <div
        className="absolute inset-0 opacity-[0.5]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(56,189,248,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.06) 1px, transparent 1px)',
          backgroundSize: '34px 34px',
          maskImage: 'radial-gradient(80% 100% at 10% 0%, #000 30%, transparent 75%)',
        }}
      />
      <div className="absolute left-0 top-0 h-full w-1 bg-sky-500" />
      <div className="relative px-7 py-12 md:px-10 md:py-14">
        <p className="caps-label mb-3 flex items-center gap-2 text-sky-400">
          <span className="h-px w-7 bg-sky-500" /> ZeroTrace
        </p>
        <h1 className="txt text-4xl font-extrabold tracking-tight md:text-5xl">{title}</h1>
        <p className="muted mt-3 max-w-xl text-[15px] leading-relaxed">{subtitle}</p>
        {meta && (
          <p className="bd muted mt-6 inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs">
            <FileText size={14} /> {meta}
          </p>
        )}
      </div>
    </div>
  )
}

function TocDoc({ hero, header, preface, sections }) {
  const refs = useRef({})
  const goto = (id) => refs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  return (
    <div>
      {hero}
      <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
        <Card className="h-fit p-5 lg:sticky lg:top-6">
          <h3 className="txt mb-4 flex items-center gap-2 text-base font-semibold">
            <FileText size={17} className="text-sky-500" /> Table of Contents
          </h3>
          <nav className="max-h-[70vh] space-y-1 overflow-y-auto">
            {sections.map((s) => (
              <button
                key={s.id}
                onClick={() => goto(s.id)}
                className={`hoverable flex w-full items-start gap-3 rounded-lg px-3 py-2 text-left text-sm ${
                  s.sub ? 'pl-8' : ''
                }`}
              >
                <span className="text-sky-500">{s.n}</span>
                <span className="txt">{s.title}</span>
              </button>
            ))}
          </nav>
        </Card>

        <div className="space-y-6">
          {header}
          {preface}
          {sections.map((s) => (
            <div
              key={s.id}
              ref={(el) => (refs.current[s.id] = el)}
              className="scroll-mt-6 space-y-4"
            >
              <Card className="flex items-center gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-600/15 text-sm font-bold text-sky-400">
                  {s.n}
                </span>
                <h2 className="txt text-xl font-bold md:text-2xl">{s.title}</h2>
              </Card>
              <Card className="p-6 md:p-8">{s.content}</Card>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function P({ children }) {
  return <p className="muted text-[15px] leading-relaxed">{children}</p>
}
function Group({ title, items }) {
  return (
    <div className="mb-6 last:mb-0">
      <p className="mb-2 text-base font-semibold text-sky-400">{title}</p>
      <ul className="space-y-3">
        {items.map((it) => (
          <li key={it.h}>
            <p className="txt text-sm font-semibold">• {it.h}</p>
            <ul className="mt-1 space-y-0.5 pl-5">
              {it.sub.map((x) => (
                <li key={x} className="muted text-sm">– {x}</li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </div>
  )
}
function Bullets({ items }) {
  return (
    <ul className="space-y-2">
      {items.map((x) => (
        <li key={x} className="muted flex gap-2 text-[15px] leading-relaxed">
          <span className="text-sky-500">•</span> {x}
        </li>
      ))}
    </ul>
  )
}

/* ------------------ Terms of Service (Legal Agreement) ----------------- */
const AGREEMENT = [
  { n: '1', id: 't1', title: 'Description of the Software', body: ['ZeroTrace is a post-mortem anti-cheat and screenshare assistance framework. It inspects processes, modules, files and system artifacts on a consenting user’s machine and reports indicators of cheating to the operator who initiated the scan.', 'The ZeroTrace Monthly/Yearly/Lifetime License and the ZeroTrace Enterprise License, collectively “The Licenses”, are classified as Products. A License can be a Personal Licence or an Enterprise Licence.'] },
  { n: '2', id: 't2', title: 'Use of ZeroTrace', body: ['ZeroTrace may only be used to scan a device with the explicit, informed consent of that device’s owner. Operators are responsible for obtaining consent and for moderation decisions made from results.', 'A Personal Licence is granted to an individual upon payment and may not be shared. An Enterprise Licence provides operator slots for an organisation.'] },
  { n: '3', id: 't3', title: 'Intellectual Property', body: ['All ZeroTrace software, branding, signatures and documentation are the intellectual property of ZeroTrace and its licensors. Cheat client names are referenced solely for detection and education.'] },
  { n: '4', id: 't4', title: 'Privacy Policy', body: ['Scan data produced by the scanner is delivered to the operator who initiated the scan. This dashboard stores all data locally; no scan content is transmitted to ZeroTrace unless the operator configures their own backend.'] },
  { n: '5', id: 't5', title: 'Disclaimer of Warranty', body: ['The Services are provided “as is” without warranty. Usermode scanning cannot detect kernel-mode, DMA or external (second-PC) cheats. Detection results are indicators and must not be treated as conclusive proof.'] },
  { n: '6', id: 't6', title: 'Modification of Terms', body: ['ZeroTrace reserves the right to modify this Agreement at any time. Modifications take effect the day they are posted. Continued use constitutes acceptance.'] },
  { n: '7', id: 't7', title: 'Prohibited Activities and Enforcement', body: ['You may not scan devices without consent, harass individuals, reverse-engineer the software, or redistribute licenses. Violations may result in immediate termination without refund.'] },
  { n: '7.4', id: 't74', title: 'Appeals Process', sub: true, body: ['A user subjected to a scan may request a review through the operator. Operators may escalate disputed detections via Support; ZeroTrace reviews evidence and methodology, not the moderation decision itself.'] },
  { n: '8', id: 't8', title: 'Data Collection and Privacy', body: ['A scanned user’s Discord ID is stored with the pin to correlate repeat scans. No analytics or third-party trackers are used by this dashboard.'] },
  { n: '9', id: 't9', title: 'Self-Scanning Limitations', body: ['Scanning your own machine for testing is permitted, but results may differ from a genuine screenshare scenario and should not be used to certify third parties.'] },
  { n: '10', id: 't10', title: 'Termination of Use', body: ['ZeroTrace may suspend or terminate access for breach of these Terms. Upon termination your right to use the Services ends immediately; locally stored data remains under your control.'] },
  { n: '11', id: 't11', title: 'Chargebacks and Reversals', body: ['Initiating a chargeback without first contacting support results in permanent termination of all associated licenses and accounts.'] },
]

export function Terms() {
  return (
    <TocDoc
      hero={
        <HeroBanner
          title="Legal Agreement"
          subtitle="Terms and conditions governing the use of ZeroTrace Anti-Cheat services"
          meta="Last updated  18 May, 2026"
        />
      }
      preface={
        <Card className="muted space-y-4 p-6 text-sm leading-relaxed md:p-8">
          <p>This Terms and Conditions of Use (“Agreement”) is a legally binding agreement between “us” or “we” and the entity or person (“you”, “your”, or “user”) that registered an account to receive cheat detection services (“Services”).</p>
          <p>ZeroTrace reserves the right to make modifications to this Agreement at any time. Unless otherwise specified, any modifications will take effect the day they are posted to this page.</p>
          <p>By accessing or utilizing our Services, you acknowledge and agree to abide by these Terms. If you do not accept these Terms, we kindly ask that you refrain from using our Services.</p>
        </Card>
      }
      sections={AGREEMENT.map((s) => ({
        ...s,
        content: s.body.map((p, i) => <P key={i}>{p}</P>),
      }))}
    />
  )
}

/* --------------------------- Privacy Policy ---------------------------- */
const PRIVACY = [
  { title: 'Types of Data we Collect' },
  { title: 'Data Usage and Processing' },
  { title: 'Data Retention' },
  { title: 'Data Security' },
  { title: 'Data Storage Location' },
  { title: 'Links to Other Sites' },
  { title: "Children's Privacy" },
  { title: 'Your Privacy Rights' },
  { title: 'Legal Basis for Processing' },
  { title: 'International Data Protection' },
  { title: 'Data Protection Measures' },
  { title: 'Data Breach Procedures' },
  { title: 'Third-Party Service Providers' },
  { title: 'Business Transfers' },
  { title: 'COPPA Compliance' },
  { title: 'Dispute Resolution' },
  { title: 'Additional Rights and Questions' },
  { title: 'Scanner Usage' },
  { title: 'Security Research Program' },
  { title: 'Service Improvements' },
  { title: 'Contact for Support' },
]

const PRIVACY_BODY = {
  1: (
    <div>
      <h3 className="txt mb-4 text-lg font-bold">Account and Platform Data</h3>
      <Group
        title="User Registration Information:"
        items={[
          { h: 'Email address:', sub: ['Used for account verification', 'Required for communications', 'Encrypted storage', 'Retained for account duration'] },
          { h: 'Discord ID:', sub: ['Service integration', 'Support communications', 'Community features'] },
          { h: 'Nametag:', sub: ['Public identification', 'Community interaction', 'User recognition'] },
        ]}
      />
      <Group
        title="Authentication Data:"
        items={[
          { h: 'IP Addresses:', sub: ['Login security', 'Fraud prevention', '90-day retention'] },
          { h: 'User Agent:', sub: ['Session integrity', 'Abuse detection', 'Diagnostics'] },
        ]}
      />
    </div>
  ),
  2: <Bullets items={['Data is processed only to deliver cheat-detection services and account functions.', 'Scan results are tied to the operator who initiated the scan.', 'No automated decision-making with legal effect is performed.']} />,
  3: <Bullets items={['Account data: retained for the lifetime of the account.', 'IP / authentication logs: 90 days.', 'Scan results: retained by the operator on their own device (localStorage).']} />,
  4: <Bullets items={['Encryption in transit and at rest for account data.', 'Principle of least privilege for internal access.', 'This dashboard keeps all scan data client-side.']} />,
  5: <Bullets items={['Account infrastructure is hosted within the EU/EEA where possible.', 'Dashboard scan data never leaves the user’s browser.']} />,
  6: <P>Our services may link to third-party sites (e.g. Discord). We are not responsible for the privacy practices of external sites.</P>,
  7: <P>ZeroTrace is not directed to children under 16. We do not knowingly collect data from minors. See COPPA Compliance below.</P>,
  8: <Bullets items={['Right of access, rectification and erasure.', 'Right to restrict or object to processing.', 'Right to data portability.', 'Right to lodge a complaint with a supervisory authority.']} />,
  9: <P>Processing is based on contract performance, legitimate interest in fraud prevention, and consent where required.</P>,
  10: <P>Where data is transferred outside the EEA, appropriate safeguards (SCCs) are applied.</P>,
  11: <Bullets items={['Hardened infrastructure and monitoring.', 'Regular dependency and security review.', 'Tamper-evident scan tokens.']} />,
  12: <P>In the event of a breach affecting personal data, affected users and the competent authority will be notified within 72 hours where required by law.</P>,
  13: <Bullets items={['Payment processing via a Merchant of Record.', 'Discord for authentication & community.', 'No advertising or analytics processors.']} />,
  14: <P>If ZeroTrace is involved in a merger or acquisition, data may be transferred subject to this policy.</P>,
  15: <P>We comply with the Children’s Online Privacy Protection Act. Accounts identified as belonging to children under 13 will be removed.</P>,
  16: <P>Disputes are handled via the Support page first; unresolved matters are subject to the governing law stated in the Legal Agreement.</P>,
  17: <P>For additional rights requests or questions, contact us through the Support page with your account details.</P>,
  18: <Bullets items={['The scanner only runs after explicit consent.', 'It collects anti-cheat artifacts, not arbitrary personal files.', 'Results are delivered only to the initiating operator.']} />,
  19: <P>Security researchers may report vulnerabilities responsibly via Support. We do not pursue good-faith research.</P>,
  20: <P>Aggregated, non-identifying signals may be used to improve detection quality.</P>,
  21: <P>Questions about this policy? Open a ticket on the Support page.</P>,
}

export function Privacy() {
  const sections = PRIVACY.map((s, i) => ({
    n: String(i + 1),
    id: 'pp' + (i + 1),
    title: s.title,
    content: PRIVACY_BODY[i + 1] || <P>Details for this section are available on request via Support.</P>,
  }))
  return (
    <TocDoc
      hero={
        <HeroBanner
          title="Privacy Policy"
          subtitle="How ZeroTrace Anti-Cheat collects, uses and protects data"
          meta="Last updated  18 May, 2026"
        />
      }
      preface={
        <Card className="p-5">
          <p className="muted text-sm">GDPR compliance verification:</p>
          <a
            href="#"
            onClick={(e) => e.preventDefault()}
            className="break-all font-mono text-sm text-sky-500"
          >
            https://gdpr.euverify.com/verify/c0e9c62b-0d75-4c0d-9146-df73801cfdb2
          </a>
        </Card>
      }
      sections={sections}
    />
  )
}

/* --------------------------- Legal Notice ------------------------------ */
const LEGAL_NOTICE = [
  {
    title: 'Legal Notice / Impressum',
    content: (
      <div>
        <p className="muted bd mb-5 border-l-2 border-sky-500 pl-4 text-sm italic">
          Information provided strictly for transparency and regulatory compliance purposes
          (e.g., according to § 5 DDG).
        </p>
        <div className="space-y-2 text-sm">
          {[
            ['Operator', 'ZeroTrace Anti-Cheat'],
            ['Service', 'anticheat.ac'],
            ['Type', 'Online anti-cheat / screenshare service'],
            ['Represented by', 'ZeroTrace Operations'],
            ['Contact', 'Via the Support page within the dashboard'],
          ].map(([k, v]) => (
            <div key={k} className="bd flex justify-between border-b py-2 last:border-0">
              <span className="muted">{k}</span>
              <span className="txt font-medium">{v}</span>
            </div>
          ))}
        </div>
      </div>
    ),
  },
  { title: 'Company Operations & Headquarters', content: <P>ZeroTrace operates as an online service. Day-to-day operations are handled remotely; correspondence is processed through the in-dashboard Support channel.</P> },
  { title: 'Contact Information', content: <P>For legal, billing or data-protection enquiries, open a ticket on the Support page including your account email and a description of your request.</P> },
  { title: 'Merchant of Record', content: <P>Payments are processed by a third-party Merchant of Record who acts as the reseller of the Licenses and handles billing, tax and chargebacks on our behalf.</P> },
  { title: 'EU Privacy & GDPR (Art. 27)', content: <P>For matters relating to the EU General Data Protection Regulation, requests can be submitted via Support and will be routed to the responsible representative under Art. 27 GDPR where applicable.</P> },
]

export function Legal() {
  return (
    <TocDoc
      hero={
        <HeroBanner
          title="Legal Notice"
          subtitle="Impressum, transparency & company information for ZeroTrace Anti-Cheat"
          meta="Last updated  18 May, 2026"
        />
      }
      sections={LEGAL_NOTICE.map((s, i) => ({
        n: String(i + 1),
        id: 'ln' + (i + 1),
        title: s.title,
        content: s.content,
      }))}
    />
  )
}

/* ------------------------------ Changelog ------------------------------ */
const VERSIONS = [
  {
    v: '0.3', title: 'ZeroTrace Changelog 0.3', date: '17 December 2025', author: 'NotRancio',
    tags: ['FEATURE', 'BUGFIX', 'IMPROVEMENT'], badge: 'Changelog 3',
    intro: 'We’ve released a new update bringing general improvements and system enhancements across ZeroTrace.',
    items: ['New Scan Results layout with category drill-down', 'Repeat-scan detection via Discord ID', 'Tool Designer + style import/export', 'Numerous stability and UI fixes'],
  },
  {
    v: '0.2', title: 'ZeroTrace Release 0.2', date: '02 November 2025', author: 'NotRancio',
    tags: ['FEATURE', 'IMPROVEMENT'], badge: 'Changelog 2',
    intro: 'Release 0.2 expands detection coverage and adds the forensic toolset.',
    items: ['Cheat Database & Forensic Tools', 'String / YARA-lite analysis', 'Activity log + CSV export'],
  },
  {
    v: '0.1', title: 'BETA Release 0.1', date: '10 October 2025', author: 'NotRancio',
    tags: ['FEATURE'], badge: 'Beta',
    intro: 'First public beta of the ZeroTrace dashboard and FiveM scanner.',
    items: ['Dashboard, Pins and Strings', 'C++ FiveM scanner with .zerotrace sessions'],
  },
]

export function Changelogs() {
  const refs = useRef({})
  const [openV, setOpenV] = useState({ '0.3': true })
  const goto = (v) => refs.current[v]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  return (
    <div>
      <HeroBanner
        title="Changelog"
        subtitle="Stay up to date with the latest updates, improvements and new features of ZeroTrace"
        meta={`${VERSIONS.length} versions published`}
      />
      <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
        <Card className="h-fit p-5 lg:sticky lg:top-6">
          <p className="caps-label mb-2">Navigation</p>
          <h3 className="txt mb-4 flex items-center gap-2 text-base font-semibold">
            <History size={17} className="text-sky-500" /> Versions
          </h3>
          <nav className="space-y-1">
            {VERSIONS.map((r) => (
              <button
                key={r.v}
                onClick={() => goto(r.v)}
                className="hoverable flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm"
              >
                <span className="bd tile muted rounded border px-1.5 py-0.5 font-mono text-[11px]">
                  v{r.v}
                </span>
                <span className="txt">{r.title}</span>
              </button>
            ))}
          </nav>
        </Card>

        <div className="space-y-6">
          {VERSIONS.map((r, i) => (
            <Card key={r.v} className="overflow-hidden" >
              <div ref={(el) => (refs.current[r.v] = el)} className="scroll-mt-6">
                <div className="bd flex items-center justify-between gap-4 border-b p-5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-600/15 text-sm font-bold text-sky-400">
                      {i + 1}
                    </span>
                    <h2 className="txt text-xl font-bold">{r.title}</h2>
                    <span className="bd tile muted rounded border px-2 py-0.5 font-mono text-[11px]">
                      v{r.v}
                    </span>
                  </div>
                  <button
                    onClick={() => setOpenV((o) => ({ ...o, [r.v]: !o[r.v] }))}
                    className="bd txt rounded-lg border px-3 py-1.5 text-xs font-medium hover:border-sky-500"
                  >
                    {openV[r.v] ? 'Show less' : 'Show more'}
                  </button>
                </div>
                <div className="p-5">
                  <div className="muted flex flex-wrap items-center gap-4 text-xs">
                    <span>📅 {r.date}</span>
                    <span>👤 {r.author}</span>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="muted text-xs">🏷</span>
                    <span className="bd tile muted rounded-md border px-2 py-1 text-[11px] font-semibold tracking-wide">
                      {r.tags.join(', ')}
                    </span>
                  </div>
                  {openV[r.v] && (
                    <div className="bd mt-5 border-t pt-5">
                      <h3 className="txt mb-2 flex items-center gap-2 text-lg font-bold">
                        <span className="rounded bg-sky-600/20 px-1.5 py-0.5 text-[10px] font-bold text-sky-400">
                          NEW
                        </span>
                        {r.badge}
                      </h3>
                      <p className="muted text-[15px] leading-relaxed">{r.intro}</p>
                      <ul className="mt-3 space-y-1.5">
                        {r.items.map((it) => (
                          <li key={it} className="muted flex items-start gap-2 text-sm">
                            <Check size={14} className="mt-0.5 text-green-500" /> {it}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}
