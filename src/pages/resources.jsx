import { useMemo, useRef, useState } from 'react'
import {
  Trophy, BookOpen, Download, FileText, Scale, History,
  Check, ScanLine, Eye, ShieldAlert, Terminal, Search,
  ChevronDown, ChevronRight, Monitor, Shield, Ticket, ExternalLink,
  AlertCircle, CheckCircle2, Activity, Code2,
} from 'lucide-react'
import { PageHeader, Card, StatTile, Badge } from '../components/kit.jsx'
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
      <PageHeader
        icon={Trophy}
        kicker="Top detections across your games"
        title="Leaderboard"
        subtitle="Ranking is computed live from your own scan data."
      />
      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile icon={ScanLine} label="Total Scans" value={stats.totalScans} />
        <StatTile icon={Eye} label="Detections" value={stats.detections} accent="text-red-500" />
        <StatTile icon={ShieldAlert} label="Unique Cheats" value={stats.uniqueCheats} accent="text-yellow-500" />
        <StatTile icon={Trophy} label="Games Tracked" value={ranked.length} accent="text-blue-500" />
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
      { h: null, p: 'Welcome to the official documentation of Ocean Anticheat Solutions, a post-mortem detection framework designed to identify and analyze cheating activity across multiple game environments including FiveM, Minecraft, and other supported platforms.' },
      { h: null, p: "This portal provides a complete reference for developers, partners, and server administrators who work with Ocean's detection systems. Here you will find detailed explanations of detection categories, integrity modules, logging schemas, and implementation details for the Ocean Dashboard and Ocean+ APIs." },
      { h: 'Getting Started', list: [
        'Use the navigation sidebar to explore categories such as Detections, Logs, and Integrity Systems.',
        'Read each section to understand how Ocean classifies detections, processes memory and file artifacts, and communicates results through the dashboard.',
        'Use the search bar to quickly locate specific detection signatures or log entries by name.',
        'Generate a pin from the Pins page, run the scanner, and review the results on the Scan Results page.',
      ] },
    ],
  },
  'detects-logs': {
    title: 'Detects Logs',
    blocks: [
      { p: 'Detects Logs are high-confidence findings produced when Ocean matches a known cheat signature in memory, on disk, or in the loaded module list of the game process. Each entry includes the matched signature, severity (High/Critical), and the evidence (process, module or file path).' },
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
      { p: 'Ocean combines several engines to reach a verdict:' },
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
      { p: 'The Ocean+ API exposes scan sessions and results. All endpoints require a Bearer API key. Base URL: https://api.anticheat.ac/v1.' },
      { code: 'GET /v1/pins\nAuthorization: Bearer <API_KEY>' },
      { p: 'This dashboard is client-side; the API reference here describes the schema the OCEAN1 token / .ocean session files follow.' },
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
                    active === n.id ? 'bg-blue-600/15 text-blue-500' : 'txt hoverable'
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
                          active === c.id ? 'bg-blue-600/15 text-blue-500' : 'muted hoverable'
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
        <h1 className="txt text-4xl font-bold tracking-tight">{doc.title}</h1>
        <div className="mt-6 space-y-6">
          {doc.blocks.map((b, i) => (
            <div key={i}>
              {b.h && <h2 className="txt mb-3 text-2xl font-bold">{b.h}</h2>}
              {b.p && <p className="muted text-[15px] leading-relaxed">{b.p}</p>}
              {b.list && (
                <ol className="mt-2 space-y-2">
                  {b.list.map((li, j) => (
                    <li key={j} className="muted flex gap-3 text-[15px] leading-relaxed">
                      <span className="text-blue-500">{j + 1}.</span> {li}
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
            <span className="text-blue-500">•</span> {f}
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
      <button
        onClick={() => toast({ type: 'info', title: 'Claim license', body: 'No pending licenses on this account.' })}
        className="muted hover:txt mx-auto mb-8 flex items-center gap-2 text-sm"
      >
        <Ticket size={16} /> Have a pending license? <span className="text-blue-500">Claim it here</span>
      </button>

      <div className="mb-4 flex items-center gap-4">
        <span className="bd h-px flex-1 border-t" />
        <span className="caps-label">Personal Plans</span>
        <span className="bd h-px flex-1 border-t" />
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <PriceCard
          title="Ocean FiveM - Yearly Personal"
          desc="Specific license that supports scans for the game FiveM, including its respective detection modules."
          price="$79.99"
          period="/year"
          features={personalFeatures}
          onBuy={() => buy('Yearly Personal')}
        />
        <PriceCard
          title="Ocean FiveM - 6 Month Personal"
          desc="Specific license that supports scans for the game FiveM, including its respective detection modules."
          price="$44.99"
          period="/6 months"
          features={personalFeatures}
          onBuy={() => buy('6 Month Personal')}
        />
        <PriceCard
          title="Ocean FiveM - Monthly Personal"
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
          title="Ocean FiveM - Enterprise+ (6 months) 20 Slots"
          desc="Team license for organisations. Supports FiveM scans across multiple operators."
          price="$249.99"
          period="/6 months"
          features={['20 slots', 'Team / organisation use', 'FIVEM access', 'Unlimited pin generation', 'Shared pins & access', 'Priority support']}
          onBuy={() => buy('Enterprise+ 20 Slots')}
        />
        <PriceCard
          title="Ocean FiveM - Enterprise (6 months) 10 Slots"
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
      product: `Ocean Scanner (${name})`,
      pin: match.pin,
      game: match.game,
      name: match.name,
      discordId: match.discordId || '',
      createdAt: match.createdAt,
      expiresAt: match.createdAt + 24 * 3600 * 1000,
    }
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' }))
    a.download = `OceanScan-${match.pin}.ocean`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Session downloaded', body: `OceanScan-${match.pin}.ocean` })
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
      <div className="flex flex-col items-center py-8 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-500 to-blue-700 font-mono text-xl font-bold text-white shadow-lg shadow-blue-600/25">
          {'(*>'}
        </div>
        <p className="caps-label mt-5">Downloads</p>
        <h1 className="txt mt-2 text-4xl font-bold tracking-tight">Start Detecting</h1>
        <p className="muted mt-2">Download Ocean for your platform.</p>
        <p className="muted mt-4 flex items-center gap-2 text-sm">
          <Download size={15} /> Available for Windows &amp; Linux
        </p>
      </div>

      <div className="mt-6 grid gap-5 lg:grid-cols-3">
        <DownloadCard icon={Monitor} name="Windows" tagTone="#ef4444" accent="#dc2626"
          desc="Advanced cheat detection" hint="Enter your 8-character PIN."
          pins={state.pins} toast={toast} />
        <DownloadCard icon={Monitor} name="Linux" tagTone="#f59e0b" accent="#d97706"
          desc="Cheat detection for Linux systems" hint="Enter your 8-character PIN."
          pins={state.pins} toast={toast} />
        <DownloadCard icon={Shield} name="Anti SS Tool" tagTone="#3b82f6" accent="#2563eb"
          desc="Bypass blocks preventing Ocean from running"
          hint="Enter your 8-character PIN to download the Anti SS Tool."
          pins={state.pins} toast={toast} />
      </div>

      <div className="mt-14 text-center">
        <h2 className="txt text-3xl font-bold">Can't run Ocean?</h2>
        <p className="muted mt-2">Let's solve that.</p>
      </div>
      <div className="mt-6 grid gap-5 lg:grid-cols-2">
        <Card className="p-6">
          <p className="caps-label">Troubleshooting</p>
          <h3 className="txt mt-1 flex items-center gap-2 text-lg font-semibold">
            <AlertCircle size={18} className="text-yellow-500" /> VC++ Runtime Error
          </h3>
          <ol className="mt-4 space-y-3">
            {['Download and install vcredist (x64)', 'Restart your computer.', 'Try running Ocean again.', 'Contact support if persists.'].map((s, i) => (
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
            className="bd txt mt-5 flex w-full items-center justify-center gap-2 rounded-lg border py-2.5 text-sm font-medium hover:border-blue-500"
          >
            <ExternalLink size={15} /> Discord
          </button>
        </Card>
      </div>
    </div>
  )
}

/* --------------------------- Privacy / Terms --------------------------- */
function LegalDoc({ icon, title, kicker, sections }) {
  return (
    <div>
      <PageHeader icon={icon} kicker={kicker} title={title} subtitle="Last updated: 2026-05-18" />
      <Card className="space-y-6 p-6 md:p-8">
        {sections.map((s) => (
          <div key={s.h}>
            <h3 className="txt mb-2 text-base font-semibold">{s.h}</h3>
            <p className="muted text-sm leading-relaxed">{s.p}</p>
          </div>
        ))}
      </Card>
    </div>
  )
}

export function Terms() {
  return (
    <LegalDoc
      icon={FileText}
      kicker="Legal"
      title="Terms of Service"
      sections={[
        { h: '1. Acceptance', p: 'By using the Ocean dashboard you agree to these terms. The service is provided as-is for anti-cheat investigation purposes only.' },
        { h: '2. Acceptable use', p: 'You may only scan systems with the explicit, informed consent of the device owner. Unauthorised scanning is prohibited and your responsibility.' },
        { h: '3. No warranty', p: 'Detection results are indicators, not proof. Usermode scanning cannot detect kernel, DMA or external cheats. No outcome is guaranteed.' },
        { h: '4. Liability', p: 'Operators are responsible for moderation decisions made based on scan results. We are not liable for actions taken on your platform.' },
        { h: '5. Changes', p: 'These terms may be updated. Continued use after changes constitutes acceptance.' },
      ]}
    />
  )
}

export function Privacy() {
  return (
    <LegalDoc
      icon={FileText}
      kicker="Legal"
      title="Privacy Policy"
      sections={[
        { h: 'Data we store', p: 'This dashboard is fully client-side. Pins, scans, settings, tickets and tool styles are stored only in your browser localStorage. Nothing is sent to a server.' },
        { h: 'Scan data', p: 'Scan results live on your device. The scanner produces a token you import manually — there is no automatic upload unless you configure your own backend URL.' },
        { h: 'Discord IDs', p: 'A scanned user’s Discord ID is stored locally with the pin so repeat scans can be correlated. It never leaves your browser.' },
        { h: 'Third parties', p: 'No analytics, trackers or third-party data processors are used. Optional web fonts are loaded from Google Fonts.' },
        { h: 'Your control', p: 'Use Settings → Data Management to export, clear or factory-reset all locally stored data at any time.' },
      ]}
    />
  )
}

/* ------------------------------- Legal --------------------------------- */
const LEGAL_SECTIONS = [
  { n: '1', id: 's1', title: 'Description of the Software', body: [
    'Ocean is a post-mortem anti-cheat and screenshare assistance framework. It inspects processes, modules, files and system artifacts on a consenting user’s machine and reports indicators of cheating to the server administrator who initiated the scan.',
    'The Ocean Monthly/Yearly/Lifetime License and the Ocean Enterprise License, collectively "The Licenses", are classified as Products under these Terms. A License can be a Personal Licence or an Enterprise Licence.',
  ] },
  { n: '2', id: 's2', title: 'Use of Ocean', body: [
    'Ocean may only be used to scan a device with the explicit, informed consent of that device’s owner. Operators are responsible for obtaining consent and for the moderation decisions they make based on results.',
    'A Personal Licence is granted to an individual upon payment to their Ocean account and may not be shared. An Enterprise Licence provides a number of operator slots for an organisation.',
  ] },
  { n: '3', id: 's3', title: 'Intellectual Property', body: [
    'All Ocean software, branding, signatures and documentation are the intellectual property of Ocean and its licensors. Cheat client names are referenced solely for detection and education; all trademarks belong to their respective owners.',
  ] },
  { n: '4', id: 's4', title: 'Privacy Policy', body: [
    'Scan data produced by the scanner is delivered to the operator who initiated the scan. This dashboard stores all data locally in the browser; no scan content is transmitted to Ocean unless the operator configures their own backend.',
  ] },
  { n: '5', id: 's5', title: 'Disclaimer of Warranty', body: [
    'The Services are provided "as is" without warranty of any kind. Usermode scanning cannot detect kernel-mode, DMA or external (second-PC) cheats. Detection results are indicators and must not be treated as conclusive proof.',
  ] },
  { n: '6', id: 's6', title: 'Modification of Terms', body: [
    'Ocean reserves the right to modify this Agreement at any time. Unless otherwise specified, modifications take effect the day they are posted to this page. Continued use constitutes acceptance.',
  ] },
  { n: '7', id: 's7', title: 'Prohibited Activities and Enforcement', body: [
    'You may not use Ocean to scan devices without consent, to harass individuals, to reverse-engineer the software, or to redistribute licenses. Violations may result in immediate termination without refund.',
  ] },
  { n: '7.4', id: 's74', title: 'Appeals Process', sub: true, body: [
    'A user subjected to a scan may request a review of the result through the operator. Operators may escalate disputed detections via the Support page; Ocean will review the evidence and the methodology, not the moderation decision itself.',
  ] },
  { n: '8', id: 's8', title: 'Data Collection and Privacy', body: [
    'A scanned user’s Discord ID is stored with the pin to correlate repeat scans. No analytics or third-party trackers are used by this dashboard. Operators are the data controllers for any results they retain.',
  ] },
  { n: '9', id: 's9', title: 'Self-Scanning Limitations', body: [
    'Scanning your own machine for testing is permitted, but results may differ from a genuine screenshare scenario and should not be used to certify third parties.',
  ] },
  { n: '10', id: 's10', title: 'Termination of Use', body: [
    'Ocean may suspend or terminate access for breach of these Terms. Upon termination your right to use the Services ends immediately; locally stored data remains under your control.',
  ] },
  { n: '11', id: 's11', title: 'Chargebacks and Reversals', body: [
    'Initiating a chargeback or payment reversal without first contacting support will result in permanent termination of all associated licenses and accounts.',
  ] },
]

export function Legal() {
  const refs = useRef({})
  const goto = (id) =>
    refs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })

  return (
    <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
      <Card className="h-fit p-5 lg:sticky lg:top-6">
        <h3 className="txt mb-4 flex items-center gap-2 text-base font-semibold">
          <FileText size={17} className="text-blue-500" /> Table of Contents
        </h3>
        <nav className="space-y-1">
          {LEGAL_SECTIONS.map((s) => (
            <button
              key={s.id}
              onClick={() => goto(s.id)}
              className={`hoverable flex w-full items-start gap-3 rounded-lg px-3 py-2 text-left text-sm ${
                s.sub ? 'pl-8' : ''
              }`}
            >
              <span className="text-blue-500">{s.n}</span>
              <span className="txt">{s.title}</span>
            </button>
          ))}
        </nav>
      </Card>

      <Card className="p-6 md:p-8">
        <div className="bd mb-6 flex items-start gap-4 border-b pb-6">
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 text-white">
            <Scale size={22} />
          </span>
          <div>
            <h1 className="txt text-2xl font-bold">Legal Agreement</h1>
            <p className="muted mt-1 text-sm">
              Terms and conditions governing the use of Ocean Anti-Cheat services
            </p>
          </div>
        </div>

        <div className="muted space-y-4 text-sm leading-relaxed">
          <p>
            This Terms and Conditions of Use ("Agreement") is a legally binding agreement between
            "us" or "we" and the entity or person ("you", "your", or "user") that registered an
            account to receive cheat detection services ("Services").
          </p>
          <p>
            Ocean reserves the right to make modifications to this Agreement at any time. Unless
            otherwise specified, any modifications to this Agreement will take effect the day they
            are posted to this page.
          </p>
          <p>
            By accessing or utilizing our Services, you acknowledge and agree to abide by these
            Terms. If you do not accept these Terms, we kindly ask that you refrain from using our
            Services.
          </p>
        </div>

        <div className="mt-8 space-y-8">
          {LEGAL_SECTIONS.map((s) => (
            <section
              key={s.id}
              ref={(el) => (refs.current[s.id] = el)}
              className="scroll-mt-6"
            >
              <h2 className={`txt font-semibold ${s.sub ? 'text-base' : 'text-lg'}`}>
                {s.n}. {s.title}
              </h2>
              {s.body.map((p, i) => (
                <p key={i} className="muted mt-2 text-sm leading-relaxed">
                  {p}
                </p>
              ))}
            </section>
          ))}
        </div>
      </Card>
    </div>
  )
}

/* ------------------------------ Changelogs ----------------------------- */
export function Changelogs() {
  const log = [
    { v: '2.5.0', date: '2026-05-18', items: ['Full Documentation portal, Pricing, Download & Legal pages', 'PIN-gated downloads (.ocean session)'] },
    { v: '2.4.0', date: '2026-05-18', items: ['Resources hub with sub-pages', 'Fixed iOS scroll-to-top when opening modals'] },
    { v: '2.3.0', date: '2026-05-18', items: ['Required Discord ID per pin', 'Repeat-scan notification + previous-results popup'] },
    { v: '2.2.0', date: '2026-05-18', items: ['Full Scan Results page (real scan data only)', 'Scanner .ocean session files'] },
    { v: '2.1.0', date: '2026-05-18', items: ['Pin Created dialog', 'Delete confirmation modal', 'Actions menu'] },
    { v: '2.0.0', date: '2026-05-18', items: ['Cheat Database, Forensic Tools, Activity Log, Settings, Support', 'Tool Designer + command palette'] },
    { v: '1.0.0', date: '2026-05-18', items: ['Initial dashboard: Dashboard, Pins, Strings', 'C++ FiveM scanner'] },
  ]
  return (
    <div>
      <PageHeader icon={History} kicker="What’s new" title="Changelogs" subtitle="Recent updates to the Ocean platform." />
      <Card className="p-6 md:p-8">
        <ol className="relative ml-3 border-l border-line">
          {log.map((e) => (
            <li key={e.v} className="mb-8 ml-6 last:mb-0">
              <span className="panel absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full border">
                <Terminal size={11} className="muted" />
              </span>
              <div className="flex items-center gap-3">
                <Badge tone="Open">v{e.v}</Badge>
                <time className="muted text-xs">{e.date}</time>
              </div>
              <ul className="mt-2 space-y-1">
                {e.items.map((it) => (
                  <li key={it} className="muted flex items-start gap-2 text-sm">
                    <Check size={14} className="mt-0.5 text-green-500" /> {it}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  )
}
