import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Trophy, BookOpen, ShoppingCart, Download, FileText, Scale, History,
  Check, ScanLine, Eye, ShieldAlert, Terminal, ArrowRight,
} from 'lucide-react'
import { PageHeader, Card, Accordion, StatTile, Badge } from '../components/kit.jsx'
import { useStats } from '../store.jsx'

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
                  className="flex h-8 w-8 items-center justify-center rounded-full text-sm font-bold text-black"
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
export function Documentation() {
  const docs = [
    { q: 'Creating a scan pin', a: 'Go to Pins → Create Pin. Enter a name and the scanned user’s Discord ID, pick the game and visibility. An 8-character pin code is generated and a downloadable .ocean session file is offered.' },
    { q: 'Running the scanner', a: 'Open the OceanScan-<PIN>.ocean file with OceanScanner.exe (built from the scanner/ folder). The pin is filled in automatically — accept the consent prompt and press Start Scan.' },
    { q: 'Importing results', a: 'The scanner produces an OCEAN1.… token. On the Pins page click "Import Result", paste the token, and the pin, dashboard and activity log update automatically.' },
    { q: 'Viewing scan results', a: 'Use the "…" menu on a pin → View Results. The Scan Results page shows only the data the scan actually produced; empty categories show their empty state.' },
    { q: 'Repeat-scan detection', a: 'If you create a pin with a Discord ID that was scanned before, a notification appears — tap it to view the previous scan results.' },
    { q: 'String & file analysis', a: 'The Strings page extracts ASCII/UTF-16 strings from any uploaded file, flags suspicious keywords, supports presence detection and a YARA-lite rule editor + scanner.' },
    { q: 'Cheat Database & Forensic Tools', a: 'The Cheat Database is a searchable catalogue of known clients. Forensic Tools analyse browser history, DNS cache, system artefacts and compute SHA-256 hashes — all client-side.' },
    { q: 'Tool Designer', a: 'Settings → Tool Designer lets you customise the scanner GUI (logo, colours, texts) with a live preview and an import/export style code. Changes save on "Save All".' },
    { q: 'Keyboard shortcuts', a: 'Press Ctrl/⌘ + K anywhere to open the command palette for fast navigation and actions.' },
  ]
  return (
    <div>
      <PageHeader icon={BookOpen} kicker="Guides & how-tos" title="Documentation" subtitle="Everything you need to operate the Ocean dashboard and scanner." />
      <Card className="p-6">
        <Accordion items={docs} />
      </Card>
    </div>
  )
}

/* ------------------------------- Pricing ------------------------------- */
export function Pricing() {
  const tiers = [
    { name: 'Free', price: '€0', period: '/mo', highlight: false, features: ['1 daily pin', 'Manual result import', 'Cheat database (read-only)', 'String extractor', 'Community support'] },
    { name: 'Pro', price: '€9', period: '/mo', highlight: true, features: ['Unlimited pins', 'Scanner session files', 'Custom cheat signatures', 'YARA-lite scanner', 'Forensic tools', 'Priority support'] },
    { name: 'Team', price: '€29', period: '/mo', highlight: false, features: ['Everything in Pro', 'Shared pins & access', 'Activity audit export', 'Tool Designer branding', 'Multiple operators', 'Dedicated support'] },
  ]
  return (
    <div>
      <PageHeader icon={ShoppingCart} kicker="Plans & limits" title="Pricing" subtitle="Pick the plan that fits your community." />
      <div className="grid gap-5 lg:grid-cols-3">
        {tiers.map((t) => (
          <Card key={t.name} className={`p-6 ${t.highlight ? 'ring-1 ring-blue-500/40' : ''}`}>
            {t.highlight && <Badge tone="Open">Most popular</Badge>}
            <h3 className="txt mt-3 text-xl font-bold">{t.name}</h3>
            <p className="txt mt-2 text-3xl font-bold">
              {t.price}<span className="muted text-base font-normal">{t.period}</span>
            </p>
            <ul className="mt-5 space-y-2.5">
              {t.features.map((f) => (
                <li key={f} className="txt flex items-center gap-2.5 text-sm">
                  <Check size={15} className="text-green-500" /> {f}
                </li>
              ))}
            </ul>
            <button className={`mt-6 w-full rounded-lg px-4 py-2.5 text-sm font-semibold ${t.highlight ? 'bg-blue-600 text-white hover:bg-blue-500' : 'bd txt border hover:border-blue-500'}`}>
              Choose {t.name}
            </button>
          </Card>
        ))}
      </div>
      <p className="muted mt-6 text-center text-xs">Demo pricing — no payment processing is wired up.</p>
    </div>
  )
}

/* ------------------------------ Download ------------------------------- */
export function DownloadPage() {
  return (
    <div>
      <PageHeader icon={Download} kicker="Get the scanner" title="Download" subtitle="The Ocean FiveM Scanner is built from source." />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt text-lg font-semibold">Ocean Scanner (Windows x64)</h3>
          <p className="muted mt-1 text-sm">Dear ImGui / DirectX 11 desktop client. Source in the <code className="txt">scanner/</code> folder.</p>
          <div className="tile mt-4 rounded-lg border p-3 font-mono text-xs">
            <p className="muted">vcpkg install imgui[dx11-binding,win32-binding]:x64-windows-static</p>
            <p className="muted mt-1">cmake -B build -S scanner &amp;&amp; cmake --build build --config Release</p>
          </div>
          <p className="muted mt-3 text-xs">Output: <code className="txt">scanner/build/Release/OceanScanner.exe</code></p>
        </Card>
        <Card className="p-6">
          <h3 className="txt text-lg font-semibold">Per-scan session file</h3>
          <p className="muted mt-1 text-sm">
            There is no hosted installer. Create a pin to download an
            <code className="txt"> OceanScan-&lt;PIN&gt;.ocean</code> file — opening it with the
            scanner pre-fills the pin so the user only accepts consent and scans.
          </p>
          <Link to="/pins" className="mt-5 inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500">
            Go to Pins <ArrowRight size={15} />
          </Link>
        </Card>
      </div>
    </div>
  )
}

/* --------------------------- Legal documents --------------------------- */
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

export function Legal() {
  return (
    <LegalDoc
      icon={Scale}
      kicker="Legal"
      title="Legal"
      sections={[
        { h: 'Disclaimer', p: 'Ocean is an anti-cheat / screenshare assistance tool. It must be used only with consent and in compliance with applicable laws and your platform’s rules.' },
        { h: 'Trademarks', p: 'Cheat client names listed in the database are referenced solely for detection and education. All trademarks belong to their respective owners.' },
        { h: 'Open-source notices', p: 'Built with React, Vite, Tailwind CSS, lucide-react and Recharts. The scanner uses Dear ImGui. These are distributed under their respective licenses.' },
        { h: 'Contact', p: 'For legal enquiries open a ticket via the Support page.' },
      ]}
    />
  )
}

/* ------------------------------ Changelogs ----------------------------- */
export function Changelogs() {
  const log = [
    { v: '2.4.0', date: '2026-05-18', items: ['Resources hub: Leaderboard, Docs, Pricing, Download, Legal, Changelogs', 'Fixed iOS scroll-to-top when opening modals'] },
    { v: '2.3.0', date: '2026-05-18', items: ['Required Discord ID per pin', 'Repeat-scan notification + previous-results popup'] },
    { v: '2.2.0', date: '2026-05-18', items: ['Full Scan Results page (real scan data only)', 'Scanner .ocean session files'] },
    { v: '2.1.0', date: '2026-05-18', items: ['Pin Created dialog', 'Delete confirmation modal', 'Actions menu (View/Edit/Manage Access/Delete)'] },
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
