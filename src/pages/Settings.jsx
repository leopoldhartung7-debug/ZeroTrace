import { useRef, useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Settings as Cog, Sun, Moon, Download, Upload, Trash2, RotateCcw,
  SlidersHorizontal, Wand2, ShieldAlert, Gamepad2, CalendarCheck, ShieldCheck, KeyRound,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { Select, useToast } from '../components/ui.jsx'
import { useStore, ALL_GAMES, deriveScanReport } from '../store.jsx'
import { sendScanSummary } from '../lib/webhook.js'
import ToolDesigner from './ToolDesigner.jsx'

function Row({ title, desc, children }) {
  return (
    <div className="bd flex flex-col gap-3 border-b py-5 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="txt text-sm font-medium">{title}</p>
        <p className="muted mt-0.5 text-xs">{desc}</p>
      </div>
      <div className="sm:w-56">{children}</div>
    </div>
  )
}

function General() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const fileRef = useRef(null)
  const backupFileRef = useRef(null)

  const exportData = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }))
    a.download = 'zerotrace-ac-backup.json'
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Backup exported' })
  }

  const importData = (file) => {
    const fr = new FileReader()
    fr.onload = () => {
      try {
        dispatch({ type: 'import-state', state: JSON.parse(fr.result) })
        toast({ type: 'success', title: 'Backup restored' })
      } catch {
        toast({ type: 'error', title: 'Invalid backup file' })
      }
    }
    fr.readAsText(file)
  }

  return (
    <div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-1 text-lg font-semibold">Appearance</h3>
          <p className="muted mb-2 text-sm">Theme and language settings.</p>
          <Row title="Theme" desc="Dark or light interface">
            <button
              onClick={() =>
                dispatch({ type: 'set-setting', key: 'theme', value: state.settings.theme === 'dark' ? 'light' : 'dark' })
              }
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
            >
              {state.settings.theme === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
              {state.settings.theme === 'dark' ? 'Dark' : 'Light'}
            </button>
          </Row>
          <Row title="Language" desc="Interface language">
            <Select
              value={state.settings.lang}
              onChange={(v) => dispatch({ type: 'set-setting', key: 'lang', value: v })}
              options={[
                { value: 'en', label: 'English' },
                { value: 'de', label: 'Deutsch' },
              ]}
            />
          </Row>
          <Row title="Default Game" desc="Pre-selected when creating pins">
            <Select
              value={state.settings.defaultGame}
              onChange={(v) => dispatch({ type: 'set-setting', key: 'defaultGame', value: v })}
              options={ALL_GAMES.map((g) => ({ value: g, label: g }))}
            />
          </Row>
          {state.role === 'admin' && (
            <Row title="Scanner download URL" desc="Where the ZeroTrace Checker is hosted (shown in the pin popup)">
              <input
                value={state.settings.scannerUrl || ''}
                onChange={(e) => dispatch({ type: 'set-setting', key: 'scannerUrl', value: e.target.value })}
                placeholder="https://…/ZeroTrace.exe"
                className="bd tile txt w-full rounded-lg border px-3 py-2.5 text-sm focus:outline-none"
              />
            </Row>
          )}
          {state.role === 'admin' && (
            <Row title="Scanner API URL (optional)" desc="Bot URL hosting /scanner?pin= — makes the copyable pin link a one-click ZIP download. Leave empty for the static link.">
              <input
                value={state.settings.scannerApiUrl || ''}
                onChange={(e) => dispatch({ type: 'set-setting', key: 'scannerApiUrl', value: e.target.value })}
                placeholder="https://your-bot-host"
                className="bd tile txt w-full rounded-lg border px-3 py-2.5 text-sm focus:outline-none"
              />
            </Row>
          )}
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-1 text-lg font-semibold">Data Management</h3>
          <p className="muted mb-2 text-sm">Everything is stored locally in your browser.</p>
          <Row title="Export backup" desc="Download all data as JSON">
            <button onClick={exportData} className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium">
              <Download size={16} /> Export
            </button>
          </Row>
          <Row title="Import backup" desc="Restore from a JSON file">
            <input ref={fileRef} type="file" accept="application/json" className="hidden" onChange={(e) => e.target.files[0] && importData(e.target.files[0])} />
            <button onClick={() => fileRef.current?.click()} className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium">
              <Upload size={16} /> Import
            </button>
          </Row>
          <Row title="Clear data" desc="Wipe pins, scans and files (keeps settings)">
            <button
              onClick={() => {
                if (confirm('Clear all scan data? This cannot be undone.')) {
                  dispatch({ type: 'clear-data' })
                  toast({ type: 'success', title: 'Data cleared' })
                }
              }}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-4 py-2.5 text-sm font-medium text-red-500"
            >
              <Trash2 size={16} /> Clear
            </button>
          </Row>
          <Row title="Factory reset" desc="Restore demo seed data">
            <button
              onClick={() => {
                if (confirm('Reset everything to demo defaults?')) {
                  dispatch({ type: 'reset' })
                  toast({ type: 'success', title: 'Reset complete' })
                }
              }}
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
            >
              <RotateCcw size={16} /> Reset
            </button>
          </Row>
        </Card>
      </div>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-3 text-lg font-semibold">About</h3>
        <div className="muted grid gap-2 text-sm sm:grid-cols-3">
          <p>Version <span className="txt">2.1.0</span></p>
          <p>Build <span className="txt">client-side SPA</span></p>
          <p>Storage <span className="txt">localStorage</span></p>
        </div>
      </Card>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Data Backup</h3>
        <p className="muted mb-4 text-sm">Export or import a selective backup (tickets, proposals, cheats, pins and scans only).</p>
        <Row title="Export selective backup" desc="Downloads as zerotrace-backup-{date}.json, excludes theme/lang settings">
          <button
            onClick={() => {
              const { settings: s } = state
              const { theme, lang, ...otherSettings } = s
              const exportObj = {
                tickets: state.tickets,
                proposals: state.proposals,
                customCheats: state.customCheats,
                pins: state.pins,
                scans: state.scans,
                settings: otherSettings,
              }
              const date = new Date().toISOString().slice(0, 10)
              const a = document.createElement('a')
              a.href = URL.createObjectURL(new Blob([JSON.stringify(exportObj, null, 2)], { type: 'application/json' }))
              a.download = `zerotrace-backup-${date}.json`
              a.click()
              URL.revokeObjectURL(a.href)
              toast({ type: 'success', title: 'Backup exported' })
            }}
            className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
          >
            <Download size={16} /> Export
          </button>
        </Row>
        <Row title="Import & merge backup" desc="Merges imported tickets, proposals, cheats, pins and scans with existing data.">
          <>
            <p className="mb-2 rounded-lg border border-yellow-500/20 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
              ⚠ This will merge imported data with your existing data.
            </p>
            <input
              ref={backupFileRef}
              type="file"
              accept="application/json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (!file) return
                const fr = new FileReader()
                fr.onload = () => {
                  try {
                    const data = JSON.parse(fr.result)
                    dispatch({ type: 'import-backup', data })
                    toast({ type: 'success', title: 'Backup merged' })
                  } catch {
                    toast({ type: 'error', title: 'Invalid backup file' })
                  }
                }
                fr.readAsText(file)
              }}
            />
            <button
              onClick={() => backupFileRef.current?.click()}
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
            >
              <Upload size={16} /> Import & Merge
            </button>
          </>
        </Row>
      </Card>
    </div>
  )
}

function RiskScoreTab() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const w = state.settings?.riskWeights || { detect: 8, warn: 2, susp: 5 }
  const [detect, setDetect] = useState(w.detect)
  const [warn, setWarn] = useState(w.warn)
  const [susp, setSusp] = useState(w.susp)
  const save = () => {
    dispatch({ type: 'set-risk-weights', weights: { detect: Number(detect) || 0, warn: Number(warn) || 0, susp: Number(susp) || 0 } })
    toast({ type: 'success', title: 'Risk weights saved' })
  }
  return (
    <Card className="p-6">
      <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
        <ShieldAlert size={18} /> Risk Score Formula
      </h3>
      <p className="muted mb-4 text-sm">
        Tune how the risk score is computed. Final score = detects × A + warnings × B + suspicious × C, capped at 100.
      </p>
      <div className="grid gap-4 sm:grid-cols-3">
        <div>
          <p className="caps-label mb-1">A — Detect weight</p>
          <input type="number" min="0" value={detect} onChange={(e) => setDetect(e.target.value)} className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        </div>
        <div>
          <p className="caps-label mb-1">B — Warning weight</p>
          <input type="number" min="0" value={warn} onChange={(e) => setWarn(e.target.value)} className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        </div>
        <div>
          <p className="caps-label mb-1">C — Suspicious weight</p>
          <input type="number" min="0" value={susp} onChange={(e) => setSusp(e.target.value)} className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        </div>
      </div>
      <div className="mt-4 flex justify-end">
        <button onClick={save} className="rounded-lg bg-sky-600 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-500">Save</button>
      </div>
    </Card>
  )
}

function GameProfilesTab() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const profiles = state.settings?.gameProfiles || {}
  const webhooks = state.integrations?.discordWebhooks || []
  return (
    <Card className="p-6">
      <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
        <Gamepad2 size={18} /> Per-Game Profiles
      </h3>
      <p className="muted mb-4 text-sm">
        Default settings used when creating a pin for a given game.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="caps-label bd border-b">
              <th className="px-3 py-3">Game</th>
              <th className="px-3 py-3">Default visibility</th>
              <th className="px-3 py-3">Default webhook</th>
            </tr>
          </thead>
          <tbody>
            {ALL_GAMES.map((g) => {
              const p = profiles[g] || {}
              return (
                <tr key={g} className="bd border-b last:border-0">
                  <td className="txt px-3 py-3 font-medium">{g}</td>
                  <td className="px-3 py-3">
                    <Select
                      value={p.visibility || 'Private'}
                      onChange={(v) => {
                        dispatch({ type: 'set-game-profiles', profiles: { [g]: { ...p, visibility: v } } })
                        toast({ type: 'success', title: 'Saved' })
                      }}
                      options={[
                        { value: 'Private', label: 'Private' },
                        { value: 'Public', label: 'Public' },
                      ]}
                    />
                  </td>
                  <td className="px-3 py-3">
                    <Select
                      value={p.webhookId || ''}
                      onChange={(v) => {
                        dispatch({ type: 'set-game-profiles', profiles: { [g]: { ...p, webhookId: v } } })
                        toast({ type: 'success', title: 'Saved' })
                      }}
                      options={[
                        { value: '', label: '— default —' },
                        ...webhooks.map((w) => ({ value: w.id, label: w.label || w.url.slice(0, 40) })),
                      ]}
                    />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function WeeklyReportTab() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const wr = state.settings?.weeklyReport || { enabled: false, lastSentAt: 0 }
  const sendNow = async () => {
    const webhook = state.integrations?.discordWebhook || ''
    const week = Date.now() - 7 * 86400000
    const recent = (state.pins || []).filter((p) => (p.scannedAt || p.createdAt || 0) >= week)
    const cheats = recent.filter((p) => p.result === 'Cheating').length
    const susp = recent.filter((p) => p.result === 'Suspicious').length
    const clean = recent.filter((p) => p.result === 'Clean').length
    const top = {}
    recent.forEach((p) => (p.cheats || []).forEach((c) => (top[c] = (top[c] || 0) + 1)))
    const topList = Object.entries(top)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([k, v]) => `${k} ×${v}`)
      .join(', ') || '—'
    if (webhook) {
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: 'ZeroTrace Weekly',
            embeds: [
              {
                title: 'ZeroTrace — Weekly summary',
                color: 0x38bdf8,
                fields: [
                  { name: 'Total scans (7d)', value: String(recent.length), inline: true },
                  { name: 'Cheating', value: String(cheats), inline: true },
                  { name: 'Suspicious', value: String(susp), inline: true },
                  { name: 'Clean', value: String(clean), inline: true },
                  { name: 'Top cheats', value: topList },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          }),
        })
      } catch { /* ignore */ }
    }
    dispatch({ type: 'set-weekly-report', value: { lastSentAt: Date.now() } })
    toast({ type: 'success', title: 'Weekly summary sent' })
  }
  return (
    <Card className="p-6">
      <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
        <CalendarCheck size={18} /> Weekly Report
      </h3>
      <p className="muted mb-4 text-sm">
        Posts a weekly summary (7-day stats) to the configured Discord webhook.
      </p>
      <Row title="Auto-send every 7 days" desc="When enabled, the dashboard sends one summary per week while it's open.">
        <button
          onClick={() => {
            dispatch({ type: 'set-weekly-report', value: { enabled: !wr.enabled } })
            toast({ type: 'success', title: wr.enabled ? 'Auto-send disabled' : 'Auto-send enabled' })
          }}
          className={`flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium ${wr.enabled ? 'border-green-600/40 bg-green-600/15 text-green-500' : 'bd txt'}`}
        >
          {wr.enabled ? 'Enabled' : 'Disabled'}
        </button>
      </Row>
      <Row title="Send now" desc={`Last sent: ${wr.lastSentAt ? new Date(wr.lastSentAt).toLocaleString() : 'never'}`}>
        <button onClick={sendNow} className="rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">
          Send weekly summary
        </button>
      </Row>
    </Card>
  )
}

function SecuritySettingsTab() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const lo = state.security?.lockout || { maxAttempts: 5, lockMinutes: 15 }
  const [maxA, setMaxA] = useState(lo.maxAttempts)
  const [lockM, setLockM] = useState(lo.lockMinutes)
  return (
    <Card className="p-6">
      <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
        <ShieldCheck size={18} /> Login Lockout
      </h3>
      <p className="muted mb-4 text-sm">
        Block sign-in for a while after too many wrong passwords.
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <p className="caps-label mb-1">Max attempts (in 10 min)</p>
          <input type="number" min="1" value={maxA} onChange={(e) => setMaxA(e.target.value)} className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        </div>
        <div>
          <p className="caps-label mb-1">Lock duration (minutes)</p>
          <input type="number" min="1" value={lockM} onChange={(e) => setLockM(e.target.value)} className="bd tile txt w-full rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        </div>
      </div>
      <div className="mt-4 flex justify-end">
        <button
          onClick={() => {
            dispatch({ type: 'set-login-lockout', value: { maxAttempts: Number(maxA) || 5, lockMinutes: Number(lockM) || 15 } })
            toast({ type: 'success', title: 'Saved' })
          }}
          className="rounded-lg bg-sky-600 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-500"
        >
          Save
        </button>
      </div>
    </Card>
  )
}

const TAB_FROM_QUERY = {
  general: 'General',
  risk: 'Risk Score',
  games: 'Game Profiles',
  weekly: 'Weekly Report',
  security: 'Security',
  designer: 'Tool Designer',
}

export default function SettingsPage() {
  const [params] = useSearchParams()
  const initial = TAB_FROM_QUERY[params.get('tab')] || 'General'
  const [tab, setTab] = useState(initial)
  useEffect(() => {
    const t = TAB_FROM_QUERY[params.get('tab')]
    if (t) setTab(t)
  }, [params])
  return (
    <div>
      <PageHeader icon={Cog} kicker="Preferences & data" title="Settings" subtitle="Configure the dashboard, manage data, and design the scanner GUI." />
      <Tabs
        tabs={[
          { label: 'General', icon: SlidersHorizontal },
          { label: 'Risk Score', icon: ShieldAlert },
          { label: 'Game Profiles', icon: Gamepad2 },
          { label: 'Weekly Report', icon: CalendarCheck },
          { label: 'Security', icon: ShieldCheck },
          { label: 'Tool Designer', icon: Wand2 },
        ]}
        active={tab}
        onChange={setTab}
      />
      <div className="mt-8">
        {tab === 'General' && <General />}
        {tab === 'Risk Score' && <RiskScoreTab />}
        {tab === 'Game Profiles' && <GameProfilesTab />}
        {tab === 'Weekly Report' && <WeeklyReportTab />}
        {tab === 'Security' && <SecuritySettingsTab />}
        {tab === 'Tool Designer' && <ToolDesigner embedded />}
      </div>
    </div>
  )
}
