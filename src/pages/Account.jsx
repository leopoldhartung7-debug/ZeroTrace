import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  UserCog, User, Palette, Shield, Globe, Clock, CreditCard, Zap,
  Database, Eye, EyeOff, Check, MoreVertical, Lock, Download,
  Trash2, Fingerprint, KeyRound, Monitor, Smartphone, Tablet, ShieldOff,
  ShieldCheck, FileJson, FileSpreadsheet, Activity, ScanLine,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { Select, Menu, Modal, useToast } from '../components/ui.jsx'
import { useStore, deriveScanReport } from '../store.jsx'

function ago(ts) {
  if (!ts) return 'just now'
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `about ${Math.floor(s / 60)} minutes ago`
  if (s < 86400) return `about ${Math.floor(s / 3600)} hours ago`
  return `${Math.floor(s / 86400)} days ago`
}
function inDays(ts, days = 7) {
  const left = ts + days * 86400000 - Date.now()
  const d = Math.ceil(left / 86400000)
  return d <= 0 ? 'expired' : `in ${d} day${d === 1 ? '' : 's'}`
}

function detectDevice() {
  const ua = navigator.userAgent || ''
  const touch = navigator.maxTouchPoints || 0
  const isTablet = /iPad/i.test(ua) || /Tablet/i.test(ua) || (/Macintosh/.test(ua) && touch > 1)
  const isMobile = !isTablet && /Mobi|Android|iPhone|iPod/i.test(ua)
  const kind = isTablet ? 'Tablet' : isMobile ? 'Mobile' : 'Desktop'
  let os = 'Unknown'
  let m
  if (/Windows NT/.test(ua)) os = 'Windows'
  else if ((m = ua.match(/OS (\d+[_.]\d+(?:[_.]\d+)?)/)) && /iPhone|iPad|iPod|Mac/.test(ua) && isMobile)
    os = 'iOS ' + m[1].replace(/_/g, '.')
  else if ((m = ua.match(/iPhone OS (\d+[_.]\d+)/))) os = 'iOS ' + m[1].replace(/_/g, '.')
  else if ((m = ua.match(/CPU OS (\d+[_.]\d+)/))) os = 'iOS ' + m[1].replace(/_/g, '.')
  else if ((m = ua.match(/Mac OS X (\d+[_.]\d+(?:[_.]\d+)?)/))) os = 'macOS ' + m[1].replace(/_/g, '.')
  else if ((m = ua.match(/Android (\d+(?:\.\d+)?)/))) os = 'Android ' + m[1]
  else if (/Linux/.test(ua)) os = 'Linux'
  let browser = 'Browser'
  if (/Edg\/(\d+)/.test(ua)) browser = 'Edge ' + RegExp.$1
  else if (/OPR\/(\d+)/.test(ua)) browser = 'Opera ' + RegExp.$1
  else if (/Firefox\/(\d+)/.test(ua)) browser = 'Firefox ' + RegExp.$1
  else if (/Chrome\/(\d+)/.test(ua) && !/Edg|OPR/.test(ua))
    browser = (isMobile || isTablet ? 'Mobile Chrome ' : 'Chrome ') + RegExp.$1
  else if (/Version\/(\d+).*Safari/.test(ua))
    browser = (isMobile || isTablet ? 'Mobile Safari ' : 'Safari ') + RegExp.$1
  return { kind, os: os.trim(), browser }
}
const DeviceIcon = ({ kind, size = 16 }) =>
  kind === 'Mobile' ? <Smartphone size={size} /> : kind === 'Tablet' ? <Tablet size={size} /> : <Monitor size={size} />

function randHex(n = 16) {
  const a = new Uint8Array(n)
  crypto.getRandomValues(a)
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('')
}
function randBase32(n = 32) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const a = new Uint8Array(n)
  crypto.getRandomValues(a)
  return [...a].map((b) => A[b % 32]).join('')
}

const TABS = [
  { id: 'general', label: 'General', icon: User },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'connections', label: 'Connections', icon: Globe },
  { id: 'sessions', label: 'Sessions', icon: Clock },
  { id: 'billing', label: 'Billing', icon: CreditCard },
  { id: 'integrations', label: 'Integrations', icon: Zap },
  { id: 'privacy', label: 'Privacy & Data', icon: Database },
]
const inputCls =
  'bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500/40'

function Field({ label, children }) {
  return (
    <div>
      <label className="txt mb-1.5 block text-sm font-medium">{label}</label>
      {children}
    </div>
  )
}

export default function Account() {
  const nav = useNavigate()
  const toast = useToast()
  const { state, dispatch } = useStore()
  const [tab, setTab] = useState('general')
  const [profile, setProfile] = useState({ name: 'Ham', email: 'ham@anticheat.ac' })
  const [pwOpen, setPwOpen] = useState(false)
  const [pw, setPw] = useState({ cur: '', next: '', confirm: '' })
  const [tfaOpen, setTfaOpen] = useState(false)
  const [hook, setHook] = useState(state.integrations?.discordWebhook || '')
  const [vt, setVt] = useState(state.integrations?.virusTotalKey || '')
  const [botUrl, setBotUrl] = useState(state.integrations?.discordBotUrl || '')
  const [botKey, setBotKey] = useState(state.integrations?.discordBotKey || '')
  const [showHook, setShowHook] = useState(false)
  const [showVt, setShowVt] = useState(false)
  const [showBotKey, setShowBotKey] = useState(false)
  const [fmt, setFmt] = useState('json')
  const [sel, setSel] = useState({ profile: true, pins: true, scans: false, activity: false, all: false, security: false })
  const toggleSel = (key) =>
    setSel((s) => {
      // "Include Security Data" is an independent add-on — never cleared.
      if (key === 'security') return { ...s, security: !s.security }
      if (key === 'all') {
        return !s.all
          ? { ...s, profile: false, pins: false, scans: false, activity: false, all: true }
          : { ...s, all: false }
      }
      return { ...s, all: false, [key]: !s[key] }
    })

  const device = useMemo(detectDevice, [])
  const tfaSecret = useMemo(() => randBase32(32), [tfaOpen])
  const sess = state.session

  const exportData = () => {
    const out = {}
    if (sel.all || sel.profile) out.profile = { ...profile, settings: state.settings }
    if (sel.all || sel.pins) out.pins = state.pins
    if (sel.all || sel.scans)
      out.scanResults = state.pins
        .filter((p) => p.status === 'Finished')
        .map((p) => ({ pin: p.pin, result: p.result, report: deriveScanReport(p) }))
    if (sel.all || sel.activity) out.activity = state.events
    if (sel.all || sel.security)
      out.security = { ...state.security, session: sess, otherSessions: state.otherSessions, connections: state.connections }
    if (sel.all) Object.assign(out, { settings: state.settings, customCheats: state.customCheats })

    if (Object.keys(out).length === 0) {
      toast({ type: 'error', title: 'Select data to export' })
      return
    }
    let blob, ext
    if (fmt === 'csv') {
      const rows = out.pins || []
      const cols = ['pin', 'name', 'discordId', 'game', 'status', 'result', 'detections']
      const csv = [
        cols.join(','),
        ...rows.map((r) => cols.map((c) => `"${String(r[c] ?? '').replace(/"/g, "'")}"`).join(',')),
      ].join('\n')
      blob = new Blob([csv], { type: 'text/csv' })
      ext = 'csv'
    } else {
      blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' })
      ext = 'json'
    }
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `ocean-export.${ext}`
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Data exported', body: ext.toUpperCase() })
  }

  return (
    <div>
      <PageHeader icon={UserCog} kicker="Manage your account settings and preferences" title="Account Settings" />

      <div className="grid gap-6 lg:grid-cols-[230px_1fr]">
        <Card className="h-fit p-2">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium ${
                tab === t.id ? 'bg-white/[0.06] txt' : 'muted hoverable'
              }`}
            >
              <t.icon size={17} /> {t.label}
            </button>
          ))}
        </Card>

        <Card className="p-6 md:p-8">
          {tab === 'general' && (
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">General</h3>
                <p className="muted text-sm">Your account profile.</p>
              </div>
              <Field label="Display name">
                <input className={inputCls} value={profile.name} onChange={(e) => setProfile({ ...profile, name: e.target.value })} />
              </Field>
              <Field label="Email">
                <input className={inputCls} value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} />
              </Field>
              <button onClick={() => toast({ type: 'success', title: 'Profile saved' })} className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500">
                Save changes
              </button>
            </div>
          )}

          {tab === 'appearance' && (
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">Appearance</h3>
                <p className="muted text-sm">Theme and language.</p>
              </div>
              <Field label="Theme">
                <button
                  onClick={() => dispatch({ type: 'set-setting', key: 'theme', value: state.settings.theme === 'dark' ? 'light' : 'dark' })}
                  className="bd txt w-full max-w-xs rounded-lg border px-4 py-2.5 text-sm font-medium"
                >
                  {state.settings.theme === 'dark' ? 'Dark' : 'Light'}
                </button>
              </Field>
              <Field label="Language">
                <div className="max-w-xs">
                  <Select
                    value={state.settings.lang}
                    onChange={(v) => dispatch({ type: 'set-setting', key: 'lang', value: v })}
                    options={[{ value: 'en', label: 'English' }, { value: 'de', label: 'Deutsch' }]}
                  />
                </div>
              </Field>
            </div>
          )}

          {tab === 'security' && (
            <div className="space-y-2">
              <div className="bd flex flex-col gap-3 border-b py-5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="txt text-lg font-semibold">Password</p>
                  <p className="muted text-sm">Change your password to keep your account secure</p>
                </div>
                <button onClick={() => setPwOpen(true)} className="bd txt flex items-center gap-2 rounded-lg border px-5 py-2.5 text-sm font-medium hover:border-blue-500">
                  <Lock size={15} /> Change Password
                </button>
              </div>

              <div className="bd flex flex-col gap-3 border-b py-5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="txt text-lg font-semibold">Two-Factor Authentication</p>
                  <p className={`text-sm font-medium ${state.security.twoFA ? 'text-green-500' : 'text-red-500'}`}>
                    {state.security.twoFA ? 'Enabled' : 'Disabled'}
                  </p>
                </div>
                {state.security.twoFA ? (
                  <button
                    onClick={() => {
                      dispatch({ type: 'set-2fa', value: false })
                      toast({ type: 'success', title: '2FA disabled' })
                    }}
                    className="flex items-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-5 py-2.5 text-sm font-medium text-red-500"
                  >
                    <ShieldOff size={15} /> Disable 2FA
                  </button>
                ) : (
                  <button onClick={() => setTfaOpen(true)} className="flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-black hover:opacity-90">
                    <ShieldCheck size={15} /> Setup 2FA
                  </button>
                )}
              </div>

              <div className="py-5">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3">
                    <Fingerprint size={20} className="txt" />
                    <div>
                      <p className="txt text-lg font-semibold">Passkeys</p>
                      <p className="muted text-sm">Passwordless authentication</p>
                    </div>
                  </div>
                  {state.security.passkeys.length > 0 && (
                    <button
                      onClick={() => {
                        dispatch({ type: 'add-passkey', name: `${device.kind} · ${device.browser}` })
                        toast({ type: 'success', title: 'Passkey added' })
                      }}
                      className="flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-black hover:opacity-90"
                    >
                      + Add Passkey
                    </button>
                  )}
                </div>
                {state.security.passkeys.length === 0 ? (
                  <div className="bd mt-5 flex flex-col items-center rounded-xl border border-dashed p-10 text-center">
                    <KeyRound size={34} className="muted" />
                    <p className="txt mt-4 font-semibold">No Passkeys</p>
                    <p className="muted mt-1 text-sm">Add a passkey for faster sign-in.</p>
                    <button
                      onClick={() => {
                        dispatch({ type: 'add-passkey', name: `${device.kind} · ${device.browser}` })
                        toast({ type: 'success', title: 'Passkey added' })
                      }}
                      className="mt-5 flex items-center gap-2 rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-black hover:opacity-90"
                    >
                      + Add First Passkey
                    </button>
                  </div>
                ) : (
                  <div className="mt-4 space-y-2">
                    {state.security.passkeys.map((p) => (
                      <div key={p.id} className="tile flex items-center justify-between rounded-lg border px-4 py-3">
                        <div className="flex items-center gap-3">
                          <KeyRound size={16} className="muted" />
                          <div>
                            <p className="txt text-sm font-medium">{p.name}</p>
                            <p className="muted text-xs">Added {ago(p.createdAt)} · {p.id}</p>
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            dispatch({ type: 'remove-passkey', id: p.id })
                            toast({ type: 'success', title: 'Passkey removed' })
                          }}
                          className="muted hover:text-red-500 rounded p-1.5"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === 'connections' && (
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">Connected Accounts</h3>
                <p className="muted text-sm">Connect your accounts to enable additional features and seamless integration.</p>
              </div>
              <p className="caps-label">Connected Accounts</p>
              {state.connections.length === 0 ? (
                <div className="tile rounded-xl border p-8 text-center">
                  <p className="muted text-sm">No accounts connected with Ocean yet.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {state.connections.map((c) => (
                    <div key={c.id} className="tile flex items-center gap-3 rounded-xl border p-4">
                      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-600 text-sm font-bold text-white">
                        {c.name[0]?.toUpperCase()}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="txt truncate text-sm font-medium">{c.name} <span className="muted">({c.id})</span></p>
                        <p className="muted text-xs">Connected {ago(c.connectedAt)}</p>
                      </div>
                      <Menu
                        trigger={<button className="muted hover:txt p-1"><MoreVertical size={16} /></button>}
                        items={[{ label: 'Disconnect', icon: <Trash2 size={14} />, danger: true, onClick: () => { dispatch({ type: 'disconnect-account', id: c.id }); toast({ type: 'success', title: 'Disconnected', body: c.name }) } }]}
                      />
                    </div>
                  ))}
                </div>
              )}
              <button
                onClick={() => {
                  const id = String(1000000000000000000 + Math.floor(Math.random() * 9e17)).slice(0, 19)
                  dispatch({ type: 'connect-account', account: { id, name: 'discord_user' } })
                  toast({ type: 'success', title: 'Discord connected', body: `ID ${id}` })
                }}
                className="flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
              >
                <Globe size={16} /> Connect Discord
              </button>
            </div>
          )}

          {tab === 'sessions' && (
            <div className="space-y-8">
              <div>
                <h3 className="txt text-xl font-bold">Current Session</h3>
                <div className="bd mt-4 overflow-hidden rounded-xl border">
                  <div className="caps-label bd grid grid-cols-[1.4fr_1.2fr_1fr_0.8fr] gap-2 border-b px-4 py-3">
                    <span>Device Info</span><span>Session Details</span><span>Location</span><span>Status</span>
                  </div>
                  <div className="grid grid-cols-[1.4fr_1.2fr_1fr_0.8fr] gap-2 px-4 py-4 text-sm">
                    <div className="space-y-1">
                      <p className="txt flex items-center gap-2 font-medium"><DeviceIcon kind={device.kind} /> {device.kind}</p>
                      <p className="muted text-xs">{device.os}</p>
                      <p className="muted text-xs">{device.browser}</p>
                    </div>
                    <div className="muted space-y-1 text-xs">
                      <p>ID: {sess?.id?.slice(0, 12)}…</p>
                      <p>Created: {ago(sess?.createdAt)}</p>
                      <p>Expires: {sess ? inDays(sess.createdAt) : '—'}</p>
                    </div>
                    <p className="muted text-xs">Unknown</p>
                    <div className="flex flex-col items-start gap-1">
                      <span className="rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-xs font-semibold text-green-500">Active</span>
                      <span className="bd muted rounded-md border px-2 py-0.5 text-xs">Current</span>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between">
                  <h3 className="txt text-xl font-bold">Other Sessions</h3>
                  {state.otherSessions.length > 0 && (
                    <button
                      onClick={() => { dispatch({ type: 'revoke-all-sessions' }); toast({ type: 'success', title: 'All other sessions revoked' }) }}
                      className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-500"
                    >
                      <ShieldOff size={15} /> Revoke All Other
                    </button>
                  )}
                </div>
                {state.otherSessions.length === 0 ? (
                  <div className="tile mt-4 rounded-xl border p-8 text-center">
                    <p className="muted text-sm">No other active sessions.</p>
                  </div>
                ) : (
                  <div className="bd mt-4 space-y-3 rounded-xl border p-4">
                    {state.otherSessions.map((s) => (
                      <div key={s.id} className="flex items-center justify-between gap-3 text-sm">
                        <div>
                          <p className="txt flex items-center gap-2 font-medium"><DeviceIcon kind={s.kind} /> {s.kind}</p>
                          <p className="muted text-xs">{s.os} · {s.browser}</p>
                        </div>
                        <div className="muted text-xs">ID: {s.id.slice(0, 10)}…<br />Created: {ago(s.created)}</div>
                        <p className="muted text-xs">{s.location}</p>
                        <button
                          onClick={() => { dispatch({ type: 'revoke-session', id: s.id }); toast({ type: 'success', title: 'Session revoked' }) }}
                          className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-500"
                        >
                          ✕ Revoke
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === 'billing' && (
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">Billing</h3>
                <p className="muted text-sm">Your current plan.</p>
              </div>
              <div className="tile flex items-center justify-between rounded-xl border p-5">
                <div>
                  <p className="txt font-semibold">Free plan</p>
                  <p className="muted text-xs">1 daily pin · basic support</p>
                </div>
                <button onClick={() => nav('/pricing')} className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500">
                  View plans
                </button>
              </div>
            </div>
          )}

          {tab === 'integrations' && (
            <div className="space-y-6">
              <div>
                <h3 className="txt text-lg font-semibold">API Integrations</h3>
                <p className="muted text-sm">Connect third-party services</p>
              </div>
              <div className="tile flex items-center gap-3 rounded-xl border px-4 py-3">
                <Lock size={16} className="muted" /><span className="txt text-sm">Keys are encrypted.</span>
              </div>
              <div className="tile rounded-xl border p-5">
                <div className="flex items-center gap-3">
                  <Zap size={18} className="text-blue-500" />
                  <h4 className="txt text-lg font-bold">Discord Webhook</h4>
                  {state.integrations.discordWebhook && (
                    <span className="flex items-center gap-1 rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-bold text-green-500"><Check size={11} /> CONNECTED</span>
                  )}
                </div>
                <p className="muted mt-1 text-sm">Discord notifications</p>
                <Field label="Webhook URL">
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input type={showHook ? 'text' : 'password'} value={hook} onChange={(e) => setHook(e.target.value)} placeholder="https://discord.com/api/webhooks/..." className={inputCls} />
                      <button onClick={() => setShowHook((s) => !s)} className="muted hover:txt absolute right-3 top-1/2 -translate-y-1/2">{showHook ? <EyeOff size={16} /> : <Eye size={16} />}</button>
                    </div>
                    <button onClick={() => { dispatch({ type: 'set-integration', key: 'discordWebhook', value: hook.trim() }); toast({ type: 'success', title: 'Webhook saved' }) }} className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500">Save</button>
                  </div>
                </Field>
                {state.integrations.discordWebhook && (
                  <button onClick={() => { dispatch({ type: 'set-integration', key: 'discordWebhook', value: '' }); setHook(''); toast({ type: 'success', title: 'Webhook removed' }) }} className="bd txt mt-3 flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm hover:border-red-500"><Trash2 size={14} /> Remove</button>
                )}
              </div>
              <div className="tile rounded-xl border p-5">
                <div className="flex items-center gap-3">
                  <Shield size={18} className="text-blue-500" />
                  <h4 className="txt text-lg font-bold">VirusTotal API</h4>
                  {state.integrations.virusTotalKey && (
                    <span className="flex items-center gap-1 rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-bold text-green-500"><Check size={11} /> CONNECTED</span>
                  )}
                </div>
                <p className="muted mt-1 text-sm">VirusTotal intelligence</p>
                <Field label="API Key">
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input type={showVt ? 'text' : 'password'} value={vt} onChange={(e) => setVt(e.target.value)} placeholder="Enter VirusTotal API key" className={inputCls} />
                      <button onClick={() => setShowVt((s) => !s)} className="muted hover:txt absolute right-3 top-1/2 -translate-y-1/2">{showVt ? <EyeOff size={16} /> : <Eye size={16} />}</button>
                    </div>
                    <button onClick={() => { dispatch({ type: 'set-integration', key: 'virusTotalKey', value: vt.trim() }); toast({ type: 'success', title: 'API key saved' }) }} className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500">Save</button>
                  </div>
                </Field>
              </div>
              <div className="tile rounded-xl border p-5">
                <div className="flex items-center gap-3">
                  <Zap size={18} className="text-blue-500" />
                  <h4 className="txt text-lg font-bold">Discord Server Bot</h4>
                  {state.integrations.discordBotUrl && (
                    <span className="flex items-center gap-1 rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-bold text-green-500"><Check size={11} /> CONNECTED</span>
                  )}
                </div>
                <p className="muted mt-1 text-sm">Live server / role lookup by Discord ID (see bot/README.md)</p>
                <Field label="Bot API URL">
                  <div className="flex gap-2">
                    <input value={botUrl} onChange={(e) => setBotUrl(e.target.value)} placeholder="https://yourhost.example" className={inputCls} />
                    <button onClick={() => { dispatch({ type: 'set-integration', key: 'discordBotUrl', value: botUrl.trim().replace(/\/$/, '') }); toast({ type: 'success', title: 'Saved' }) }} className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500">Save</button>
                  </div>
                </Field>
                <Field label="API Key">
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input type={showBotKey ? 'text' : 'password'} value={botKey} onChange={(e) => setBotKey(e.target.value)} placeholder="Bot API key" className={inputCls} />
                      <button onClick={() => setShowBotKey((s) => !s)} className="muted hover:txt absolute right-3 top-1/2 -translate-y-1/2">{showBotKey ? <EyeOff size={16} /> : <Eye size={16} />}</button>
                    </div>
                    <button onClick={() => { dispatch({ type: 'set-integration', key: 'discordBotKey', value: botKey.trim() }); toast({ type: 'success', title: 'API key saved' }) }} className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500">Save</button>
                  </div>
                </Field>
                {state.integrations.discordBotUrl && (
                  <button onClick={() => { dispatch({ type: 'set-integration', key: 'discordBotUrl', value: '' }); dispatch({ type: 'set-integration', key: 'discordBotKey', value: '' }); setBotUrl(''); setBotKey(''); toast({ type: 'success', title: 'Removed' }) }} className="bd txt mt-3 flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm hover:border-red-500"><Trash2 size={14} /> Remove</button>
                )}
              </div>
            </div>
          )}

          {tab === 'privacy' && (
            <div className="space-y-6">
              <div>
                <h3 className="txt text-lg font-semibold">Privacy &amp; Data</h3>
                <p className="muted text-sm">Export your data. Everything is stored locally in your browser.</p>
              </div>
              <div className="flex gap-6">
                {[
                  { v: 'json', label: 'JSON', icon: FileJson },
                  { v: 'csv', label: 'CSV', icon: FileSpreadsheet },
                ].map((f) => (
                  <button key={f.v} onClick={() => setFmt(f.v)} className="flex items-center gap-2 text-sm">
                    <span className={`flex h-4 w-4 items-center justify-center rounded-full border ${fmt === f.v ? 'border-blue-500' : 'bd'}`}>
                      {fmt === f.v && <span className="h-2 w-2 rounded-full bg-blue-500" />}
                    </span>
                    <f.icon size={16} className={f.v === 'json' ? 'text-yellow-500' : 'text-green-500'} />
                    <span className="txt">{f.label}</span>
                  </button>
                ))}
              </div>
              <div>
                <p className="caps-label mb-3">Data to Export</p>
                <div className="space-y-3">
                  {[
                    { k: 'profile', icon: User, t: 'Profile Data', d: 'Account info and preferences' },
                    { k: 'pins', icon: Database, t: 'Pins', d: 'Your pins and results' },
                    { k: 'scans', icon: ScanLine, t: 'Scan Results', d: 'Detailed scan results' },
                    { k: 'activity', icon: Activity, t: 'Activity Log', d: 'Login history and activity' },
                    { k: 'all', icon: Download, t: 'All Data', d: 'All data types' },
                  ].map((o) => (
                    <button
                      key={o.k}
                      onClick={() => toggleSel(o.k)}
                      className={`tile flex w-full items-center gap-4 rounded-xl border p-4 text-left ${sel[o.k] ? 'border-blue-500/50' : ''}`}
                    >
                      <span className={`flex h-5 w-5 items-center justify-center rounded ${sel[o.k] ? 'bg-blue-600 text-white' : 'bd tile'}`}>
                        {sel[o.k] && <Check size={13} />}
                      </span>
                      <o.icon size={18} className="muted" />
                      <span>
                        <span className="txt block text-sm font-medium">{o.t}</span>
                        <span className="muted block text-xs">{o.d}</span>
                      </span>
                    </button>
                  ))}
                  <button
                    onClick={() => toggleSel('security')}
                    className={`tile flex w-full items-center gap-4 rounded-xl border p-4 text-left ${sel.security ? 'border-yellow-500/50' : ''}`}
                  >
                    <span className={`flex h-5 w-5 items-center justify-center rounded ${sel.security ? 'bg-yellow-500 text-black' : 'bd tile'}`}>
                      {sel.security && <Check size={13} />}
                    </span>
                    <Shield size={18} className="text-yellow-500" />
                    <span>
                      <span className="txt block text-sm font-medium">Include Security Data</span>
                      <span className="muted block text-xs">Sessions, IPs, devices</span>
                    </span>
                  </button>
                </div>
              </div>
              <button onClick={exportData} className="flex w-full items-center justify-center gap-2 rounded-xl bg-white py-3.5 text-sm font-semibold text-black hover:opacity-90">
                <Download size={17} /> Export Data
              </button>
            </div>
          )}
        </Card>
      </div>

      <Modal
        open={pwOpen}
        onClose={() => setPwOpen(false)}
        title="Change Password"
        footer={
          <>
            <button onClick={() => setPwOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button
              onClick={() => {
                if (!pw.cur || !pw.next) return toast({ type: 'error', title: 'Fill in all fields' })
                if (pw.next.length < 6) return toast({ type: 'error', title: 'Password too short' })
                if (pw.next !== pw.confirm) return toast({ type: 'error', title: 'Passwords do not match' })
                setPw({ cur: '', next: '', confirm: '' })
                setPwOpen(false)
                toast({ type: 'success', title: 'Password changed' })
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Update
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <input type="password" placeholder="Current password" className={inputCls} value={pw.cur} onChange={(e) => setPw({ ...pw, cur: e.target.value })} />
          <input type="password" placeholder="New password" className={inputCls} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
          <input type="password" placeholder="Confirm new password" className={inputCls} value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
        </div>
      </Modal>

      <Modal
        open={tfaOpen}
        onClose={() => setTfaOpen(false)}
        title="Set up Two-Factor Authentication"
        footer={
          <>
            <button onClick={() => setTfaOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button
              onClick={() => {
                dispatch({ type: 'set-2fa', value: true })
                setTfaOpen(false)
                toast({ type: 'success', title: '2FA enabled' })
              }}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Enable 2FA
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="muted text-sm">Add this secret to your authenticator app (TOTP):</p>
          <div className="tile flex items-center justify-between gap-3 rounded-lg border p-3">
            <code className="txt break-all font-mono text-sm">{tfaSecret}</code>
            <button
              onClick={() => { navigator.clipboard?.writeText(tfaSecret); toast({ type: 'success', title: 'Secret copied' }) }}
              className="bd txt shrink-0 rounded-md border px-2.5 py-1.5 text-xs hover:border-blue-500"
            >
              Copy
            </button>
          </div>
          <p className="muted break-all text-xs">otpauth://totp/Ocean:{profile.email}?secret={tfaSecret}&amp;issuer=Ocean</p>
        </div>
      </Modal>
    </div>
  )
}
