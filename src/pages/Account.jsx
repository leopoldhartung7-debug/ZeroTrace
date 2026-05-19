import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  UserCog, User, Palette, Shield, Globe, Clock, CreditCard, Zap,
  Database, LogOut, Eye, EyeOff, Check, MoreVertical, Lock, Download,
  Trash2, RotateCcw,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import { Select, Menu, useToast } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

function ago(ts) {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `about ${Math.floor(s / 60)} minutes ago`
  if (s < 86400) return `about ${Math.floor(s / 3600)} hours ago`
  return `${Math.floor(s / 86400)} days ago`
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

function Field({ label, children }) {
  return (
    <div>
      <label className="txt mb-1.5 block text-sm font-medium">{label}</label>
      {children}
    </div>
  )
}
const inputCls =
  'bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500/40'

export default function Account() {
  const nav = useNavigate()
  const toast = useToast()
  const { state, dispatch } = useStore()
  const [tab, setTab] = useState('general')
  const [profile, setProfile] = useState({ name: 'Ham', email: 'ham@anticheat.ac' })
  const [pw, setPw] = useState({ cur: '', next: '', confirm: '' })
  const [showHook, setShowHook] = useState(false)
  const [showVt, setShowVt] = useState(false)
  const [hook, setHook] = useState(state.integrations?.discordWebhook || '')
  const [vt, setVt] = useState(state.integrations?.virusTotalKey || '')

  const logout = () => {
    dispatch({ type: 'logout' })
    nav('/')
  }

  return (
    <div>
      <PageHeader
        icon={UserCog}
        kicker="Manage your account settings and preferences"
        title="Account Settings"
      />

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
                <p className="muted text-sm">Your public profile.</p>
              </div>
              <Field label="Display name">
                <input className={inputCls} value={profile.name} onChange={(e) => setProfile({ ...profile, name: e.target.value })} />
              </Field>
              <Field label="Email">
                <input className={inputCls} value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} />
              </Field>
              <button
                onClick={() => toast({ type: 'success', title: 'Profile saved' })}
                className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
              >
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
            <div className="space-y-3">
              <div>
                <h3 className="txt text-lg font-semibold">Security</h3>
                <p className="muted text-sm">Change your password.</p>
              </div>
              <input type="password" placeholder="Current password" className={inputCls} value={pw.cur} onChange={(e) => setPw({ ...pw, cur: e.target.value })} />
              <input type="password" placeholder="New password" className={inputCls} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
              <input type="password" placeholder="Confirm new password" className={inputCls} value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
              <button
                onClick={() => {
                  if (!pw.cur || !pw.next) return toast({ type: 'error', title: 'Fill in all fields' })
                  if (pw.next !== pw.confirm) return toast({ type: 'error', title: 'Passwords do not match' })
                  setPw({ cur: '', next: '', confirm: '' })
                  toast({ type: 'success', title: 'Password changed' })
                }}
                className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
              >
                Change password
              </button>
            </div>
          )}

          {tab === 'connections' && (
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">Connected Accounts</h3>
                <p className="muted text-sm">
                  Connect your accounts to enable additional features and seamless integration.
                </p>
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
                        <p className="txt truncate text-sm font-medium">
                          {c.name} <span className="muted">({c.id})</span>
                        </p>
                        <p className="muted text-xs">Connected {ago(c.connectedAt)}</p>
                      </div>
                      <Menu
                        trigger={
                          <button className="muted hover:txt p-1">
                            <MoreVertical size={16} />
                          </button>
                        }
                        items={[
                          {
                            label: 'Disconnect',
                            icon: <Trash2 size={14} />,
                            danger: true,
                            onClick: () => {
                              dispatch({ type: 'disconnect-account', id: c.id })
                              toast({ type: 'success', title: 'Disconnected', body: c.name })
                            },
                          },
                        ]}
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
            <div className="space-y-5">
              <div>
                <h3 className="txt text-lg font-semibold">Sessions</h3>
                <p className="muted text-sm">Devices signed in to your account.</p>
              </div>
              <div className="tile flex items-center justify-between rounded-xl border p-4">
                <div>
                  <p className="txt text-sm font-medium">This device</p>
                  <p className="muted text-xs">Active now · this browser</p>
                </div>
                <button
                  onClick={logout}
                  className="flex items-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-4 py-2 text-sm font-medium text-red-500"
                >
                  <LogOut size={15} /> Log out
                </button>
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
                <button
                  onClick={() => nav('/pricing')}
                  className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
                >
                  View plans
                </button>
              </div>
              <p className="muted text-xs">Billing is handled by our Merchant of Record (demo — no charges).</p>
            </div>
          )}

          {tab === 'integrations' && (
            <div className="space-y-6">
              <div>
                <h3 className="txt text-lg font-semibold">API Integrations</h3>
                <p className="muted text-sm">Connect third-party services</p>
              </div>
              <div className="tile flex items-center gap-3 rounded-xl border px-4 py-3">
                <Lock size={16} className="muted" />
                <span className="txt text-sm">Keys are encrypted.</span>
              </div>

              <div className="tile rounded-xl border p-5">
                <div className="flex items-center gap-3">
                  <Zap size={18} className="text-blue-500" />
                  <h4 className="txt text-lg font-bold">Discord Webhook</h4>
                  {state.integrations.discordWebhook && (
                    <span className="flex items-center gap-1 rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-bold text-green-500">
                      <Check size={11} /> CONNECTED
                    </span>
                  )}
                </div>
                <p className="muted mt-1 text-sm">Discord notifications</p>
                <Field label="Webhook URL">
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input
                        type={showHook ? 'text' : 'password'}
                        value={hook}
                        onChange={(e) => setHook(e.target.value)}
                        placeholder="https://discord.com/api/webhooks/..."
                        className={inputCls}
                      />
                      <button onClick={() => setShowHook((s) => !s)} className="muted hover:txt absolute right-3 top-1/2 -translate-y-1/2">
                        {showHook ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    <button
                      onClick={() => {
                        dispatch({ type: 'set-integration', key: 'discordWebhook', value: hook.trim() })
                        toast({ type: 'success', title: 'Webhook saved' })
                      }}
                      className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500"
                    >
                      Save
                    </button>
                  </div>
                </Field>
                {state.integrations.discordWebhook && (
                  <button
                    onClick={() => {
                      dispatch({ type: 'set-integration', key: 'discordWebhook', value: '' })
                      setHook('')
                      toast({ type: 'success', title: 'Webhook removed' })
                    }}
                    className="bd txt mt-3 flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm hover:border-red-500"
                  >
                    <Trash2 size={14} /> Remove
                  </button>
                )}
              </div>

              <div className="tile rounded-xl border p-5">
                <div className="flex items-center gap-3">
                  <Shield size={18} className="text-blue-500" />
                  <h4 className="txt text-lg font-bold">VirusTotal API</h4>
                  {state.integrations.virusTotalKey && (
                    <span className="flex items-center gap-1 rounded-md border border-green-600/40 bg-green-600/15 px-2 py-0.5 text-[11px] font-bold text-green-500">
                      <Check size={11} /> CONNECTED
                    </span>
                  )}
                </div>
                <p className="muted mt-1 text-sm">VirusTotal intelligence</p>
                <Field label="API Key">
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input
                        type={showVt ? 'text' : 'password'}
                        value={vt}
                        onChange={(e) => setVt(e.target.value)}
                        placeholder="Enter VirusTotal API key"
                        className={inputCls}
                      />
                      <button onClick={() => setShowVt((s) => !s)} className="muted hover:txt absolute right-3 top-1/2 -translate-y-1/2">
                        {showVt ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    <button
                      onClick={() => {
                        dispatch({ type: 'set-integration', key: 'virusTotalKey', value: vt.trim() })
                        toast({ type: 'success', title: 'API key saved' })
                      }}
                      className="rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500"
                    >
                      Save
                    </button>
                  </div>
                </Field>
              </div>
            </div>
          )}

          {tab === 'privacy' && (
            <div className="space-y-4">
              <div>
                <h3 className="txt text-lg font-semibold">Privacy &amp; Data</h3>
                <p className="muted text-sm">Everything is stored locally in your browser.</p>
              </div>
              <button
                onClick={() => {
                  const a = document.createElement('a')
                  a.href = URL.createObjectURL(new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }))
                  a.download = 'ocean-account-data.json'
                  a.click()
                  URL.revokeObjectURL(a.href)
                  toast({ type: 'success', title: 'Data exported' })
                }}
                className="bd txt flex w-full max-w-sm items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
              >
                <Download size={16} /> Export my data
              </button>
              <button
                onClick={() => {
                  if (confirm('Clear all scan data? This cannot be undone.')) {
                    dispatch({ type: 'clear-data' })
                    toast({ type: 'success', title: 'Data cleared' })
                  }
                }}
                className="flex w-full max-w-sm items-center justify-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-4 py-2.5 text-sm font-medium text-red-500"
              >
                <Trash2 size={16} /> Clear data
              </button>
              <button
                onClick={() => {
                  if (confirm('Reset everything to demo defaults?')) {
                    dispatch({ type: 'reset' })
                    toast({ type: 'success', title: 'Reset complete' })
                  }
                }}
                className="bd txt flex w-full max-w-sm items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
              >
                <RotateCcw size={16} /> Factory reset
              </button>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
