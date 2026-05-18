import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { UserCog, ShieldCheck, LogOut, Link2, KeyRound } from 'lucide-react'
import { PageHeader, Card, Field } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

function Row({ title, desc, children }) {
  return (
    <div className="bd flex flex-col gap-3 border-b py-5 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="txt text-sm font-medium">{title}</p>
        <p className="muted mt-0.5 text-xs">{desc}</p>
      </div>
      <div className="sm:w-64">{children}</div>
    </div>
  )
}

export default function Account() {
  const nav = useNavigate()
  const toast = useToast()
  const { dispatch } = useStore()
  const [profile, setProfile] = useState({ name: 'Ham', email: 'ham@anticheat.ac' })
  const [pw, setPw] = useState({ cur: '', next: '', confirm: '' })

  const saveProfile = () => toast({ type: 'success', title: 'Profile saved', body: profile.name })
  const changePw = () => {
    if (!pw.cur || !pw.next) return toast({ type: 'error', title: 'Fill in all fields' })
    if (pw.next !== pw.confirm) return toast({ type: 'error', title: 'Passwords do not match' })
    setPw({ cur: '', next: '', confirm: '' })
    toast({ type: 'success', title: 'Password changed' })
  }

  return (
    <div>
      <PageHeader
        icon={UserCog}
        kicker="Your account"
        title="Account Settings"
        subtitle="Manage your profile, security and connected accounts. (Dashboard & tool options are under Settings.)"
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
            <UserCog size={18} className="text-blue-500" /> Profile
          </h3>
          <p className="muted mb-3 text-sm">Your public identity.</p>
          <div className="space-y-4 py-2">
            <Field label="Display name">
              <input
                value={profile.name}
                onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
              />
            </Field>
            <Field label="Email">
              <input
                value={profile.email}
                onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
              />
            </Field>
            <button
              onClick={saveProfile}
              className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Save profile
            </button>
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
            <KeyRound size={18} className="text-blue-500" /> Security
          </h3>
          <p className="muted mb-3 text-sm">Change your password.</p>
          <div className="space-y-3 py-2">
            <input
              type="password"
              placeholder="Current password"
              value={pw.cur}
              onChange={(e) => setPw({ ...pw, cur: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
            />
            <input
              type="password"
              placeholder="New password"
              value={pw.next}
              onChange={(e) => setPw({ ...pw, next: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
            />
            <input
              type="password"
              placeholder="Confirm new password"
              value={pw.confirm}
              onChange={(e) => setPw({ ...pw, confirm: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none"
            />
            <button
              onClick={changePw}
              className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500"
            >
              Change password
            </button>
          </div>
        </Card>
      </div>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
          <Link2 size={18} className="text-blue-500" /> Connected accounts
        </h3>
        <p className="muted mb-2 text-sm">Link external accounts to your Ocean account.</p>
        <Row title="Discord" desc="Used for support and community features">
          <button
            onClick={() => toast({ type: 'info', title: 'Discord', body: 'Linking is not available in this demo.' })}
            className="bd txt w-full rounded-lg border px-4 py-2.5 text-sm font-medium hover:border-blue-500"
          >
            Connect Discord
          </button>
        </Row>
        <Row title="Passkey" desc="Sign in without a password">
          <button
            onClick={() => toast({ type: 'info', title: 'Passkey', body: 'Passkey setup is not available in this demo.' })}
            className="bd txt w-full rounded-lg border px-4 py-2.5 text-sm font-medium hover:border-blue-500"
          >
            Add passkey
          </button>
        </Row>
      </Card>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold">
          <ShieldCheck size={18} className="text-blue-500" /> Session
        </h3>
        <Row title="This device" desc="You are signed in on this browser">
          <button
            onClick={() => {
              dispatch({ type: 'logout' })
              nav('/')
            }}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-4 py-2.5 text-sm font-medium text-red-500"
          >
            <LogOut size={16} /> Log out
          </button>
        </Row>
      </Card>
    </div>
  )
}
