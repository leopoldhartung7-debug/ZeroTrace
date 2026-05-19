import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LogIn, Eye, EyeOff, Fingerprint, KeyRound, UserPlus } from 'lucide-react'
import Logo from '../components/Logo.jsx'
import { useStore } from '../store.jsx'
import { useToast, Modal } from '../components/ui.jsx'

export default function Login() {
  const nav = useNavigate()
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [show, setShow] = useState(false)
  const [registerOpen, setRegisterOpen] = useState(false)
  const [reg, setReg] = useState({ username: '', email: '', pw: '', discordId: '', key: '' })
  const [form, setForm] = useState({ id: '', pw: '' })

  const ADMIN = { user: 'admin', email: 'admin@anticheat.ac', pass: 'OceanAdmin1' }
  const ANALYST = { user: 'analyst', email: 'analyst@anticheat.ac', pass: 'ZeroTraceAnalyst1' }

  const enterDashboard = (role, method) => {
    dispatch({ type: 'login', role })
    toast({
      type: 'success',
      title: 'Welcome back',
      body: method ? `Signed in with ${method}` : `Signed in as ${role}`,
    })
    nav('/dashboard')
  }

  const submitCredentials = () => {
    const id = form.id.trim().toLowerCase()
    if ((id === ADMIN.user || id === ADMIN.email) && form.pw === ADMIN.pass) {
      enterDashboard('admin', null)
      return
    }
    if ((id === ANALYST.user || id === ANALYST.email) && form.pw === ANALYST.pass) {
      enterDashboard('analyst', null)
      return
    }
    const user = (state.users || []).find(
      (u) => (u.username || '').toLowerCase() === id || (u.email || '').toLowerCase() === id,
    )
    if (user && user.pass === form.pw) {
      const key = (state.licenseKeys || []).find((k) => k.key === user.key)
      const expired = !key || key.status === 'Revoked' ||
        (key.expiresAt && Date.now() > key.expiresAt)
      if (expired) {
        toast({
          type: 'error',
          title: 'License key expired',
          body: 'Contact an admin for a new key.',
        })
        dispatch({
          type: 'add-notification',
          title: 'Login blocked — key expired',
          body: `${user.username} tried to sign in with an expired/revoked key (${user.key}).`,
        })
        if (key) dispatch({ type: 'mark-key-expired-notified', id: key.id })
        return
      }
      dispatch({ type: 'login', role: 'analyst', userId: user.id })
      toast({ type: 'success', title: 'Welcome back', body: `Signed in as ${user.username}` })
      nav('/dashboard')
      return
    }
    toast({ type: 'error', title: 'Invalid credentials', body: 'Wrong username or password.' })
  }

  const signIn = (method) => enterDashboard('analyst', method)

  const submitRegister = () => {
    const username = reg.username.trim()
    const email = reg.email.trim().toLowerCase()
    const pw = reg.pw
    const discordId = reg.discordId.trim()
    const keyCode = reg.key.trim().toUpperCase()
    if (!username || !email) return toast({ type: 'error', title: 'Username and email required' })
    if (pw.length < 6) return toast({ type: 'error', title: 'Password too short', body: 'At least 6 characters.' })
    if (!/^\d{17,20}$/.test(discordId))
      return toast({ type: 'error', title: 'Invalid Discord ID', body: '17–20 digits.' })
    if (!keyCode) return toast({ type: 'error', title: 'License key required' })
    if ((state.users || []).some(
      (u) => u.email.toLowerCase() === email || u.username.toLowerCase() === username.toLowerCase(),
    )) {
      return toast({ type: 'error', title: 'Account already exists', body: 'Username or email is taken.' })
    }
    const key = (state.licenseKeys || []).find((k) => k.key.toUpperCase() === keyCode)
    if (!key) return toast({ type: 'error', title: 'Unknown key', body: 'No such license key.' })
    if (key.status !== 'Active' || (key.expiresAt && Date.now() > key.expiresAt))
      return toast({ type: 'error', title: 'Key not usable', body: 'Key is revoked or expired.' })
    if (key.usedBy) return toast({ type: 'error', title: 'Key already used', body: 'This key is bound to another account.' })

    const user = {
      id: 'u_' + Date.now().toString(36),
      username,
      email,
      pass: pw,
      discordId,
      key: key.key,
      createdAt: Date.now(),
    }
    dispatch({ type: 'register-user', user })
    dispatch({ type: 'login', role: 'analyst', userId: user.id })
    toast({ type: 'success', title: 'Account created', body: `Welcome, ${username}` })
    setRegisterOpen(false)
    setReg({ username: '', email: '', pw: '', discordId: '', key: '' })
    nav('/dashboard')
  }

  return (
    <div className="force-dark app-bg flex min-h-screen items-center justify-center px-4 py-10 text-white">
      <div
        className="pointer-events-none fixed inset-0"
        style={{ background: 'radial-gradient(60% 50% at 50% 0%, rgba(56,189,248,0.15), transparent 70%)' }}
      />
      <div className="relative w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.02] p-8 md:p-10">
        <div className="flex flex-col items-center">
          <Logo size="lg" sub />
          <h1 className="mt-6 text-3xl font-bold">Login</h1>
          <p className="mt-1 text-sm text-neutral-400">Enter your credentials to access your account</p>
        </div>

        <form
          className="mt-8 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submitCredentials()
          }}
        >
          <input
            value={form.id}
            onChange={(e) => setForm({ ...form, id: e.target.value })}
            placeholder="Email or Username"
            className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3.5 text-sm placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none"
          />
          <div className="relative">
            <input
              type={show ? 'text' : 'password'}
              value={form.pw}
              onChange={(e) => setForm({ ...form, pw: e.target.value })}
              placeholder="Password"
              className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3.5 pr-12 text-sm placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShow((s) => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-white"
            >
              {show ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => toast({ type: 'info', title: 'Password reset', body: 'Contact support to reset your password.' })}
              className="text-sm text-neutral-400 hover:text-white"
            >
              Forgot your password?
            </button>
          </div>

          <button
            type="submit"
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-white py-3.5 text-sm font-semibold text-black transition-opacity hover:opacity-90"
          >
            <LogIn size={17} /> Login
          </button>
        </form>

        <div className="my-6 flex items-center gap-4">
          <span className="h-px flex-1 bg-white/10" />
          <span className="text-xs font-semibold tracking-widest text-neutral-500">OR CONTINUE WITH</span>
          <span className="h-px flex-1 bg-white/10" />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <button
            onClick={() => signIn('Discord')}
            className="flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] py-3 text-sm font-medium hover:bg-white/[0.06]"
          >
            <span className="text-[#5865F2]">◆</span> Discord
          </button>
          <button
            onClick={() => signIn('Passkey')}
            className="flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] py-3 text-sm font-medium hover:bg-white/[0.06]"
          >
            <Fingerprint size={17} /> Passkey
          </button>
        </div>

        <p className="mt-7 text-center text-sm text-neutral-400">
          Don't have an account?{' '}
          <button
            onClick={() => setRegisterOpen(true)}
            className="text-white underline-offset-2 hover:underline"
          >
            Register
          </button>
        </p>
        <p className="mt-4 rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-center text-[11px] leading-relaxed text-neutral-500">
          Demo logins — Admin: <span className="text-neutral-300">admin / OceanAdmin1</span>
          {' · '}Analyst: <span className="text-neutral-300">analyst / ZeroTraceAnalyst1</span>
        </p>
        <p className="mt-3 text-center text-xs text-neutral-500">
          Need help?{' '}
          <button
            onClick={() => toast({ type: 'info', title: 'Support', body: 'Open a ticket from the dashboard Support page.' })}
            className="text-neutral-300 hover:text-white"
          >
            Contact support
          </button>
        </p>
      </div>

      <Modal
        open={registerOpen}
        onClose={() => setRegisterOpen(false)}
        title="Create an account"
        footer={
          <button
            onClick={submitRegister}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-500"
          >
            <UserPlus size={16} /> Create account
          </button>
        }
      >
        <div className="space-y-3 text-sm">
          <p className="muted">Bind your account to a license key issued by an admin.</p>
          <div>
            <label className="txt mb-1 block text-xs font-medium">Username</label>
            <input
              autoFocus
              value={reg.username}
              onChange={(e) => setReg({ ...reg, username: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-3 py-2.5 focus:outline-none"
            />
          </div>
          <div>
            <label className="txt mb-1 block text-xs font-medium">Email</label>
            <input
              type="email"
              value={reg.email}
              onChange={(e) => setReg({ ...reg, email: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-3 py-2.5 focus:outline-none"
            />
          </div>
          <div>
            <label className="txt mb-1 block text-xs font-medium">Password</label>
            <input
              type="password"
              value={reg.pw}
              onChange={(e) => setReg({ ...reg, pw: e.target.value })}
              className="bd tile txt w-full rounded-lg border px-3 py-2.5 focus:outline-none"
            />
          </div>
          <div>
            <label className="txt mb-1 block text-xs font-medium">Discord ID</label>
            <input
              value={reg.discordId}
              onChange={(e) => setReg({ ...reg, discordId: e.target.value.replace(/\D/g, '') })}
              placeholder="e.g. 145481082291945490"
              className="bd tile txt w-full rounded-lg border px-3 py-2.5 font-mono focus:outline-none"
            />
          </div>
          <div>
            <label className="txt mb-1 flex items-center gap-2 text-xs font-medium">
              <KeyRound size={13} /> License key
            </label>
            <input
              value={reg.key}
              onChange={(e) => setReg({ ...reg, key: e.target.value.toUpperCase() })}
              placeholder="ZT-XXXX-XXXX-XXXX-XXXX"
              className="bd tile txt w-full rounded-lg border px-3 py-2.5 font-mono focus:outline-none"
            />
          </div>
        </div>
      </Modal>
    </div>
  )
}
