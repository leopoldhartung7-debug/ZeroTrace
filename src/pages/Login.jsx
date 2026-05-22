import { useEffect, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { LogIn, Eye, EyeOff, Fingerprint, KeyRound, UserPlus } from 'lucide-react'
import Logo from '../components/Logo.jsx'
import { useStore, isBlocked } from '../store.jsx'
import { useToast, Modal } from '../components/ui.jsx'
import { verifyHtml, welcomeHtml } from '../lib/emailTemplates.js'
import { verifyTotp } from '../lib/totp.js'

export default function Login() {
  const nav = useNavigate()
  const loc = useLocation()
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [show, setShow] = useState(false)
  const [registerOpen, setRegisterOpen] = useState(false)
  const [reg, setReg] = useState({ username: '', email: '', pw: '', discordId: '', key: '' })
  const [totpOpen, setTotpOpen] = useState(false)
  const [totpCode, setTotpCode] = useState('')
  const [pendingLogin, setPendingLogin] = useState(null)
  const [verifyStep, setVerifyStep] = useState('form')
  const [pendingUser, setPendingUser] = useState(null)
  const [sentCode, setSentCode] = useState('')
  const [inputCode, setInputCode] = useState('')
  const [checking, setChecking] = useState(false)

  const closeRegister = () => {
    setRegisterOpen(false)
    setVerifyStep('form')
    setPendingUser(null)
    setSentCode('')
    setInputCode('')
    setReg({ username: '', email: '', pw: '', discordId: '', key: '' })
  }

  async function checkMx(domain) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`)
      if (!r.ok) return null
      const j = await r.json()
      if (j.Status !== 0) return false
      return Array.isArray(j.Answer) && j.Answer.length > 0
    } catch {
      return null
    }
  }

  async function sendVerificationCode(email, code, username) {
    const cfg = state.integrations || {}
    if (!cfg.emailJsServiceId || !cfg.emailJsTemplateId || !cfg.emailJsPublicKey) return { ok: false, error: 'EmailJS not configured' }
    const lang = state.settings?.lang || 'en'
    const subject = lang === 'de' ? 'ZeroTrace – E-Mail bestätigen' : 'Verify your ZeroTrace email'
    const message = lang === 'de'
      ? `Hallo ${username || ''}, dein ZeroTrace-Bestätigungscode lautet: ${code}\n\nDieser Code läuft in 15 Minuten ab. Wenn du diese Registrierung nicht angefordert hast, ignoriere diese E-Mail.`
      : `Hi ${username || ''}, your ZeroTrace verification code is: ${code}\n\nThe code expires in 15 minutes. If you did not request this, you can ignore this email.`
    try {
      const resp = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id: cfg.emailJsServiceId,
          template_id: cfg.emailJsTemplateId,
          user_id: cfg.emailJsPublicKey,
          template_params: {
            to_email: email,
            email,
            to_name: username || '',
            subject,
            message,
            message_html: verifyHtml({ username: username || '', code }, lang),
          },
        }),
      })
      if (resp.ok) return { ok: true }
      const text = await resp.text().catch(() => '')
      return { ok: false, error: `HTTP ${resp.status}: ${text || 'unknown error'}` }
    } catch (e) {
      return { ok: false, error: e.message || 'Network error' }
    }
  }

  async function sendWelcomeMail(email, username) {
    const cfg = state.integrations || {}
    if (!cfg.emailJsServiceId || !cfg.emailJsTemplateId || !cfg.emailJsPublicKey) return false
    const de = (state.settings?.lang || 'en') === 'de'
    const subject = de
      ? 'Willkommen bei ZeroTrace'
      : 'Welcome to ZeroTrace'
    const message = de
      ? `Hallo ${username},\n\n` +
        `herzlich willkommen bei ZeroTrace und vielen Dank, dass du dich für unser Tool entschieden hast.\n\n` +
        `Dein Konto wurde erfolgreich erstellt und mit deinem Lizenz-Key verknüpft. Du kannst dich jetzt im Dashboard anmelden und sofort loslegen — Pins erstellen, Scans auswerten und verdächtige Discord-Server erkennen.\n\n` +
        `Wenn du Fragen hast oder Hilfe brauchst, melde dich gerne über die Support-Seite.\n\n` +
        `— Das ZeroTrace-Team`
      : `Hi ${username},\n\n` +
        `welcome to ZeroTrace, and thank you for choosing our tool.\n\n` +
        `Your account has been created and bound to your license key. You can sign in to the dashboard right away — create pins, review scans and surface suspicious Discord servers.\n\n` +
        `If you ever need a hand, reach out via the Support page.\n\n` +
        `— The ZeroTrace team`
    try {
      const resp = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id: cfg.emailJsServiceId,
          template_id: cfg.emailJsTemplateId,
          user_id: cfg.emailJsPublicKey,
          template_params: {
            to_email: email,
            subject,
            message,
            message_html: welcomeHtml({ username }, de ? 'de' : 'en'),
          },
        }),
      })
      return resp.ok
    } catch {
      return false
    }
  }

  const finalizeRegistration = (user) => {
    dispatch({ type: 'register-user', user })
    dispatch({ type: 'login', role: 'analyst', userId: user.id })
    toast({ type: 'success', title: 'Account created', body: `Welcome, ${user.username}` })
    // Fire-and-forget welcome email (only when EmailJS is configured).
    sendWelcomeMail(user.email, user.username)
    closeRegister()
    nav('/dashboard')
  }

  useEffect(() => {
    const sp = new URLSearchParams(loc.search)
    if (sp.get('register') === '1') setRegisterOpen(true)
  }, [loc.search])
  const [form, setForm] = useState({ id: '', pw: '' })

  const ADMIN = { user: 'admin', email: 'admin@anticheat.ac', pass: 'ZeroTraceAdmin1' }
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
    const att = state.security?.attempts?.[id]
    if (att && att.lockedUntil && Date.now() < att.lockedUntil) {
      const minLeft = Math.ceil((att.lockedUntil - Date.now()) / 60000)
      toast({
        type: 'error',
        title: 'Too many attempts',
        body: `This account is locked for ${minLeft} more minute(s).`,
      })
      return
    }
    const wrong = () =>
      dispatch({ type: 'record-login-attempt', id, kind: 'fail' })
    const ok = () =>
      dispatch({ type: 'record-login-attempt', id, kind: 'success' })
    if ((id === ADMIN.user || id === ADMIN.email) && form.pw === ADMIN.pass) {
      ok()
      const secret = state.security?.totpSecret
      if (secret) {
        setPendingLogin({ role: 'admin' })
        setTotpCode('')
        setTotpOpen(true)
        return
      }
      enterDashboard('admin', null)
      return
    }
    if ((id === ANALYST.user || id === ANALYST.email) && form.pw === ANALYST.pass) {
      ok()
      enterDashboard('analyst', null)
      return
    }
    const isEmail = id.includes('@')
    const user = (state.users || []).find((u) =>
      isEmail ? (u.email || '').toLowerCase() === id : (u.username || '').toLowerCase() === id,
    )
    if (!user) {
      const wasDeleted = (state.deletedAccounts || []).some((d) =>
        isEmail ? (d.email || '').toLowerCase() === id : (d.username || '').toLowerCase() === id,
      )
      wrong()
      if (wasDeleted) {
        toast({
          type: 'error',
          title: 'Your account was removed by an admin',
          body: 'The license key tied to this account was deleted. You can register a new account with the same details, but you will need a new key from an admin.',
        })
      } else {
        toast({
          type: 'error',
          title: isEmail ? 'Email not found' : 'Username not found',
          body: 'No account is registered with these details.',
        })
      }
      return
    }
    if (user.pass !== form.pw) {
      wrong()
      toast({ type: 'error', title: 'Wrong password', body: 'The password does not match this account.' })
      return
    }
    if (user.suspended) {
      wrong()
      toast({
        type: 'error',
        title: 'Account suspended',
        body: 'Your account has been suspended by an administrator. Contact support.',
      })
      return
    }
    ok()
    const key = (state.licenseKeys || []).find((k) => k.key === user.key)
    const expired = !key || key.status === 'Revoked' ||
      (key.expiresAt && Date.now() > key.expiresAt)
    if (expired) {
      toast({ type: 'error', title: 'License key expired', body: 'Contact an admin for a new key.' })
      dispatch({
        type: 'add-notification',
        title: 'Login blocked — key expired',
        body: `${user.username} tried to sign in with an expired/revoked key (${user.key}).`,
        ownerId: 'admin',
      })
      if (key) dispatch({ type: 'mark-key-expired-notified', id: key.id })
      return
    }
    dispatch({ type: 'login', role: 'analyst', userId: user.id })
    toast({ type: 'success', title: 'Welcome back', body: `Signed in as ${user.username}` })
    if (user.force2FASetup) {
      toast({
        type: 'info',
        title: '2FA setup required',
        body: 'Your administrator requires you to enable 2FA. Redirecting to settings…',
      })
      nav('/settings?tab=security')
      return
    }
    if (user.forceResetPassword) {
      toast({
        type: 'info',
        title: 'Password change required',
        body: 'Please update your password in the account settings.',
      })
      nav('/account')
      return
    }
    nav('/dashboard')
  }

  const signIn = (method) => enterDashboard('analyst', method)

  const submitRegister = async () => {
    const username = reg.username.trim()
    const email = reg.email.trim().toLowerCase()
    const pw = reg.pw
    const discordId = reg.discordId.trim()
    const keyCode = reg.key.trim().toUpperCase()
    if (!username || !email) return toast({ type: 'error', title: 'Username and email required' })
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return toast({ type: 'error', title: 'Invalid email', body: 'That does not look like a valid email address.' })
    if (pw.length < 6) return toast({ type: 'error', title: 'Password too short', body: 'At least 6 characters.' })
    if (!/^\d{17,20}$/.test(discordId))
      return toast({ type: 'error', title: 'Invalid Discord ID', body: '17–20 digits.' })
    if (!keyCode) return toast({ type: 'error', title: 'License key required' })
    const blocked = isBlocked(state, { discordId, email })
    if (blocked) {
      return toast({
        type: 'error',
        title: 'Registration blocked',
        body: `Blocked by ${blocked.kind} blacklist${blocked.reason ? ` — ${blocked.reason}` : ''}.`,
      })
    }
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

    // Real email check #1: the domain must have a mail server (MX record).
    setChecking(true)
    const domain = email.split('@')[1]
    const mx = await checkMx(domain)
    setChecking(false)
    if (mx === false) {
      return toast({
        type: 'error',
        title: 'Email not deliverable',
        body: `${domain} has no mail server (no MX record).`,
      })
    }

    const user = {
      id: 'u_' + Date.now().toString(36),
      username, email, pass: pw, discordId,
      key: key.key,
      createdAt: Date.now(),
    }

    // Real email check #2 (when EmailJS is set up): send a 6-digit code.
    const cfg = state.integrations || {}
    const emailJsReady = !!(cfg.emailJsServiceId && cfg.emailJsTemplateId && cfg.emailJsPublicKey)
    if (emailJsReady) {
      const code = String(Math.floor(100000 + Math.random() * 900000))
      setChecking(true)
      const res = await sendVerificationCode(email, code, username)
      setChecking(false)
      if (!res.ok) {
        return toast({
          type: 'error',
          title: 'Could not send verification email',
          body: res.error || 'Check your EmailJS configuration.',
        })
      }
      setSentCode(code)
      setPendingUser(user)
      setInputCode('')
      setVerifyStep('code')
      toast({ type: 'success', title: 'Verification code sent', body: `Check your inbox at ${email}` })
      return
    }

    if (mx === null) {
      toast({
        type: 'info',
        title: 'Email domain not verified',
        body: "Couldn't reach the DNS service — proceeding without domain check.",
      })
    }
    finalizeRegistration(user)
  }

  const submitVerify = () => {
    if (!pendingUser) return
    if (inputCode.trim() !== sentCode) {
      return toast({ type: 'error', title: 'Wrong code', body: 'The verification code does not match.' })
    }
    finalizeRegistration(pendingUser)
  }

  const resendCode = async () => {
    if (!pendingUser) return
    const code = String(Math.floor(100000 + Math.random() * 900000))
    setChecking(true)
    const res = await sendVerificationCode(pendingUser.email, code, pendingUser.username)
    setChecking(false)
    if (!res.ok) return toast({ type: 'error', title: 'Could not resend code', body: res.error })
    setSentCode(code)
    toast({ type: 'success', title: 'Code resent', body: `New code sent to ${pendingUser.email}` })
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
        onClose={closeRegister}
        title={verifyStep === 'code' ? 'Verify your email' : 'Create an account'}
        footer={
          verifyStep === 'code' ? (
            <div className="flex w-full flex-col gap-2 sm:flex-row">
              <button
                onClick={resendCode}
                disabled={checking}
                className="bd txt rounded-lg border px-4 py-2.5 text-sm hover:border-sky-500 disabled:opacity-60"
              >
                Resend code
              </button>
              <button
                onClick={submitVerify}
                disabled={checking || inputCode.length < 6}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
              >
                Verify &amp; finish
              </button>
            </div>
          ) : (
            <button
              onClick={submitRegister}
              disabled={checking}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
            >
              <UserPlus size={16} /> {checking ? 'Checking email…' : 'Create account'}
            </button>
          )
        }
      >
        {verifyStep === 'code' ? (
          <div className="space-y-3 text-sm">
            <p className="muted">
              A 6-digit verification code was sent to <span className="txt">{pendingUser?.email}</span>.
              Enter it below to finish creating your account.
            </p>
            <div>
              <label className="txt mb-1 block text-xs font-medium">Verification code</label>
              <input
                autoFocus
                inputMode="numeric"
                maxLength={6}
                value={inputCode}
                onChange={(e) => setInputCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="bd tile txt w-full rounded-lg border px-3 py-3 text-center font-mono text-lg tracking-[0.4em] focus:outline-none"
              />
            </div>
            <p className="muted text-[11px]">
              Didn't get it? Check spam, or use Resend. EmailJS must be configured under Account → Integrations.
            </p>
          </div>
        ) : (
          <div className="space-y-3 text-sm">
            <p className="muted">
              Bind your account to a license key issued by an admin. The email is checked (MX record)
              and — if EmailJS is set up — a verification code is sent to it.
            </p>
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
        )}
      </Modal>

      <Modal
        open={totpOpen}
        onClose={() => { setTotpOpen(false); setTotpCode(''); setPendingLogin(null) }}
        title="Two-Factor code"
        footer={
          <button
            onClick={async () => {
              const ok = await verifyTotp(state.security?.totpSecret || '', totpCode)
              if (!ok) {
                toast({ type: 'error', title: 'Wrong code', body: 'The code does not match.' })
                return
              }
              const role = pendingLogin?.role || 'admin'
              setTotpOpen(false)
              setTotpCode('')
              setPendingLogin(null)
              enterDashboard(role, null)
            }}
            disabled={totpCode.length < 6}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
          >
            Verify &amp; sign in
          </button>
        }
      >
        <div className="space-y-3 text-sm">
          <p className="muted">Enter the 6-digit code from your authenticator app.</p>
          <input
            autoFocus
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder="123456"
            className="bd tile txt w-full rounded-lg border px-3 py-3 text-center font-mono text-lg tracking-[0.4em] focus:outline-none"
          />
        </div>
      </Modal>
    </div>
  )
}
