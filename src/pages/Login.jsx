import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LogIn, Eye, EyeOff, Fingerprint } from 'lucide-react'
import { useStore } from '../store.jsx'
import { useToast } from '../components/ui.jsx'

export default function Login() {
  const nav = useNavigate()
  const { dispatch } = useStore()
  const toast = useToast()
  const [show, setShow] = useState(false)
  const [form, setForm] = useState({ id: '', pw: '' })

  const ADMIN = { user: 'admin', email: 'admin@anticheat.ac', pass: 'OceanAdmin1' }

  const enterDashboard = (method) => {
    dispatch({ type: 'login' })
    toast({ type: 'success', title: 'Welcome back', body: method ? `Signed in with ${method}` : 'Signed in as admin' })
    nav('/dashboard')
  }

  const submitCredentials = () => {
    const id = form.id.trim().toLowerCase()
    if ((id === ADMIN.user || id === ADMIN.email) && form.pw === ADMIN.pass) {
      enterDashboard(null)
    } else {
      toast({ type: 'error', title: 'Invalid credentials', body: 'Wrong username or password.' })
    }
  }

  const signIn = (method) => enterDashboard(method)

  return (
    <div className="flex min-h-screen items-center justify-center bg-black px-4 py-10 text-white">
      <div
        className="pointer-events-none fixed inset-0"
        style={{ background: 'radial-gradient(60% 50% at 50% 0%, rgba(37,99,235,0.15), transparent 70%)' }}
      />
      <div className="relative w-full max-w-md rounded-2xl border border-white/10 bg-white/[0.02] p-8 md:p-10">
        <div className="flex flex-col items-center">
          <span className="font-mono text-4xl font-bold">{'(*>'}</span>
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
            className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3.5 text-sm placeholder:text-neutral-500 focus:border-blue-500 focus:outline-none"
          />
          <div className="relative">
            <input
              type={show ? 'text' : 'password'}
              value={form.pw}
              onChange={(e) => setForm({ ...form, pw: e.target.value })}
              placeholder="Password"
              className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3.5 pr-12 text-sm placeholder:text-neutral-500 focus:border-blue-500 focus:outline-none"
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
            onClick={() => toast({ type: 'info', title: 'Registration closed', body: 'Use the provided admin credentials to sign in.' })}
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
    </div>
  )
}
