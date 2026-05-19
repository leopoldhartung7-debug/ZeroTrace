import { Outlet, useNavigate } from 'react-router-dom'
import { Globe } from 'lucide-react'
import { useStore } from '../store.jsx'
import Logo from './Logo.jsx'
import { useToast } from './ui.jsx'

const NAV = [
  { label: 'Features', to: '/#features' },
  { label: 'Pricing', to: '/pricing' },
  { label: 'Docs', to: '/docs' },
  { label: 'Branding', to: '/branding' },
  { label: 'FAQ', to: '/#faq' },
  { label: 'Download', to: '/download' },
  { label: 'Discord', to: 'discord' },
]

export function PublicHeader() {
  const nav = useNavigate()
  const { state } = useStore()
  const toast = useToast()

  const onNav = (to) => {
    if (to === 'discord') toast({ type: 'info', title: 'Discord', body: 'Community link is not configured in this demo.' })
    else if (to.startsWith('/#')) nav('/')
    else nav(to)
  }

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between border-b border-white/5 bg-black/80 px-6 py-5 backdrop-blur md:px-12">
      <button onClick={() => nav('/')} className="flex items-center gap-3">
        <Logo size="md" />
      </button>
      <nav className="hidden items-center gap-7 lg:flex">
        {NAV.map((n) => (
          <button key={n.label} onClick={() => onNav(n.to)} className="text-sm text-neutral-400 transition-colors hover:text-white">
            {n.label}
          </button>
        ))}
      </nav>
      <div className="flex items-center gap-4">
        <Globe size={18} className="hidden text-neutral-500 sm:block" />
        {state.auth ? (
          <button onClick={() => nav('/dashboard')} className="flex items-center gap-3">
            <span className="text-sm text-neutral-300 hover:text-white">Dashboard</span>
            <span className="flex h-9 w-9 items-center justify-center rounded-full border border-white/15 bg-white/[0.05] text-sm font-semibold text-white">
              H
            </span>
          </button>
        ) : (
          <>
            <button onClick={() => nav('/login')} className="text-sm text-neutral-300 transition-colors hover:text-white">
              Login
            </button>
            <button onClick={() => nav('/login')} className="rounded-lg bg-teal-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-teal-500">
              Sign Up
            </button>
          </>
        )}
      </div>
    </header>
  )
}

export default function PublicLayout() {
  return (
    <div className="force-dark min-h-screen bg-black text-white">
      <PublicHeader />
      <main className="mx-auto max-w-6xl px-6 py-12 md:px-12">
        <Outlet />
      </main>
      <footer className="border-t border-white/10 px-6 py-8 text-center text-sm text-neutral-600 md:px-12">
        © 2026 ZeroTrace Anti-Cheat — anticheat.ac
      </footer>
    </div>
  )
}
