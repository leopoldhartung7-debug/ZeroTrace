import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import {
  Search, LayoutGrid, Pin, FileText, Database, Wrench, History,
  LifeBuoy, BookOpen, Settings, Sun, Moon, Wand2,
} from 'lucide-react'
import { useStore } from '../store.jsx'

export default function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [i, setI] = useState(0)
  const nav = useNavigate()
  const { state, dispatch } = useStore()

  useEffect(() => {
    const h = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const commands = useMemo(
    () => [
      { label: 'Go to Dashboard', icon: LayoutGrid, run: () => nav('/dashboard') },
      { label: 'Go to Pins', icon: Pin, run: () => nav('/pins') },
      { label: 'Go to Strings', icon: FileText, run: () => nav('/strings') },
      { label: 'Go to Cheat Database', icon: Database, run: () => nav('/database') },
      { label: 'Go to Forensic Tools', icon: Wrench, run: () => nav('/tools') },
      { label: 'Go to Tool Designer', icon: Wand2, run: () => nav('/designer') },
      { label: 'Go to Activity Log', icon: History, run: () => nav('/history') },
      { label: 'Go to Support', icon: LifeBuoy, run: () => nav('/support') },
      { label: 'Go to Resources', icon: BookOpen, run: () => nav('/resources') },
      { label: 'Go to Settings', icon: Settings, run: () => nav('/settings') },
      {
        label: state.settings.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
        icon: state.settings.theme === 'dark' ? Sun : Moon,
        run: () =>
          dispatch({
            type: 'set-setting',
            key: 'theme',
            value: state.settings.theme === 'dark' ? 'light' : 'dark',
          }),
      },
    ],
    [nav, state.settings.theme, dispatch],
  )

  const filtered = commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase()))

  useEffect(() => setI(0), [q, open])

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-start justify-center p-4 pt-[15vh]">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(false)} />
      <div className="panel relative z-10 w-full max-w-lg overflow-hidden rounded-2xl border shadow-2xl">
        <div className="bd flex items-center gap-3 border-b px-4 py-3">
          <Search size={18} className="muted" />
          <input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') setI((x) => Math.min(filtered.length - 1, x + 1))
              if (e.key === 'ArrowUp') setI((x) => Math.max(0, x - 1))
              if (e.key === 'Enter' && filtered[i]) {
                filtered[i].run()
                setOpen(false)
                setQ('')
              }
            }}
            placeholder="Type a command or search…"
            className="txt flex-1 bg-transparent text-sm focus:outline-none"
          />
          <kbd className="bd muted rounded border px-1.5 py-0.5 text-[10px]">ESC</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.map((c, idx) => (
            <button
              key={c.label}
              onMouseEnter={() => setI(idx)}
              onClick={() => {
                c.run()
                setOpen(false)
                setQ('')
              }}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm ${
                idx === i ? 'bg-blue-600/15 text-blue-400' : 'txt hoverable'
              }`}
            >
              <c.icon size={16} />
              {c.label}
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="muted px-3 py-6 text-center text-sm">No commands found.</p>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}
