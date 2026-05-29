import { NavLink } from 'react-router-dom'
import {
  LayoutGrid,
  Pin,
  FileText,
  LifeBuoy,
  BookOpen,
  ChevronRight,
  Wifi,
  Bell,
  Globe,
  Moon,
  Waves,
} from 'lucide-react'
import { currentUser } from '../data.js'

const services = [
  { to: '/', label: 'Dashboard', icon: LayoutGrid, end: true },
  { to: '/pins', label: 'Pins', icon: Pin },
  { to: '/strings', label: 'Strings', icon: FileText },
]

function SectionLabel({ children }) {
  return <p className="caps-label px-3 pb-2 pt-5">{children}</p>
}

function ExternalItem({ icon: Icon, label }) {
  return (
    <button type="button" className="nav-item w-full justify-between">
      <span className="flex items-center gap-3">
        <Icon size={18} strokeWidth={1.8} />
        {label}
      </span>
      <ChevronRight size={16} className="text-zinc-600" />
    </button>
  )
}

export default function Sidebar() {
  return (
    <aside className="flex h-full w-[280px] shrink-0 flex-col border-r border-ink-700 bg-ink-900">
      <div className="flex items-center gap-3 px-6 py-6">
        <div className="grid h-10 w-10 animate-pulse-glow place-items-center rounded-xl bg-accent shadow-glow">
          <Waves size={22} className="text-white" strokeWidth={2.2} />
        </div>
        <div className="leading-tight">
          <p className="text-base font-bold text-white">Ocean</p>
          <p className="text-xs text-zinc-500">anticheat.ac</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-4">
        <SectionLabel>Services</SectionLabel>
        <div className="space-y-1">
          {services.map(({ to, label, icon: Icon, end }, i) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              style={{ animationDelay: `${i * 70}ms` }}
              className={({ isActive }) =>
                `nav-item animate-fade-in-up ${isActive ? 'nav-item-active' : ''}`
              }
            >
              <Icon size={18} strokeWidth={1.8} />
              {label}
            </NavLink>
          ))}
        </div>

        <SectionLabel>Support</SectionLabel>
        <ExternalItem icon={LifeBuoy} label="Support" />

        <SectionLabel>Others</SectionLabel>
        <ExternalItem icon={BookOpen} label="Resources" />
      </nav>

      <div className="border-t border-ink-700 px-4 py-4">
        <div className="mb-4 flex items-center justify-around text-zinc-500">
          <button type="button" className="rounded-md p-2 transition-all duration-200 hover:scale-110 hover:bg-ink-800 hover:text-zinc-300 active:scale-95">
            <Wifi size={17} />
          </button>
          <button type="button" className="rounded-md p-2 transition-all duration-200 hover:scale-110 hover:bg-ink-800 hover:text-zinc-300 active:scale-95">
            <Bell size={17} />
          </button>
          <button type="button" className="rounded-md p-2 transition-all duration-200 hover:scale-110 hover:bg-ink-800 hover:text-zinc-300 active:scale-95">
            <Globe size={17} />
          </button>
          <button type="button" className="rounded-md p-2 transition-all duration-200 hover:scale-110 hover:bg-ink-800 hover:text-zinc-300 active:scale-95">
            <Moon size={17} />
          </button>
        </div>

        <div className="flex items-center gap-3 rounded-xl border border-ink-700 bg-ink-850 p-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-accent text-sm font-bold text-white">
            {currentUser.initial}
          </div>
          <div className="min-w-0 leading-tight">
            <p className="truncate text-sm font-semibold text-white">
              {currentUser.name}
            </p>
            <p className="truncate text-xs text-zinc-500">{currentUser.email}</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
