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
      <ChevronRight
        size={16}
        className="text-zinc-600 transition-transform duration-200 group-hover:translate-x-0.5"
      />
    </button>
  )
}

export default function Sidebar() {
  return (
    <aside className="relative z-10 flex h-full w-[280px] shrink-0 flex-col border-r border-ink-700 bg-ink-900/80 backdrop-blur-md">
      <div className="flex items-center gap-3 px-6 py-6">
        <div className="ring-pulse grid h-10 w-10 place-items-center rounded-xl bg-accent shadow-glow">
          <Waves
            size={22}
            className="animate-wave text-white"
            strokeWidth={2.2}
          />
        </div>
        <div className="leading-tight">
          <p className="text-base font-bold text-white">Ocean</p>
          <p className="text-xs text-zinc-500">anticheat.ac</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-4">
        <SectionLabel>Services</SectionLabel>
        <div className="stagger space-y-1">
          {services.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `nav-item group ${isActive ? 'nav-item-active' : ''}`
              }
            >
              <Icon
                size={18}
                strokeWidth={1.8}
                className="transition-transform duration-200 group-hover:scale-110"
              />
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
          {[Wifi, Bell, Globe, Moon].map((Icon, i) => (
            <button
              key={i}
              type="button"
              className="rounded-md p-2 transition-all duration-200 hover:-translate-y-0.5 hover:bg-ink-800 hover:text-accent"
            >
              <Icon size={17} />
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 rounded-xl border border-ink-700 bg-ink-850 p-3 transition-all duration-300 hover:border-accent/40 hover:shadow-glow">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-accent text-sm font-bold text-white shadow-glow">
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
