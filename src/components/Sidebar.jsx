import { NavLink } from 'react-router-dom'
import {
  LayoutGrid,
  Pin,
  FileText,
  LifeBuoy,
  BookText,
  Wifi,
  Bell,
  Globe,
  Moon,
  ChevronRight,
  ChevronsUpDown,
} from 'lucide-react'

const services = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutGrid },
  { to: '/pins', label: 'Pins', icon: Pin },
  { to: '/strings', label: 'Strings', icon: FileText },
]

function SectionLabel({ children }) {
  return <p className="caps-label mb-2 mt-6 px-3">{children}</p>
}

function ExpandableItem({ icon: Icon, label }) {
  return (
    <button className="flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium text-neutral-400 transition-colors hover:bg-white/[0.03] hover:text-neutral-200">
      <span className="flex items-center gap-3">
        <Icon size={18} />
        {label}
      </span>
      <ChevronRight size={16} className="text-neutral-600" />
    </button>
  )
}

export default function Sidebar() {
  return (
    <aside className="flex w-[280px] shrink-0 flex-col border-r border-line bg-ink-950">
      <div className="flex items-center gap-3 px-6 py-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600 font-mono text-sm font-bold text-white">
          {'(*>'}
        </div>
        <div>
          <p className="text-[15px] font-semibold leading-tight text-white">Ocean</p>
          <p className="text-xs tracking-wide text-neutral-500">anticheat.ac</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3">
        <SectionLabel>Services</SectionLabel>
        {services.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 shadow-[inset_0_0_0_1px_rgba(59,130,246,0.18)]'
                  : 'text-neutral-400 hover:bg-white/[0.03] hover:text-neutral-200'
              }`
            }
          >
            <Icon size={18} />
            {label}
          </NavLink>
        ))}

        <SectionLabel>Support</SectionLabel>
        <ExpandableItem icon={LifeBuoy} label="Support" />

        <SectionLabel>Others</SectionLabel>
        <ExpandableItem icon={BookText} label="Resources" />
      </nav>

      <div className="border-t border-line px-4 py-4">
        <div className="flex items-center gap-6 px-2 pb-4 text-neutral-500">
          <Wifi size={16} className="text-green-500" />
          <Bell size={16} className="transition-colors hover:text-neutral-300" />
          <Globe size={16} className="transition-colors hover:text-neutral-300" />
          <Moon size={16} className="transition-colors hover:text-neutral-300" />
        </div>
        <button className="flex w-full items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-white/[0.03]">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-neutral-800 text-sm font-semibold text-neutral-300">
            H
          </div>
          <div className="flex-1 text-left">
            <p className="text-sm font-medium leading-tight text-white">Ham</p>
            <p className="text-xs text-neutral-500">ham@anticheat.ac</p>
          </div>
          <ChevronsUpDown size={16} className="text-neutral-600" />
        </button>
      </div>
    </aside>
  )
}
