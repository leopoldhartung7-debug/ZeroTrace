import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'

export default function Layout() {
  const location = useLocation()
  return (
    <div className="relative flex h-screen w-full overflow-hidden bg-ink-950">
      <div className="pointer-events-none absolute inset-0 bg-aurora" />
      <div className="pointer-events-none absolute inset-0 grid-bg" />
      <Sidebar />
      <main className="relative flex-1 overflow-y-auto">
        <div
          key={location.pathname}
          className="mx-auto max-w-6xl animate-fade-up px-8 py-10"
        >
          <Outlet />
        </div>
      </main>
    </div>
  )
}
