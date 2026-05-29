import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'

export default function Layout() {
  const location = useLocation()
  return (
    <div className="flex h-screen w-full overflow-hidden bg-ink-950">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        {/* Re-key on route change so each page fades in fresh */}
        <div
          key={location.pathname}
          className="mx-auto max-w-6xl animate-fade-in px-8 py-10"
        >
          <Outlet />
        </div>
      </main>
    </div>
  )
}
