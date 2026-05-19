import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom'
import { Menu, X } from 'lucide-react'
import { StoreProvider, useStore } from './store.jsx'
import { ToastProvider } from './components/ui.jsx'
import CommandPalette from './components/CommandPalette.jsx'
import Sidebar from './components/Sidebar.jsx'
import Landing from './pages/Landing.jsx'
import Login from './pages/Login.jsx'
import PublicLayout from './components/PublicLayout.jsx'
import Branding from './pages/Branding.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Pins from './pages/Pins.jsx'
import Strings from './pages/Strings.jsx'
import CheatDatabase from './pages/Database.jsx'
import Tools from './pages/Tools.jsx'
import ScanResults from './pages/ScanResults.jsx'
import History from './pages/History.jsx'
import Support from './pages/Support.jsx'
import {
  Leaderboard, Documentation, Pricing, DownloadPage,
  Terms, Privacy, Legal, Changelogs,
} from './pages/resources.jsx'
import SettingsPage from './pages/Settings.jsx'
import Account from './pages/Account.jsx'

function DashboardLayout() {
  const { state } = useStore()
  const loc = useLocation()
  const [navOpen, setNavOpen] = useState(false)

  useEffect(() => {
    setNavOpen(false)
  }, [loc.pathname])

  if (!state.auth) return <Navigate to="/login" replace />
  return (
    <div className="app-bg flex h-screen overflow-hidden">
      {/* Desktop / tablet sidebar */}
      <div className="hidden shrink-0 lg:block">
        <Sidebar />
      </div>

      {/* Mobile drawer */}
      {navOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setNavOpen(false)} />
          <div className="absolute left-0 top-0 h-full">
            <Sidebar />
          </div>
        </div>
      )}

      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Mobile top bar */}
        <div className="bd panel flex shrink-0 items-center gap-3 border-b px-4 py-3 lg:hidden">
          <button
            onClick={() => setNavOpen((o) => !o)}
            className="txt rounded-lg p-1.5"
            aria-label="Menu"
          >
            {navOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          <span className="font-mono text-lg font-bold text-blue-500">{'(*>'}</span>
          <span className="txt text-sm font-semibold">Ocean</span>
        </div>

        <main id="app-main" className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 md:px-10 md:py-10">
            <Outlet />
          </div>
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}

export default function App() {
  return (
    <StoreProvider>
      <ToastProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route element={<PublicLayout />}>
            <Route path="/pricing" element={<Pricing />} />
            <Route path="/docs" element={<Documentation />} />
            <Route path="/download" element={<DownloadPage />} />
            <Route path="/branding" element={<Branding />} />
            <Route path="/terms" element={<Terms />} />
            <Route path="/privacy" element={<Privacy />} />
            <Route path="/legal" element={<Legal />} />
            <Route path="/changelog" element={<Changelogs />} />
          </Route>
          <Route element={<DashboardLayout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/pins" element={<Pins />} />
            <Route path="/scan/:id" element={<ScanResults />} />
            <Route path="/strings" element={<Strings />} />
            <Route path="/database" element={<CheatDatabase />} />
            <Route path="/tools" element={<Tools />} />
            <Route path="/history" element={<History />} />
            <Route path="/support" element={<Support />} />
            <Route path="/resources" element={<Navigate to="/resources/leaderboard" replace />} />
            <Route path="/resources/leaderboard" element={<Leaderboard />} />
            <Route path="/resources/documentation" element={<Documentation />} />
            <Route path="/resources/pricing" element={<Pricing />} />
            <Route path="/resources/download" element={<DownloadPage />} />
            <Route path="/resources/terms" element={<Terms />} />
            <Route path="/resources/privacy" element={<Privacy />} />
            <Route path="/resources/legal" element={<Legal />} />
            <Route path="/resources/changelogs" element={<Changelogs />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/account" element={<Account />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ToastProvider>
    </StoreProvider>
  )
}
