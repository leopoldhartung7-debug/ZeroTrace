import { Routes, Route, Navigate } from 'react-router-dom'
import { StoreProvider } from './store.jsx'
import { ToastProvider } from './components/ui.jsx'
import CommandPalette from './components/CommandPalette.jsx'
import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Pins from './pages/Pins.jsx'
import Strings from './pages/Strings.jsx'
import CheatDatabase from './pages/Database.jsx'
import Tools from './pages/Tools.jsx'
import ScanResults from './pages/ScanResults.jsx'
import History from './pages/History.jsx'
import Support from './pages/Support.jsx'
import Resources from './pages/Resources.jsx'
import SettingsPage from './pages/Settings.jsx'

export default function App() {
  return (
    <StoreProvider>
      <ToastProvider>
        <div className="app-bg flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-6xl px-6 py-10 md:px-10">
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/pins" element={<Pins />} />
                <Route path="/scan/:id" element={<ScanResults />} />
                <Route path="/strings" element={<Strings />} />
                <Route path="/database" element={<CheatDatabase />} />
                <Route path="/tools" element={<Tools />} />
                <Route path="/history" element={<History />} />
                <Route path="/support" element={<Support />} />
                <Route path="/resources" element={<Resources />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </div>
          </main>
          <CommandPalette />
        </div>
      </ToastProvider>
    </StoreProvider>
  )
}
