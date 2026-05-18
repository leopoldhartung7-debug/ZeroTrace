import { Routes, Route, Navigate } from 'react-router-dom'
import { StoreProvider } from './store.jsx'
import { ToastProvider } from './components/ui.jsx'
import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Pins from './pages/Pins.jsx'
import Strings from './pages/Strings.jsx'

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
                <Route path="/strings" element={<Strings />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </div>
          </main>
        </div>
      </ToastProvider>
    </StoreProvider>
  )
}
