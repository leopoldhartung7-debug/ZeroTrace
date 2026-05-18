import { useRef, useState } from 'react'
import { Settings as Cog, Sun, Moon, Download, Upload, Trash2, RotateCcw, SlidersHorizontal, Wand2 } from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { Select, useToast } from '../components/ui.jsx'
import { useStore, ALL_GAMES } from '../store.jsx'
import ToolDesigner from './ToolDesigner.jsx'

function Row({ title, desc, children }) {
  return (
    <div className="bd flex flex-col gap-3 border-b py-5 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="txt text-sm font-medium">{title}</p>
        <p className="muted mt-0.5 text-xs">{desc}</p>
      </div>
      <div className="sm:w-56">{children}</div>
    </div>
  )
}

function General() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const fileRef = useRef(null)

  const exportData = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }))
    a.download = 'ocean-ac-backup.json'
    a.click()
    URL.revokeObjectURL(a.href)
    toast({ type: 'success', title: 'Backup exported' })
  }

  const importData = (file) => {
    const fr = new FileReader()
    fr.onload = () => {
      try {
        dispatch({ type: 'import-state', state: JSON.parse(fr.result) })
        toast({ type: 'success', title: 'Backup restored' })
      } catch {
        toast({ type: 'error', title: 'Invalid backup file' })
      }
    }
    fr.readAsText(file)
  }

  return (
    <div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-1 text-lg font-semibold">Appearance</h3>
          <p className="muted mb-2 text-sm">Theme and language settings.</p>
          <Row title="Theme" desc="Dark or light interface">
            <button
              onClick={() =>
                dispatch({ type: 'set-setting', key: 'theme', value: state.settings.theme === 'dark' ? 'light' : 'dark' })
              }
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
            >
              {state.settings.theme === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
              {state.settings.theme === 'dark' ? 'Dark' : 'Light'}
            </button>
          </Row>
          <Row title="Language" desc="Interface language">
            <Select
              value={state.settings.lang}
              onChange={(v) => dispatch({ type: 'set-setting', key: 'lang', value: v })}
              options={[
                { value: 'en', label: 'English' },
                { value: 'de', label: 'Deutsch' },
              ]}
            />
          </Row>
          <Row title="Default Game" desc="Pre-selected when creating pins">
            <Select
              value={state.settings.defaultGame}
              onChange={(v) => dispatch({ type: 'set-setting', key: 'defaultGame', value: v })}
              options={ALL_GAMES.map((g) => ({ value: g, label: g }))}
            />
          </Row>
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-1 text-lg font-semibold">Data Management</h3>
          <p className="muted mb-2 text-sm">Everything is stored locally in your browser.</p>
          <Row title="Export backup" desc="Download all data as JSON">
            <button onClick={exportData} className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium">
              <Download size={16} /> Export
            </button>
          </Row>
          <Row title="Import backup" desc="Restore from a JSON file">
            <input ref={fileRef} type="file" accept="application/json" className="hidden" onChange={(e) => e.target.files[0] && importData(e.target.files[0])} />
            <button onClick={() => fileRef.current?.click()} className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium">
              <Upload size={16} /> Import
            </button>
          </Row>
          <Row title="Clear data" desc="Wipe pins, scans and files (keeps settings)">
            <button
              onClick={() => {
                if (confirm('Clear all scan data? This cannot be undone.')) {
                  dispatch({ type: 'clear-data' })
                  toast({ type: 'success', title: 'Data cleared' })
                }
              }}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-red-600/30 bg-red-600/10 px-4 py-2.5 text-sm font-medium text-red-500"
            >
              <Trash2 size={16} /> Clear
            </button>
          </Row>
          <Row title="Factory reset" desc="Restore demo seed data">
            <button
              onClick={() => {
                if (confirm('Reset everything to demo defaults?')) {
                  dispatch({ type: 'reset' })
                  toast({ type: 'success', title: 'Reset complete' })
                }
              }}
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium"
            >
              <RotateCcw size={16} /> Reset
            </button>
          </Row>
        </Card>
      </div>

      <Card className="mt-6 p-6">
        <h3 className="txt mb-3 text-lg font-semibold">About</h3>
        <div className="muted grid gap-2 text-sm sm:grid-cols-3">
          <p>Version <span className="txt">2.0.0</span></p>
          <p>Build <span className="txt">client-side SPA</span></p>
          <p>Storage <span className="txt">localStorage</span></p>
        </div>
      </Card>
    </div>
  )
}

export default function SettingsPage() {
  const [tab, setTab] = useState('General')
  return (
    <div>
      <PageHeader icon={Cog} kicker="Preferences & data" title="Settings" subtitle="Configure the dashboard, manage data, and design the scanner GUI." />
      <Tabs
        tabs={[
          { label: 'General', icon: SlidersHorizontal },
          { label: 'Tool Designer', icon: Wand2 },
        ]}
        active={tab}
        onChange={setTab}
      />
      <div className="mt-8">
        {tab === 'General' ? <General /> : <ToolDesigner embedded />}
      </div>
    </div>
  )
}
