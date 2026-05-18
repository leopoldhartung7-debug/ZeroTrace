import { useMemo, useState } from 'react'
import {
  FileText,
  ShieldCheck,
  Search,
  Upload as UploadIcon,
  Info,
  Code2,
  FileWarning,
  ScanLine,
  ChevronDown,
  Shield,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'

function Dropzone({ hint }) {
  return (
    <div className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-line py-16 text-center transition-colors hover:border-neutral-700">
      <UploadIcon size={32} className="text-neutral-500" />
      <p className="mt-4 text-base font-medium text-neutral-300">
        Drag and drop or click
      </p>
      <p className="mt-1 text-xs text-neutral-600">{hint}</p>
    </div>
  )
}

function ModeAndStatus({ statusRows }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="card p-6">
        <p className="caps-label">Select File Mode</p>
        <h3 className="mt-1 text-lg font-semibold text-white">Working Mode</h3>
        <button className="mt-4 flex w-full items-center justify-between rounded-lg border border-line bg-ink-950 px-4 py-3 text-sm text-neutral-200 hover:border-neutral-700">
          <span className="flex items-center gap-2">
            <Shield size={16} className="text-neutral-400" />
            Personal
          </span>
          <ChevronDown size={16} className="text-neutral-500" />
        </button>
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-line bg-white/[0.03] px-4 py-3 text-sm font-medium text-neutral-200">
          <Shield size={16} className="text-neutral-400" />
          Personal Mode
        </div>
      </div>

      <div className="card p-6">
        <p className="caps-label">Current Status</p>
        <h3 className="mt-1 text-lg font-semibold text-white">Status</h3>
        <div className="mt-5 space-y-4">
          {statusRows.map((row) => (
            <div
              key={row.label}
              className="flex items-center justify-between text-sm"
            >
              <span className="text-neutral-400">{row.label}</span>
              <span className="font-semibold text-neutral-200">{row.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StringExtractor() {
  const [tab, setTab] = useState('Upload')
  return (
    <div className="mt-8">
      <Tabs
        tabs={[
          { label: 'Upload', icon: UploadIcon },
          { label: 'Results', icon: FileText },
        ]}
        active={tab}
        onChange={setTab}
      />
      <div className="mt-8 rounded-2xl border border-line bg-ink-900/40 p-6 md:p-8">
        {tab === 'Upload' ? (
          <>
            <p className="caps-label">Extractor</p>
            <h3 className="mt-1 text-xl font-semibold text-white">Upload File</h3>
            <p className="mt-1 text-sm text-neutral-500">
              Upload a file to analyze
            </p>
            <div className="mt-6">
              <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
            </div>
            <div className="mt-6 flex justify-end">
              <button
                disabled
                className="cursor-not-allowed rounded-lg bg-ink-800 px-5 py-2.5 text-sm font-medium text-neutral-500"
              >
                Analyze File
              </button>
            </div>
          </>
        ) : (
          <div className="py-16 text-center text-sm text-neutral-500">
            No analysis results yet.
          </div>
        )}
      </div>
    </div>
  )
}

function PresenceDetection() {
  const [tab, setTab] = useState('Upload')
  return (
    <div className="mt-8 space-y-8">
      <ModeAndStatus
        statusRows={[
          { label: 'Detection Files:', value: '0' },
          { label: 'Last Updated:', value: 'Never' },
        ]}
      />

      <div>
        <Tabs
          tabs={[
            { label: 'Upload', icon: UploadIcon },
            { label: 'My Files', icon: Info },
          ]}
          active={tab}
          onChange={setTab}
        />
        <div className="mt-8 rounded-2xl border border-line bg-ink-900/40 p-6 md:p-8">
          {tab === 'Upload' ? (
            <>
              <p className="caps-label">Upload for presence detection</p>
              <h3 className="mt-1 text-xl font-semibold text-white">
                Upload File
              </h3>
              <div className="mt-5 flex items-center gap-2 rounded-lg border border-line bg-white/[0.03] px-4 py-3 text-sm font-medium text-neutral-200">
                <Shield size={16} className="text-neutral-400" />
                Uploading to Personal
              </div>
              <div className="mt-6">
                <label className="mb-2 block text-sm font-medium text-neutral-300">
                  Client Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. Vape V4"
                  className="w-full rounded-lg border border-line bg-ink-950 px-4 py-3 text-sm text-neutral-200 placeholder:text-neutral-600 focus:border-neutral-700 focus:outline-none"
                />
              </div>
              <div className="mt-6">
                <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-sm text-neutral-500">
              No detection files uploaded.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function CodeEditor({ value, onChange }) {
  const lineCount = useMemo(
    () => Math.max(value.split('\n').length, 1),
    [value],
  )
  return (
    <div className="flex overflow-hidden rounded-lg border border-line bg-ink-950 font-mono text-sm">
      <div className="select-none border-r border-line bg-ink-900/60 px-3 py-3 text-right text-neutral-600">
        {Array.from({ length: Math.max(lineCount, 16) }, (_, i) => (
          <div key={i} className="leading-6">
            {i + 1}
          </div>
        ))}
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        placeholder="rule example { strings: ... condition: ... }"
        className="min-h-[420px] flex-1 resize-none bg-transparent p-3 leading-6 text-neutral-200 placeholder:text-neutral-700 focus:outline-none"
      />
    </div>
  )
}

function SuspiciousDetection() {
  const [tab, setTab] = useState('YARA Rules')
  const [rule, setRule] = useState('')
  return (
    <div className="mt-8 space-y-8">
      <ModeAndStatus
        statusRows={[
          { label: 'YARA Rule:', value: 'Not configured' },
          { label: 'Suspicious Files:', value: '0' },
        ]}
      />

      <div>
        <Tabs
          tabs={[
            { label: 'YARA Rules', icon: Code2 },
            { label: 'Suspicious Files', icon: FileWarning },
            { label: 'Scan', icon: ScanLine },
          ]}
          active={tab}
          onChange={setTab}
        />
        <div className="mt-8 rounded-2xl border border-line bg-ink-900/40 p-6 md:p-8">
          {tab === 'YARA Rules' && (
            <>
              <p className="caps-label">Write YARA Rules</p>
              <h3 className="mt-1 text-xl font-semibold text-white">
                Rule Editor
              </h3>
              <p className="mt-4 mb-2 text-sm text-neutral-500">New Rule</p>
              <CodeEditor value={rule} onChange={setRule} />
              <div className="mt-6 flex justify-end gap-3">
                <button className="rounded-lg border border-line px-5 py-2.5 text-sm font-medium text-neutral-300 hover:border-neutral-700">
                  Validate
                </button>
                <button className="rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90">
                  Save Rule
                </button>
              </div>
            </>
          )}
          {tab === 'Suspicious Files' && (
            <div className="py-16 text-center text-sm text-neutral-500">
              No suspicious files detected.
            </div>
          )}
          {tab === 'Scan' && (
            <div className="py-16 text-center text-sm text-neutral-500">
              Configure a YARA rule to start scanning.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Strings() {
  const [mode, setMode] = useState('String Extractor')

  return (
    <div>
      <p className="caps-label">Upload and analyze files for string detection.</p>
      <h1 className="mt-3 text-4xl font-bold tracking-tight text-white">
        String Analysis
      </h1>

      <div className="mt-8">
        <Tabs
          tabs={[
            { label: 'String Extractor', icon: FileText },
            { label: 'Presence Detection', icon: ShieldCheck },
            { label: 'Suspicious Detection', icon: Search },
          ]}
          active={mode}
          onChange={setMode}
        />
      </div>

      {mode === 'String Extractor' && <StringExtractor />}
      {mode === 'Presence Detection' && <PresenceDetection />}
      {mode === 'Suspicious Detection' && <SuspiciousDetection />}
    </div>
  )
}
