import { useState } from 'react'
import {
  UploadCloud,
  ChevronDown,
  FileCode2,
  Clock,
  ScanSearch,
} from 'lucide-react'
import { PageHeader, Tabs } from '../components/ui.jsx'

function Dropzone({ hint }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-ink-600 bg-ink-950 px-6 py-14 text-center transition-colors hover:border-accent/50">
      <div className="grid h-14 w-14 place-items-center rounded-full border border-ink-700 bg-ink-850 text-accent">
        <UploadCloud size={26} strokeWidth={1.8} />
      </div>
      <p className="mt-4 text-sm font-medium text-zinc-200">
        Drag and drop or click
      </p>
      <p className="mt-1 text-xs text-zinc-500">{hint}</p>
    </div>
  )
}

function WorkingModeSelect() {
  return (
    <div>
      <label className="caps-label mb-2 block">Working Mode</label>
      <button
        type="button"
        className="flex w-full items-center justify-between rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5 text-sm text-zinc-200 sm:w-56"
      >
        Personal
        <ChevronDown size={15} className="text-zinc-600" />
      </button>
    </div>
  )
}

function StatusBox() {
  return (
    <div className="card flex gap-8 p-5">
      <div className="flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-lg border border-ink-700 bg-ink-850 text-accent">
          <FileCode2 size={18} />
        </div>
        <div>
          <p className="caps-label">Detection Files</p>
          <p className="mt-0.5 text-lg font-bold text-white">128</p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-lg border border-ink-700 bg-ink-850 text-accent">
          <Clock size={18} />
        </div>
        <div>
          <p className="caps-label">Last Updated</p>
          <p className="mt-0.5 text-sm font-semibold text-zinc-200">
            2h ago
          </p>
        </div>
      </div>
    </div>
  )
}

function ClientNameInput() {
  return (
    <div>
      <label className="caps-label mb-2 block">Client Name</label>
      <input
        placeholder="e.g. Vape Lite, Doomsday..."
        className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2.5 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-accent focus:outline-none"
      />
    </div>
  )
}

function StringExtractor() {
  return (
    <div className="card space-y-6 p-6">
      <div>
        <h3 className="text-sm font-semibold text-white">String Extractor</h3>
        <p className="mt-1 text-xs text-zinc-500">
          Upload a binary to extract and analyze embedded strings.
        </p>
      </div>
      <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
      <button
        type="button"
        className="w-full rounded-lg bg-accent py-2.5 text-sm font-semibold text-white shadow-glow transition-colors hover:bg-blue-500"
      >
        Analyze File
      </button>
    </div>
  )
}

function PresenceDetection() {
  const [subTab, setSubTab] = useState('Upload')
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <WorkingModeSelect />
        <StatusBox />
      </div>

      <div className="card space-y-6 p-6">
        <Tabs
          tabs={['Upload', 'My Files']}
          active={subTab}
          onChange={setSubTab}
        />
        {subTab === 'Upload' ? (
          <>
            <ClientNameInput />
            <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
            <button
              type="button"
              className="w-full rounded-lg bg-accent py-2.5 text-sm font-semibold text-white shadow-glow transition-colors hover:bg-blue-500"
            >
              Upload Detection File
            </button>
          </>
        ) : (
          <div className="rounded-lg border border-ink-700">
            {['vape_v4.exe', 'doomsday.jar', 'liquidbounce.dll'].map(
              (file, i) => (
                <div
                  key={file}
                  className={`flex items-center justify-between px-4 py-3 text-sm ${
                    i !== 0 ? 'border-t border-ink-800' : ''
                  }`}
                >
                  <span className="font-mono text-zinc-300">{file}</span>
                  <span className="text-xs text-zinc-500">
                    indexed
                  </span>
                </div>
              )
            )}
          </div>
        )}
      </div>
    </div>
  )
}

const sampleRule = `rule SuspiciousLoader
{
    meta:
        author = "ocean"
        severity = "high"

    strings:
        $a = "InjectModule" ascii
        $b = { 4D 5A 90 00 03 00 00 00 }
        $c = /hook_[a-z]{4,12}/

    condition:
        $a and ($b or $c)
}`

function RuleEditor() {
  const [code, setCode] = useState(sampleRule)
  const lineCount = code.split('\n').length

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between border-b border-ink-700 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Rule Editor</h3>
        <span className="caps-label">YARA</span>
      </div>
      <div className="flex font-mono text-[13px] leading-6">
        <div className="select-none border-r border-ink-700 bg-ink-950 px-3 py-3 text-right text-zinc-600">
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i}>{i + 1}</div>
          ))}
        </div>
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          spellCheck={false}
          rows={lineCount}
          className="w-full resize-none bg-ink-950 px-4 py-3 text-zinc-200 focus:outline-none"
        />
      </div>
    </div>
  )
}

function SuspiciousDetection() {
  const [subTab, setSubTab] = useState('YARA Rules')
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <WorkingModeSelect />
        <StatusBox />
      </div>

      <div className="card space-y-6 p-6">
        <Tabs
          tabs={['YARA Rules', 'Suspicious Files', 'Scan']}
          active={subTab}
          onChange={setSubTab}
        />

        {subTab === 'YARA Rules' && (
          <>
            <ClientNameInput />
            <RuleEditor />
            <button
              type="button"
              className="w-full rounded-lg bg-accent py-2.5 text-sm font-semibold text-white shadow-glow transition-colors hover:bg-blue-500"
            >
              Save Rule
            </button>
          </>
        )}

        {subTab === 'Suspicious Files' && (
          <>
            <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
            <button
              type="button"
              className="w-full rounded-lg bg-accent py-2.5 text-sm font-semibold text-white shadow-glow transition-colors hover:bg-blue-500"
            >
              Upload Suspicious File
            </button>
          </>
        )}

        {subTab === 'Scan' && (
          <div className="flex flex-col items-center justify-center rounded-xl border border-ink-700 bg-ink-950 px-6 py-14 text-center">
            <div className="grid h-14 w-14 place-items-center rounded-full border border-ink-700 bg-ink-850 text-accent">
              <ScanSearch size={26} strokeWidth={1.8} />
            </div>
            <p className="mt-4 text-sm font-medium text-zinc-200">
              Run YARA rules against indexed files
            </p>
            <p className="mt-1 text-xs text-zinc-500">
              128 detection files · 14 rules loaded
            </p>
            <button
              type="button"
              className="mt-5 rounded-lg bg-accent px-6 py-2 text-sm font-semibold text-white shadow-glow transition-colors hover:bg-blue-500"
            >
              Start Scan
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Strings() {
  const [mode, setMode] = useState('String Extractor')

  return (
    <div>
      <PageHeader
        eyebrow="Extract strings and manage detection signatures"
        title="Strings"
      />

      <div className="mb-8">
        <Tabs
          tabs={['String Extractor', 'Presence Detection', 'Suspicious Detection']}
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
