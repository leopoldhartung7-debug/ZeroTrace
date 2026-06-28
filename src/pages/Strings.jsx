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
    <div className="group relative flex flex-col items-center justify-center overflow-hidden rounded-xl border-2 border-dashed border-ink-600 bg-ink-950 px-6 py-14 text-center transition-all duration-300 hover:-translate-y-0.5 hover:border-accent/60 hover:shadow-glow">
      <div className="pointer-events-none absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-accent/10 to-transparent transition-transform duration-1000 group-hover:translate-x-full" />
      <div className="ring-pulse grid h-14 w-14 place-items-center rounded-full border border-ink-700 bg-ink-850 text-accent transition-transform duration-300 group-hover:scale-110">
        <UploadCloud
          size={26}
          strokeWidth={1.8}
          className="transition-transform duration-300 group-hover:-translate-y-0.5"
        />
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
        className="group flex w-full items-center justify-between rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5 text-sm text-zinc-200 transition-all duration-200 hover:border-accent/40 sm:w-56"
      >
        Personal
        <ChevronDown
          size={15}
          className="text-zinc-600 transition-transform duration-200 group-hover:translate-y-0.5"
        />
      </button>
    </div>
  )
}

function StatusBox() {
  return (
    <div className="card card-interactive flex gap-8 p-5">
      <div className="group flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-lg border border-ink-700 bg-ink-850 text-accent transition-all duration-300 group-hover:scale-110 group-hover:border-accent/40">
          <FileCode2 size={18} />
        </div>
        <div>
          <p className="caps-label">Detection Files</p>
          <p className="stat-value mt-0.5 text-lg font-bold tabular-nums">
            128
          </p>
        </div>
      </div>
      <div className="group flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-lg border border-ink-700 bg-ink-850 text-accent transition-all duration-300 group-hover:scale-110 group-hover:border-accent/40">
          <Clock size={18} className="transition-transform duration-700 group-hover:rotate-180" />
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
        className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2.5 text-sm text-zinc-200 placeholder:text-zinc-600 transition-all duration-200 focus:border-accent focus:shadow-glow focus:outline-none"
      />
    </div>
  )
}

function StringExtractor() {
  return (
    <div className="card card-interactive space-y-6 p-6 animate-fade-up">
      <div>
        <h3 className="text-sm font-semibold text-white">String Extractor</h3>
        <p className="mt-1 text-xs text-zinc-500">
          Upload a binary to extract and analyze embedded strings.
        </p>
      </div>
      <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
      <button type="button" className="btn-primary w-full">
        Analyze File
      </button>
    </div>
  )
}

function PresenceDetection() {
  const [subTab, setSubTab] = useState('Upload')
  return (
    <div className="space-y-6 animate-fade-up">
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
        <div key={subTab} className="animate-fade-up-sm space-y-6">
          {subTab === 'Upload' ? (
            <>
              <ClientNameInput />
              <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
              <button type="button" className="btn-primary w-full">
                Upload Detection File
              </button>
            </>
          ) : (
            <div className="rounded-lg border border-ink-700 stagger">
              {['vape_v4.exe', 'doomsday.jar', 'liquidbounce.dll'].map(
                (file, i) => (
                  <div
                    key={file}
                    className={`row-hover flex items-center justify-between px-4 py-3 text-sm ${
                      i !== 0 ? 'border-t border-ink-800' : ''
                    }`}
                  >
                    <span className="font-mono text-zinc-300">{file}</span>
                    <span className="inline-flex items-center gap-1.5 text-xs text-zinc-500">
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-success shadow-[0_0_8px_#22c55e]" />
                      indexed
                    </span>
                  </div>
                )
              )}
            </div>
          )}
        </div>
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
    <div className="card card-interactive overflow-hidden">
      <div className="flex items-center justify-between border-b border-ink-700 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Rule Editor</h3>
        <span className="caps-label inline-flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent shadow-[0_0_8px_#3b82f6]" />
          YARA
        </span>
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
          className="w-full resize-none bg-ink-950 px-4 py-3 text-zinc-200 transition-colors duration-200 focus:outline-none"
        />
      </div>
    </div>
  )
}

function SuspiciousDetection() {
  const [subTab, setSubTab] = useState('YARA Rules')
  return (
    <div className="space-y-6 animate-fade-up">
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

        <div key={subTab} className="animate-fade-up-sm space-y-6">
          {subTab === 'YARA Rules' && (
            <>
              <ClientNameInput />
              <RuleEditor />
              <button type="button" className="btn-primary w-full">
                Save Rule
              </button>
            </>
          )}

          {subTab === 'Suspicious Files' && (
            <>
              <Dropzone hint="Supported: .exe, .jar, .dll, .sys" />
              <button type="button" className="btn-primary w-full">
                Upload Suspicious File
              </button>
            </>
          )}

          {subTab === 'Scan' && (
            <div className="flex flex-col items-center justify-center rounded-xl border border-ink-700 bg-ink-950 px-6 py-14 text-center">
              <div className="ring-pulse grid h-14 w-14 place-items-center rounded-full border border-ink-700 bg-ink-850 text-accent">
                <ScanSearch
                  size={26}
                  strokeWidth={1.8}
                  className="animate-float"
                />
              </div>
              <p className="mt-4 text-sm font-medium text-zinc-200">
                Run YARA rules against indexed files
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                128 detection files · 14 rules loaded
              </p>
              <button
                type="button"
                className="btn-primary mt-5 px-6"
              >
                Start Scan
              </button>
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
      <PageHeader
        eyebrow="Extract strings and manage detection signatures"
        title="Strings"
      />

      <div className="mb-8 animate-fade-up" style={{ animationDelay: '60ms' }}>
        <Tabs
          tabs={['String Extractor', 'Presence Detection', 'Suspicious Detection']}
          active={mode}
          onChange={setMode}
        />
      </div>

      <div key={mode}>
        {mode === 'String Extractor' && <StringExtractor />}
        {mode === 'Presence Detection' && <PresenceDetection />}
        {mode === 'Suspicious Detection' && <SuspiciousDetection />}
      </div>
    </div>
  )
}
