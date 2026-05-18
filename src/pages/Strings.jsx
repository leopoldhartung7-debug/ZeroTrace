import { useMemo, useRef, useState } from 'react'
import {
  FileText, ShieldCheck, Search, Upload as UploadIcon, Info, Code2,
  FileWarning, ScanLine, Shield, Download, Copy, Trash2, CheckCircle2, XCircle,
} from 'lucide-react'
import Tabs from '../components/Tabs.jsx'
import { Select, useToast } from '../components/ui.jsx'
import { useStore, useT } from '../store.jsx'
import {
  extractStrings, scanSuspicious, parseYaraRule, runYaraRule, formatBytes, readFileBytes,
} from '../lib/analyze.js'

function Dropzone({ onFile, hint, accept = '.exe,.jar,.dll,.sys' }) {
  const ref = useRef(null)
  const [drag, setDrag] = useState(false)
  return (
    <div
      onClick={() => ref.current?.click()}
      onDragOver={(e) => {
        e.preventDefault()
        setDrag(true)
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault()
        setDrag(false)
        if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0])
      }}
      className={`bd flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed py-16 text-center transition-colors ${
        drag ? 'border-blue-500 bg-blue-500/5' : ''
      }`}
    >
      <input
        ref={ref}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => e.target.files[0] && onFile(e.target.files[0])}
      />
      <UploadIcon size={32} className="muted" />
      <p className="txt mt-4 text-base font-medium">Drag and drop or click</p>
      <p className="muted mt-1 text-xs">{hint}</p>
    </div>
  )
}

function ModeAndStatus({ mode, setMode, statusRows }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="panel rounded-xl border p-6">
        <p className="caps-label">Select File Mode</p>
        <h3 className="txt mt-1 text-lg font-semibold">Working Mode</h3>
        <div className="mt-4">
          <Select
            value={mode}
            onChange={setMode}
            options={[
              { value: 'Personal', label: 'Personal' },
              { value: 'Team', label: 'Team' },
            ]}
          />
        </div>
        <div className="bd txt mt-3 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium">
          <Shield size={16} className="muted" />
          {mode} Mode
        </div>
      </div>

      <div className="panel rounded-xl border p-6">
        <p className="caps-label">Current Status</p>
        <h3 className="txt mt-1 text-lg font-semibold">Status</h3>
        <div className="mt-5 space-y-4">
          {statusRows.map((row) => (
            <div key={row.label} className="flex items-center justify-between text-sm">
              <span className="muted">{row.label}</span>
              <span className="txt font-semibold">{row.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StringExtractor() {
  const toast = useToast()
  const [tab, setTab] = useState('Upload')
  const [file, setFile] = useState(null)
  const [results, setResults] = useState(null)
  const [busy, setBusy] = useState(false)
  const [q, setQ] = useState('')
  const [onlySusp, setOnlySusp] = useState(false)

  const analyze = async () => {
    if (!file) return
    setBusy(true)
    try {
      const bytes = await readFileBytes(file)
      const strings = extractStrings(bytes, { min: 4 })
      const susp = scanSuspicious(strings)
      const suspSet = new Set(susp.map((s) => s.offset))
      setResults({ file: file.name, size: bytes.length, strings, susp, suspSet })
      setTab('Results')
      toast({
        type: susp.length ? 'error' : 'success',
        title: `${strings.length} strings extracted`,
        body: susp.length ? `${susp.length} suspicious indicators` : 'No suspicious indicators',
      })
    } catch {
      toast({ type: 'error', title: 'Failed to read file' })
    } finally {
      setBusy(false)
    }
  }

  const shown = useMemo(() => {
    if (!results) return []
    return results.strings
      .filter((s) => (onlySusp ? results.suspSet.has(s.offset) : true))
      .filter((s) => (q ? s.value.toLowerCase().includes(q.toLowerCase()) : true))
      .slice(0, 2000)
  }, [results, q, onlySusp])

  const download = () => {
    const blob = new Blob([results.strings.map((s) => s.value).join('\n')], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${results.file}.strings.txt`
    a.click()
    URL.revokeObjectURL(a.href)
  }

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
      <div className="panel mt-8 rounded-2xl border p-6 md:p-8">
        {tab === 'Upload' ? (
          <>
            <p className="caps-label">Extractor</p>
            <h3 className="txt mt-1 text-xl font-semibold">Upload File</h3>
            <p className="muted mt-1 text-sm">Upload a file to extract printable strings</p>
            <div className="mt-6">
              <Dropzone onFile={setFile} hint="Supported: .exe, .jar, .dll, .sys" accept="*" />
            </div>
            {file && (
              <div className="tile mt-4 flex items-center justify-between rounded-lg border px-4 py-3 text-sm">
                <span className="txt">
                  {file.name} <span className="muted">({formatBytes(file.size)})</span>
                </span>
                <button className="muted hover:txt" onClick={() => setFile(null)}>
                  <Trash2 size={15} />
                </button>
              </div>
            )}
            <div className="mt-6 flex justify-end">
              <button
                disabled={!file || busy}
                onClick={analyze}
                className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? 'Analyzing…' : 'Analyze File'}
              </button>
            </div>
          </>
        ) : !results ? (
          <div className="muted py-16 text-center text-sm">No analysis results yet.</div>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="caps-label">Results — {results.file}</p>
                <p className="txt mt-1 text-lg font-semibold">
                  {results.strings.length} strings · {results.susp.length} suspicious
                </p>
              </div>
              <button
                onClick={download}
                className="bd txt flex items-center gap-2 rounded-lg border px-4 py-2 text-sm"
              >
                <Download size={15} /> Export .txt
              </button>
            </div>
            <div className="mt-5 flex flex-wrap gap-3">
              <div className="relative flex-1">
                <Search size={15} className="muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Filter strings..."
                  className="bd tile txt w-full rounded-lg border py-2 pl-9 pr-3 text-sm focus:outline-none"
                />
              </div>
              <button
                onClick={() => setOnlySusp((v) => !v)}
                className={`rounded-lg border px-4 py-2 text-sm ${
                  onlySusp
                    ? 'border-red-600/40 bg-red-600/15 text-red-500'
                    : 'bd txt'
                }`}
              >
                Suspicious only
              </button>
            </div>
            <div className="bd tile mt-4 max-h-[420px] overflow-y-auto rounded-lg border font-mono text-xs">
              {shown.map((s, i) => {
                const flagged = results.suspSet.has(s.offset)
                return (
                  <div
                    key={i}
                    className={`bd flex items-start gap-3 border-b px-3 py-1.5 last:border-0 ${
                      flagged ? 'bg-red-600/10' : ''
                    }`}
                  >
                    <span className="muted w-20 shrink-0">
                      0x{s.offset.toString(16)}
                    </span>
                    <span className={`break-all ${flagged ? 'text-red-500' : 'txt'}`}>
                      {s.value}
                    </span>
                  </div>
                )
              })}
              {shown.length === 0 && (
                <p className="muted px-3 py-8 text-center">No strings match.</p>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function PresenceDetection() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [mode, setMode] = useState('Personal')
  const [tab, setTab] = useState('Upload')
  const [client, setClient] = useState('')
  const [busy, setBusy] = useState(false)

  const files = state.detectionFiles
  const last = files[0]

  const handleFile = async (file) => {
    if (!client.trim()) {
      toast({ type: 'error', title: 'Client Name required' })
      return
    }
    setBusy(true)
    try {
      const bytes = await readFileBytes(file)
      const strings = extractStrings(bytes, { min: 6 })
      const signatures = strings
        .map((s) => s.value)
        .filter((v) => v.length >= 8 && v.length <= 64)
        .slice(0, 25)
      dispatch({
        type: 'add-detection-file',
        clientName: client.trim(),
        fileName: file.name,
        size: bytes.length,
        mode,
        signatures,
      })
      toast({ type: 'success', title: 'Detection file added', body: `${client} — ${signatures.length} signatures` })
      setClient('')
      setTab('My Files')
    } catch {
      toast({ type: 'error', title: 'Failed to read file' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-8 space-y-8">
      <ModeAndStatus
        mode={mode}
        setMode={setMode}
        statusRows={[
          { label: 'Detection Files:', value: files.length },
          { label: 'Last Updated:', value: last ? new Date(last.addedAt).toLocaleString() : 'Never' },
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
        <div className="panel mt-8 rounded-2xl border p-6 md:p-8">
          {tab === 'Upload' ? (
            <>
              <p className="caps-label">Upload for presence detection</p>
              <h3 className="txt mt-1 text-xl font-semibold">Upload File</h3>
              <div className="bd txt mt-5 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium">
                <Shield size={16} className="muted" />
                Uploading to {mode}
              </div>
              <div className="mt-6">
                <label className="txt mb-2 block text-sm font-medium">Client Name</label>
                <input
                  value={client}
                  onChange={(e) => setClient(e.target.value)}
                  placeholder="e.g. Vape V4"
                  className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none"
                />
              </div>
              <div className="mt-6">
                <Dropzone
                  onFile={handleFile}
                  hint={busy ? 'Processing…' : 'Supported: .exe, .jar, .dll, .sys'}
                  accept="*"
                />
              </div>
            </>
          ) : (
            <>
              <p className="caps-label">Stored detection files</p>
              <h3 className="txt mb-5 mt-1 text-xl font-semibold">My Files</h3>
              {files.length === 0 ? (
                <p className="muted py-12 text-center text-sm">No detection files uploaded.</p>
              ) : (
                <div className="space-y-3">
                  {files.map((f) => (
                    <div
                      key={f.id}
                      className="tile flex items-center justify-between rounded-lg border px-4 py-3"
                    >
                      <div>
                        <p className="txt text-sm font-medium">{f.clientName}</p>
                        <p className="muted text-xs">
                          {f.fileName} · {formatBytes(f.size)} · {f.signatures.length} signatures · {f.mode}
                        </p>
                      </div>
                      <button
                        className="muted hover:text-red-500"
                        onClick={() => {
                          dispatch({ type: 'delete-detection-file', id: f.id })
                          toast({ type: 'success', title: 'Removed', body: f.clientName })
                        }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function SuspiciousDetection() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [mode, setMode] = useState('Personal')
  const [tab, setTab] = useState('YARA Rules')
  const [rule, setRule] = useState(
    'rule ExampleCheat\n{\n  strings:\n    $a = "KillAura"\n    $b = "injector"\n  condition:\n    any of them\n}',
  )
  const [validation, setValidation] = useState(null)
  const [scanResult, setScanResult] = useState(null)
  const [busy, setBusy] = useState(false)

  const rules = state.yaraRules
  const lineCount = Math.max(rule.split('\n').length, 16)

  const validate = () => {
    const parsed = parseYaraRule(rule)
    setValidation(parsed)
    toast({
      type: parsed.ok ? 'success' : 'error',
      title: parsed.ok ? `Valid rule: ${parsed.name}` : 'Invalid rule',
      body: parsed.ok ? `${parsed.literals.length} string pattern(s)` : parsed.errors[0],
    })
    return parsed
  }

  const save = () => {
    const parsed = validate()
    if (!parsed.ok) return
    dispatch({ type: 'save-yara', name: parsed.name, source: rule })
    toast({ type: 'success', title: 'Rule saved', body: parsed.name })
  }

  const scanFile = async (file) => {
    if (rules.length === 0) {
      toast({ type: 'error', title: 'No YARA rule configured' })
      return
    }
    setBusy(true)
    try {
      const bytes = await readFileBytes(file)
      const strings = extractStrings(bytes, { min: 4 })
      const matches = []
      for (const r of rules) {
        const parsed = parseYaraRule(r.source)
        if (!parsed.ok) continue
        const res = runYaraRule(parsed, bytes, strings)
        if (res.matched) matches.push({ rule: r.name, hits: res.hits })
      }
      setScanResult({ file: file.name, size: bytes.length, matches })
      dispatch({
        type: 'add-suspicious',
        fileName: file.name,
        size: bytes.length,
        matches: matches.map((m) => m.rule),
      })
      toast({
        type: matches.length ? 'error' : 'success',
        title: matches.length ? `${matches.length} rule(s) matched` : 'No matches',
        body: file.name,
      })
    } catch {
      toast({ type: 'error', title: 'Failed to read file' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-8 space-y-8">
      <ModeAndStatus
        mode={mode}
        setMode={setMode}
        statusRows={[
          { label: 'YARA Rule:', value: rules.length ? `${rules.length} configured` : 'Not configured' },
          { label: 'Suspicious Files:', value: state.suspiciousFiles.length },
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
        <div className="panel mt-8 rounded-2xl border p-6 md:p-8">
          {tab === 'YARA Rules' && (
            <>
              <p className="caps-label">Write YARA Rules</p>
              <h3 className="txt mt-1 text-xl font-semibold">Rule Editor</h3>
              <p className="muted mb-2 mt-4 text-sm">New Rule</p>
              <div className="bd tile flex overflow-hidden rounded-lg border font-mono text-sm">
                <div className="bd muted select-none border-r px-3 py-3 text-right">
                  {Array.from({ length: lineCount }, (_, i) => (
                    <div key={i} className="leading-6">
                      {i + 1}
                    </div>
                  ))}
                </div>
                <textarea
                  value={rule}
                  onChange={(e) => setRule(e.target.value)}
                  spellCheck={false}
                  className="txt min-h-[380px] flex-1 resize-none bg-transparent p-3 leading-6 focus:outline-none"
                />
              </div>
              {validation && (
                <div
                  className={`mt-4 rounded-lg border px-4 py-3 text-sm ${
                    validation.ok
                      ? 'border-green-600/30 bg-green-600/10 text-green-500'
                      : 'border-red-600/30 bg-red-600/10 text-red-500'
                  }`}
                >
                  {validation.ok ? (
                    <span className="flex items-center gap-2">
                      <CheckCircle2 size={15} /> Valid rule "{validation.name}" —{' '}
                      {validation.literals.length} pattern(s)
                    </span>
                  ) : (
                    <ul className="space-y-1">
                      {validation.errors.map((e, i) => (
                        <li key={i} className="flex items-center gap-2">
                          <XCircle size={15} /> {e}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
              <div className="mt-6 flex justify-end gap-3">
                <button
                  onClick={validate}
                  className="bd txt rounded-lg border px-5 py-2.5 text-sm font-medium"
                >
                  Validate
                </button>
                <button
                  onClick={save}
                  className="rounded-lg bg-white px-5 py-2.5 text-sm font-semibold text-black hover:opacity-90"
                >
                  Save Rule
                </button>
              </div>

              {rules.length > 0 && (
                <div className="mt-8">
                  <p className="caps-label mb-3">Saved Rules ({rules.length})</p>
                  <div className="space-y-2">
                    {rules.map((r) => (
                      <div
                        key={r.id}
                        className="tile flex items-center justify-between rounded-lg border px-4 py-3"
                      >
                        <div className="flex items-center gap-3">
                          <Code2 size={15} className="muted" />
                          <button
                            className="txt text-sm font-medium hover:text-blue-500"
                            onClick={() => setRule(r.source)}
                          >
                            {r.name}
                          </button>
                        </div>
                        <button
                          className="muted hover:text-red-500"
                          onClick={() => dispatch({ type: 'delete-yara', id: r.id })}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {tab === 'Suspicious Files' && (
            <>
              <p className="caps-label">Scanned files</p>
              <h3 className="txt mb-5 mt-1 text-xl font-semibold">Suspicious Files</h3>
              {state.suspiciousFiles.length === 0 ? (
                <p className="muted py-12 text-center text-sm">No files scanned yet.</p>
              ) : (
                <div className="space-y-3">
                  {state.suspiciousFiles.map((f) => (
                    <div
                      key={f.id}
                      className="tile flex items-center justify-between rounded-lg border px-4 py-3"
                    >
                      <div>
                        <p className="txt text-sm font-medium">{f.fileName}</p>
                        <p className="muted text-xs">
                          {formatBytes(f.size)} · {new Date(f.scannedAt).toLocaleString()}
                        </p>
                      </div>
                      {f.matches.length ? (
                        <span className="rounded-md border border-red-600/30 bg-red-600/10 px-2.5 py-1 text-xs font-semibold text-red-500">
                          {f.matches.length} MATCH
                        </span>
                      ) : (
                        <span className="rounded-md border border-green-600/30 bg-green-600/10 px-2.5 py-1 text-xs font-semibold text-green-500">
                          CLEAN
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {tab === 'Scan' && (
            <>
              <p className="caps-label">Scan a file against your rules</p>
              <h3 className="txt mb-5 mt-1 text-xl font-semibold">Scan</h3>
              {rules.length === 0 && (
                <div className="mb-5 rounded-lg border border-yellow-600/30 bg-yellow-600/10 px-4 py-3 text-sm text-yellow-500">
                  Configure a YARA rule first to start scanning.
                </div>
              )}
              <Dropzone onFile={scanFile} hint={busy ? 'Scanning…' : 'Any file type'} accept="*" />
              {scanResult && (
                <div className="mt-6">
                  <p className="txt text-sm font-semibold">
                    {scanResult.file} — {scanResult.matches.length} rule(s) matched
                  </p>
                  {scanResult.matches.map((m) => (
                    <div
                      key={m.rule}
                      className="mt-3 rounded-lg border border-red-600/30 bg-red-600/10 p-4"
                    >
                      <p className="text-sm font-semibold text-red-500">{m.rule}</p>
                      <ul className="muted mt-2 space-y-1 font-mono text-xs">
                        {m.hits.map((h, i) => (
                          <li key={i}>
                            [{h.type}] {h.pattern}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                  {scanResult.matches.length === 0 && (
                    <p className="mt-3 text-sm text-green-500">No rules matched — file looks clean.</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Strings() {
  const t = useT()
  const [mode, setMode] = useState('String Extractor')

  return (
    <div>
      <p className="caps-label">{t('strings.kicker')}</p>
      <h1 className="txt mt-3 text-4xl font-bold tracking-tight">{t('strings.title')}</h1>

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
