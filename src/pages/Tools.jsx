import { useRef, useState } from 'react'
import {
  Wrench, Globe, Network, FileSearch, Hash, AlertTriangle,
  CheckCircle2, Copy, Upload as UploadIcon,
} from 'lucide-react'
import { PageHeader, Card, EmptyState, Textarea } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { useToast } from '../components/ui.jsx'
import { analyzeText, sha256, readFileBytes, formatBytes } from '../lib/analyze.js'

function TextAnalyzer({ mode, placeholder, hint }) {
  const toast = useToast()
  const [text, setText] = useState('')
  const [res, setRes] = useState(null)

  const run = () => {
    if (!text.trim()) return toast({ type: 'error', title: 'Paste some data first' })
    const r = analyzeText(text, mode)
    setRes(r)
    toast({
      type: r.clean ? 'success' : 'error',
      title: r.clean ? 'No indicators found' : `${r.flagged.length} suspicious line(s)`,
      body: `${r.scanned} lines scanned`,
    })
  }

  return (
    <Card className="p-6 md:p-8">
      <p className="caps-label">Paste data</p>
      <h3 className="txt mt-1 text-xl font-semibold">Analyzer</h3>
      <p className="muted mb-4 mt-1 text-sm">{hint}</p>
      <Textarea
        rows={9}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={placeholder}
        className="font-mono text-xs"
      />
      <div className="mt-4 flex justify-end gap-3">
        <button onClick={() => { setText(''); setRes(null) }} className="bd txt rounded-lg border px-4 py-2 text-sm">
          Clear
        </button>
        <button onClick={run} className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white hover:bg-blue-500">
          Analyze
        </button>
      </div>

      {res && (
        <div className="mt-6">
          <div
            className={`flex items-center gap-2 rounded-lg border px-4 py-3 text-sm ${
              res.clean
                ? 'border-green-600/30 bg-green-600/10 text-green-500'
                : 'border-red-600/30 bg-red-600/10 text-red-500'
            }`}
          >
            {res.clean ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
            {res.clean
              ? `Clean — ${res.scanned} lines scanned, nothing flagged.`
              : `${res.flagged.length} of ${res.scanned} lines flagged.`}
          </div>
          {res.flagged.length > 0 && (
            <div className="bd tile mt-3 max-h-72 overflow-y-auto rounded-lg border font-mono text-xs">
              {res.flagged.map((f) => (
                <div key={f.idx} className="bd border-b px-3 py-2 last:border-0">
                  <div className="flex items-start gap-3">
                    <span className="muted w-10 shrink-0">#{f.idx}</span>
                    <span className="break-all text-red-500">{f.line}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1 pl-10">
                    {f.hits.map((h) => (
                      <span key={h} className="rounded border border-red-600/30 bg-red-600/10 px-1.5 py-0.5 text-[10px] text-red-400">
                        {h}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function FileHasher() {
  const toast = useToast()
  const ref = useRef(null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)

  const handle = async (file) => {
    setBusy(true)
    try {
      const bytes = await readFileBytes(file)
      const hash = await sha256(bytes)
      setResult({ name: file.name, size: bytes.length, hash })
    } catch {
      toast({ type: 'error', title: 'Failed to hash file' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="p-6 md:p-8">
      <p className="caps-label">Integrity</p>
      <h3 className="txt mt-1 text-xl font-semibold">SHA-256 File Hash</h3>
      <p className="muted mb-4 mt-1 text-sm">
        Compute a cryptographic hash to verify a file against VirusTotal or known databases.
      </p>
      <input ref={ref} type="file" className="hidden" onChange={(e) => e.target.files[0] && handle(e.target.files[0])} />
      <button
        onClick={() => ref.current?.click()}
        className="bd flex w-full flex-col items-center justify-center rounded-xl border-2 border-dashed py-14 hover:border-blue-500"
      >
        <UploadIcon size={30} className="muted" />
        <span className="txt mt-3 text-sm font-medium">{busy ? 'Hashing…' : 'Select a file to hash'}</span>
      </button>
      {result && (
        <div className="tile mt-5 rounded-lg border p-4">
          <p className="txt text-sm font-medium">{result.name}</p>
          <p className="muted text-xs">{formatBytes(result.size)}</p>
          <div className="bd mt-3 flex items-center gap-2 rounded-lg border bg-black/20 px-3 py-2">
            <code className="txt flex-1 break-all font-mono text-xs">{result.hash}</code>
            <button
              className="muted hover:txt"
              onClick={() => {
                navigator.clipboard?.writeText(result.hash)
                toast({ type: 'success', title: 'Hash copied' })
              }}
            >
              <Copy size={15} />
            </button>
          </div>
        </div>
      )}
    </Card>
  )
}

export default function Tools() {
  const [tab, setTab] = useState('Browser History')
  return (
    <div>
      <PageHeader
        icon={Wrench}
        kicker="Screenshare & forensic helpers"
        title="Forensic Tools"
        subtitle="Client-side analyzers for browser history, DNS cache, system artifacts and file integrity."
      />
      <Tabs
        tabs={[
          { label: 'Browser History', icon: Globe },
          { label: 'DNS Cache', icon: Network },
          { label: 'System Artifacts', icon: FileSearch },
          { label: 'File Hash', icon: Hash },
        ]}
        active={tab}
        onChange={setTab}
      />
      <div className="mt-8">
        {tab === 'Browser History' && (
          <TextAnalyzer
            mode="history"
            hint="Paste exported browser history or a list of visited URLs — known cheat domains get flagged."
            placeholder={'https://example.com/...\nhttps://vape.gg/download\nhttps://liquidbounce.net/'}
          />
        )}
        {tab === 'DNS Cache' && (
          <TextAnalyzer
            mode="dns"
            hint="Paste the output of `ipconfig /displaydns` — resolved cheat domains get flagged."
            placeholder={'Record Name . . . . . : vape.gg\nRecord Name . . . . . : google.com'}
          />
        )}
        {tab === 'System Artifacts' && (
          <TextAnalyzer
            mode="artifacts"
            hint="Paste Prefetch / Recent Files / USN journal listings — cheat clients & anti-forensic tools get flagged."
            placeholder={'JAVAW.EXE-1A2B.pf\nVAPE-LOADER.EXE-99FF.pf\nBLEACHBIT.EXE-...'}
          />
        )}
        {tab === 'File Hash' && <FileHasher />}
      </div>
    </div>
  )
}
