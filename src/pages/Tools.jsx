import { useRef, useState } from 'react'
import {
  Wrench, Globe, Network, FileSearch, Hash, AlertTriangle,
  CheckCircle2, Copy, Upload as UploadIcon, MessageSquare, Send, Server, ShieldAlert,
} from 'lucide-react'
import { PageHeader, Card, EmptyState, Textarea } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, deriveScanReport } from '../store.jsx'
import { analyzeText, sha256, readFileBytes, formatBytes } from '../lib/analyze.js'

const DISCORD_EPOCH = 1420070400000

function decodeSnowflake(id) {
  try {
    const ms = Number(BigInt(id) >> 22n) + DISCORD_EPOCH
    const d = new Date(ms)
    if (isNaN(d.getTime())) return null
    return d
  } catch {
    return null
  }
}

function DiscordChecker() {
  const toast = useToast()
  const { state } = useStore()
  const [id, setId] = useState('')
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)

  const webhook = state.integrations?.discordWebhook || ''
  const botUrl = state.integrations?.discordBotUrl || ''
  const botKey = state.integrations?.discordBotKey || ''

  const liveCheck = async (cleanId) => {
    const resp = await fetch(`${botUrl}/check?id=${encodeURIComponent(cleanId)}`, {
      headers: botKey ? { 'x-api-key': botKey } : {},
    })
    if (!resp.ok) throw new Error(`Bot HTTP ${resp.status}`)
    const data = await resp.json()
    const servers = (data.results || [])
      .filter((s) => s.member)
      .map((s) => ({
        name: s.guild,
        id: s.guildId,
        flag: s.flag || 'clean',
        roles: Array.isArray(s.roles) ? s.roles : [],
        joinedAt: s.joinedAt || null,
      }))
      .sort((a, b) => (a.flag === 'clean' ? 1 : 0) - (b.flag === 'clean' ? 1 : 0))
    return {
      id: cleanId,
      created: data.createdAt || (decodeSnowflake(cleanId)?.toISOString() ?? null),
      source: 'bot',
      totalServers: data.totalServers || 0,
      found: data.found ?? servers.length,
      scans: 0,
      servers,
      cheat: servers.filter((s) => s.flag === 'cheat'),
      reselling: servers.filter((s) => s.flag === 'reselling'),
    }
  }

  const build = (cleanId) => {
    const created = decodeSnowflake(cleanId)
    // Real data only: aggregate servers detected in past scans bound to this ID.
    const pins = state.pins.filter((p) => (p.discordId || '') === cleanId)
    const seen = new Set()
    const servers = []
    let scans = 0
    pins.forEach((p) => {
      const r = deriveScanReport(p)
      if (!r) return
      scans++
      r.discordServers.forEach((g) => {
        const k = `${g.name}|${g.id}`
        if (seen.has(k)) return
        seen.add(k)
        servers.push(g)
      })
    })
    servers.sort((a, b) => (a.flag === 'clean' ? 1 : 0) - (b.flag === 'clean' ? 1 : 0))
    return {
      id: cleanId,
      created: created ? created.toISOString() : null,
      source: 'scans',
      pins: pins.length,
      scans,
      servers,
      cheat: servers.filter((s) => s.flag === 'cheat'),
      reselling: servers.filter((s) => s.flag === 'reselling'),
    }
  }

  const sendWebhook = async (r) => {
    if (!webhook) {
      toast({ type: 'error', title: 'No webhook configured', body: 'Add a Discord webhook in Settings → Integrations.' })
      return
    }
    const flagged = [...r.cheat, ...r.reselling]
    const line = (s) => {
      const roles = s.roles && s.roles.length ? ` — roles: ${s.roles.join(', ')}` : ''
      return `• ${s.name} (${s.flag})${roles}`
    }
    const list = (arr) => (arr.length ? arr.map(line).join('\n').slice(0, 1024) : '—')
    const srcField =
      r.source === 'bot'
        ? { name: 'Servers (member / checked)', value: `${r.found} / ${r.totalServers}`, inline: true }
        : { name: 'Scans on record', value: String(r.scans), inline: true }
    const embed = {
      title: 'Discord ID Server Check',
      color: r.cheat.length ? 0xdc2626 : r.reselling.length ? 0xf59e0b : 0x22c55e,
      fields: [
        { name: 'Discord ID', value: '`' + r.id + '`', inline: true },
        { name: 'Account created', value: r.created ? `<t:${Math.floor(new Date(r.created).getTime() / 1000)}:F>` : 'Unknown', inline: true },
        srcField,
        { name: 'Source', value: r.source === 'bot' ? 'Live bot lookup' : 'Past scan data', inline: true },
        { name: `Servers (${r.servers.length})`, value: list(r.servers) },
        { name: `Flagged (${flagged.length})`, value: list(flagged) },
      ],
      footer: { text: 'Ocean Anti-Cheat — Forensic Tools' },
      timestamp: new Date().toISOString(),
    }
    setBusy(true)
    try {
      const resp = await fetch(webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'Ocean Anti-Cheat', embeds: [embed] }),
      })
      if (resp.ok || resp.status === 204) {
        toast({ type: 'success', title: 'Sent to webhook' })
      } else {
        toast({ type: 'error', title: 'Webhook failed', body: `HTTP ${resp.status}` })
      }
    } catch (e) {
      toast({ type: 'error', title: 'Webhook failed', body: e.message })
    } finally {
      setBusy(false)
    }
  }

  const run = async () => {
    const cleanId = id.trim()
    if (!/^\d{17,20}$/.test(cleanId)) {
      return toast({ type: 'error', title: 'Invalid Discord ID', body: 'Enter a numeric Discord ID (17–20 digits).' })
    }
    let r
    if (botUrl) {
      setBusy(true)
      try {
        r = await liveCheck(cleanId)
      } catch (e) {
        toast({ type: 'error', title: 'Bot lookup failed — using scan data', body: e.message })
        r = build(cleanId)
      } finally {
        setBusy(false)
      }
    } else {
      r = build(cleanId)
    }
    setRes(r)
    await sendWebhook(r)
  }

  return (
    <Card className="p-6 md:p-8">
      <p className="caps-label">Discord</p>
      <h3 className="txt mt-1 text-xl font-semibold">Discord ID Server Checker</h3>
      <p className="muted mb-4 mt-1 text-sm">
        Enter only a Discord ID. With the Discord Server Bot configured (Account → Integrations)
        it checks live which cheat / reselling servers the account is in and which roles it holds.
        Without the bot it falls back to servers detected in past scans for this ID. Reselling and
        cheat servers are flagged and the result is sent to the configured webhook.
      </p>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          value={id}
          onChange={(e) => setId(e.target.value.replace(/[^\d]/g, ''))}
          placeholder="e.g. 145481082291945490"
          className="bd tile txt w-full rounded-lg border px-3 py-2.5 font-mono text-sm focus:outline-none"
        />
        <button
          onClick={run}
          disabled={busy}
          className="flex shrink-0 items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-60"
        >
          <Send size={15} /> {busy ? 'Sending…' : 'Check & Send'}
        </button>
      </div>
      {!webhook && (
        <p className="mt-3 flex items-center gap-2 text-xs text-yellow-500">
          <AlertTriangle size={13} /> No webhook configured in Settings → Integrations.
        </p>
      )}

      {res && (
        <div className="mt-6 space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="tile rounded-lg border p-3">
              <p className="caps-label">Account created</p>
              <p className="txt mt-1 text-sm font-medium">
                {res.created ? new Date(res.created).toLocaleString() : 'Unknown'}
              </p>
            </div>
            <div className="tile rounded-lg border p-3">
              <p className="caps-label">{res.source === 'bot' ? 'Member / checked' : 'Scans on record'}</p>
              <p className="txt mt-1 text-sm font-medium">
                {res.source === 'bot' ? `${res.found} / ${res.totalServers}` : res.scans}
              </p>
            </div>
            <div className="tile rounded-lg border p-3">
              <p className="caps-label">Flagged servers</p>
              <p className="txt mt-1 text-sm font-medium">
                {res.cheat.length + res.reselling.length} / {res.servers.length}
              </p>
            </div>
          </div>

          <p className="muted text-xs">
            Source: {res.source === 'bot' ? 'Live Discord bot lookup' : 'Past scan data'}
          </p>

          {res.servers.length === 0 ? (
            <p className="muted py-8 text-center text-sm">
              {res.source === 'bot'
                ? 'This account is not in any server the bot monitors.'
                : 'No server data on record for this ID. Run a scan with a pin bound to this Discord ID.'}
            </p>
          ) : (
            <div className="space-y-2">
              {res.servers.map((g, i) => {
                const tone =
                  g.flag === 'cheat'
                    ? 'border-red-600/40 bg-red-600/15 text-red-500'
                    : g.flag === 'reselling'
                      ? 'border-orange-500/40 bg-orange-500/15 text-orange-400'
                      : 'bd muted'
                const tag = g.flag === 'cheat' ? 'Cheat Discord' : g.flag === 'reselling' ? 'Reselling Discord' : 'Member'
                return (
                  <div key={i} className="tile rounded-lg border px-4 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-600/15 text-blue-400">
                          <Server size={15} />
                        </span>
                        <div>
                          <p className="txt text-sm font-medium">{g.name}</p>
                          <p className="muted font-mono text-xs">ID: {g.id}</p>
                        </div>
                      </div>
                      <span className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold ${tone}`}>{tag}</span>
                    </div>
                    {g.roles && g.roles.length > 0 && (
                      <div className="bd mt-3 border-t pt-3">
                        <p className="caps-label mb-2">Roles ({g.roles.length})</p>
                        <div className="flex flex-wrap gap-1.5">
                          {g.roles.map((rn, k) => (
                            <span key={k} className="bd tile muted rounded-md border px-2 py-1 text-[11px]">{rn}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

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
          { label: 'Discord ID', icon: MessageSquare },
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
        {tab === 'Discord ID' && <DiscordChecker />}
        {tab === 'File Hash' && <FileHasher />}
      </div>
    </div>
  )
}
