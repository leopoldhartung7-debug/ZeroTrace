import { useEffect, useMemo, useState } from 'react'
import { Wand2, Save, Download, Upload, RotateCcw, Eye, Copy, FileJson, Link, AlertTriangle, Check } from 'lucide-react'
import { PageHeader, Card, Field } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, defaultToolStyle } from '../store.jsx'

// ── colour helpers ──────────────────────────────────────────────────────────

function hexToRgb(hex) {
  const h = hex.replace('#', '')
  return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16) }
}

function rgbToHex(r, g, b) {
  return '#' + [r, g, b]
    .map((x) => Math.min(255, Math.max(0, Math.round(x))).toString(16).padStart(2, '0'))
    .join('')
}

function shiftRgb(hex, delta) {
  const { r, g, b } = hexToRgb(hex)
  return rgbToHex(r + delta, g + delta, b + delta)
}

function relativeLuminance(hex) {
  try {
    const { r, g, b } = hexToRgb(hex)
    return [r, g, b].reduce((acc, c, i) => {
      const s = c / 255
      return acc + (s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)) * [0.2126, 0.7152, 0.0722][i]
    }, 0)
  } catch { return 0 }
}

function contrastRatio(hex1, hex2) {
  const l1 = relativeLuminance(hex1)
  const l2 = relativeLuminance(hex2)
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)
}

// ── preset themes ───────────────────────────────────────────────────────────

const PRESET_THEMES = [
  {
    label: 'Dark Navy',
    colors: { background: '#0d1326', mutedBackground: '#161d33', titlebar: '#070b16', text: '#e8eaf0', mutedText: '#8b93a7', accent: '#38bdf8' },
  },
  {
    label: 'Midnight Purple',
    colors: { background: '#0f0b1e', mutedBackground: '#1a1430', titlebar: '#07050d', text: '#ede8f5', mutedText: '#9b90b8', accent: '#a78bfa' },
  },
  {
    label: 'Forest',
    colors: { background: '#0a150f', mutedBackground: '#111f18', titlebar: '#050a07', text: '#dff0e5', mutedText: '#88aa95', accent: '#22c55e' },
  },
  {
    label: 'Sunset',
    colors: { background: '#1a0e08', mutedBackground: '#261508', titlebar: '#0d0703', text: '#f5ede5', mutedText: '#b09080', accent: '#f97316' },
  },
  {
    label: 'Rose',
    colors: { background: '#1a0a12', mutedBackground: '#26101c', titlebar: '#0d0509', text: '#f5e0ea', mutedText: '#b09098', accent: '#f43f5e' },
  },
]

// ── scanner export helpers ───────────────────────────────────────────────────

function buildScannerDelta(s) {
  const def = defaultToolStyle()
  const delta = {}
  const colorDelta = {}
  for (const [k, v] of Object.entries(s.colors)) {
    if (v.toLowerCase() !== (def.colors[k] ?? '').toLowerCase()) colorDelta[k] = v
  }
  if (Object.keys(colorDelta).length) delta.colors = colorDelta

  const textDelta = {}
  for (const [k, v] of Object.entries(s.text)) {
    if (v !== def.text[k]) textDelta[k] = v
  }
  if (Object.keys(textDelta).length) delta.text = textDelta
  if (s.version !== def.version) delta.version = s.version
  return delta
}

function downloadScannerJson(delta) {
  const blob = new Blob([JSON.stringify(delta, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'zerotrace-ui.json'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ── sub-components ───────────────────────────────────────────────────────────

function ColorField({ label, value, onChange }) {
  return (
    <div>
      <label className="muted mb-1.5 block text-sm">{label}</label>
      <div className="bd tile flex items-center gap-3 rounded-lg border px-3 py-2">
        <input
          type="color"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="h-7 w-9 cursor-pointer rounded border-0 bg-transparent p-0"
        />
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="txt w-full bg-transparent font-mono text-sm focus:outline-none"
        />
      </div>
    </div>
  )
}

function Toggle({ label, checked, onChange, accent }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-3 py-1.5 text-sm"
    >
      <span
        className={`flex h-5 w-5 items-center justify-center rounded border transition-colors ${
          checked
            ? accent
              ? 'border-violet-500 bg-violet-600 text-white'
              : 'border-sky-500 bg-sky-600 text-white'
            : 'bd tile'
        }`}
      >
        {checked && (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <path d="M5 13l4 4L19 7" />
          </svg>
        )}
      </span>
      <span className="txt">{label}</span>
    </button>
  )
}

function GuiPreview({ s }) {
  const c = s.colors
  const [imgErr, setImgErr] = useState(false)
  useEffect(() => setImgErr(false), [s.logoUrl])
  const showCustom = !s.useDefaultLogo && !!s.logoUrl && !imgErr
  return (
    <div className="overflow-hidden rounded-xl border" style={{ borderColor: c.titlebar }}>
      <div className="flex items-center gap-2 px-3 py-2" style={{ background: c.titlebar }}>
        <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
        <span className="h-2.5 w-2.5 rounded-full bg-yellow-500" />
        <span className="h-2.5 w-2.5 rounded-full bg-green-500" />
        <span className="ml-2 text-xs" style={{ color: c.mutedText }}>ZeroTrace FiveM Scanner</span>
      </div>

      <div
        className="relative px-8 py-10"
        style={{
          background: s.gameBackground
            ? `radial-gradient(120% 90% at 50% 0%, ${c.mutedBackground}, ${c.background})`
            : c.background,
          color: c.text,
        }}
      >
        <div className="flex flex-col items-center">
          {showCustom ? (
            <img src={s.logoUrl} alt="logo" onError={() => setImgErr(true)} className="h-[90px] w-[180px] rounded object-fill" />
          ) : (
            <p className="font-mono text-3xl font-bold" style={{ color: c.accent }}>ZEROTRACE</p>
          )}
          {!s.useDefaultLogo && s.logoUrl && imgErr && (
            <p className="mt-1 text-[10px] text-red-400">Logo failed to load — check the URL</p>
          )}
          <p className="mt-1.5 text-xs" style={{ color: c.mutedText }}>{s.version}</p>
        </div>

        <p className="mt-8 text-sm" style={{ color: c.text }}>{s.text.pin}</p>
        <div className="mt-2.5 rounded-md px-4 py-2.5 text-sm tracking-widest" style={{ background: c.mutedBackground, color: c.mutedText }}>
          F1T5F8C0
        </div>

        {[{ label: s.text.scanning, pct: 25 }, { label: s.text.heuristic, pct: 75 }].map((step) => (
          <div key={step.label} className="mt-5 rounded-lg p-5" style={{ background: c.mutedBackground }}>
            <p className="mb-2.5 text-sm" style={{ color: c.text }}>{step.label}</p>
            <div className="h-2.5 w-full overflow-hidden rounded-full" style={{ background: c.background }}>
              <div className="h-full rounded-full transition-all duration-300" style={{ width: `${step.pct}%`, background: c.accent }} />
            </div>
            <p className="mt-1.5 text-right text-xs" style={{ color: c.mutedText }}>{step.pct}%</p>
          </div>
        ))}

        <p className="mt-5 text-center text-xs" style={{ color: c.mutedText }}>{s.text.finished}</p>
      </div>
    </div>
  )
}

const PREFIX = 'ZEROTRACEUI1.'
const LEGACY_PREFIX = 'OCEANUI1.'

// ── main component ───────────────────────────────────────────────────────────

export default function ToolDesigner({ embedded = false }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const saved = state.toolStyle || defaultToolStyle()

  const [s, setS] = useState(saved)
  const [importText, setImportText] = useState('')
  const [importUrl, setImportUrl] = useState('')
  const [urlLoading, setUrlLoading] = useState(false)
  const [harmonyMode, setHarmonyMode] = useState(false)

  const savedKey = useMemo(() => JSON.stringify(saved), [saved])
  useEffect(() => {
    setS((cur) => (JSON.stringify(cur) === savedKey ? cur : JSON.parse(savedKey)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedKey])

  const dirty = useMemo(() => JSON.stringify(s) !== savedKey, [s, savedKey])

  const set = (patch) => setS((cur) => ({ ...cur, ...patch }))

  const setColor = (k, v) => {
    if (harmonyMode && k === 'background') {
      setS((cur) => ({
        ...cur,
        colors: {
          ...cur.colors,
          background: v,
          mutedBackground: shiftRgb(v, 15),
          titlebar: shiftRgb(v, -5),
        },
      }))
    } else {
      setS((cur) => ({ ...cur, colors: { ...cur.colors, [k]: v } }))
    }
  }

  const setText = (k, v) => setS((cur) => ({ ...cur, text: { ...cur.text, [k]: v } }))

  const exportCode = useMemo(
    () => PREFIX + btoa(unescape(encodeURIComponent(JSON.stringify(s)))),
    [s],
  )

  const saveAll = () => {
    dispatch({ type: 'save-tool-style', style: s })
    const delta = buildScannerDelta(s)
    const hasDelta = Object.keys(delta).length > 0
    if (hasDelta) downloadScannerJson(delta)
    toast({
      type: 'success',
      title: 'Gespeichert',
      body: hasDelta
        ? 'Stil gespeichert — zerotrace-ui.json heruntergeladen. Neben ZeroTrace.exe ablegen.'
        : 'Stil gespeichert (keine Abweichung von den Standardwerten)',
    })
  }

  const parseStyleCode = (raw) => {
    const b64 = raw.startsWith(PREFIX)
      ? raw.slice(PREFIX.length)
      : raw.startsWith(LEGACY_PREFIX)
        ? raw.slice(LEGACY_PREFIX.length)
        : raw
    return JSON.parse(decodeURIComponent(escape(atob(b64))))
  }

  const doImport = () => {
    try {
      const obj = parseStyleCode(importText.trim())
      setS({ ...defaultToolStyle(), ...obj })
      toast({ type: 'success', title: 'Stil geladen', body: 'Alles speichern zum Übernehmen' })
      setImportText('')
    } catch (e) {
      toast({ type: 'error', title: 'Ungültiger Stil-Code', body: e.message })
    }
  }

  const doImportUrl = async () => {
    setUrlLoading(true)
    try {
      const res = await fetch(importUrl.trim())
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = (await res.text()).trim()
      let obj
      try {
        obj = parseStyleCode(text)
      } catch {
        obj = JSON.parse(text)
      }
      setS({ ...defaultToolStyle(), ...obj })
      toast({ type: 'success', title: 'Stil geladen', body: 'Alles speichern zum Übernehmen' })
      setImportUrl('')
    } catch (e) {
      toast({ type: 'error', title: 'Import fehlgeschlagen', body: e.message })
    } finally {
      setUrlLoading(false)
    }
  }

  // Contrast checks for the three most important pairs
  const contrastChecks = useMemo(() => [
    { label: 'Text / Hintergrund',     fg: s.colors.text,      bg: s.colors.background },
    { label: 'Gedämpft / Hintergrund', fg: s.colors.mutedText, bg: s.colors.background },
    { label: 'Text / Karten-BG',       fg: s.colors.text,      bg: s.colors.mutedBackground },
  ].map(({ label, fg, bg }) => ({ label, ratio: contrastRatio(fg, bg) })), [s.colors])

  const anyContrastFail = contrastChecks.some((c) => c.ratio < 4.5)

  return (
    <div>
      {!embedded && (
        <PageHeader
          icon={Wand2}
          kicker="Dashboard / Tool Designer"
          title="Tool Designer"
          subtitle="Passe das Aussehen des FiveM-Scanner-GUIs an. Änderungen werden gespeichert und erzeugen eine zerotrace-ui.json, die der Scanner automatisch lädt."
        />
      )}

      <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(340px,420px)]">
        {/* Options */}
        <Card className="p-6 md:p-8">
          <h3 className="txt mb-6 text-lg font-semibold">Alle Optionen</h3>

          {/* ── Preset themes ── */}
          <p className="caps-label mb-4">Vorgefertigte Themes</p>
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
            {PRESET_THEMES.map((theme) => (
              <button
                key={theme.label}
                onClick={() => set({ colors: theme.colors })}
                title={theme.label}
                className="bd hoverable group flex flex-col items-center gap-2 rounded-xl border px-2 py-3 text-center transition-colors hover:border-sky-500"
              >
                <div className="flex gap-1">
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.background }} />
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.accent }} />
                  <span className="h-3 w-3 rounded-full border border-white/10" style={{ background: theme.colors.text }} />
                </div>
                <span className="txt text-[11px] font-medium leading-tight">{theme.label}</span>
              </button>
            ))}
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Logo ── */}
          <p className="caps-label mb-4">Logo</p>
          <div className="space-y-4">
            <Toggle label="ZeroTrace-Logo verwenden" checked={s.useDefaultLogo} onChange={(v) => set({ useDefaultLogo: v })} />
            <Field label="Eigene Logo-URL (gestreckt auf 600×300)">
              <input
                value={s.logoUrl}
                onChange={(e) => {
                  const url = e.target.value
                  set({ logoUrl: url, useDefaultLogo: url.trim() ? false : s.useDefaultLogo })
                }}
                placeholder="https://cdn.example.com/logo.png"
                className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none"
              />
              {s.logoUrl && !s.useDefaultLogo && (
                <p className="muted mt-1.5 text-xs">Eigenes Logo ist in der Vorschau aktiv.</p>
              )}
            </Field>
            <Toggle label="Spiel-Hintergrund" checked={s.gameBackground} onChange={(v) => set({ gameBackground: v })} />
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Colours ── */}
          <div className="mb-4 flex items-center justify-between">
            <p className="caps-label">Farben</p>
            <Toggle
              label="Harmonie-Modus"
              checked={harmonyMode}
              onChange={setHarmonyMode}
              accent
            />
          </div>
          {harmonyMode && (
            <p className="muted mb-4 rounded-lg bg-violet-500/10 px-3 py-2 text-xs text-violet-400">
              Harmonie-Modus aktiv — Karten-BG und Titelleiste werden automatisch aus der Hauptfarbe abgeleitet.
            </p>
          )}
          <div className="grid gap-5 sm:grid-cols-2">
            <ColorField label="Textfarbe" value={s.colors.text} onChange={(v) => setColor('text', v)} />
            <ColorField label="Gedämpfte Textfarbe" value={s.colors.mutedText} onChange={(v) => setColor('mutedText', v)} />
            <ColorField label="Hintergrundfarbe" value={s.colors.background} onChange={(v) => setColor('background', v)} />
            <ColorField
              label={harmonyMode ? 'Karten-BG (automatisch)' : 'Karten-Hintergrundfarbe'}
              value={s.colors.mutedBackground}
              onChange={(v) => setColor('mutedBackground', v)}
            />
            <ColorField
              label={harmonyMode ? 'Titelleiste (automatisch)' : 'Titelleistenfarbe'}
              value={s.colors.titlebar}
              onChange={(v) => setColor('titlebar', v)}
            />
            <ColorField label="Akzentfarbe" value={s.colors.accent} onChange={(v) => setColor('accent', v)} />
          </div>

          {/* Contrast check */}
          <div className={`bd mt-5 rounded-lg border p-4 ${anyContrastFail ? 'border-yellow-500/30 bg-yellow-500/5' : ''}`}>
            <p className="caps-label mb-3">Kontrast-Check (WCAG AA ≥ 4,5:1)</p>
            <div className="space-y-2">
              {contrastChecks.map(({ label, ratio }) => {
                const pass = ratio >= 4.5
                return (
                  <div key={label} className="flex items-center justify-between text-xs">
                    <span className="muted">{label}</span>
                    <span className={`flex items-center gap-1.5 font-mono font-semibold ${pass ? 'text-green-500' : 'text-yellow-400'}`}>
                      {ratio.toFixed(1)}:1
                      {pass ? <Check size={11} /> : <AlertTriangle size={11} />}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="bd my-7 border-t" />

          {/* ── Text ── */}
          <p className="caps-label mb-4">Texte</p>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="PIN-Eingabe-Beschriftung">
              <input value={s.text.pin} onChange={(e) => setText('pin', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Scan-Text">
              <input value={s.text.scanning} onChange={(e) => setText('scanning', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Heuristik-Text">
              <input value={s.text.heuristic} onChange={(e) => setText('heuristic', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Abschluss-Text">
              <input value={s.text.finished} onChange={(e) => setText('finished', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Versionsbezeichnung">
              <input value={s.version} onChange={(e) => set({ version: e.target.value })} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
          </div>
        </Card>

        {/* Right column */}
        <div className="space-y-6 lg:sticky lg:top-6 lg:self-start">
          <div>
            <button
              onClick={saveAll}
              disabled={!dirty}
              className={`flex w-full items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold transition-colors ${
                dirty ? 'bg-sky-600 text-white hover:bg-sky-500' : 'bd tile muted cursor-default'
              }`}
            >
              <Save size={17} /> {dirty ? 'Alles speichern' : 'Gespeichert'}
            </button>
            {dirty ? (
              <p className="mt-2 flex items-center justify-center gap-1.5 text-xs text-yellow-500">
                <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
                Ungespeicherte Änderungen — Alles speichern drücken
              </p>
            ) : (
              <p className="muted mt-2 text-center text-xs">Alle Änderungen gespeichert</p>
            )}
          </div>

          <Card className="p-6">
            <h3 className="txt mb-5 flex items-center gap-2 text-lg font-semibold">
              <Eye size={18} /> Vorschau GUI
            </h3>
            <GuiPreview s={s} />
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Upload size={15} /> Stil importieren
            </h4>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder="Stil-Code einfügen…"
              rows={3}
              className="bd tile txt w-full rounded-lg border p-3 font-mono text-[11px] focus:outline-none"
            />
            <button
              onClick={doImport}
              className="bd txt mt-2 w-full rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              Stil-Code importieren
            </button>

            <div className="bd my-3 border-t" />

            <p className="muted mb-2 flex items-center gap-1.5 text-xs font-medium">
              <Link size={11} /> Per URL importieren
            </p>
            <div className="flex gap-2">
              <input
                value={importUrl}
                onChange={(e) => setImportUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && importUrl.trim() && doImportUrl()}
                placeholder="https://example.com/style.txt"
                className="bd tile txt min-w-0 flex-1 rounded-lg border px-3 py-2 text-xs focus:outline-none"
              />
              <button
                onClick={doImportUrl}
                disabled={!importUrl.trim() || urlLoading}
                className="bd txt rounded-lg border px-3 py-2 text-xs font-medium hover:border-sky-500 disabled:opacity-40"
              >
                {urlLoading ? '…' : 'Laden'}
              </button>
            </div>
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Download size={15} /> Stil exportieren
            </h4>
            <div className="bd tile max-h-40 overflow-y-auto break-all rounded-lg border p-3 font-mono text-[11px]">
              <span className="muted">{exportCode}</span>
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(exportCode)
                toast({ type: 'success', title: 'Stil-Code kopiert' })
              }}
              className="bd txt mt-3 flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              <Copy size={14} /> Code kopieren
            </button>
            <button
              onClick={() => {
                setS(defaultToolStyle())
                toast({ type: 'info', title: 'Standardwerte geladen', body: 'Alles speichern zum Übernehmen' })
              }}
              className="muted hover:txt mt-2 flex w-full items-center justify-center gap-2 py-1.5 text-xs"
            >
              <RotateCcw size={13} /> Auf Standard zurücksetzen
            </button>
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-1 flex items-center gap-2 text-sm font-semibold">
              <FileJson size={15} /> Für Scanner exportieren
            </h4>
            <p className="muted mb-3 text-xs">
              Lädt <code className="txt">zerotrace-ui.json</code> herunter — nur Felder, die vom Standard abweichen.
              Datei neben <code className="txt">ZeroTrace.exe</code> ablegen, Scanner neu starten.
            </p>
            <button
              onClick={() => {
                const delta = buildScannerDelta(s)
                if (!Object.keys(delta).length) {
                  toast({ type: 'info', title: 'Keine Änderungen', body: 'Alle Werte entsprechen den Standardwerten' })
                  return
                }
                downloadScannerJson(delta)
                toast({ type: 'success', title: 'Heruntergeladen', body: 'zerotrace-ui.json neben ZeroTrace.exe ablegen' })
              }}
              className="bd txt flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-sky-500"
            >
              <Download size={14} /> zerotrace-ui.json herunterladen
            </button>
          </Card>
        </div>
      </div>
    </div>
  )
}
