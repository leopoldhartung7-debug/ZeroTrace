import { useMemo, useState } from 'react'
import { Wand2, Save, Download, Upload, RotateCcw, Eye, Copy } from 'lucide-react'
import { PageHeader, Card, Field } from '../components/kit.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, defaultToolStyle } from '../store.jsx'

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

function Toggle({ label, checked, onChange }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-3 py-1.5 text-sm"
    >
      <span
        className={`flex h-5 w-5 items-center justify-center rounded border transition-colors ${
          checked ? 'border-blue-500 bg-blue-600 text-white' : 'bd tile'
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

// Faithful-ish mock of the native scanner window using the chosen style.
function GuiPreview({ s }) {
  const c = s.colors
  return (
    <div className="overflow-hidden rounded-xl border" style={{ borderColor: c.titlebar }}>
      <div
        className="flex items-center gap-2 px-3 py-2"
        style={{ background: c.titlebar }}
      >
        <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
        <span className="h-2.5 w-2.5 rounded-full bg-yellow-500" />
        <span className="h-2.5 w-2.5 rounded-full bg-green-500" />
        <span className="ml-2 text-xs" style={{ color: c.mutedText }}>
          Ocean FiveM Scanner
        </span>
      </div>

      <div
        className="relative px-6 py-7"
        style={{
          background: s.gameBackground
            ? `radial-gradient(120% 90% at 50% 0%, ${c.mutedBackground}, ${c.background})`
            : c.background,
          color: c.text,
        }}
      >
        <div className="flex flex-col items-center">
          {s.useDefaultLogo || !s.logoUrl ? (
            <p className="font-mono text-2xl font-bold" style={{ color: c.accent }}>
              {'(*>'} OCEAN
            </p>
          ) : (
            <img src={s.logoUrl} alt="logo" className="h-12 object-contain" />
          )}
          <p className="mt-1 text-xs" style={{ color: c.mutedText }}>
            {s.version}
          </p>
        </div>

        <p className="mt-6 text-sm" style={{ color: c.text }}>
          {s.text.pin}
        </p>
        <div
          className="mt-2 rounded-md px-3 py-2 text-sm"
          style={{ background: c.mutedBackground, color: c.mutedText }}
        >
          F1T5F8C0
        </div>

        {[
          { label: s.text.scanning, pct: 25 },
          { label: s.text.heuristic, pct: 75 },
        ].map((step) => (
          <div
            key={step.label}
            className="mt-4 rounded-lg p-4"
            style={{ background: c.mutedBackground }}
          >
            <p className="mb-2 text-sm" style={{ color: c.text }}>
              {step.label}
            </p>
            <div className="h-2 w-full overflow-hidden rounded-full" style={{ background: c.background }}>
              <div
                className="h-full rounded-full"
                style={{ width: `${step.pct}%`, background: c.accent }}
              />
            </div>
            <p className="mt-1 text-right text-xs" style={{ color: c.mutedText }}>
              {step.pct}%
            </p>
          </div>
        ))}

        <p className="mt-4 text-center text-xs" style={{ color: c.mutedText }}>
          {s.text.finished}
        </p>
      </div>
    </div>
  )
}

const PREFIX = 'OCEANUI1.'

export default function ToolDesigner({ embedded = false }) {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const s = state.toolStyle || defaultToolStyle()
  const [importText, setImportText] = useState('')

  const set = (patch) => dispatch({ type: 'set-tool-style', patch })
  const setColor = (k, v) => set({ colors: { ...s.colors, [k]: v } })
  const setText = (k, v) => set({ text: { ...s.text, [k]: v } })

  const exportCode = useMemo(
    () => PREFIX + btoa(unescape(encodeURIComponent(JSON.stringify(s)))),
    [s],
  )

  const doImport = () => {
    try {
      const raw = importText.trim()
      const b64 = raw.startsWith(PREFIX) ? raw.slice(PREFIX.length) : raw
      const obj = JSON.parse(decodeURIComponent(escape(atob(b64))))
      dispatch({ type: 'import-tool-style', style: obj })
      toast({ type: 'success', title: 'Style imported' })
      setImportText('')
    } catch (e) {
      toast({ type: 'error', title: 'Invalid style code', body: e.message })
    }
  }

  return (
    <div>
      {!embedded && (
        <PageHeader
          icon={Wand2}
          kicker="Dashboard / Tool Designer"
          title="Tool Designer"
          subtitle="Customize the look of the FiveM Scanner GUI. Changes save automatically and produce a style code the scanner can load."
        />
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_minmax(320px,420px)_280px]">
        {/* Options */}
        <Card className="p-6">
          <h3 className="txt mb-5 text-lg font-semibold">All Options</h3>

          <p className="caps-label mb-3">Logo</p>
          <div className="space-y-1">
            <Toggle label="Use Ocean logo" checked={s.useDefaultLogo} onChange={(v) => set({ useDefaultLogo: v })} />
            <Field label="Custom Logo URL (stretched to 600×300)">
              <input
                value={s.logoUrl}
                onChange={(e) => set({ logoUrl: e.target.value })}
                disabled={s.useDefaultLogo}
                placeholder="https://cdn.example.com/logo.png"
                className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none disabled:opacity-50"
              />
            </Field>
            <Toggle label="Game background" checked={s.gameBackground} onChange={(v) => set({ gameBackground: v })} />
          </div>

          <p className="caps-label mb-3 mt-6">Colours</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <ColorField label="Text colour" value={s.colors.text} onChange={(v) => setColor('text', v)} />
            <ColorField label="Muted text colour" value={s.colors.mutedText} onChange={(v) => setColor('mutedText', v)} />
            <ColorField label="Background colour" value={s.colors.background} onChange={(v) => setColor('background', v)} />
            <ColorField label="Muted background colour" value={s.colors.mutedBackground} onChange={(v) => setColor('mutedBackground', v)} />
            <ColorField label="Titlebar colour" value={s.colors.titlebar} onChange={(v) => setColor('titlebar', v)} />
            <ColorField label="Accent colour" value={s.colors.accent} onChange={(v) => setColor('accent', v)} />
          </div>

          <p className="caps-label mb-3 mt-6">Text</p>
          <div className="space-y-4">
            <Field label="Enter pin text">
              <input value={s.text.pin} onChange={(e) => setText('pin', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none" />
            </Field>
            <Field label="Scanning process text">
              <input value={s.text.scanning} onChange={(e) => setText('scanning', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none" />
            </Field>
            <Field label="Heuristic analysis text">
              <input value={s.text.heuristic} onChange={(e) => setText('heuristic', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none" />
            </Field>
            <Field label="Finished text">
              <input value={s.text.finished} onChange={(e) => setText('finished', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none" />
            </Field>
            <Field label="Version label">
              <input value={s.version} onChange={(e) => set({ version: e.target.value })} className="bd tile txt w-full rounded-lg border px-4 py-2.5 text-sm focus:outline-none" />
            </Field>
          </div>
        </Card>

        {/* Live preview */}
        <Card className="h-fit p-6">
          <h3 className="txt mb-5 flex items-center gap-2 text-lg font-semibold">
            <Eye size={18} /> View Final GUI
          </h3>
          <GuiPreview s={s} />
        </Card>

        {/* Save / Import / Export */}
        <div className="space-y-6">
          <button
            onClick={() => toast({ type: 'success', title: 'Saved', body: 'Style stored locally' })}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white hover:bg-blue-500"
          >
            <Save size={17} /> Save All
          </button>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Upload size={15} /> Import Style
            </h4>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder="Paste a style code…"
              rows={5}
              className="bd tile txt w-full rounded-lg border p-3 font-mono text-[11px] focus:outline-none"
            />
            <button
              onClick={doImport}
              className="bd txt mt-3 w-full rounded-lg border py-2 text-sm font-medium hover:border-blue-500"
            >
              Import Style
            </button>
          </Card>

          <Card className="p-5">
            <h4 className="txt mb-3 flex items-center gap-2 text-sm font-semibold">
              <Download size={15} /> Export Style
            </h4>
            <div className="bd tile max-h-40 overflow-y-auto break-all rounded-lg border p-3 font-mono text-[11px]">
              <span className="muted">{exportCode}</span>
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(exportCode)
                toast({ type: 'success', title: 'Style code copied' })
              }}
              className="bd txt mt-3 flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-blue-500"
            >
              <Copy size={14} /> Copy code
            </button>
            <button
              onClick={() => {
                dispatch({ type: 'reset-tool-style' })
                toast({ type: 'success', title: 'Reset to defaults' })
              }}
              className="muted hover:txt mt-2 flex w-full items-center justify-center gap-2 py-1.5 text-xs"
            >
              <RotateCcw size={13} /> Reset to defaults
            </button>
          </Card>
        </div>
      </div>
    </div>
  )
}
