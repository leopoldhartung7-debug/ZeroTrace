import { useEffect, useMemo, useState } from 'react'
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
          checked ? 'border-teal-500 bg-teal-600 text-white' : 'bd tile'
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
  const [imgErr, setImgErr] = useState(false)
  useEffect(() => setImgErr(false), [s.logoUrl])
  const showCustom = !s.useDefaultLogo && !!s.logoUrl && !imgErr
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
          ZeroTrace FiveM Scanner
        </span>
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
            <img
              src={s.logoUrl}
              alt="logo"
              onError={() => setImgErr(true)}
              className="h-[90px] w-[180px] rounded object-fill"
            />
          ) : (
            <p className="font-mono text-3xl font-bold" style={{ color: c.accent }}>
              ZEROTRACE
            </p>
          )}
          {!s.useDefaultLogo && s.logoUrl && imgErr && (
            <p className="mt-1 text-[10px] text-red-400">Logo failed to load — check the URL</p>
          )}
          <p className="mt-1.5 text-xs" style={{ color: c.mutedText }}>
            {s.version}
          </p>
        </div>

        <p className="mt-8 text-sm" style={{ color: c.text }}>
          {s.text.pin}
        </p>
        <div
          className="mt-2.5 rounded-md px-4 py-2.5 text-sm tracking-widest"
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
            className="mt-5 rounded-lg p-5"
            style={{ background: c.mutedBackground }}
          >
            <p className="mb-2.5 text-sm" style={{ color: c.text }}>
              {step.label}
            </p>
            <div className="h-2.5 w-full overflow-hidden rounded-full" style={{ background: c.background }}>
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{ width: `${step.pct}%`, background: c.accent }}
              />
            </div>
            <p className="mt-1.5 text-right text-xs" style={{ color: c.mutedText }}>
              {step.pct}%
            </p>
          </div>
        ))}

        <p className="mt-5 text-center text-xs" style={{ color: c.mutedText }}>
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
  const saved = state.toolStyle || defaultToolStyle()

  // Local draft — edits stay here and only persist on "Save All".
  const [s, setS] = useState(saved)
  const [importText, setImportText] = useState('')

  // Re-sync the draft if the saved style changes externally
  // (e.g. backup import) and there are no pending edits.
  const savedKey = useMemo(() => JSON.stringify(saved), [saved])
  useEffect(() => {
    setS((cur) => (JSON.stringify(cur) === savedKey ? cur : JSON.parse(savedKey)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedKey])

  const dirty = useMemo(() => JSON.stringify(s) !== savedKey, [s, savedKey])

  const set = (patch) => setS((cur) => ({ ...cur, ...patch }))
  const setColor = (k, v) => setS((cur) => ({ ...cur, colors: { ...cur.colors, [k]: v } }))
  const setText = (k, v) => setS((cur) => ({ ...cur, text: { ...cur.text, [k]: v } }))

  const exportCode = useMemo(
    () => PREFIX + btoa(unescape(encodeURIComponent(JSON.stringify(s)))),
    [s],
  )

  const saveAll = () => {
    dispatch({ type: 'save-tool-style', style: s })
    toast({ type: 'success', title: 'Saved', body: 'Tool design stored' })
  }

  const doImport = () => {
    try {
      const raw = importText.trim()
      const b64 = raw.startsWith(PREFIX) ? raw.slice(PREFIX.length) : raw
      const obj = JSON.parse(decodeURIComponent(escape(atob(b64))))
      setS({ ...defaultToolStyle(), ...obj })
      toast({ type: 'success', title: 'Style loaded', body: 'Press Save All to apply' })
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

      <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(340px,420px)]">
        {/* Options */}
        <Card className="p-6 md:p-8">
          <h3 className="txt mb-6 text-lg font-semibold">All Options</h3>

          <p className="caps-label mb-4">Logo</p>
          <div className="space-y-4">
            <Toggle
              label="Use ZeroTrace logo"
              checked={s.useDefaultLogo}
              onChange={(v) => set({ useDefaultLogo: v })}
            />
            <Field label="Custom Logo URL (stretched to 600×300)">
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
                <p className="muted mt-1.5 text-xs">Custom logo is active in the preview.</p>
              )}
            </Field>
            <Toggle label="Game background" checked={s.gameBackground} onChange={(v) => set({ gameBackground: v })} />
          </div>

          <div className="bd my-7 border-t" />
          <p className="caps-label mb-4">Colours</p>
          <div className="grid gap-5 sm:grid-cols-2">
            <ColorField label="Text colour" value={s.colors.text} onChange={(v) => setColor('text', v)} />
            <ColorField label="Muted text colour" value={s.colors.mutedText} onChange={(v) => setColor('mutedText', v)} />
            <ColorField label="Background colour" value={s.colors.background} onChange={(v) => setColor('background', v)} />
            <ColorField label="Muted background colour" value={s.colors.mutedBackground} onChange={(v) => setColor('mutedBackground', v)} />
            <ColorField label="Titlebar colour" value={s.colors.titlebar} onChange={(v) => setColor('titlebar', v)} />
            <ColorField label="Accent colour" value={s.colors.accent} onChange={(v) => setColor('accent', v)} />
          </div>

          <div className="bd my-7 border-t" />
          <p className="caps-label mb-4">Text</p>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Enter pin text">
              <input value={s.text.pin} onChange={(e) => setText('pin', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Scanning process text">
              <input value={s.text.scanning} onChange={(e) => setText('scanning', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Heuristic analysis text">
              <input value={s.text.heuristic} onChange={(e) => setText('heuristic', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Finished text">
              <input value={s.text.finished} onChange={(e) => setText('finished', e.target.value)} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
            <Field label="Version label">
              <input value={s.version} onChange={(e) => set({ version: e.target.value })} className="bd tile txt w-full rounded-lg border px-4 py-3 text-sm focus:outline-none" />
            </Field>
          </div>
        </Card>

        {/* Right column — sticky, so the live preview always reflects
            the current options while you scroll through them */}
        <div className="space-y-6 lg:sticky lg:top-6 lg:self-start">
          <div>
            <button
              onClick={saveAll}
              disabled={!dirty}
              className={`flex w-full items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold transition-colors ${
                dirty
                  ? 'bg-teal-600 text-white hover:bg-teal-500'
                  : 'bd tile muted cursor-default'
              }`}
            >
              <Save size={17} /> {dirty ? 'Save All' : 'Saved'}
            </button>
            {dirty ? (
              <p className="mt-2 flex items-center justify-center gap-1.5 text-xs text-yellow-500">
                <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
                Unsaved changes — press Save All to apply
              </p>
            ) : (
              <p className="muted mt-2 text-center text-xs">All changes saved</p>
            )}
          </div>

          <Card className="p-6">
            <h3 className="txt mb-5 flex items-center gap-2 text-lg font-semibold">
              <Eye size={18} /> View Final GUI
            </h3>
            <GuiPreview s={s} />
          </Card>

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
              className="bd txt mt-3 w-full rounded-lg border py-2 text-sm font-medium hover:border-teal-500"
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
              className="bd txt mt-3 flex w-full items-center justify-center gap-2 rounded-lg border py-2 text-sm font-medium hover:border-teal-500"
            >
              <Copy size={14} /> Copy code
            </button>
            <button
              onClick={() => {
                setS(defaultToolStyle())
                toast({ type: 'info', title: 'Defaults loaded', body: 'Press Save All to apply' })
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
