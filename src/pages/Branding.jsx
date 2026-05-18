import { useToast } from '../components/ui.jsx'

const COLORS = [
  { name: 'Ocean Blue', hex: '#2563eb' },
  { name: 'Accent', hex: '#3b82f6' },
  { name: 'Background', hex: '#0a0a0a' },
  { name: 'Panel', hex: '#111111' },
  { name: 'Success', hex: '#22c55e' },
  { name: 'Danger', hex: '#dc2626' },
]

export default function Branding() {
  const toast = useToast()
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-neutral-500">Brand kit</p>
      <h1 className="mt-2 text-4xl font-bold tracking-tight md:text-5xl">Branding</h1>
      <p className="mt-3 text-neutral-400">Logos, colours and usage guidelines for Ocean Anti-Cheat.</p>

      <div className="mt-10 grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
          <p className="text-sm font-semibold text-white">Logo</p>
          <div className="mt-5 flex items-center justify-center gap-4 rounded-xl border border-white/10 bg-black py-12">
            <span className="font-mono text-4xl font-bold text-white">{'(*>'}</span>
            <span className="text-3xl font-semibold text-white">ocean</span>
          </div>
          <button
            onClick={() => toast({ type: 'success', title: 'Copied', body: 'Logo mark: (*>' })}
            className="mt-4 w-full rounded-lg border border-white/10 py-2.5 text-sm font-medium text-neutral-300 hover:border-blue-500"
          >
            Copy logo mark
          </button>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
          <p className="text-sm font-semibold text-white">Colours</p>
          <div className="mt-5 grid grid-cols-2 gap-3">
            {COLORS.map((c) => (
              <button
                key={c.hex}
                onClick={() => {
                  navigator.clipboard?.writeText(c.hex)
                  toast({ type: 'success', title: 'Copied', body: `${c.name} ${c.hex}` })
                }}
                className="flex items-center gap-3 rounded-lg border border-white/10 p-3 text-left hover:border-white/20"
              >
                <span className="h-9 w-9 rounded-md border border-white/10" style={{ background: c.hex }} />
                <span>
                  <span className="block text-sm text-white">{c.name}</span>
                  <span className="block font-mono text-xs text-neutral-500">{c.hex}</span>
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/[0.02] p-8">
        <p className="text-sm font-semibold text-white">Usage guidelines</p>
        <ul className="mt-4 space-y-2 text-sm text-neutral-400">
          <li>• Keep clear space around the logo equal to the height of the mark.</li>
          <li>• Do not stretch, recolour or add effects to the logo.</li>
          <li>• Use the Ocean Blue on dark backgrounds for primary actions.</li>
          <li>• Reference “Ocean Anti-Cheat” in full on first mention.</li>
        </ul>
      </div>
    </div>
  )
}
