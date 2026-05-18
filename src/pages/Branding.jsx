import { useState } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useToast } from '../components/ui.jsx'

/* ---- asset generation (functional downloads, no backend) ---- */
function triggerDownload(blob, filename) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}
function downloadSVG(text, filename, fg = '#ffffff', bg = 'none') {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="600" height="300" viewBox="0 0 600 300">
  <rect width="600" height="300" fill="${bg}"/>
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="ui-monospace, Menlo, monospace" font-size="110" font-weight="700" fill="${fg}">${text}</text>
</svg>`
  triggerDownload(new Blob([svg], { type: 'image/svg+xml' }), filename)
}
function downloadPNG(draw, w, h, filename) {
  const c = document.createElement('canvas')
  c.width = w
  c.height = h
  const ctx = c.getContext('2d')
  draw(ctx, w, h)
  c.toBlob((b) => b && triggerDownload(b, filename), 'image/png')
}

const COLORS = [
  { hex: '#3A63EC', rgb: 'rgb(58, 99, 236)' },
  { hex: '#F1F2F2', rgb: 'rgb(241, 242, 242)' },
  { hex: '#DFDFDF', rgb: 'rgb(223, 223, 223)' },
]
const WEIGHTS = [
  { w: 'Regular', m: '400 · BODY', c: 'font-normal' },
  { w: 'Medium', m: '500 · UI', c: 'font-medium' },
  { w: 'Semibold', m: '600 · SUBTITLES', c: 'font-semibold' },
  { w: 'Bold', m: '700 · TITLES', c: 'font-bold' },
]
const WALLPAPERS = [
  { title: 'Desktop', label: 'logo-xl' },
  { title: 'Desktop', label: 'logo-sm' },
  { title: 'Desktop', label: 'tagline' },
  { title: 'Desktop (GIF)', label: 'think' },
]

function Section({ n, label, title, desc, children }) {
  return (
    <section className="grid gap-12 border-t border-white/10 py-20 lg:grid-cols-2">
      <div>
        <p className="text-xs font-semibold tracking-[0.3em] text-neutral-600">
          {n} — {label}
        </p>
        <h2 className="mt-6 text-5xl font-bold tracking-tight md:text-6xl">{title}</h2>
        <p className="mt-6 max-w-xs leading-relaxed text-neutral-400">{desc}</p>
      </div>
      <div className="flex items-center">{children}</div>
    </section>
  )
}

export default function Branding() {
  const toast = useToast()
  const [logo, setLogo] = useState(0)
  const LOGOS = ['(*>', ')<(((*>']

  const copy = (c) => {
    navigator.clipboard?.writeText(c.hex)
    toast({ type: 'success', title: 'Copied', body: `${c.hex} · ${c.rgb}` })
  }

  const wpDraw = (kind) => (ctx, w, h) => {
    ctx.fillStyle = '#000000'
    ctx.fillRect(0, 0, w, h)
    ctx.fillStyle = '#ffffff'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    if (kind === 'think') {
      ctx.font = `bold ${Math.floor(h / 6)}px Inter, sans-serif`
      ctx.fillText('THINK', w / 2, h / 2)
    } else if (kind === 'tagline') {
      ctx.font = `bold ${Math.floor(h / 12)}px Inter, sans-serif`
      ctx.fillText('Think. Scan. Find.', w / 2, h / 2)
    } else {
      ctx.font = `bold ${Math.floor(h / (kind === 'logo-sm' ? 6 : 3))}px ui-monospace, monospace`
      ctx.fillText('(*>', w / 2, h / 2)
    }
  }

  return (
    <div className="relative">
      <div
        className="pointer-events-none fixed inset-0 -z-10"
        style={{ background: 'radial-gradient(60% 70% at 75% 35%, rgba(37,99,235,0.22), transparent 60%)' }}
      />

      {/* Hero */}
      <section className="py-20">
        <p className="text-xs font-semibold tracking-[0.3em] text-neutral-500">BRANDING</p>
        <h1 className="mt-6 text-7xl font-bold leading-[0.95] tracking-tight md:text-8xl">
          Think.
          <br />
          Scan.
          <br />
          <span className="text-neutral-600">Find.</span>
        </h1>
        <p className="mt-10 max-w-md leading-relaxed text-neutral-400">
          Logo, color, type, and assets built with clarity and hierarchy in mind.
        </p>
      </section>

      {/* 01 Logo */}
      <Section n="01" label="IDENTITY" title="Logo" desc="Fixed aspect ratio. No effects or distortion. Same geometry in both backgrounds.">
        <div className="grid w-full gap-10 sm:grid-cols-2">
          <div>
            <div className="flex items-center justify-center gap-4">
              <button onClick={() => setLogo((l) => (l + 1) % 2)} className="rounded-md border border-white/10 p-2 hover:border-white/30">
                <ChevronLeft size={18} />
              </button>
              <span className="font-mono text-5xl font-bold">{LOGOS[logo]}</span>
              <button onClick={() => setLogo((l) => (l + 1) % 2)} className="rounded-md border border-white/10 bg-white/5 p-2 hover:border-white/30">
                <ChevronRight size={18} />
              </button>
            </div>
            <div className="mt-5 flex justify-center gap-1.5">
              {[0, 1].map((i) => (
                <span key={i} className={`h-1 rounded-full ${i === logo ? 'w-6 bg-white' : 'w-1.5 bg-white/30'}`} />
              ))}
            </div>
            <div className="mt-7 grid grid-cols-2 gap-x-6 gap-y-2 text-center text-[11px] font-semibold tracking-[0.15em] text-neutral-400">
              <button onClick={() => downloadSVG('(*>', 'ocean-logo.svg')} className="underline-offset-4 hover:text-white hover:underline">SVG · LOGO</button>
              <button onClick={() => downloadPNG(wpDraw('logo-sm'), 600, 300, 'ocean-logo.png')} className="underline-offset-4 hover:text-white hover:underline">PNG · LOGO</button>
              <button onClick={() => downloadSVG(')<(((*>', 'ocean-variant.svg')} className="underline-offset-4 hover:text-white hover:underline">SVG · VARIANT</button>
              <button onClick={() => downloadPNG((x, w, h) => { x.fillStyle = '#000'; x.fillRect(0,0,w,h); x.fillStyle='#fff'; x.textAlign='center'; x.textBaseline='middle'; x.font='bold 90px ui-monospace, monospace'; x.fillText(')<(((*>', w/2, h/2) }, 700, 300, 'ocean-variant.png')} className="underline-offset-4 hover:text-white hover:underline">PNG · VARIANT</button>
            </div>
          </div>
          <div>
            <div className="flex items-center justify-center">
              <span className="font-mono text-5xl font-bold">{')<(((*>'}</span>
            </div>
            <div className="mt-12 flex justify-center gap-8 text-[11px] font-semibold tracking-[0.15em] text-neutral-400">
              <button onClick={() => downloadSVG(')<(((*>', 'ocean-variant.svg')} className="underline-offset-4 hover:text-white hover:underline">SVG</button>
              <button onClick={() => downloadPNG((x, w, h) => { x.fillStyle='#000'; x.fillRect(0,0,w,h); x.fillStyle='#fff'; x.textAlign='center'; x.textBaseline='middle'; x.font='bold 90px ui-monospace, monospace'; x.fillText(')<(((*>', w/2, h/2) }, 700, 300, 'ocean-variant.png')} className="underline-offset-4 hover:text-white hover:underline">PNG</button>
            </div>
          </div>
        </div>
      </Section>

      {/* 02 Color */}
      <Section n="02" label="PALETTE" title="Color" desc="A base of grays and black; blue as an accent.">
        <div className="grid w-full grid-cols-3 gap-6">
          {COLORS.map((c) => (
            <button key={c.hex} onClick={() => copy(c)} className="text-left">
              <div className="h-44 w-full rounded-sm" style={{ background: c.hex }} />
              <p className="mt-4 font-mono text-sm text-neutral-200">{c.hex}</p>
              <p className="font-mono text-xs text-neutral-500">{c.rgb}</p>
            </button>
          ))}
        </div>
      </Section>

      {/* 03 Typography */}
      <Section n="03" label="TYPO" title="Typography" desc="Geist Sans for interface and communication. Geist Mono for data. Plus Jakarta for brand accents.">
        <div className="w-full">
          <p className="text-8xl font-medium leading-none">Aa</p>
          <p className="mt-6 text-2xl text-neutral-300">Ocean Anticheat - antcheat.ac</p>
          <div className="my-8 h-px w-full bg-white/10" />
          <div className="grid grid-cols-2 gap-x-12 gap-y-8">
            {WEIGHTS.map((x) => (
              <div key={x.w}>
                <p className={`text-2xl text-white ${x.c}`}>{x.w}</p>
                <p className="mt-1 text-xs tracking-[0.2em] text-neutral-500">{x.m}</p>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* 04 Spacing */}
      <Section n="04" label="RULE" title="Spacing" desc="Minimum clearance around the symbol. Scales with the size of the logo.">
        <div className="w-full">
          <div className="relative mx-auto flex h-72 max-w-md items-center justify-center rounded-sm border border-dashed border-white/15">
            <div className="flex h-44 w-72 items-center justify-center border border-dashed border-white/15">
              <span className="font-mono text-6xl font-bold">{'(*>'}</span>
            </div>
          </div>
          <p className="mt-6 text-center text-[11px] font-semibold tracking-[0.25em] text-neutral-600">
            OUTER FRAME = BREATHABLE MINIMUM
          </p>
        </div>
      </Section>

      {/* 05 Wallpapers */}
      <Section n="05" label="MEDIA" title="Wallpapers" desc="Official wallpapers for desktops and social media.">
        <div className="grid w-full gap-x-8 gap-y-10 sm:grid-cols-2">
          {WALLPAPERS.map((wp, i) => (
            <div key={i}>
              <div className="flex aspect-video items-center justify-center overflow-hidden rounded border border-white/10 bg-black">
                {wp.label === 'think' ? (
                  <span className="text-2xl font-bold">THINK</span>
                ) : wp.label === 'tagline' ? (
                  <span className="text-sm font-semibold text-neutral-300">Think. Scan. Find.</span>
                ) : (
                  <span className={`font-mono font-bold ${wp.label === 'logo-sm' ? 'text-3xl' : 'text-6xl'}`}>
                    {'(*>'}
                  </span>
                )}
              </div>
              <div className="mt-4 flex items-center justify-between">
                <span className="text-xs tracking-[0.2em] text-neutral-500">16:9</span>
                <button
                  onClick={() => downloadPNG(wpDraw(wp.label), 1920, 1080, `ocean-wallpaper-${i + 1}.png`)}
                  className="text-[11px] font-semibold tracking-[0.2em] text-neutral-300 underline-offset-4 hover:text-white hover:underline"
                >
                  DOWNLOAD
                </button>
              </div>
              <p className="mt-3 text-lg">{wp.title}</p>
              <p className="text-sm text-neutral-500">1920×1080</p>
            </div>
          ))}
        </div>
      </Section>

      {/* 06 Naming */}
      <Section n="06" label="VOICE" title="Naming" desc="Use the name consistently in communications and on products.">
        <div className="grid w-full grid-cols-2 gap-10">
          <div>
            <p className="mb-6 text-xs font-semibold tracking-[0.3em] text-neutral-600">CORRECT</p>
            <ul className="space-y-6 text-2xl">
              <li>Ocean Anticheat</li>
              <li>Ocean</li>
              <li>antcheat.ac</li>
            </ul>
          </div>
          <div>
            <p className="mb-6 text-xs font-semibold tracking-[0.3em] text-neutral-600">INCORRECT</p>
            <ul className="space-y-6 text-2xl text-neutral-600 line-through">
              <li>OCEAN ANTICHEAT</li>
              <li>OceanAC</li>
              <li>Ocean Anti Cheat</li>
            </ul>
          </div>
        </div>
      </Section>
    </div>
  )
}
