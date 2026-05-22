import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LayoutGrid, Pin, ScanLine, Coins, X, ArrowRight, Check } from 'lucide-react'
import { useStore } from '../store.jsx'

const STEPS = [
  {
    icon: LayoutGrid,
    title: 'Welcome to ZeroTrace',
    body: 'This is your dashboard. It shows your scan statistics, detection results and any announcements at a glance.',
  },
  {
    icon: Pin,
    title: 'Create a Pin',
    body: 'Go to “Pins” to generate a one-time PIN. Send it together with the scanner to the player you want to check.',
  },
  {
    icon: ScanLine,
    title: 'Read the scan',
    body: 'When a scan finishes, open the pin’s “View Results” to see the full forensic report, verdict and risk score.',
  },
  {
    icon: Coins,
    title: 'Earn coins',
    body: 'Every cheater you catch earns coins. Spend them in the Casino on games, discount codes or even real license keys.',
  },
]

export default function OnboardingTour() {
  const { state, dispatch } = useStore()
  const nav = useNavigate()
  const [step, setStep] = useState(0)

  if (!state.auth || state.onboardingDone) return null
  if (state.maintenance?.enabled && state.role !== 'admin') return null

  const finish = () => dispatch({ type: 'complete-onboarding' })
  const s = STEPS[step]
  const Icon = s.icon
  const last = step === STEPS.length - 1

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="panel relative w-full max-w-md rounded-2xl border p-6 shadow-2xl">
        <button onClick={finish} className="muted hover:txt absolute right-4 top-4" aria-label="Skip">
          <X size={18} />
        </button>

        <div className="tile mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border">
          <Icon size={26} className="text-sky-400" />
        </div>
        <p className="caps-label">Step {step + 1} of {STEPS.length}</p>
        <h2 className="txt mt-1 text-xl font-bold">{s.title}</h2>
        <p className="muted mt-2 text-sm leading-relaxed">{s.body}</p>

        <div className="mt-5 flex items-center gap-1.5">
          {STEPS.map((_, i) => (
            <span key={i} className={`h-1.5 rounded-full transition-all ${i === step ? 'w-6 bg-sky-500' : 'w-2 bg-white/15'}`} />
          ))}
        </div>

        <div className="mt-6 flex items-center justify-between">
          <button onClick={finish} className="muted hover:txt text-sm">Skip</button>
          <div className="flex gap-2">
            {step > 0 && (
              <button onClick={() => setStep(step - 1)} className="bd txt rounded-lg border px-4 py-2 text-sm hover:border-sky-500">Back</button>
            )}
            {last ? (
              <button
                onClick={() => { finish(); nav('/pins') }}
                className="flex items-center gap-2 rounded-lg bg-sky-600 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-500"
              >
                <Check size={15} /> Get started
              </button>
            ) : (
              <button
                onClick={() => setStep(step + 1)}
                className="flex items-center gap-2 rounded-lg bg-sky-600 px-5 py-2 text-sm font-semibold text-white hover:bg-sky-500"
              >
                Next <ArrowRight size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
