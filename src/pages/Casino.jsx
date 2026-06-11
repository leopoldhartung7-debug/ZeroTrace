import { useState, useRef, useEffect } from 'react'
import {
  Coins, Dices, Disc3, ShoppingBag, History as HistoryIcon, Copy, Check,
  TrendingUp, TrendingDown, Sparkles, Plus, Cherry, Target, CircleDollarSign,
  Rocket, Bomb, Gem, ArrowUp, ArrowDown, Trophy, Award, Gift, Volume2, VolumeX,
  BarChart3, Repeat,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { useToast } from '../components/ui.jsx'
import Confetti from '../components/Confetti.jsx'
import { useStore, useWallet, generateLicenseKey, validateDiscountCode } from '../store.jsx'
import { ACHIEVEMENTS, levelProgress, playSound, dailyBonusAmount, canClaimDaily } from '../lib/casino.js'

// Count-up animation hook for the balance.
function useCountUp(value) {
  const [shown, setShown] = useState(value)
  const ref = useRef(value)
  useEffect(() => {
    const from = ref.current
    const to = value
    if (from === to) return
    const start = performance.now()
    const dur = 600
    let raf
    const tick = (t) => {
      const p = Math.min(1, (t - start) / dur)
      const eased = 1 - Math.pow(1 - p, 3)
      setShown(Math.round(from + (to - from) * eased))
      if (p < 1) raf = requestAnimationFrame(tick)
      else ref.current = to
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value])
  return shown
}

const WHEEL_COLORS = ['#0ea5e9', '#1e293b', '#38bdf8', '#0f172a', '#0284c7', '#1e293b', '#38bdf8', '#0f172a', '#0ea5e9', '#1e293b']
const WHEEL_MULT = 7 // hit your exact number → 7× your stake back

function polar(cx, cy, r, deg) {
  const rad = ((deg - 90) * Math.PI) / 180
  return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)]
}

function segmentPath(cx, cy, r, a0, a1) {
  const [x0, y0] = polar(cx, cy, r, a0)
  const [x1, y1] = polar(cx, cy, r, a1)
  const large = a1 - a0 > 180 ? 1 : 0
  return `M ${cx} ${cy} L ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} Z`
}

function LuckyWheel({ wallet, dispatch, toast, fx = {} }) {
  const [bet, setBet] = useState(50)
  const [pick, setPick] = useState(0)
  const [rotation, setRotation] = useState(0)
  const [spinning, setSpinning] = useState(false)
  const [last, setLast] = useState(null)
  const spinningRef = useRef(false)

  const spin = () => {
    if (spinningRef.current) return
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })

    spinningRef.current = true
    setSpinning(true)
    setLast(null)
    fx.spin?.()
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: `Lucky Wheel bet on ${pick}`, notifyOwnerId: wallet.ownerId })

    const result = Math.floor(Math.random() * 10)
    const spins = 5 + Math.floor(Math.random() * 4) // 5–8 full turns for variety
    // We want the wheel to end with segment `result` centered under the top
    // pointer: final rotation mod 360 must equal -(result*36 + 18).
    const targetMod = ((360 - (result * 36 + 18)) % 360 + 360) % 360
    setRotation((prev) => {
      const prevMod = ((prev % 360) + 360) % 360
      let delta = targetMod - prevMod
      if (delta < 0) delta += 360
      return prev + spins * 360 + delta
    })

    setTimeout(() => {
      const won = result === pick
      if (won) {
        const payout = amount * WHEEL_MULT
        dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Lucky Wheel hit ${result} (×${WHEEL_MULT})`, notifyOwnerId: wallet.ownerId })
        fx.win?.(payout, amount)
        toast({ type: 'success', title: `You won ${payout} coins!`, body: `Number ${result} hit` })
      } else {
        fx.lose?.()
        toast({ type: 'error', title: `Landed on ${result}`, body: `You bet on ${pick}` })
      }
      setLast({ result, won })
      setSpinning(false)
      spinningRef.current = false
    }, 4200)
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center p-6">
        <div className="relative h-72 w-72">
          {/* Pointer */}
          <div className="absolute left-1/2 top-[-6px] z-10 -translate-x-1/2">
            <div className="h-0 w-0 border-l-[10px] border-r-[10px] border-t-[18px] border-l-transparent border-r-transparent border-t-sky-400" />
          </div>
          <svg
            viewBox="0 0 200 200"
            className="h-full w-full"
            style={{
              transform: `rotate(${rotation}deg)`,
              transition: spinning ? 'transform 4s cubic-bezier(0.17, 0.67, 0.12, 0.99)' : 'none',
            }}
          >
            {Array.from({ length: 10 }, (_, i) => {
              const a0 = i * 36
              const a1 = (i + 1) * 36
              const [tx, ty] = polar(100, 100, 64, a0 + 18)
              return (
                <g key={i}>
                  <path d={segmentPath(100, 100, 95, a0, a1)} fill={WHEEL_COLORS[i]} stroke="#0b0e14" strokeWidth="1" />
                  <text x={tx} y={ty} fill="#fff" fontSize="15" fontWeight="700" textAnchor="middle" dominantBaseline="middle">
                    {i}
                  </text>
                </g>
              )
            })}
            <circle cx="100" cy="100" r="14" fill="#0b0e14" stroke="#38bdf8" strokeWidth="2" />
          </svg>
        </div>
        {last && (
          <div className={`mt-5 rounded-lg border px-4 py-2 text-sm font-semibold ${last.won ? 'border-green-600/40 bg-green-600/15 text-green-400' : 'border-red-600/40 bg-red-600/15 text-red-400'}`}>
            {last.won ? `Hit ${last.result} — you won!` : `Landed on ${last.result} — better luck next time`}
          </div>
        )}
      </Card>

      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Lucky Wheel</h3>
        <p className="muted mb-5 text-sm">Bet on a number 0–9. Hit it and get <span className="text-sky-400 font-semibold">{WHEEL_MULT}×</span> your stake back.</p>

        <p className="caps-label mb-2">Your bet</p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="number"
            min="1"
            value={bet}
            onChange={(e) => setBet(e.target.value)}
            className="bd tile txt w-32 rounded-lg border px-3 py-2 text-sm focus:outline-none"
          />
          {[10, 50, 100, 500].map((v) => (
            <button key={v} onClick={() => setBet(v)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
              {v}
            </button>
          ))}
          <button onClick={() => setBet(wallet.balance)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">
            Max
          </button>
        </div>

        <p className="caps-label mb-2 mt-5">Pick a number</p>
        <div className="grid grid-cols-5 gap-2">
          {Array.from({ length: 10 }, (_, i) => (
            <button
              key={i}
              onClick={() => setPick(i)}
              className={`rounded-lg border py-2.5 text-sm font-bold ${pick === i ? 'border-sky-500 bg-sky-500/15 text-sky-400' : 'bd tile txt hover:border-sky-500'}`}
            >
              {i}
            </button>
          ))}
        </div>

        <button
          onClick={spin}
          disabled={spinning}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
        >
          <Disc3 size={16} className={spinning ? 'animate-spin' : ''} /> {spinning ? 'Spinning…' : `Spin for ${Math.floor(Number(bet) || 0)} coins`}
        </button>
        <p className="muted mt-2 text-center text-xs">Potential win: {Math.floor((Number(bet) || 0) * WHEEL_MULT)} coins</p>
      </Card>
    </div>
  )
}

/* ---------------- Blackjack ---------------- */

const SUITS = ['♠', '♥', '♦', '♣']
const RANKS = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']

function freshDeck() {
  const deck = []
  for (const s of SUITS) for (const r of RANKS) deck.push({ r, s })
  for (let i = deck.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[deck[i], deck[j]] = [deck[j], deck[i]]
  }
  return deck
}

function handValue(cards) {
  let total = 0
  let aces = 0
  for (const c of cards) {
    if (c.r === 'A') { total += 11; aces++ }
    else if (['K', 'Q', 'J'].includes(c.r)) total += 10
    else total += Number(c.r)
  }
  while (total > 21 && aces > 0) { total -= 10; aces-- }
  return total
}

function PlayingCard({ card, hidden }) {
  if (hidden) {
    return (
      <div className="zt-deal flex h-24 w-16 items-center justify-center rounded-lg border border-sky-500/40 bg-gradient-to-br from-sky-900/60 to-slate-900 text-sky-500">
        <Sparkles size={20} />
      </div>
    )
  }
  const red = card.s === '♥' || card.s === '♦'
  return (
    <div className="zt-deal flex h-24 w-16 flex-col justify-between rounded-lg border border-line bg-white p-1.5 shadow-md">
      <span className={`text-sm font-bold ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.r}</span>
      <span className={`text-center text-xl ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.s}</span>
      <span className={`rotate-180 text-sm font-bold ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.r}</span>
    </div>
  )
}

function Blackjack({ wallet, dispatch, toast, fx = {} }) {
  const [bet, setBet] = useState(50)
  const [deck, setDeck] = useState([])
  const [player, setPlayer] = useState([])
  const [dealer, setDealer] = useState([])
  const [phase, setPhase] = useState('idle') // idle | player | done
  const [msg, setMsg] = useState(null)
  const [activeBet, setActiveBet] = useState(0)

  const settle = (delta, type, detail) => {
    if (delta !== 0) dispatch({ type: 'wallet-tx', key: wallet.key, delta, txType: type, detail, notifyOwnerId: wallet.ownerId })
  }

  const deal = () => {
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Blackjack bet', notifyOwnerId: wallet.ownerId })
    fx.spin?.()
    setActiveBet(amount)
    const d = freshDeck()
    const p = [d.pop(), d.pop()]
    const dl = [d.pop(), d.pop()]
    setDeck(d); setPlayer(p); setDealer(dl); setMsg(null)
    const pv = handValue(p)
    if (pv === 21) {
      // Natural blackjack pays 2.5× (stake + 1.5×)
      const payout = Math.floor(amount * 2.5)
      settle(payout, 'win', 'Blackjack!')
      fx.win?.(payout, amount)
      setPhase('done')
      setMsg({ tone: 'win', text: `Blackjack! You won ${payout - amount} coins.` })
    } else {
      setPhase('player')
    }
  }

  const hit = () => {
    const d = [...deck]
    const p = [...player, d.pop()]
    setDeck(d); setPlayer(p)
    if (handValue(p) > 21) {
      setPhase('done')
      fx.lose?.()
      setMsg({ tone: 'lose', text: `Bust with ${handValue(p)}. You lost ${activeBet} coins.` })
    }
  }

  const stand = () => {
    const d = [...deck]
    const dl = [...dealer]
    while (handValue(dl) < 17) dl.push(d.pop())
    setDeck(d); setDealer(dl)
    const pv = handValue(player)
    const dv = handValue(dl)
    let result, payout = 0
    if (dv > 21 || pv > dv) { payout = activeBet * 2; result = { tone: 'win', text: `You win! ${pv} vs ${dv}. +${activeBet} coins.` } }
    else if (pv === dv) { payout = activeBet; result = { tone: 'push', text: `Push at ${pv}. Bet returned.` } }
    else { payout = 0; result = { tone: 'lose', text: `Dealer wins ${dv} vs ${pv}. -${activeBet} coins.` } }
    if (payout > 0) settle(payout, 'win', 'Blackjack round')
    if (result.tone === 'win') fx.win?.(payout, activeBet)
    else if (result.tone === 'lose') fx.lose?.()
    setPhase('done')
    setMsg(result)
  }

  const playerVal = handValue(player)
  const dealerVal = handValue(dealer)

  return (
    <Card className="p-6">
      <h3 className="txt mb-1 text-lg font-semibold">Blackjack</h3>
      <p className="muted mb-5 text-sm">Beat the dealer without going over 21. Blackjack pays 3:2.</p>

      {phase === 'idle' ? (
        <div>
          <p className="caps-label mb-2">Your bet</p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="number"
              min="1"
              value={bet}
              onChange={(e) => setBet(e.target.value)}
              className="bd tile txt w-32 rounded-lg border px-3 py-2 text-sm focus:outline-none"
            />
            {[10, 50, 100, 500].map((v) => (
              <button key={v} onClick={() => setBet(v)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">{v}</button>
            ))}
            <button onClick={() => setBet(wallet.balance)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">Max</button>
          </div>
          <button onClick={deal} className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500">
            <Dices size={16} /> Deal — {Math.floor(Number(bet) || 0)} coins
          </button>
        </div>
      ) : (
        <div>
          <div className="mb-5">
            <p className="caps-label mb-2">Dealer {phase === 'done' ? `(${dealerVal})` : ''}</p>
            <div className="flex gap-2">
              {dealer.map((c, i) => (
                <PlayingCard key={i} card={c} hidden={phase !== 'done' && i === 1} />
              ))}
            </div>
          </div>
          <div className="mb-5">
            <p className="caps-label mb-2">You ({playerVal})</p>
            <div className="flex flex-wrap gap-2">
              {player.map((c, i) => <PlayingCard key={i} card={c} />)}
            </div>
          </div>

          {msg && (
            <div className={`mb-4 rounded-lg border px-4 py-2 text-sm font-semibold ${
              msg.tone === 'win' ? 'border-green-600/40 bg-green-600/15 text-green-400' :
              msg.tone === 'push' ? 'border-sky-600/40 bg-sky-600/15 text-sky-400' :
              'border-red-600/40 bg-red-600/15 text-red-400'
            }`}>
              {msg.text}
            </div>
          )}

          {phase === 'player' ? (
            <div className="flex gap-2">
              <button onClick={hit} className="flex-1 rounded-lg bg-sky-600 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">Hit</button>
              <button onClick={stand} className="bd txt flex-1 rounded-lg border py-2.5 text-sm font-semibold hover:border-sky-500">Stand</button>
            </div>
          ) : (
            <button onClick={() => { setPhase('idle'); setPlayer([]); setDealer([]); setMsg(null) }} className="w-full rounded-lg bg-sky-600 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">
              New round
            </button>
          )}
        </div>
      )}
    </Card>
  )
}

/* ---------------- Roulette ---------------- */

const ROULETTE_RED = new Set([1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36])
const rColor = (n) => (n === 0 ? 'green' : ROULETTE_RED.has(n) ? 'red' : 'black')
// Real European wheel pocket order (clockwise from 0).
const WHEEL_ORDER = [0, 32, 15, 19, 4, 21, 2, 25, 17, 34, 6, 27, 13, 36, 11, 30, 8, 23, 10, 5, 24, 16, 33, 1, 20, 14, 31, 9, 22, 18, 29, 7, 28, 12, 35, 3, 26]
const POCKET = 360 / 37

const ROULETTE_BETS = [
  { id: 'red', label: 'Red', mult: 2, test: (n) => n !== 0 && ROULETTE_RED.has(n) },
  { id: 'black', label: 'Black', mult: 2, test: (n) => n !== 0 && !ROULETTE_RED.has(n) },
  { id: 'even', label: 'Even', mult: 2, test: (n) => n !== 0 && n % 2 === 0 },
  { id: 'odd', label: 'Odd', mult: 2, test: (n) => n % 2 === 1 },
  { id: 'low', label: '1–18', mult: 2, test: (n) => n >= 1 && n <= 18 },
  { id: 'high', label: '19–36', mult: 2, test: (n) => n >= 19 && n <= 36 },
  { id: 'd1', label: '1st 12', mult: 3, test: (n) => n >= 1 && n <= 12 },
  { id: 'd2', label: '2nd 12', mult: 3, test: (n) => n >= 13 && n <= 24 },
  { id: 'd3', label: '3rd 12', mult: 3, test: (n) => n >= 25 && n <= 36 },
]

function Roulette({ wallet, dispatch, toast, fx = {} }) {
  const [bet, setBet] = useState(50)
  const [betType, setBetType] = useState('red') // a ROULETTE_BETS id or 'number'
  const [pickNumber, setPickNumber] = useState(0)
  const [wheelRot, setWheelRot] = useState(0)
  const [ballRot, setBallRot] = useState(0)
  const [spinning, setSpinning] = useState(false)
  const [last, setLast] = useState(null)
  const spinningRef = useRef(false)
  const timerRef = useRef(null)

  useEffect(() => () => clearTimeout(timerRef.current), [])

  const spin = () => {
    if (spinningRef.current) return
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })

    spinningRef.current = true
    setSpinning(true)
    setLast(null)
    const betLabel = betType === 'number' ? `number ${pickNumber}` : ROULETTE_BETS.find((b) => b.id === betType)?.label
    fx.spin?.()
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: `Roulette on ${betLabel}`, notifyOwnerId: wallet.ownerId })

    const result = Math.floor(Math.random() * 37) // 0–36
    const index = WHEEL_ORDER.indexOf(result)
    // Rotate the wheel so the result pocket centre sits under the top pointer.
    const targetMod = ((360 - (index * POCKET + POCKET / 2)) % 360 + 360) % 360
    setWheelRot((prev) => {
      const prevMod = ((prev % 360) + 360) % 360
      let delta = targetMod - prevMod
      if (delta < 0) delta += 360
      return prev + 6 * 360 + delta
    })
    // Ball spins the opposite way and always settles at the top (0 mod 360).
    setBallRot((prev) => prev - 10 * 360)

    timerRef.current = setTimeout(() => {
      let won = false
      let mult = 0
      if (betType === 'number') {
        won = pickNumber === result
        mult = 36
      } else {
        const b = ROULETTE_BETS.find((x) => x.id === betType)
        won = b.test(result)
        mult = b.mult
      }
      if (won) {
        const payout = amount * mult
        dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Roulette hit ${result}`, notifyOwnerId: wallet.ownerId })
        fx.win?.(payout, amount)
        toast({ type: 'success', title: `You won ${payout.toLocaleString()} coins!`, body: `Landed on ${result} (${rColor(result)})` })
      } else {
        fx.lose?.()
        toast({ type: 'error', title: `Landed on ${result} (${rColor(result)})`, body: 'No win' })
      }
      setLast({ result, won })
      setSpinning(false)
      spinningRef.current = false
    }, 5200)
  }

  const segFill = { green: '#16a34a', red: '#dc2626', black: '#171717' }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center justify-center p-6">
        <div className="relative h-72 w-72">
          {/* Top pointer */}
          <div className="absolute left-1/2 top-[-4px] z-20 -translate-x-1/2">
            <div className="h-0 w-0 border-l-[9px] border-r-[9px] border-t-[16px] border-l-transparent border-r-transparent border-t-sky-400" />
          </div>

          {/* Wheel */}
          <svg
            viewBox="0 0 200 200"
            className="absolute inset-0 h-full w-full"
            style={{ transform: `rotate(${wheelRot}deg)`, transition: 'transform 5s cubic-bezier(0.12,0.7,0.1,1)' }}
          >
            <circle cx="100" cy="100" r="98" fill="#0b0e14" />
            {WHEEL_ORDER.map((n, i) => {
              const a0 = i * POCKET
              const a1 = (i + 1) * POCKET
              const [tx, ty] = polar(100, 100, 84, a0 + POCKET / 2)
              return (
                <g key={n}>
                  <path d={segmentPath(100, 100, 96, a0, a1)} fill={segFill[rColor(n)]} stroke="#0b0e14" strokeWidth="0.5" />
                  <text
                    x={tx} y={ty} fill="#fff" fontSize="8" fontWeight="700"
                    textAnchor="middle" dominantBaseline="middle"
                    transform={`rotate(${a0 + POCKET / 2} ${tx} ${ty})`}
                  >
                    {n}
                  </text>
                </g>
              )
            })}
            <circle cx="100" cy="100" r="46" fill="#11151f" stroke="#2a2c33" strokeWidth="2" />
            <circle cx="100" cy="100" r="30" fill="#0b0e14" />
          </svg>

          {/* Ball orbit */}
          <div
            className="absolute inset-0"
            style={{ transform: `rotate(${ballRot}deg)`, transition: 'transform 5s cubic-bezier(0.15,0.6,0.1,1)' }}
          >
            <div className="absolute left-1/2 top-[6px] h-3 w-3 -translate-x-1/2 rounded-full bg-white shadow-[0_0_6px_rgba(255,255,255,0.8)]" />
          </div>
        </div>

        {last && (
          <div className={`mt-4 flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-semibold ${last.won ? 'border-green-600/40 bg-green-600/15 text-green-400' : 'border-red-600/40 bg-red-600/15 text-red-400'}`}>
            <span className={`flex h-6 w-6 items-center justify-center rounded-full text-xs text-white`} style={{ background: segFill[rColor(last.result)] }}>{last.result}</span>
            {last.won ? 'You won!' : 'No win'}
          </div>
        )}
      </Card>

      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Roulette</h3>
        <p className="muted mb-5 text-sm">European single-zero. Straight number pays 35:1, dozens 2:1, even-money bets 1:1.</p>

        <p className="caps-label mb-2">Your bet</p>
        <div className="flex flex-wrap items-center gap-2">
          <input type="number" min="1" value={bet} onChange={(e) => setBet(e.target.value)} className="bd tile txt w-32 rounded-lg border px-3 py-2 text-sm focus:outline-none" />
          {[10, 50, 100, 500].map((v) => (
            <button key={v} onClick={() => setBet(v)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">{v}</button>
          ))}
          <button onClick={() => setBet(wallet.balance)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">Max</button>
        </div>

        <p className="caps-label mb-2 mt-5">Bet on</p>
        <div className="grid grid-cols-3 gap-2">
          {ROULETTE_BETS.map((b) => (
            <button
              key={b.id}
              onClick={() => setBetType(b.id)}
              className={`rounded-lg border py-2 text-xs font-semibold ${betType === b.id ? 'border-sky-500 bg-sky-500/15 text-sky-400' : 'bd tile txt hover:border-sky-500'}`}
            >
              {b.label}
            </button>
          ))}
          <button
            onClick={() => setBetType('number')}
            className={`col-span-3 rounded-lg border py-2 text-xs font-semibold ${betType === 'number' ? 'border-sky-500 bg-sky-500/15 text-sky-400' : 'bd tile txt hover:border-sky-500'}`}
          >
            Single number (35:1)
          </button>
        </div>

        {betType === 'number' && (
          <div className="mt-3">
            <p className="caps-label mb-2">Pick a number (0–36)</p>
            <div className="grid grid-cols-9 gap-1">
              {Array.from({ length: 37 }, (_, n) => {
                const col = rColor(n)
                const active = pickNumber === n
                return (
                  <button
                    key={n}
                    onClick={() => setPickNumber(n)}
                    className={`rounded py-1 text-[11px] font-bold text-white ${active ? 'ring-2 ring-sky-400' : ''} ${col === 'green' ? 'bg-green-600' : col === 'red' ? 'bg-red-600' : 'bg-neutral-700'}`}
                  >
                    {n}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        <button
          onClick={spin}
          disabled={spinning}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
        >
          <Target size={16} className={spinning ? 'animate-spin' : ''} /> {spinning ? 'Spinning…' : `Spin for ${Math.floor(Number(bet) || 0)} coins`}
        </button>
      </Card>
    </div>
  )
}

/* ---------------- Slot Machine ---------------- */
const SLOT_SYMBOLS = ['🍒', '🍋', '🔔', '⭐', '7️⃣', '💎']
const SLOT_THREE = { '🍒': 2, '🍋': 3, '🔔': 4, '⭐': 6, '7️⃣': 10, '💎': 16 }
const SLOT_TWO_MULT = 1.25

function SlotMachine({ wallet, dispatch, toast, fx = {} }) {
  const [bet, setBet] = useState(50)
  const [reels, setReels] = useState(['🍒', '🍋', '🔔'])
  const [spinning, setSpinning] = useState(false)
  const [last, setLast] = useState(null)
  const intervalRef = useRef(null)
  const spinningRef = useRef(false)

  useEffect(() => () => clearInterval(intervalRef.current), [])

  const spin = () => {
    if (spinningRef.current) return
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })

    spinningRef.current = true
    setSpinning(true)
    setLast(null)
    fx.spin?.()
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Slots spin', notifyOwnerId: wallet.ownerId })

    const rnd = () => SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)]
    const final = [rnd(), rnd(), rnd()]
    const stopped = [false, false, false]

    // Flicker only the reels that haven't stopped yet; keep stopped reels fixed.
    intervalRef.current = setInterval(() => {
      setReels((prev) => prev.map((s, i) => (stopped[i] ? final[i] : rnd())))
    }, 80)

    // Stop reels one by one.
    const stops = [800, 1300, 1800]
    stops.forEach((t, i) => {
      setTimeout(() => {
        stopped[i] = true
        setReels((prev) => prev.map((s, idx) => (stopped[idx] ? final[idx] : s)))
        if (i === 2) {
          clearInterval(intervalRef.current)
          setReels([...final]) // guarantee the display equals the scored result
          resolve(final, amount)
        }
      }, t)
    })
  }

  const resolve = (final, amount) => {
    const [a, b, c] = final
    let payout = 0
    let text = ''
    if (a === b && b === c) {
      payout = Math.round(amount * SLOT_THREE[a])
      text = `Jackpot! ${a}${a}${a} → ×${SLOT_THREE[a]}`
    } else if (a === b || b === c || a === c) {
      payout = Math.round(amount * SLOT_TWO_MULT)
      text = `Two of a kind → ×${SLOT_TWO_MULT}`
    } else {
      text = 'No match — try again'
    }
    if (payout > 0) {
      dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Slots ${final.join('')}`, notifyOwnerId: wallet.ownerId })
      fx.win?.(payout, amount)
      toast({ type: 'success', title: `You won ${payout.toLocaleString()} coins!`, body: final.join(' ') })
    } else {
      fx.lose?.()
      toast({ type: 'error', title: 'No win', body: final.join(' ') })
    }
    setLast({ payout, text, win: payout > 0 })
    setSpinning(false)
    spinningRef.current = false
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center justify-center p-6">
        <div className="flex gap-3">
          {reels.map((s, i) => (
            <div
              key={i}
              className={`flex h-28 w-24 items-center justify-center rounded-xl border-2 bg-black/40 text-5xl ${
                spinning ? 'border-sky-500/60' : 'border-line'
              }`}
            >
              {s}
            </div>
          ))}
        </div>
        {last && (
          <div className={`mt-5 rounded-lg border px-4 py-2 text-sm font-semibold ${last.win ? 'border-green-600/40 bg-green-600/15 text-green-400' : 'border-red-600/40 bg-red-600/15 text-red-400'}`}>
            {last.text}
          </div>
        )}
      </Card>

      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Slot Machine</h3>
        <p className="muted mb-5 text-sm">Match 3 symbols for the jackpot. Two of a kind pays ×{SLOT_TWO_MULT}.</p>

        <p className="caps-label mb-2">Your bet</p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="number"
            min="1"
            value={bet}
            onChange={(e) => setBet(e.target.value)}
            className="bd tile txt w-32 rounded-lg border px-3 py-2 text-sm focus:outline-none"
          />
          {[10, 50, 100, 500].map((v) => (
            <button key={v} onClick={() => setBet(v)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">{v}</button>
          ))}
          <button onClick={() => setBet(wallet.balance)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">Max</button>
        </div>

        <button
          onClick={spin}
          disabled={spinning}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
        >
          <Cherry size={16} /> {spinning ? 'Spinning…' : `Spin for ${Math.floor(Number(bet) || 0)} coins`}
        </button>

        <div className="mt-6">
          <p className="caps-label mb-2">Payouts (3 of a kind)</p>
          <div className="grid grid-cols-3 gap-2 text-sm sm:grid-cols-6">
            {SLOT_SYMBOLS.map((s) => (
              <div key={s} className="bd tile flex flex-col items-center rounded-lg border py-2">
                <span className="text-xl">{s}</span>
                <span className="muted text-[11px]">×{SLOT_THREE[s]}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  )
}

/* ---------------- Shop ---------------- */

const SHOP_ITEMS = [
  { id: 'disc10', kind: 'discount', label: '10% discount code', cost: 3500, desc: '10% off your next license purchase.' },
  { id: 'disc25', kind: 'discount', label: '25% discount code', cost: 9000, desc: '25% off your next license purchase.' },
  { id: 'disc50', kind: 'discount', label: '50% discount code', cost: 18000, desc: 'Half off your next license purchase.' },
  { id: 'key7', kind: 'key', label: '7-day license key', cost: 28000, desc: 'A real 7-day ZeroTrace key.', days: 7 },
  { id: 'key30', kind: 'key', label: '30-day license key', cost: 75000, desc: 'A real 30-day ZeroTrace key.', days: 30 },
  { id: 'key365', kind: 'key', label: '1-year license key', cost: 250000, desc: 'A real 1-year ZeroTrace key.', days: 365 },
]

function randCode(prefix) {
  const s = Math.random().toString(36).slice(2, 8).toUpperCase()
  const s2 = Math.random().toString(36).slice(2, 6).toUpperCase()
  return `${prefix}-${s}-${s2}`
}

function Shop({ wallet, state, dispatch, toast }) {
  const [copied, setCopied] = useState(null)
  const [codeInput, setCodeInput] = useState('')
  const [applied, setApplied] = useState(null) // validated discount code object
  const myPurchases = (state.shopPurchases || []).filter((p) => p.ownerKey === wallet.key)

  const priceFor = (item) => {
    if (item.kind === 'key' && applied) {
      return Math.max(0, Math.round(item.cost * (1 - applied.percent / 100)))
    }
    return item.cost
  }

  const applyCode = () => {
    const res = validateDiscountCode(state, codeInput)
    if (!res.ok) {
      setApplied(null)
      return toast({ type: 'error', title: 'Invalid code', body: res.reason })
    }
    setApplied(res.code)
    toast({ type: 'success', title: `Code applied — ${res.code.percent}% off keys`, body: res.code.code })
  }

  const buy = (item) => {
    const cost = priceFor(item)
    if (wallet.balance < cost) return toast({ type: 'error', title: 'Not enough coins' })
    const usingDiscount = item.kind === 'key' && applied
    if (!confirm(`Redeem "${item.label}" for ${cost.toLocaleString()} coins${usingDiscount ? ` (−${applied.percent}%)` : ''}?`)) return
    let code, licenseKey = null, percent = null
    if (item.kind === 'key') {
      code = generateLicenseKey()
      licenseKey = {
        id: 'k' + Date.now() + Math.random().toString(16).slice(2, 8),
        key: code,
        label: `Shop redemption (${wallet.key})`,
        plan: 'Personal',
        durationDays: item.days,
        createdAt: Date.now(),
        expiresAt: item.days > 0 ? Date.now() + item.days * 86400000 : null,
        status: 'Active',
      }
    } else {
      code = randCode('ZT' + item.label.match(/\d+/)?.[0])
      percent = Number(item.label.match(/\d+/)?.[0]) || null
    }
    dispatch({ type: 'shop-redeem', key: wallet.key, cost, label: item.label, code, kind: item.kind, licenseKey, percent })
    if (usingDiscount) {
      dispatch({ type: 'use-discount-code', id: applied.id })
      // single-use codes get cleared after use
      if (applied.maxUses === 1) setApplied(null)
    }
    toast({ type: 'success', title: 'Redeemed!', body: code })
  }

  const copy = (code) => {
    navigator.clipboard?.writeText(code).catch(() => {})
    setCopied(code)
    setTimeout(() => setCopied(null), 1500)
  }

  return (
    <div className="space-y-6">
      <Card className="p-5">
        <p className="caps-label mb-2">Have a discount code?</p>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={codeInput}
            onChange={(e) => setCodeInput(e.target.value.toUpperCase())}
            placeholder="Enter discount code (applies to license keys)"
            className="bd tile txt min-w-0 flex-1 rounded-lg border px-3 py-2.5 font-mono text-sm focus:outline-none"
          />
          {applied ? (
            <button onClick={() => { setApplied(null); setCodeInput('') }} className="bd txt rounded-lg border px-4 py-2.5 text-sm hover:border-red-500">
              Remove ({applied.percent}% off)
            </button>
          ) : (
            <button onClick={applyCode} className="shrink-0 rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">
              Apply
            </button>
          )}
        </div>
        {applied && (
          <p className="mt-2 text-xs text-green-400">Active: {applied.code} — {applied.percent}% off all license keys.</p>
        )}
      </Card>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {SHOP_ITEMS.map((item) => {
          const cost = priceFor(item)
          const discounted = cost !== item.cost
          const affordable = wallet.balance >= cost
          return (
            <Card key={item.id} className="flex flex-col p-5">
              <div className="flex items-center gap-2">
                {item.kind === 'key' ? <Sparkles size={16} className="text-sky-400" /> : <ShoppingBag size={16} className="text-sky-400" />}
                <h4 className="txt font-semibold">{item.label}</h4>
              </div>
              <p className="muted mt-1 flex-1 text-sm">{item.desc}</p>
              <div className="mt-4 flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-sm font-bold text-yellow-400">
                  <Coins size={14} />
                  {discounted && <span className="muted mr-1 text-xs line-through">{item.cost.toLocaleString()}</span>}
                  {cost.toLocaleString()}
                </span>
                <button
                  onClick={() => buy(item)}
                  disabled={!affordable}
                  className="rounded-lg bg-sky-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-40"
                >
                  {affordable ? 'Redeem' : 'Locked'}
                </button>
              </div>
            </Card>
          )
        })}
      </div>

      {myPurchases.length > 0 && (
        <Card className="p-6">
          <h3 className="txt mb-4 flex items-center gap-2 text-lg font-semibold">
            <ShoppingBag size={18} /> Your redemptions ({myPurchases.length})
          </h3>
          <div className="space-y-2">
            {myPurchases.map((p) => (
              <div key={p.id} className="bd flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2.5 text-sm">
                <div className="min-w-0">
                  <p className="txt font-medium">{p.label}</p>
                  <p className="muted text-xs">{new Date(p.time).toLocaleString()} · {p.cost.toLocaleString()} coins</p>
                </div>
                <div className="flex items-center gap-2">
                  <code className="txt break-all rounded-md border border-line bg-black/30 px-2 py-1 font-mono text-xs">{p.code}</code>
                  <button onClick={() => copy(p.code)} className="muted hover:text-sky-400" title="Copy">
                    {copied === p.code ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

/* ---------------- Admin panel ---------------- */

function AdminCoinPanel({ wallet, dispatch, toast }) {
  const [custom, setCustom] = useState('')
  const add = (amount) => {
    if (!amount) return
    dispatch({ type: 'grant-coins', key: wallet.key, amount, detail: 'Admin self-grant' })
    toast({ type: 'success', title: amount >= 0 ? 'Coins added' : 'Coins removed', body: `${amount > 0 ? '+' : ''}${amount.toLocaleString()}` })
  }
  return (
    <Card className="mb-6 mt-6 p-5">
      <p className="caps-label mb-3 flex items-center gap-2"><Plus size={12} /> Admin — add coins to your own wallet</p>
      <div className="flex flex-wrap items-center gap-2">
        {[1000, 5000, 25000, 100000].map((v) => (
          <button
            key={v}
            onClick={() => add(v)}
            className="bd tile txt rounded-lg border px-3 py-2 text-sm font-semibold hover:border-yellow-500"
          >
            +{v.toLocaleString()}
          </button>
        ))}
        <div className="flex items-center gap-2">
          <input
            type="number"
            value={custom}
            onChange={(e) => setCustom(e.target.value)}
            placeholder="Custom amount"
            className="bd tile txt w-36 rounded-lg border px-3 py-2 text-sm focus:outline-none"
          />
          <button
            onClick={() => { const a = Math.floor(Number(custom) || 0); if (a) { add(a); setCustom('') } }}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"
          >
            Add
          </button>
        </div>
        <button
          onClick={() => add(-wallet.balance)}
          className="bd muted rounded-lg border px-3 py-2 text-sm hover:border-red-500"
        >
          Reset to 0
        </button>
      </div>
      <p className="muted mt-2 text-xs">Use a negative custom amount to remove coins.</p>
    </Card>
  )
}

/* ---------------- Bet input (shared) ---------------- */

function BetRow({ bet, setBet, balance }) {
  return (
    <>
      <p className="caps-label mb-2">Your bet</p>
      <div className="flex flex-wrap items-center gap-2">
        <input type="number" min="1" value={bet} onChange={(e) => setBet(e.target.value)} className="bd tile txt w-32 rounded-lg border px-3 py-2 text-sm focus:outline-none" />
        {[10, 50, 100, 500].map((v) => (
          <button key={v} onClick={() => setBet(v)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">{v}</button>
        ))}
        <button onClick={() => setBet(balance)} className="bd tile txt rounded-md border px-2.5 py-1 text-xs hover:border-sky-500">Max</button>
      </div>
    </>
  )
}

/* ---------------- Coinflip ---------------- */

function Coinflip({ wallet, dispatch, toast, fx }) {
  const [bet, setBet] = useState(50)
  const [side, setSide] = useState('heads')
  const [flipping, setFlipping] = useState(false)
  const [coinRot, setCoinRot] = useState(0) // current X rotation in degrees
  const [last, setLast] = useState(null)
  const ref = useRef(false)
  const timerRef = useRef(null)
  useEffect(() => () => clearTimeout(timerRef.current), [])

  const flip = () => {
    if (ref.current) return
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    ref.current = true; setFlipping(true); setLast(null)
    fx.spin()
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Coinflip', notifyOwnerId: wallet.ownerId })
    const result = Math.random() < 0.5 ? 'heads' : 'tails'
    // Heads face up at rotateX ≡ 0, Tails at ≡ 180 (mod 360).
    const targetMod = result === 'heads' ? 0 : 180
    setCoinRot((prev) => {
      const prevMod = ((prev % 360) + 360) % 360
      let delta = targetMod - prevMod
      if (delta < 0) delta += 360
      return prev + 360 * 5 + delta // 5 full flips + land on the result
    })
    timerRef.current = setTimeout(() => {
      const won = result === side
      if (won) {
        const payout = Math.floor(amount * 1.5)
        dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: 'Coinflip win', notifyOwnerId: wallet.ownerId })
        fx.win(payout, amount)
        toast({ type: 'success', title: `${result === 'heads' ? 'Heads' : 'Tails'} — you won ${payout.toLocaleString()}!` })
      } else {
        fx.lose()
        toast({ type: 'error', title: `${result === 'heads' ? 'Heads' : 'Tails'} — you lost` })
      }
      setLast({ result, won }); setFlipping(false); ref.current = false
    }, 1400)
  }

  const faceBase = 'absolute inset-0 flex items-center justify-center rounded-full border-4 border-yellow-600 bg-gradient-to-br from-yellow-300 to-yellow-500 text-xl font-bold text-yellow-900'

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center justify-center p-6">
        <div className="flex h-40 items-center justify-center" style={{ perspective: '700px' }}>
          <div className={flipping ? 'zt-toss' : ''}>
            <div
              className="relative h-28 w-28"
              style={{
                transformStyle: 'preserve-3d',
                transform: `rotateX(${coinRot}deg)`,
                transition: flipping ? 'transform 1.4s cubic-bezier(0.33,0,0.2,1)' : 'none',
              }}
            >
              <div className={faceBase} style={{ backfaceVisibility: 'hidden' }}>Heads</div>
              <div className={faceBase} style={{ backfaceVisibility: 'hidden', transform: 'rotateX(180deg)' }}>Tails</div>
            </div>
          </div>
        </div>
        {last && (
          <div className={`mt-6 rounded-lg border px-4 py-2 text-sm font-semibold ${last.won ? 'border-green-600/40 bg-green-600/15 text-green-400' : 'border-red-600/40 bg-red-600/15 text-red-400'}`}>
            {last.result === 'heads' ? 'Heads' : 'Tails'} — {last.won ? 'you won!' : 'you lost'}
          </div>
        )}
      </Card>
      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Coinflip</h3>
        <p className="muted mb-5 text-sm">Heads or tails — 50/50, hit your side to win ×1.5.</p>
        <BetRow bet={bet} setBet={setBet} balance={wallet.balance} />
        <p className="caps-label mb-2 mt-5">Pick a side</p>
        <div className="grid grid-cols-2 gap-2">
          {['heads', 'tails'].map((s) => (
            <button key={s} onClick={() => setSide(s)} className={`rounded-lg border py-3 text-sm font-bold capitalize ${side === s ? 'border-sky-500 bg-sky-500/15 text-sky-400' : 'bd tile txt hover:border-sky-500'}`}>{s}</button>
          ))}
        </div>
        <button onClick={flip} disabled={flipping} className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-50">
          <CircleDollarSign size={16} /> {flipping ? 'Flipping…' : `Flip for ${Math.floor(Number(bet) || 0)}`}
        </button>
      </Card>
    </div>
  )
}

/* ---------------- Crash ---------------- */

function Crash({ wallet, dispatch, toast, fx }) {
  const [bet, setBet] = useState(50)
  const [mult, setMult] = useState(1)
  const [phase, setPhase] = useState('idle') // idle | running | crashed | cashed
  const [crashAt, setCrashAt] = useState(0)
  const [activeBet, setActiveBet] = useState(0)
  const rafRef = useRef(null)
  const startRef = useRef(0)

  useEffect(() => () => cancelAnimationFrame(rafRef.current), [])

  const start = () => {
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Crash', notifyOwnerId: wallet.ownerId })
    setActiveBet(amount)
    // House edge ~4%: crash point distribution.
    const r = Math.random()
    const cp = Math.max(1, Math.floor((0.92 / (1 - r)) * 100) / 100)
    setCrashAt(cp)
    setMult(1)
    setPhase('running')
    fx.spin()
    startRef.current = performance.now()
    const tick = (t) => {
      const elapsed = (t - startRef.current) / 1000
      const m = Math.floor(Math.pow(1.0718, elapsed * 10) * 100) / 100 // grows ~ exp
      if (m >= cp) {
        setMult(cp)
        setPhase('crashed')
        fx.lose()
        toast({ type: 'error', title: `Crashed at ${cp.toFixed(2)}×`, body: `You lost ${amount.toLocaleString()}` })
        return
      }
      setMult(m)
      rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
  }

  const cashOut = () => {
    if (phase !== 'running') return
    cancelAnimationFrame(rafRef.current)
    const m = mult
    const payout = Math.floor(activeBet * m)
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Crash cashout ${m.toFixed(2)}x`, notifyOwnerId: wallet.ownerId })
    fx.win(payout, activeBet)
    toast({ type: 'success', title: `Cashed out at ${m.toFixed(2)}× — +${payout.toLocaleString()}` })
    setPhase('cashed')
  }

  const color = phase === 'crashed' ? 'text-red-500' : phase === 'cashed' ? 'text-green-400' : 'text-sky-400'

  // Plane climbs a straight line with the multiplier; the line ends exactly
  // where the plane is. On crash the line freezes at the crash point and the
  // plane drops straight down from there.
  const progress = Math.min(0.85, Math.log(Math.max(1, mult)) / Math.log(25))
  const crashed = phase === 'crashed'
  const flying = phase === 'running' || phase === 'cashed'
  const lineLeft = 6 + progress * 80
  const lineBottom = 6 + progress * 78
  const planeLeft = lineLeft
  const planeBottom = crashed ? -12 : lineBottom
  const planeRot = crashed ? 110 : -18

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="relative flex flex-col items-center justify-center overflow-hidden p-6">
        <div className="relative h-56 w-full overflow-hidden rounded-xl border border-line bg-gradient-to-b from-sky-950/40 to-slate-950">
          {/* climbing trail */}
          <svg className="absolute inset-0 h-full w-full" preserveAspectRatio="none" viewBox="0 0 100 100">
            {(flying || crashed) && (
              <path
                d={`M 6 94 L ${lineLeft} ${100 - lineBottom}`}
                fill="none"
                stroke={crashed ? '#dc2626' : '#38bdf8'}
                strokeWidth="1.5"
                strokeOpacity="0.6"
              />
            )}
          </svg>
          {/* plane — sits exactly at the end of the trail line */}
          <div
            className="absolute text-3xl"
            style={{
              left: `${planeLeft}%`,
              bottom: `${planeBottom}%`,
              transform: `translate(-50%, 50%) rotate(${planeRot}deg)`,
              transition: crashed ? 'left 0.8s ease-in, bottom 0.8s ease-in, transform 0.4s' : 'none',
            }}
          >
            {crashed ? '💥' : '✈️'}
          </div>
          {/* multiplier overlay */}
          <div className="absolute inset-0 flex items-center justify-center">
            <span className={`text-5xl font-bold tabular-nums ${color}`} style={{ textShadow: '0 2px 12px rgba(0,0,0,0.6)' }}>
              {mult.toFixed(2)}×
            </span>
          </div>
        </div>
        <p className="muted mt-3 text-sm">
          {phase === 'idle' && 'Place a bet and watch it climb.'}
          {phase === 'running' && 'Cash out before it crashes!'}
          {phase === 'crashed' && `Crashed at ${crashAt.toFixed(2)}×`}
          {phase === 'cashed' && 'Cashed out — nice!'}
        </p>
      </Card>
      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Crash</h3>
        <p className="muted mb-5 text-sm">The multiplier rises. Cash out before it crashes — or lose your bet.</p>
        {phase === 'running' ? (
          <button onClick={cashOut} className="flex w-full items-center justify-center gap-2 rounded-lg bg-green-600 py-3 text-sm font-semibold text-white hover:bg-green-500">
            Cash out {Math.floor(activeBet * mult).toLocaleString()}
          </button>
        ) : (
          <>
            <BetRow bet={bet} setBet={setBet} balance={wallet.balance} />
            <button onClick={start} className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500">
              <Rocket size={16} /> Start — {Math.floor(Number(bet) || 0)}
            </button>
          </>
        )}
      </Card>
    </div>
  )
}

/* ---------------- Mines ---------------- */

function Mines({ wallet, dispatch, toast, fx }) {
  const SIZE = 25
  const [bet, setBet] = useState(50)
  const [mineCount, setMineCount] = useState(3)
  const [grid, setGrid] = useState([]) // {mine, revealed}
  const [phase, setPhase] = useState('idle') // idle | playing | dead | done
  const [picks, setPicks] = useState(0)
  const [activeBet, setActiveBet] = useState(0)

  const safeTotal = SIZE - mineCount
  const multAt = (n) => {
    // product of (remaining/safe-remaining) with house edge
    let m = 1
    for (let i = 0; i < n; i++) m *= (SIZE - i) / (safeTotal - i)
    return Math.floor(m * 0.93 * 100) / 100
  }
  const currentMult = multAt(picks)
  const nextMult = picks < safeTotal ? multAt(picks + 1) : currentMult

  const start = () => {
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Mines', notifyOwnerId: wallet.ownerId })
    setActiveBet(amount)
    const mineIdx = new Set()
    while (mineIdx.size < mineCount) mineIdx.add(Math.floor(Math.random() * SIZE))
    setGrid(Array.from({ length: SIZE }, (_, i) => ({ mine: mineIdx.has(i), revealed: false })))
    setPicks(0); setPhase('playing')
    fx.spin()
  }

  const reveal = (i) => {
    if (phase !== 'playing' || grid[i].revealed) return
    const next = grid.map((c, idx) => (idx === i ? { ...c, revealed: true } : c))
    if (grid[i].mine) {
      setGrid(next.map((c) => ({ ...c, revealed: true })))
      setPhase('dead')
      fx.lose()
      toast({ type: 'error', title: 'Boom! You hit a mine', body: `Lost ${activeBet.toLocaleString()}` })
      return
    }
    const np = picks + 1
    setGrid(next); setPicks(np)
    fx.spin()
    if (np >= safeTotal) cashOut(np, next)
  }

  const cashOut = (p = picks, g = grid) => {
    if (phase !== 'playing' || p === 0) return
    const payout = Math.floor(activeBet * multAt(p))
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Mines ${multAt(p).toFixed(2)}x`, notifyOwnerId: wallet.ownerId })
    fx.win(payout, activeBet)
    setGrid(g.map((c) => ({ ...c, revealed: true })))
    setPhase('done')
    toast({ type: 'success', title: `Cashed out ${multAt(p).toFixed(2)}× — +${payout.toLocaleString()}` })
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center p-6">
        <div className="grid grid-cols-5 gap-2">
          {(grid.length ? grid : Array.from({ length: SIZE }, () => ({}))).map((c, i) => (
            <button
              key={i}
              onClick={() => reveal(i)}
              disabled={phase !== 'playing'}
              className={`flex h-12 w-12 items-center justify-center rounded-lg border text-xl ${
                c.revealed ? (c.mine ? 'border-red-600/50 bg-red-600/20' : 'border-green-600/50 bg-green-600/20') : 'bd tile hover:border-sky-500'
              }`}
            >
              {c.revealed ? <span className="zt-pop">{c.mine ? '💣' : '💎'}</span> : ''}
            </button>
          ))}
        </div>
      </Card>
      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Mines</h3>
        <p className="muted mb-5 text-sm">Reveal gems to grow your multiplier. Hit a mine and you lose it all.</p>
        {phase === 'playing' ? (
          <div>
            <div className="mb-4 grid grid-cols-2 gap-3 text-sm">
              <div className="tile rounded-lg border p-3"><p className="caps-label">Current</p><p className="txt mt-1 font-bold">{currentMult.toFixed(2)}× · {Math.floor(activeBet * currentMult).toLocaleString()}</p></div>
              <div className="tile rounded-lg border p-3"><p className="caps-label">Next gem</p><p className="txt mt-1 font-bold">{nextMult.toFixed(2)}×</p></div>
            </div>
            <button onClick={() => cashOut()} disabled={picks === 0} className="flex w-full items-center justify-center gap-2 rounded-lg bg-green-600 py-3 text-sm font-semibold text-white hover:bg-green-500 disabled:opacity-40">
              Cash out {Math.floor(activeBet * currentMult).toLocaleString()}
            </button>
          </div>
        ) : (
          <>
            <BetRow bet={bet} setBet={setBet} balance={wallet.balance} />
            <p className="caps-label mb-2 mt-5">Mines: {mineCount}</p>
            <input type="range" min="1" max="15" value={mineCount} onChange={(e) => setMineCount(Number(e.target.value))} className="w-full" />
            <button onClick={start} className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500">
              <Bomb size={16} /> Start — {Math.floor(Number(bet) || 0)}
            </button>
          </>
        )}
      </Card>
    </div>
  )
}

/* ---------------- Higher / Lower ---------------- */

function HiLo({ wallet, dispatch, toast, fx }) {
  const [bet, setBet] = useState(50)
  const [current, setCurrent] = useState(() => 2 + Math.floor(Math.random() * 13)) // 2-14
  const [mult, setMult] = useState(1)
  const [phase, setPhase] = useState('idle') // idle | playing | done
  const [activeBet, setActiveBet] = useState(0)
  // card value 2-14 (J=11,Q=12,K=13,A=14)
  const label = (v) => ({ 11: 'J', 12: 'Q', 13: 'K', 14: 'A' }[v] || v)

  const start = () => {
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Hi-Lo', notifyOwnerId: wallet.ownerId })
    setActiveBet(amount); setMult(1); setCurrent(2 + Math.floor(Math.random() * 13)); setPhase('playing')
    fx.spin()
  }

  const guess = (dir) => {
    if (phase !== 'playing') return
    const next = 2 + Math.floor(Math.random() * 13)
    const higherChance = (14 - current) / 13
    const lowerChance = (current - 2) / 13
    const won = dir === 'higher' ? next >= current : next <= current
    fx.spin()
    if (!won) {
      setCurrent(next); setPhase('done')
      fx.lose()
      toast({ type: 'error', title: `Next was ${label(next)} — you lost` })
      return
    }
    const stepMult = dir === 'higher'
      ? (higherChance > 0 ? 0.93 / higherChance : 1)
      : (lowerChance > 0 ? 0.93 / lowerChance : 1)
    const m = Math.max(1.01, Math.floor(mult * Math.max(1.05, stepMult) * 100) / 100)
    setMult(m); setCurrent(next)
    toast({ type: 'success', title: `Next was ${label(next)} — ${m.toFixed(2)}×` })
  }

  const cashOut = () => {
    if (phase !== 'playing' || mult <= 1) return
    const payout = Math.floor(activeBet * mult)
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Hi-Lo ${mult.toFixed(2)}x`, notifyOwnerId: wallet.ownerId })
    fx.win(payout, activeBet)
    setPhase('done')
    toast({ type: 'success', title: `Cashed out ${mult.toFixed(2)}× — +${payout.toLocaleString()}` })
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="flex flex-col items-center justify-center p-6">
        <div key={current} className="zt-flipin flex h-32 w-24 items-center justify-center rounded-xl border border-line bg-white text-5xl font-bold text-slate-900">{label(current)}</div>
        {phase === 'playing' && <p className="mt-4 text-sm font-semibold text-sky-400">{mult.toFixed(2)}×</p>}
      </Card>
      <Card className="p-6">
        <h3 className="txt mb-1 text-lg font-semibold">Higher / Lower</h3>
        <p className="muted mb-5 text-sm">Guess if the next card is higher or lower. Build a streak, then cash out.</p>
        {phase === 'playing' ? (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <button onClick={() => guess('higher')} className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500"><ArrowUp size={16} /> Higher</button>
              <button onClick={() => guess('lower')} className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500"><ArrowDown size={16} /> Lower</button>
            </div>
            <button onClick={cashOut} disabled={mult <= 1} className="w-full rounded-lg bg-green-600 py-2.5 text-sm font-semibold text-white hover:bg-green-500 disabled:opacity-40">
              Cash out {Math.floor(activeBet * mult).toLocaleString()}
            </button>
          </div>
        ) : (
          <>
            <BetRow bet={bet} setBet={setBet} balance={wallet.balance} />
            <button onClick={start} className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 py-3 text-sm font-semibold text-white hover:bg-sky-500">
              <Repeat size={16} /> Deal — {Math.floor(Number(bet) || 0)}
            </button>
          </>
        )}
      </Card>
    </div>
  )
}

/* ---------------- Stats / Leaderboard / Achievements ---------------- */

function StatsTab({ wallet }) {
  const net = wallet.won - wallet.wagered
  const tiles = [
    { label: 'Total wagered', value: wallet.wagered },
    { label: 'Total won', value: wallet.won },
    { label: 'Biggest win', value: wallet.biggestWin },
    { label: 'Net profit', value: net, color: net >= 0 ? 'text-green-500' : 'text-red-500' },
  ]
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {tiles.map((t) => (
          <Card key={t.label} className="p-5">
            <p className="caps-label">{t.label}</p>
            <p className={`mt-1 text-2xl font-bold ${t.color || 'txt'}`}>{(t.value || 0).toLocaleString()}</p>
          </Card>
        ))}
      </div>
      <Card className="p-6">
        <h3 className="txt mb-4 flex items-center gap-2 text-lg font-semibold"><Award size={18} /> Achievements ({wallet.achievements.length}/{ACHIEVEMENTS.length})</h3>
        <div className="grid gap-3 sm:grid-cols-2">
          {ACHIEVEMENTS.map((a) => {
            const got = wallet.achievements.includes(a.id)
            return (
              <div key={a.id} className={`flex items-center gap-3 rounded-lg border px-4 py-3 ${got ? 'border-yellow-500/40 bg-yellow-500/10' : 'bd opacity-60'}`}>
                <Award size={20} className={got ? 'text-yellow-400' : 'muted'} />
                <div>
                  <p className="txt text-sm font-semibold">{a.name}</p>
                  <p className="muted text-xs">{a.desc}</p>
                </div>
                {got && <Check size={16} className="ml-auto text-green-500" />}
              </div>
            )
          })}
        </div>
      </Card>
    </div>
  )
}

function LeaderboardTab({ state }) {
  const rows = Object.entries(state.wallets || {})
    .map(([key, w]) => {
      const u = (state.users || []).find((x) => x.id === key)
      const name = u ? u.username : key === 'admin' ? 'Admin' : key === 'analyst' ? 'Analyst' : key
      return { key, name, balance: w.balance || 0, biggest: w.biggestWin || 0 }
    })
    .sort((a, b) => b.balance - a.balance)
    .slice(0, 20)
  return (
    <Card className="p-0">
      {rows.length === 0 ? (
        <p className="muted py-16 text-center text-sm">No players yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="caps-label bd border-b">
                <th className="px-4 py-3">#</th>
                <th className="px-4 py-3">Player</th>
                <th className="px-4 py-3 text-right">Balance</th>
                <th className="px-4 py-3 text-right">Biggest win</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.key} className="bd border-b last:border-0">
                  <td className="px-4 py-3">
                    {i === 0 ? <Trophy size={16} className="text-yellow-400" /> : <span className="muted">{i + 1}</span>}
                  </td>
                  <td className="txt px-4 py-3 font-medium">{r.name}</td>
                  <td className="px-4 py-3 text-right font-mono font-semibold text-yellow-400">{r.balance.toLocaleString()}</td>
                  <td className="muted px-4 py-3 text-right font-mono">{r.biggest.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

/* ---------------- Page ---------------- */

function GiftCard({ wallet, state, dispatch, toast }) {
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const recipients = (state.users || []).filter((u) => u.id !== wallet.key)
  const send = () => {
    const amt = Math.floor(Number(amount) || 0)
    if (!to) return toast({ type: 'error', title: 'Pick a recipient' })
    if (amt <= 0) return toast({ type: 'error', title: 'Enter an amount' })
    if (amt > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    const u = recipients.find((x) => x.id === to)
    const me = (state.users || []).find((x) => x.id === wallet.key)
    dispatch({
      type: 'gift-coins',
      fromKey: wallet.key,
      toKey: to,
      amount: amt,
      toOwnerId: to,
      fromLabel: me?.username || (wallet.key === 'admin' ? 'Admin' : 'Analyst'),
      toLabel: u?.username,
    })
    toast({ type: 'success', title: 'Coins sent', body: `${amt.toLocaleString()} → ${u?.username}` })
    setAmount('')
  }
  return (
    <Card className="p-6">
      <h3 className="txt mb-1 flex items-center gap-2 text-lg font-semibold"><Gift size={18} /> Gift coins</h3>
      <p className="muted mb-4 text-sm">Send coins to another analyst.</p>
      {recipients.length === 0 ? (
        <p className="muted text-sm">No other registered analysts to gift to yet.</p>
      ) : (
        <div className="flex flex-col gap-2 sm:flex-row">
          <select value={to} onChange={(e) => setTo(e.target.value)} className="bd tile txt min-w-0 flex-1 rounded-lg border px-3 py-2.5 text-sm">
            <option value="">— recipient —</option>
            {recipients.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <input type="number" min="1" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="Amount" className="bd tile txt w-full rounded-lg border px-3 py-2.5 text-sm sm:w-36" />
          <button onClick={send} className="shrink-0 rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500">Send</button>
        </div>
      )}
    </Card>
  )
}

function AdminCasinoPanel({ state, dispatch, toast }) {
  const disabled = new Set(state.casino?.disabledGames || [])
  const games = ['Lucky Wheel', 'Roulette', 'Slots', 'Blackjack', 'Coinflip', 'Crash', 'Mines', 'Hi-Lo']
  const profit = state.casino?.houseProfit || 0
  return (
    <Card className="p-6">
      <h3 className="txt mb-4 flex items-center gap-2 text-lg font-semibold"><BarChart3 size={18} /> Casino control (admin)</h3>
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">House profit</p>
          <p className={`mt-1 text-xl font-bold ${profit >= 0 ? 'text-green-500' : 'text-red-500'}`}>{profit.toLocaleString()}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Jackpot pool</p>
          <p className="mt-1 text-xl font-bold text-yellow-400">{(state.jackpot || 0).toLocaleString()}</p>
        </div>
        <div className="tile rounded-lg border p-3">
          <p className="caps-label">Players</p>
          <p className="txt mt-1 text-xl font-bold">{Object.keys(state.wallets || {}).length}</p>
        </div>
      </div>
      <p className="caps-label mb-2">Enable / disable games</p>
      <div className="flex flex-wrap gap-2">
        {games.map((g) => {
          const on = !disabled.has(g)
          return (
            <button
              key={g}
              onClick={() => dispatch({ type: 'set-casino-game', game: g, enabled: !on })}
              className={`rounded-md border px-3 py-1.5 text-xs font-semibold ${on ? 'border-green-600/40 bg-green-600/15 text-green-500' : 'bd muted'}`}
            >
              {g}: {on ? 'on' : 'off'}
            </button>
          )
        })}
      </div>
      <button onClick={() => { dispatch({ type: 'reset-house-profit' }); toast({ type: 'success', title: 'House profit reset' }) }} className="bd muted mt-4 rounded-lg border px-3 py-2 text-xs hover:border-sky-500">
        Reset house profit
      </button>
    </Card>
  )
}

export default function Casino() {
  const { state, dispatch } = useStore()
  const wallet = useWallet()
  const toast = useToast()
  const [tab, setTab] = useState('Lucky Wheel')
  const [confetti, setConfetti] = useState(0)
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  const soundOn = state.settings?.casinoSound !== false
  const shownBalance = useCountUp(wallet.balance)
  const lp = levelProgress(wallet.xp)
  const disabledGames = new Set(state.casino?.disabledGames || [])

  // Shared effects for all games.
  const fx = {
    spin: () => playSound('spin', soundOn),
    lose: () => playSound('lose', soundOn),
    win: (payout, bet) => {
      const big = bet > 0 && payout >= bet * 10
      playSound(big ? 'jackpot' : 'win', soundOn)
      if (big) setConfetti(Date.now())
      // ~1-in-2500 chance any win also triggers the jackpot pool.
      if (Math.random() < 0.0004) {
        const me = (state.users || []).find((u) => u.id === wallet.key)
        dispatch({ type: 'win-jackpot', key: wallet.key, name: me?.username || (wallet.key === 'admin' ? 'Admin' : 'Analyst') })
        setConfetti(Date.now() + 1)
      }
    },
  }
  const gw = { ...wallet, ownerId: state.session?.userId || null }

  const claimDaily = () => {
    if (!canClaimDaily(wallet.lastDailyBonus)) return toast({ type: 'error', title: 'Already claimed today' })
    const streak = canClaimDaily(wallet.lastDailyBonus) && (Date.now() - wallet.lastDailyBonus < 2 * 86400000) ? wallet.dailyStreak + 1 : 1
    const amount = dailyBonusAmount(streak)
    dispatch({ type: 'claim-daily-bonus', key: wallet.key, amount, streak })
    setConfetti(Date.now())
    toast({ type: 'success', title: `Daily bonus: +${amount}`, body: `Streak ${streak}` })
  }
  const nextDailyAt = (wallet.lastDailyBonus || 0) + 86_400_000
  const dailyRemaining = Math.max(0, nextDailyAt - now)
  const dailyReady = !wallet.lastDailyBonus || dailyRemaining <= 0
  const fmtCountdown = (ms) => {
    const s = Math.floor(ms / 1000)
    const h = String(Math.floor(s / 3600)).padStart(2, '0')
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0')
    const sec = String(s % 60).padStart(2, '0')
    return `${h}:${m}:${sec}`
  }

  const GAME_TABS = [
    { label: 'Lucky Wheel', icon: Disc3 },
    { label: 'Roulette', icon: Target },
    { label: 'Slots', icon: Cherry },
    { label: 'Blackjack', icon: Dices },
    { label: 'Coinflip', icon: CircleDollarSign },
    { label: 'Crash', icon: Rocket },
    { label: 'Mines', icon: Bomb },
    { label: 'Hi-Lo', icon: Repeat },
  ].filter((t) => !disabledGames.has(t.label))

  const allTabs = [
    ...GAME_TABS,
    { label: 'Shop', icon: ShoppingBag },
    { label: 'Stats', icon: BarChart3 },
    { label: 'Leaderboard', icon: Trophy },
    { label: 'Gift', icon: Gift },
    { label: 'History', icon: HistoryIcon },
  ]

  const gameUnavailable = (
    <Card className="p-12 text-center">
      <p className="muted text-sm">This game is currently disabled by an admin.</p>
    </Card>
  )

  return (
    <div>
      <Confetti trigger={confetti} />
      <PageHeader
        icon={Coins}
        kicker="Earn coins by catching cheaters"
        title="ZeroTrace Coins"
        subtitle="Every cheater you catch earns coins. Gamble them — or redeem them for discounts and license keys."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => dispatch({ type: 'set-setting', key: 'casinoSound', value: !soundOn })}
              className="bd txt flex items-center gap-2 rounded-xl border px-3 py-2 text-sm hover:border-sky-500"
              title="Toggle sound"
            >
              {soundOn ? <Volume2 size={16} /> : <VolumeX size={16} className="muted" />}
            </button>
            <div className="flex items-center gap-2 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-4 py-2">
              <Coins size={18} className="text-yellow-400" />
              <span className="text-lg font-bold text-yellow-300">{shownBalance.toLocaleString()}</span>
              <span className="muted text-xs">coins</span>
            </div>
          </div>
        }
      />

      {/* Level + jackpot + daily bonus bar */}
      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Card className="p-4">
          <div className="flex items-center justify-between text-sm">
            <span className="txt font-semibold">Level {lp.level}</span>
            <span className="muted text-xs">{wallet.xp.toLocaleString()} XP</span>
          </div>
          <div className="tile mt-2 h-2 w-full overflow-hidden rounded-full">
            <div className="h-full rounded-full bg-sky-500 transition-all" style={{ width: `${lp.pct}%` }} />
          </div>
        </Card>
        <Card className="flex items-center justify-between p-4">
          <div>
            <p className="caps-label">Jackpot pool</p>
            <p className="mt-1 text-xl font-bold text-yellow-400">{(state.jackpot || 0).toLocaleString()}</p>
            {state.role === 'admin' && (
              <button
                type="button"
                onClick={() => {
                  dispatch({ type: 'reset-jackpot', role: state.role })
                  toast?.({ type: 'success', title: 'Jackpot reset', body: 'Pool set back to 5,000.' })
                }}
                className="bd muted hover:txt mt-2 rounded-md border px-2 py-1 text-xs"
              >
                Reset jackpot
              </button>
            )}
          </div>
          <Sparkles size={26} className="text-yellow-400" />
        </Card>
        <Card className="flex items-center justify-between p-4">
          <div>
            <p className="caps-label">Daily bonus</p>
            {dailyReady ? (
              <p className="muted mt-1 text-xs">+{dailyBonusAmount((wallet.dailyStreak || 0) + 1)} ready</p>
            ) : (
              <p className="mt-1 font-mono text-lg font-bold tabular-nums text-sky-400">{fmtCountdown(dailyRemaining)}</p>
            )}
          </div>
          <button
            onClick={claimDaily}
            disabled={!dailyReady}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-40"
          >
            <Gift size={15} className="mr-1 inline" /> Claim
          </button>
        </Card>
      </div>

      {state.role === 'admin' && (
        <div className="mb-6 space-y-6">
          <AdminCoinPanel wallet={wallet} dispatch={dispatch} toast={toast} />
          <AdminCasinoPanel state={state} dispatch={dispatch} toast={toast} />
        </div>
      )}

      <Tabs tabs={allTabs} active={tab} onChange={setTab} />

      <div className="mt-8">
        {tab === 'Lucky Wheel' && (disabledGames.has('Lucky Wheel') ? gameUnavailable : <LuckyWheel wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />)}
        {tab === 'Roulette' && (disabledGames.has('Roulette') ? gameUnavailable : <Roulette wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />)}
        {tab === 'Slots' && (disabledGames.has('Slots') ? gameUnavailable : <SlotMachine wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />)}
        {tab === 'Blackjack' && (disabledGames.has('Blackjack') ? gameUnavailable : <Blackjack wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />)}
        {tab === 'Coinflip' && <Coinflip wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />}
        {tab === 'Crash' && <Crash wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />}
        {tab === 'Mines' && <Mines wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />}
        {tab === 'Hi-Lo' && <HiLo wallet={gw} dispatch={dispatch} toast={toast} fx={fx} />}
        {tab === 'Shop' && <Shop wallet={wallet} state={state} dispatch={dispatch} toast={toast} />}
        {tab === 'Stats' && <StatsTab wallet={wallet} />}
        {tab === 'Leaderboard' && <LeaderboardTab state={state} />}
        {tab === 'Gift' && <GiftCard wallet={wallet} state={state} dispatch={dispatch} toast={toast} />}
        {tab === 'History' && (
          <Card className="p-0">
            {wallet.history.length === 0 ? (
              <p className="muted py-16 text-center text-sm">No transactions yet. Catch a cheater to earn coins!</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="caps-label bd border-b">
                      <th className="px-4 py-3">Time</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Detail</th>
                      <th className="px-4 py-3 text-right">Amount</th>
                    </tr>
                  </thead>
                  <tbody>
                    {wallet.history.map((h) => (
                      <tr key={h.id} className="bd border-b last:border-0">
                        <td className="muted px-4 py-2.5 text-xs">{new Date(h.time).toLocaleString()}</td>
                        <td className="px-4 py-2.5">
                          <span className="bd txt rounded-md border px-2 py-0.5 text-[11px] font-semibold capitalize">{h.type}</span>
                        </td>
                        <td className="muted px-4 py-2.5 text-xs">{h.detail}</td>
                        <td className={`px-4 py-2.5 text-right font-mono font-semibold ${h.amount >= 0 ? 'text-green-500' : 'text-red-500'}`}>
                          <span className="inline-flex items-center gap-1">
                            {h.amount >= 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
                            {h.amount >= 0 ? '+' : ''}{h.amount.toLocaleString()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        )}
      </div>
    </div>
  )
}
