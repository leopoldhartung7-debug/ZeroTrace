import { useState, useRef, useEffect } from 'react'
import {
  Coins, Dices, Disc3, ShoppingBag, History as HistoryIcon, Copy, Check,
  TrendingUp, TrendingDown, Sparkles, Plus, Cherry,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { useToast } from '../components/ui.jsx'
import { useStore, useWallet, generateLicenseKey, validateDiscountCode } from '../store.jsx'

const WHEEL_COLORS = ['#0ea5e9', '#1e293b', '#38bdf8', '#0f172a', '#0284c7', '#1e293b', '#38bdf8', '#0f172a', '#0ea5e9', '#1e293b']
const WHEEL_MULT = 8 // hit your exact number → 8× your stake back

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

function LuckyWheel({ wallet, dispatch, toast }) {
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
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: `Lucky Wheel bet on ${pick}` })

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
        dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Lucky Wheel hit ${result} (×${WHEEL_MULT})` })
        toast({ type: 'success', title: `You won ${payout} coins!`, body: `Number ${result} hit` })
      } else {
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
      <div className="flex h-24 w-16 items-center justify-center rounded-lg border border-sky-500/40 bg-gradient-to-br from-sky-900/60 to-slate-900 text-sky-500">
        <Sparkles size={20} />
      </div>
    )
  }
  const red = card.s === '♥' || card.s === '♦'
  return (
    <div className="flex h-24 w-16 flex-col justify-between rounded-lg border border-line bg-white p-1.5 shadow-md">
      <span className={`text-sm font-bold ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.r}</span>
      <span className={`text-center text-xl ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.s}</span>
      <span className={`rotate-180 text-sm font-bold ${red ? 'text-red-600' : 'text-slate-900'}`}>{card.r}</span>
    </div>
  )
}

function Blackjack({ wallet, dispatch, toast }) {
  const [bet, setBet] = useState(50)
  const [deck, setDeck] = useState([])
  const [player, setPlayer] = useState([])
  const [dealer, setDealer] = useState([])
  const [phase, setPhase] = useState('idle') // idle | player | done
  const [msg, setMsg] = useState(null)
  const [activeBet, setActiveBet] = useState(0)

  const settle = (delta, type, detail) => {
    if (delta !== 0) dispatch({ type: 'wallet-tx', key: wallet.key, delta, txType: type, detail })
  }

  const deal = () => {
    const amount = Math.floor(Number(bet) || 0)
    if (amount <= 0) return toast({ type: 'error', title: 'Enter a bet' })
    if (amount > wallet.balance) return toast({ type: 'error', title: 'Not enough coins' })
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Blackjack bet' })
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

/* ---------------- Slot Machine ---------------- */

const SLOT_SYMBOLS = ['🍒', '🍋', '🔔', '⭐', '7️⃣', '💎']
const SLOT_THREE = { '🍒': 2, '🍋': 3, '🔔': 5, '⭐': 8, '7️⃣': 12, '💎': 20 }
const SLOT_TWO_MULT = 1.5

function SlotMachine({ wallet, dispatch, toast }) {
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
    dispatch({ type: 'wallet-tx', key: wallet.key, delta: -amount, txType: 'bet', detail: 'Slots spin' })

    const final = [
      SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
      SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
      SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
    ]

    // Flicker the reels for visual effect.
    intervalRef.current = setInterval(() => {
      setReels([
        SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
        SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
        SLOT_SYMBOLS[Math.floor(Math.random() * SLOT_SYMBOLS.length)],
      ])
    }, 80)

    // Stop reels one by one.
    const stops = [800, 1300, 1800]
    stops.forEach((t, i) => {
      setTimeout(() => {
        setReels((prev) => {
          const next = [...prev]
          next[i] = final[i]
          return next
        })
        if (i === 2) {
          clearInterval(intervalRef.current)
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
      dispatch({ type: 'wallet-tx', key: wallet.key, delta: payout, txType: 'win', detail: `Slots ${final.join('')}` })
      toast({ type: 'success', title: `You won ${payout.toLocaleString()} coins!`, body: final.join(' ') })
    } else {
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
  { id: 'disc10', kind: 'discount', label: '10% discount code', cost: 2000, desc: '10% off your next license purchase.' },
  { id: 'disc25', kind: 'discount', label: '25% discount code', cost: 5000, desc: '25% off your next license purchase.' },
  { id: 'disc50', kind: 'discount', label: '50% discount code', cost: 10000, desc: 'Half off your next license purchase.' },
  { id: 'key7', kind: 'key', label: '7-day license key', cost: 14000, desc: 'A real 7-day ZeroTrace key.', days: 7 },
  { id: 'key30', kind: 'key', label: '30-day license key', cost: 38000, desc: 'A real 30-day ZeroTrace key.', days: 30 },
  { id: 'key365', kind: 'key', label: '1-year license key', cost: 130000, desc: 'A real 1-year ZeroTrace key.', days: 365 },
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

/* ---------------- Page ---------------- */

export default function Casino() {
  const { state, dispatch } = useStore()
  const wallet = useWallet()
  const toast = useToast()
  const [tab, setTab] = useState('Lucky Wheel')

  return (
    <div>
      <PageHeader
        icon={Coins}
        kicker="Earn coins by catching cheaters"
        title="ZeroTrace Coins"
        subtitle="Every cheater you catch earns coins. Gamble them — or redeem them for discounts and license keys."
        actions={
          <div className="flex items-center gap-2 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-4 py-2">
            <Coins size={18} className="text-yellow-400" />
            <span className="text-lg font-bold text-yellow-300">{wallet.balance.toLocaleString()}</span>
            <span className="muted text-xs">coins</span>
          </div>
        }
      />

      {state.role === 'admin' && (
        <AdminCoinPanel wallet={wallet} dispatch={dispatch} toast={toast} />
      )}

      <Tabs
        tabs={[
          { label: 'Lucky Wheel', icon: Disc3 },
          { label: 'Slots', icon: Cherry },
          { label: 'Blackjack', icon: Dices },
          { label: 'Shop', icon: ShoppingBag },
          { label: 'History', icon: HistoryIcon },
        ]}
        active={tab}
        onChange={setTab}
      />

      <div className="mt-8">
        {tab === 'Lucky Wheel' && <LuckyWheel wallet={wallet} dispatch={dispatch} toast={toast} />}
        {tab === 'Slots' && <SlotMachine wallet={wallet} dispatch={dispatch} toast={toast} />}
        {tab === 'Blackjack' && <Blackjack wallet={wallet} dispatch={dispatch} toast={toast} />}
        {tab === 'Shop' && <Shop wallet={wallet} state={state} dispatch={dispatch} toast={toast} />}
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
