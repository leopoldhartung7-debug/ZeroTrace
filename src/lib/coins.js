/* Awards coins to a pin's owner when a scan comes back "Cheating".
   Fires once per pin (the reducer guards with the coinsAwarded flag). */

import { useEffect } from 'react'
import { useStore } from '../store.jsx'

export const COIN_BASE = 100 // base reward per cheater caught
export const COIN_PER_DETECTION = 10

export function coinsForPin(pin) {
  return COIN_BASE + (pin.detections || 0) * COIN_PER_DETECTION
}

export function CoinAwarder() {
  const { state, dispatch } = useStore()
  useEffect(() => {
    const pending = (state.pins || []).filter(
      (p) => p.status === 'Finished' && p.result === 'Cheating' && !p.coinsAwarded,
    )
    pending.forEach((p) => {
      dispatch({ type: 'award-coins', pinId: p.id, amount: coinsForPin(p) })
    })
  }, [state.pins, dispatch])
  return null
}
