/* Watchlist notifier: when a Discord ID on someone's watchlist gets a new
   finished scan, push an in-app notification to the watcher — once per pin. */

import { useEffect } from 'react'
import { useStore } from '../store.jsx'

export function WatchlistNotifier() {
  const { state, dispatch } = useStore()
  useEffect(() => {
    const wl = state.watchlist || []
    if (wl.length === 0) return
    const finished = (state.pins || []).filter((p) => p.status === 'Finished' && p.discordId)
    wl.forEach((w) => {
      const notified = w.notifiedPins || []
      finished.forEach((p) => {
        if (p.discordId !== w.discordId) return
        if ((p.createdAt || 0) < (w.addedAt || 0)) return
        if (notified.includes(p.id)) return
        dispatch({
          type: 'watchlist-notify',
          watchId: w.id,
          pinId: p.id,
          pinCode: p.pin,
          verdict: p.result || 'pending',
        })
      })
    })
  }, [state.pins, state.watchlist, dispatch])
  return null
}
