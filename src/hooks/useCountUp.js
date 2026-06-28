import { useEffect, useRef, useState } from 'react'

/**
 * Animates a number from 0 to `target` over `duration` ms.
 * Pass non-number values (strings like "12k", "99.9%") and they will be
 * returned untouched so existing formatted labels keep working.
 */
export function useCountUp(target, { duration = 1100, start = 0 } = {}) {
  const numeric = typeof target === 'number' && Number.isFinite(target)
  const [value, setValue] = useState(numeric ? start : target)
  const frame = useRef(0)
  const startedAt = useRef(null)

  useEffect(() => {
    if (!numeric) {
      setValue(target)
      return undefined
    }

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches

    if (prefersReducedMotion || duration <= 0) {
      setValue(target)
      return undefined
    }

    startedAt.current = null
    const step = (ts) => {
      if (startedAt.current === null) startedAt.current = ts
      const elapsed = ts - startedAt.current
      const t = Math.min(1, elapsed / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setValue(Math.round(start + (target - start) * eased))
      if (t < 1) frame.current = window.requestAnimationFrame(step)
    }
    frame.current = window.requestAnimationFrame(step)
    return () => window.cancelAnimationFrame(frame.current)
  }, [target, duration, start, numeric])

  return value
}
