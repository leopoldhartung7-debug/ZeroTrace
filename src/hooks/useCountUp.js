import { useEffect, useRef, useState } from 'react'

export function useCountUp(target, { duration = 1100, start = 0 } = {}) {
  const [value, setValue] = useState(start)
  const frame = useRef(0)
  const startedAt = useRef(null)

  useEffect(() => {
    if (typeof target !== 'number' || Number.isNaN(target)) return undefined

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
      if (t < 1) {
        frame.current = window.requestAnimationFrame(step)
      }
    }

    frame.current = window.requestAnimationFrame(step)
    return () => window.cancelAnimationFrame(frame.current)
  }, [target, duration, start])

  return value
}
