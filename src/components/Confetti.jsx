import { useEffect, useState } from 'react'

const COLORS = ['#38bdf8', '#22c55e', '#eab308', '#dc2626', '#a855f7', '#fff']

/* Fires a one-shot confetti burst whenever `trigger` changes to a truthy value. */
export default function Confetti({ trigger }) {
  const [pieces, setPieces] = useState([])

  useEffect(() => {
    if (!trigger) return
    const next = Array.from({ length: 60 }, (_, i) => ({
      id: `${trigger}-${i}`,
      left: Math.random() * 100,
      delay: Math.random() * 0.3,
      duration: 1.6 + Math.random() * 1.2,
      color: COLORS[Math.floor(Math.random() * COLORS.length)],
      size: 6 + Math.random() * 6,
      rot: Math.random() * 360,
    }))
    setPieces(next)
    const t = setTimeout(() => setPieces([]), 3200)
    return () => clearTimeout(t)
  }, [trigger])

  if (pieces.length === 0) return null
  return (
    <div className="pointer-events-none fixed inset-0 z-[70] overflow-hidden">
      <style>{`@keyframes zt-confetti-fall { 0% { transform: translateY(-10vh) rotate(0deg); opacity: 1 } 100% { transform: translateY(110vh) rotate(720deg); opacity: 0.9 } }`}</style>
      {pieces.map((p) => (
        <span
          key={p.id}
          style={{
            position: 'absolute',
            top: 0,
            left: `${p.left}%`,
            width: p.size,
            height: p.size * 1.6,
            background: p.color,
            borderRadius: 2,
            transform: `rotate(${p.rot}deg)`,
            animation: `zt-confetti-fall ${p.duration}s ${p.delay}s cubic-bezier(0.3,0.6,0.4,1) forwards`,
          }}
        />
      ))}
    </div>
  )
}
