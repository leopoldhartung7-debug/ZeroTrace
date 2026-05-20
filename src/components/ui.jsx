import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { X, Check, AlertTriangle, Info } from 'lucide-react'

function useScrollLock(open) {
  useEffect(() => {
    if (!open) return
    // Lock the real scroll container (<main>), not <body>. Toggling
    // body overflow on iOS Safari resets scroll to the top; locking
    // the scroll element preserves its position.
    const el = document.getElementById('app-main')
    if (el) {
      const prev = el.style.overflow
      el.style.overflow = 'hidden'
      return () => {
        el.style.overflow = prev
      }
    }
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [open])
}

export function Modal({ open, onClose, title, children, footer }) {
  useScrollLock(open)
  useEffect(() => {
    if (!open) return
    const onEsc = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onEsc)
    return () => window.removeEventListener('keydown', onEsc)
  }, [open, onClose])

  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="panel relative z-10 flex max-h-[88vh] w-full max-w-md flex-col rounded-2xl border shadow-2xl">
        <div className="bd flex shrink-0 items-center justify-between border-b px-6 py-4">
          <h3 className="txt text-lg font-semibold">{title}</h3>
          <button onClick={onClose} className="muted hover:txt rounded-md p-1">
            <X size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto overscroll-contain px-6 py-5">{children}</div>
        {footer && (
          <div className="bd flex shrink-0 justify-end gap-3 border-t px-6 py-4">{footer}</div>
        )}
      </div>
    </div>,
    document.body,
  )
}

export function Drawer({ open, onClose, title, children }) {
  useScrollLock(open)
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="panel absolute right-0 top-0 z-10 flex h-full w-full max-w-md flex-col border-l shadow-2xl">
        <div className="bd flex shrink-0 items-center justify-between border-b p-5">
          <h3 className="txt text-lg font-semibold">{title}</h3>
          <button onClick={onClose} className="muted hover:txt rounded-md p-1">
            <X size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto overscroll-contain p-5">{children}</div>
      </div>
    </div>,
    document.body,
  )
}

export function Menu({ trigger, items, header }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    const onClick = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false)
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])
  return (
    <div className="relative" ref={ref}>
      <span onClick={() => setOpen((o) => !o)}>{trigger}</span>
      {open && (
        <div className="panel absolute right-0 z-20 mt-2 w-56 overflow-hidden rounded-xl border py-1.5 shadow-2xl">
          {header && (
            <p className="txt px-3 pb-1.5 pt-1 text-sm font-semibold">{header}</p>
          )}
          {items.map((it, i) =>
            it.divider ? (
              <div key={i} className="bd my-1.5 border-t" />
            ) : it.disabled ? (
              <div
                key={i}
                title={it.disabledHint}
                className="muted flex w-full cursor-not-allowed items-center gap-3 px-3 py-2.5 text-left text-sm opacity-50"
              >
                {it.icon}
                <span className="flex-1">{it.label}</span>
              </div>
            ) : (
              <button
                key={i}
                onClick={() => {
                  setOpen(false)
                  it.onClick?.()
                }}
                className={`hoverable flex w-full items-center gap-3 px-3 py-2.5 text-left text-sm ${
                  it.danger ? 'text-red-500' : 'txt'
                }`}
              >
                {it.icon}
                {it.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  )
}

export function Select({ value, onChange, options, className = '' }) {
  return (
    <div className={`relative ${className}`}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bd tile txt w-full appearance-none rounded-lg border px-4 py-2.5 pr-9 text-sm focus:outline-none"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <svg
        className="muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2"
        width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      >
        <path d="M6 9l6 6 6-6" />
      </svg>
    </div>
  )
}

const ToastCtx = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const push = useCallback((toast) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, ...toast }])
    setTimeout(
      () => setToasts((t) => t.filter((x) => x.id !== id)),
      toast.duration || (toast.onClick ? 9000 : 3500),
    )
  }, [])

  const dismiss = (id) => setToasts((t) => t.filter((x) => x.id !== id))

  const icons = {
    success: <Check size={16} className="text-green-500" />,
    error: <AlertTriangle size={16} className="text-red-500" />,
    info: <Info size={16} className="text-sky-500" />,
  }

  return (
    <ToastCtx.Provider value={push}>
      {children}
      {createPortal(
        <div className="fixed bottom-5 right-5 z-[60] flex w-[min(330px,calc(100vw-2.5rem))] flex-col gap-2">
          {toasts.map((t) => (
            <div
              key={t.id}
              onClick={
                t.onClick
                  ? () => {
                      t.onClick()
                      dismiss(t.id)
                    }
                  : undefined
              }
              className={`panel flex items-start gap-3 rounded-lg border px-4 py-3 shadow-xl ${
                t.onClick ? 'hoverable cursor-pointer' : ''
              }`}
            >
              <span className="mt-0.5">{icons[t.type] || icons.info}</span>
              <div className="min-w-0">
                <p className="txt text-sm font-medium">{t.title}</p>
                {t.body && <p className="muted text-xs">{t.body}</p>}
                {t.onClick && (
                  <p className="mt-1 text-xs font-medium text-sky-500">Tap to view →</p>
                )}
              </div>
            </div>
          ))}
        </div>,
        document.body,
      )}
    </ToastCtx.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastCtx)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
