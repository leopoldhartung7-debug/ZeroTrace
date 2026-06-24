export default function Tabs({ tabs, active, onChange }) {
  return (
    <div className="bd flex gap-8 overflow-x-auto border-b">
      {tabs.map((tab) => {
        const label = typeof tab === 'string' ? tab : tab.label
        const Icon = typeof tab === 'string' ? null : tab.icon
        const isActive = active === label
        return (
          <button
            key={label}
            onClick={() => onChange(label)}
            className={`relative flex shrink-0 items-center gap-2 pb-3 text-sm font-medium transition-colors ${
              isActive ? 'txt' : 'muted hover:txt'
            }`}
          >
            {Icon && <Icon size={16} />}
            {label}
            {isActive && (
              <span
                className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-sky-400"
                style={{ animation: 'zt-grow 0.3s cubic-bezier(0.22,1,0.36,1) both' }}
              />
            )}
          </button>
        )
      })}
    </div>
  )
}
