export default function Tabs({ tabs, active, onChange }) {
  return (
    <div className="flex gap-8 border-b border-line">
      {tabs.map((tab) => {
        const label = typeof tab === 'string' ? tab : tab.label
        const icon = typeof tab === 'string' ? null : tab.icon
        const Icon = icon
        return (
          <button
            key={label}
            onClick={() => onChange(label)}
            className={`relative flex items-center gap-2 pb-3 text-sm font-medium transition-colors ${
              active === label
                ? 'text-white'
                : 'text-neutral-500 hover:text-neutral-300'
            }`}
          >
            {Icon && <Icon size={16} />}
            {label}
            {active === label && (
              <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-blue-500" />
            )}
          </button>
        )
      })}
    </div>
  )
}
