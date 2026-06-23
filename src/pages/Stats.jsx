import { useMemo } from 'react'
import { BarChart3, ShieldAlert, Database, Flame } from 'lucide-react'
import { PageHeader, Card, StatTile, Ring } from '../components/kit.jsx'
import { useStore } from '../store.jsx'

const GAME_COLORS = {
  FIVEM: '#848eb0',
  MINECRAFT: '#4ADE80',
  RUST: '#FB923C',
  FORTNITE: '#A78BFA',
  VALORANT: '#F87171',
  CS2: '#FACC15',
  OTHER: '#94A3B8',
}

const SEV_COLORS = { Critical: '#EF4444', High: '#F97316', Medium: '#EAB308', Low: '#22C55E' }

function HBar({ label, value, max, color, extra }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="flex items-center gap-3 py-2">
      <div className="flex w-36 min-w-0 items-center gap-2 shrink-0">
        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-sm" style={{ background: color || 'var(--accent)' }} />
        <span className="truncate text-xs txt">{label}</span>
      </div>
      <div className="flex-1 overflow-hidden rounded-full" style={{ height: 3, background: 'var(--border)' }}>
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: color || 'var(--accent)' }} />
      </div>
      <div className="flex w-16 items-center justify-end gap-1.5 shrink-0">
        <span className="text-xs txt font-medium">{value}</span>
        <span className="text-[10px] muted">{pct}%</span>
        {extra && <span className="text-[10px] muted">{extra}</span>}
      </div>
    </div>
  )
}

export default function StatsPage() {
  const { state } = useStore()
  const cheats = state.customCheats || []
  const scans = state.scans || []

  const byGame = useMemo(() => {
    const m = {}
    cheats.forEach(c => { m[c.game] = (m[c.game] || 0) + 1 })
    return Object.entries(m).sort((a, b) => b[1] - a[1])
  }, [cheats])

  const bySeverity = useMemo(() => {
    const order = ['Critical', 'High', 'Medium', 'Low']
    const m = {}
    cheats.forEach(c => { m[c.severity] = (m[c.severity] || 0) + 1 })
    return order.filter(s => m[s]).map(s => [s, m[s]])
  }, [cheats])

  const topDetected = useMemo(() =>
    [...cheats].filter(c => (c.detectionCount || 0) > 0)
      .sort((a, b) => (b.detectionCount || 0) - (a.detectionCount || 0))
      .slice(0, 10),
    [cheats]
  )

  const maxGame = byGame[0]?.[1] || 1
  const maxDet = topDetected[0]?.detectionCount || 1
  const totalEntries = cheats.length || 1
  const totalDetections = cheats.reduce((s, c) => s + (c.detectionCount || 0), 0)

  return (
    <div>
      <PageHeader
        icon={BarChart3}
        kicker="Cheat Database Analytics"
        title="Statistics"
        subtitle="Detection counts, severity breakdown and game distribution."
      />

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile icon={Database} label="Total Entries" value={cheats.length} />
        <StatTile icon={ShieldAlert} label="Critical Cheats" value={cheats.filter(c => c.severity === 'Critical').length} accent="text-red-500" />
        <StatTile icon={Flame} label="Total Detections" value={totalDetections} accent="text-orange-400" />
        <StatTile icon={BarChart3} label="Total Scans" value={scans.length} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-5">
          <h3 className="mb-4 text-sm font-semibold txt">Einträge nach Spiel</h3>
          {byGame.map(([game, count]) => (
            <HBar key={game} label={game} value={count} max={maxGame} color={GAME_COLORS[game] || '#94A3B8'} />
          ))}
          {byGame.length === 0 && <p className="muted text-xs text-center py-6">Keine Daten</p>}
        </Card>

        <Card className="p-5">
          <h3 className="mb-5 text-sm font-semibold txt">Einträge nach Schweregrad</h3>
          {bySeverity.length === 0 && <p className="muted text-xs text-center py-6">Keine Daten</p>}
          <div className={`grid gap-4 ${bySeverity.length <= 2 ? 'grid-cols-2' : 'grid-cols-2 sm:grid-cols-4'}`}>
            {bySeverity.map(([sev, count]) => {
              const pct = Math.round((count / totalEntries) * 100)
              return (
                <div key={sev} className="flex flex-col items-center gap-1.5 py-1">
                  <Ring value={count} max={totalEntries} color={SEV_COLORS[sev]} size={56} thickness={4} />
                  <p className="mt-1 text-xs muted">{sev}</p>
                  <p className="text-base font-semibold txt">{count}</p>
                  <p className="text-[11px] muted">{pct}%</p>
                </div>
              )
            })}
          </div>
        </Card>

        <Card className="p-5 lg:col-span-2">
          <h3 className="mb-4 text-sm font-semibold txt">Meisterkannte Cheats</h3>
          {topDetected.length === 0 && (
            <p className="muted text-xs text-center py-6">Noch keine Erkennungen — führe einen Scan durch um Daten zu sehen.</p>
          )}
          {topDetected.map(c => (
            <HBar key={c.id} label={c.name} value={c.detectionCount || 0} max={maxDet}
              color={SEV_COLORS[c.severity] || '#848eb0'} extra={c.game} />
          ))}
        </Card>
      </div>
    </div>
  )
}
