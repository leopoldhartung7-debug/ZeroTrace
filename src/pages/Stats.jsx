import { useMemo } from 'react'
import { BarChart3, ShieldAlert, Database, Flame } from 'lucide-react'
import { PageHeader, Card, StatTile } from '../components/kit.jsx'
import { useStore } from '../store.jsx'

const GAME_COLORS = {
  FIVEM: '#38BDF8',
  MINECRAFT: '#4ADE80',
  RUST: '#FB923C',
  FORTNITE: '#A78BFA',
  VALORANT: '#F87171',
  CS2: '#FACC15',
  OTHER: '#94A3B8',
}

const SEV_COLORS = { Critical: '#EF4444', High: '#F97316', Medium: '#EAB308', Low: '#22C55E' }

function HBar({ label, value, max, color, extra }) {
  const pct = max > 0 ? (value / max) * 100 : 0
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="w-36 truncate text-xs txt font-medium">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: color || '#38BDF8' }} />
      </div>
      <span className="w-8 text-right text-xs muted">{value}</span>
      {extra && <span className="text-[10px] muted">{extra}</span>}
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
  const maxSev = Math.max(...bySeverity.map(([, v]) => v), 1)
  const maxDet = topDetected[0]?.detectionCount || 1

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
          <h3 className="mb-4 text-sm font-semibold txt">Einträge nach Schweregrad</h3>
          {bySeverity.map(([sev, count]) => (
            <HBar key={sev} label={sev} value={count} max={maxSev} color={SEV_COLORS[sev]} />
          ))}
          {bySeverity.length === 0 && <p className="muted text-xs text-center py-6">Keine Daten</p>}
        </Card>

        <Card className="p-5 lg:col-span-2">
          <h3 className="mb-4 text-sm font-semibold txt">Meisterkannte Cheats</h3>
          {topDetected.length === 0 && (
            <p className="muted text-xs text-center py-6">Noch keine Erkennungen — führe einen Scan durch um Daten zu sehen.</p>
          )}
          {topDetected.map(c => (
            <HBar key={c.id} label={c.name} value={c.detectionCount || 0} max={maxDet}
              color={SEV_COLORS[c.severity] || '#38BDF8'} extra={c.game} />
          ))}
        </Card>
      </div>
    </div>
  )
}
