import { useMemo, useState } from 'react'
import {
  History as HistoryIcon, Pin, ScanLine, FileText, Code2, Database,
  LifeBuoy, Download, Activity,
} from 'lucide-react'
import { PageHeader, Card, EmptyState, StatTile } from '../components/kit.jsx'
import { Select } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

const ICONS = {
  pin: Pin, scan: ScanLine, file: FileText, rule: Code2,
  db: Database, support: LifeBuoy, default: Activity,
}

export default function History() {
  const { state } = useStore()
  const [kind, setKind] = useState('all')

  const rows = useMemo(
    () => state.events.filter((e) => kind === 'all' || e.kind === kind),
    [state.events, kind],
  )

  const exportCsv = () => {
    const csv = [
      'time,kind,title,detail',
      ...state.events.map(
        (e) =>
          `${new Date(e.time).toISOString()},${e.kind},"${e.title}","${(e.detail || '').replace(/"/g, "'")}"`,
      ),
    ].join('\n')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    a.download = 'activity-log.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const count = (k) => state.events.filter((e) => e.kind === k).length

  return (
    <div>
      <PageHeader
        icon={HistoryIcon}
        kicker="Audit trail of everything you do"
        title="Activity Log"
        subtitle="Every pin, scan, rule and database change is recorded locally."
        actions={
          <button
            onClick={exportCsv}
            className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium"
          >
            <Download size={16} /> Export CSV
          </button>
        }
      />

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile icon={Activity} label="Total Events" value={state.events.length} />
        <StatTile icon={ScanLine} label="Scans" value={count('scan')} accent="text-blue-500" />
        <StatTile icon={Pin} label="Pin Actions" value={count('pin')} />
        <StatTile icon={Code2} label="Rule Changes" value={count('rule')} accent="text-yellow-500" />
      </div>

      <Card className="p-5">
        <div className="mb-5 flex justify-end">
          <Select
            className="w-48"
            value={kind}
            onChange={setKind}
            options={[
              { value: 'all', label: 'All Activity' },
              { value: 'pin', label: 'Pins' },
              { value: 'scan', label: 'Scans' },
              { value: 'file', label: 'Files' },
              { value: 'rule', label: 'YARA Rules' },
              { value: 'db', label: 'Database' },
              { value: 'support', label: 'Support' },
            ]}
          />
        </div>
        {rows.length === 0 ? (
          <EmptyState icon={HistoryIcon} title="No activity yet" hint="Actions you take across the app will appear here." />
        ) : (
          <ol className="relative ml-3 border-l border-line">
            {rows.map((e) => {
              const Icon = ICONS[e.kind] || ICONS.default
              return (
                <li key={e.id} className="mb-6 ml-6">
                  <span className="panel absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full border">
                    <Icon size={12} className="muted" />
                  </span>
                  <div className="flex items-center justify-between">
                    <p className="txt text-sm font-medium">{e.title}</p>
                    <time className="muted text-xs">{new Date(e.time).toLocaleString()}</time>
                  </div>
                  {e.detail && <p className="muted mt-0.5 text-xs">{e.detail}</p>}
                </li>
              )
            })}
          </ol>
        )}
      </Card>
    </div>
  )
}
