import { useMemo, useState } from 'react'
import { Database, Plus, Search, Trash2, ShieldAlert, Lock } from 'lucide-react'
import { PageHeader, Card, Badge, EmptyState, StatTile, Field, Input } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore, ALL_GAMES } from '../store.jsx'

const TYPES = ['Paid Client', 'Free Client', 'Utility Mod', 'External Tool', 'Spoofer']
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

export default function CheatDatabase() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [q, setQ] = useState('')
  const [game, setGame] = useState('all')
  const [sev, setSev] = useState('all')
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({
    name: '', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: '', notes: '',
  })

  const rows = useMemo(
    () =>
      state.customCheats.filter((c) => {
        if (q && !`${c.name} ${c.notes} ${c.signatures.join(' ')}`.toLowerCase().includes(q.toLowerCase()))
          return false
        if (game !== 'all' && c.game !== game) return false
        if (sev !== 'all' && c.severity !== sev) return false
        return true
      }),
    [state.customCheats, q, game, sev],
  )

  const critical = state.customCheats.filter((c) => c.severity === 'Critical').length

  const add = () => {
    if (!form.name.trim()) return toast({ type: 'error', title: 'Name required' })
    dispatch({
      type: 'add-cheat',
      cheat: {
        ...form,
        name: form.name.trim(),
        signatures: form.signatures.split(',').map((s) => s.trim()).filter(Boolean),
      },
    })
    toast({ type: 'success', title: 'Cheat added', body: form.name })
    setForm({ name: '', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: '', notes: '' })
    setOpen(false)
  }

  return (
    <div>
      <PageHeader
        icon={Database}
        kicker="Known cheats, clients and signatures"
        title="Cheat Database"
        subtitle="Searchable catalogue of known cheat clients with detection signatures."
        actions={
          <button
            onClick={() => setOpen(true)}
            className="flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
          >
            <Plus size={18} /> Add Entry
          </button>
        }
      />

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile icon={Database} label="Total Entries" value={state.customCheats.length} />
        <StatTile icon={ShieldAlert} label="Critical" value={critical} accent="text-red-500" />
        <StatTile icon={Lock} label="Built-in" value={state.customCheats.filter((c) => c.builtin).length} />
        <StatTile icon={Plus} label="Custom" value={state.customCheats.filter((c) => !c.builtin).length} accent="text-sky-500" />
      </div>

      <Card className="p-5">
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search size={16} className="muted absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search name, signature or notes..."
              className="bd tile txt w-full rounded-lg border py-2.5 pl-10 pr-4 text-sm focus:outline-none"
            />
          </div>
          <Select
            className="sm:w-44"
            value={game}
            onChange={setGame}
            options={[{ value: 'all', label: 'All Games' }, ...ALL_GAMES.map((g) => ({ value: g, label: g }))]}
          />
          <Select
            className="sm:w-40"
            value={sev}
            onChange={setSev}
            options={[{ value: 'all', label: 'All Severity' }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]}
          />
        </div>

        <div className="mt-5 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left">
            <thead>
              <tr className="caps-label bd border-b">
                {['Name', 'Type', 'Game', 'Severity', 'Signatures', 'Notes', ''].map((h) => (
                  <th key={h} className="px-3 py-3 font-semibold">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted px-3 py-12 text-center text-sm">
                    No entries match your filters.
                  </td>
                </tr>
              )}
              {rows.map((c) => (
                <tr key={c.id} className="hoverable bd border-b align-top text-sm">
                  <td className="txt px-3 py-4 font-medium">
                    {c.name}
                    {c.builtin && <Lock size={11} className="muted ml-1.5 inline" />}
                  </td>
                  <td className="muted px-3 py-4">{c.type}</td>
                  <td className="px-3 py-4">
                    <span className="bd txt rounded-md border px-2 py-0.5 text-xs">{c.game}</span>
                  </td>
                  <td className="px-3 py-4"><Badge tone={c.severity}>{c.severity}</Badge></td>
                  <td className="px-3 py-4">
                    <div className="flex max-w-[200px] flex-wrap gap-1">
                      {c.signatures.slice(0, 3).map((s) => (
                        <code key={s} className="tile muted rounded border px-1.5 py-0.5 text-[11px]">
                          {s}
                        </code>
                      ))}
                    </div>
                  </td>
                  <td className="muted max-w-[220px] px-3 py-4 text-xs">{c.notes}</td>
                  <td className="px-3 py-4">
                    {!c.builtin && (
                      <button
                        className="muted hover:text-red-500"
                        onClick={() => {
                          dispatch({ type: 'delete-cheat', id: c.id })
                          toast({ type: 'success', title: 'Removed', body: c.name })
                        }}
                      >
                        <Trash2 size={15} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add Cheat Entry"
        footer={
          <>
            <button onClick={() => setOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">
              Cancel
            </button>
            <button onClick={add} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">
              Add
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name">
            <Input autoFocus value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Skillclient" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Type">
              <Select value={form.type} onChange={(v) => setForm({ ...form, type: v })} options={TYPES.map((t) => ({ value: t, label: t }))} />
            </Field>
            <Field label="Game">
              <Select value={form.game} onChange={(v) => setForm({ ...form, game: v })} options={ALL_GAMES.map((g) => ({ value: g, label: g }))} />
            </Field>
          </div>
          <Field label="Severity">
            <Select value={form.severity} onChange={(v) => setForm({ ...form, severity: v })} options={SEVERITIES.map((s) => ({ value: s, label: s }))} />
          </Field>
          <Field label="Signatures (comma separated)">
            <Input value={form.signatures} onChange={(e) => setForm({ ...form, signatures: e.target.value })} placeholder="domain.gg, package.name, loader.exe" />
          </Field>
          <Field label="Notes">
            <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="Detection guidance" />
          </Field>
        </div>
      </Modal>
    </div>
  )
}
