import { useMemo, useState } from 'react'
import { Database, Plus, Search, Trash2, ShieldAlert, Lock, ExternalLink, Flame, Edit2, Download } from 'lucide-react'
import { PageHeader, Card, Badge, EmptyState, StatTile, Field, Input } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore, ALL_GAMES } from '../store.jsx'

const TYPES = ['Paid Client', 'Free Client', 'Utility Mod', 'External Tool', 'Spoofer']
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

function extractFromText(text) {
  const t = text
  const lower = t.toLowerCase()
  const result = {}

  // Name: first quoted string, or first line, or capitalized phrase before keywords
  const quotedMatch = t.match(/["']([^"']{2,60})["']/)
  if (quotedMatch) {
    result.name = quotedMatch[1].trim()
  } else {
    const firstLine = t.split(/\n/)[0].trim()
    const knownKeywords = /\b(free|paid|client|loader|cheat|hack|mod|spoofer|tool|inject|bypass|esp|aimbot|wallhack)\b/i
    const nameLine = firstLine.replace(/[^\w\s.\-+]/g, '').trim()
    if (nameLine.length <= 60) result.name = nameLine
  }

  // Signatures: .exe/.dll/.bat files, domains, hashes, IPs
  const sigs = new Set()
  const fileMatches = t.match(/[\w\-. ]+\.(exe|dll|bat|sys|jar|vbs|ps1|lua)/gi) || []
  fileMatches.forEach(s => sigs.add(s.trim()))
  const domainMatches = t.match(/\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:gg|com|net|org|io|xyz|cc|to|club|shop|me|ru|de|nl)\b/gi) || []
  domainMatches.forEach(s => sigs.add(s.toLowerCase()))
  const hashMatches = t.match(/\b[0-9a-f]{32,64}\b/gi) || []
  hashMatches.forEach(s => sigs.add(s.toLowerCase()))
  const ipMatches = t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []
  ipMatches.forEach(s => sigs.add(s))
  if (sigs.size > 0) result.signatures = [...sigs].join(', ')

  // Game detection
  if (/fivem|fiveM|gta\s*5|gta\s*v|rage\s*mp|ragemp|alt\s*v|altv/i.test(t)) result.game = 'FIVEM'
  else if (/minecraft|mc\s+cheat|mc\s+client/i.test(t)) result.game = 'MINECRAFT'
  else if (/rust\s+(cheat|hack|client)/i.test(t)) result.game = 'RUST'
  else if (/fortnite/i.test(t)) result.game = 'FORTNITE'
  else if (/valorant/i.test(t)) result.game = 'VALORANT'
  else if (/csgo|cs2|counter.strike/i.test(t)) result.game = 'CS2'

  // Type detection
  if (/\bspoof(er|ing)?\b/i.test(t)) result.type = 'Spoofer'
  else if (/\bexternal\b/i.test(t)) result.type = 'External Tool'
  else if (/\butility\b|\bmod\b|\btools?\b/i.test(t)) result.type = 'Utility Mod'
  else if (/\bpaid\b|\bpremium\b|\bsubscription\b|\bmonthly\b|\bprice\b|\bcost\b|\b€\b|\b\$\b/i.test(t)) result.type = 'Paid Client'
  else if (/\bfree\b|\bopen.?source\b/i.test(t)) result.type = 'Free Client'

  // Severity
  if (/\bcritical\b|\bundetected.*all\b|\bwidespread\b|\bvery\s+dangerous\b/i.test(t)) result.severity = 'Critical'
  else if (/\bhigh\b|\bdangerous\b|\bwidely\s+used\b|\bcommon\b|\bdetect.*many\b/i.test(t)) result.severity = 'High'
  else if (/\blow\b|\brare\b|\bseldom\b|\bnot\s+common\b/i.test(t)) result.severity = 'Low'
  else if (/\bmedium\b|\bmoderate\b/i.test(t)) result.severity = 'Medium'

  // Version: v1.2, 4.2+, version 3
  const verMatch = t.match(/\bv?(\d+\.\d+[\w.+\-]*)\b|\bversion\s+(\d[\w.+\-]*)/i)
  if (verMatch) result.version = verMatch[1] || verMatch[2]

  return result
}

export default function CheatDatabase() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [q, setQ] = useState('')
  const [game, setGame] = useState('all')
  const [sev, setSev] = useState('all')
  const [open, setOpen] = useState(false)
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkText, setBulkText] = useState('')
  const [activeOnly, setActiveOnly] = useState(false)
  const [form, setForm] = useState({
    name: '', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: '', notes: '', version: '', relatedTo: [],
  })
  const [smartText, setSmartText] = useState('')
  const [smartDone, setSmartDone] = useState(false)

  const runExtract = () => {
    if (!smartText.trim()) return
    const extracted = extractFromText(smartText)
    setForm(prev => ({
      ...prev,
      ...(extracted.name && !prev.name ? { name: extracted.name } : {}),
      ...(extracted.type ? { type: extracted.type } : {}),
      ...(extracted.game ? { game: extracted.game } : {}),
      ...(extracted.severity ? { severity: extracted.severity } : {}),
      ...(extracted.signatures && !prev.signatures ? { signatures: extracted.signatures } : {}),
      ...(extracted.version && !prev.version ? { version: extracted.version } : {}),
    }))
    setSmartDone(true)
  }

  // Feature 1: Edit state
  const [editId, setEditId] = useState(null)
  const [editForm, setEditForm] = useState({})
  const [editOpen, setEditOpen] = useState(false)

  // Feature 4: Bulk selection
  const [selected, setSelected] = useState(new Set())

  const rows = useMemo(
    () =>
      state.customCheats.filter((c) => {
        if (activeOnly && c.active === false) return false
        if (q && !`${c.name} ${c.notes} ${c.signatures.join(' ')}`.toLowerCase().includes(q.toLowerCase()))
          return false
        if (game !== 'all' && c.game !== game) return false
        if (sev !== 'all' && c.severity !== sev) return false
        return true
      }),
    [state.customCheats, q, game, sev, activeOnly],
  )

  const critical = state.customCheats.filter((c) => c.severity === 'Critical').length

  const add = () => {
    if (!form.name.trim()) return toast({ type: 'error', title: 'Name required' })

    // Feature 3: Duplicate check
    const isDuplicate = state.customCheats.some(c =>
      c.name.toLowerCase() === form.name.trim().toLowerCase() ||
      (form.signatures && form.signatures.split(',').map(s => s.trim()).filter(Boolean).some(sig =>
        c.signatures.some(cs => cs.toLowerCase() === sig.toLowerCase())
      ))
    )
    if (isDuplicate) {
      toast({ type: 'error', title: 'Duplicate', body: 'A cheat with this name or signature already exists.' })
      return
    }

    dispatch({
      type: 'add-cheat',
      cheat: {
        ...form,
        name: form.name.trim(),
        signatures: form.signatures.split(',').map((s) => s.trim()).filter(Boolean),
      },
    })
    toast({ type: 'success', title: 'Cheat added', body: form.name })
    setForm({ name: '', type: 'Free Client', game: 'MINECRAFT', severity: 'Medium', signatures: '', notes: '', version: '', relatedTo: [] })
    setSmartText('')
    setSmartDone(false)
    setOpen(false)
  }

  // Feature 1: Save edit handler
  const saveEdit = () => {
    dispatch({
      type: 'edit-cheat',
      id: editId,
      patch: {
        ...editForm,
        signatures: editForm.signatures.split(',').map(s => s.trim()).filter(Boolean),
        relatedTo: editForm.relatedTo.split(',').map(s => s.trim()).filter(Boolean),
      },
    })
    setEditOpen(false)
  }

  // Feature 2: Export functions
  const exportJSON = () => {
    const data = JSON.stringify(state.customCheats, null, 2)
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([data], { type: 'application/json' }))
    a.download = 'cheat-database.json'
    a.click()
  }
  const exportCSV = () => {
    const header = 'name,type,game,severity,version,signatures,notes'
    const rows = state.customCheats.map(c =>
      [c.name, c.type, c.game, c.severity, c.version || '', (c.signatures || []).join(';'), (c.notes || '').replace(/,/g, ';')].map(v => `"${v}"`).join(',')
    )
    const csv = [header, ...rows].join('\n')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    a.download = 'cheat-database.csv'
    a.click()
  }

  return (
    <div>
      <PageHeader
        icon={Database}
        kicker="Known cheats, clients and signatures"
        title="Cheat Database"
        subtitle="Searchable catalogue of known cheat clients with detection signatures."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {state.role === 'admin' && (
              <button
                onClick={() => setBulkOpen(true)}
                className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:border-sky-500"
              >
                <Plus size={16} /> Bulk Import
              </button>
            )}
            <button onClick={exportJSON} className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:border-sky-500">
              <Download size={16} /> JSON
            </button>
            <button onClick={exportCSV} className="bd txt flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:border-sky-500">
              <Download size={16} /> CSV
            </button>
            <button
              onClick={() => setOpen(true)}
              className="flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-sky-500"
            >
              <Plus size={18} /> Add Entry
            </button>
          </div>
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
          <button
            onClick={() => setActiveOnly(v => !v)}
            className={`rounded-lg border px-3 py-2.5 text-sm font-medium transition-colors ${activeOnly ? 'border-green-600/40 bg-green-600/15 text-green-500' : 'bd txt'}`}
          >
            {activeOnly ? 'Active only' : 'Show all'}
          </button>
        </div>

        {/* Feature 4: Bulk action bar */}
        {selected.size > 0 && (
          <div className="mt-3 flex items-center gap-3 rounded-lg border border-sky-500/20 bg-sky-500/5 px-4 py-2.5">
            <span className="text-sm font-medium txt">{selected.size} ausgewählt</span>
            <button onClick={() => {
              selected.forEach(id => dispatch({ type: 'toggle-cheat-active', id }))
              setSelected(new Set())
            }} className="rounded-lg border bd txt px-3 py-1.5 text-xs hover:border-sky-500">
              Aktivierung umschalten
            </button>
            <button onClick={() => {
              if (!confirm(`${selected.size} Einträge löschen?`)) return
              selected.forEach(id => {
                const c = state.customCheats.find(x => x.id === id)
                if (c && !c.builtin) dispatch({ type: 'delete-cheat', id })
              })
              setSelected(new Set())
            }} className="rounded-lg border border-red-500/30 text-red-400 px-3 py-1.5 text-xs hover:bg-red-500/10">
              Löschen
            </button>
            <button onClick={() => setSelected(new Set())} className="ml-auto muted text-xs hover:txt">
              Abwählen
            </button>
          </div>
        )}

        <div className="mt-5 overflow-x-auto">
          <table className="w-full min-w-[760px] text-left">
            <thead>
              <tr className="caps-label bd border-b">
                {/* Feature 4: select-all checkbox */}
                <th className="px-3 py-3">
                  <input type="checkbox"
                    checked={rows.length > 0 && selected.size === rows.length}
                    onChange={e => setSelected(e.target.checked ? new Set(rows.map(r => r.id)) : new Set())}
                    className="rounded"
                  />
                </th>
                {['', 'Name', 'Version', 'Type', 'Game', 'Severity', 'Signatures', 'Notes', ''].map((h) => (
                  <th key={h} className="px-3 py-3 font-semibold">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={10} className="muted px-3 py-12 text-center text-sm">
                    No entries match your filters.
                  </td>
                </tr>
              )}
              {rows.map((c) => (
                <tr key={c.id} className="hoverable bd border-b align-top text-sm">
                  {/* Feature 4: row checkbox */}
                  <td className="px-3 py-4">
                    <input type="checkbox" checked={selected.has(c.id)}
                      onChange={e => setSelected(prev => { const s = new Set(prev); e.target.checked ? s.add(c.id) : s.delete(c.id); return s })}
                      className="rounded"
                    />
                  </td>
                  <td className="px-3 py-4">
                    <button
                      onClick={() => dispatch({ type: 'toggle-cheat-active', id: c.id })}
                      title={c.active === false ? 'Inactive (click to activate)' : 'Active (click to deactivate)'}
                      className="flex items-center justify-center"
                    >
                      <span className={`h-2.5 w-2.5 rounded-full ${c.active === false ? 'bg-white/20' : 'bg-green-500'}`} />
                    </button>
                  </td>
                  <td className="txt px-3 py-4 font-medium">
                    <div className="flex items-center gap-2">
                      <span>
                        {c.name}
                        {c.builtin && <Lock size={11} className="muted ml-1.5 inline" />}
                      </span>
                      {(c.detectionCount || 0) > 0 && (
                        <span className={`flex items-center gap-0.5 rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${(c.detectionCount || 0) > 5 ? 'text-red-400 bg-red-400/10 border-red-400/20' : 'text-orange-400 bg-orange-400/10 border-orange-400/20'}`}>
                          {(c.detectionCount || 0) > 5 && <Flame size={9} />}
                          {c.detectionCount}
                        </span>
                      )}
                    </div>
                    {(c.relatedTo || []).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {(c.relatedTo || []).map(r => (
                          <span key={r} className="rounded-full bg-white/5 border bd px-1.5 py-0.5 text-[10px] muted">{r}</span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="muted px-3 py-4 text-xs">{c.version || ''}</td>
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
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://www.virustotal.com/gui/search/${encodeURIComponent(c.name)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="muted hover:text-sky-400"
                        title="Search on VirusTotal"
                      >
                        <ExternalLink size={14} />
                      </a>
                      {c.signatures && c.signatures.some(s => /^[0-9a-f]{32,}$/i.test(s)) && (
                        <a
                          href={`https://www.virustotal.com/gui/search/${encodeURIComponent(c.signatures.find(s => /^[0-9a-f]{32,}$/i.test(s)))}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="muted hover:text-purple-400"
                          title="Hash lookup on VirusTotal"
                        >
                          <ExternalLink size={12} />
                        </a>
                      )}
                      {/* Feature 1: Edit button */}
                      <button
                        className="muted hover:text-sky-400"
                        title="Edit"
                        onClick={() => {
                          setEditId(c.id)
                          setEditForm({
                            name: c.name,
                            type: c.type,
                            game: c.game,
                            severity: c.severity,
                            signatures: c.signatures.join(', '),
                            notes: c.notes || '',
                            version: c.version || '',
                            relatedTo: (c.relatedTo || []).join(', '),
                          })
                          setEditOpen(true)
                        }}
                      >
                        <Edit2 size={14} />
                      </button>
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
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Add Entry Modal */}
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add Cheat Entry"
        footer={
          <>
            <button onClick={() => { setOpen(false); setSmartText(''); setSmartDone(false) }} className="bd txt rounded-lg border px-4 py-2 text-sm">
              Cancel
            </button>
            <button onClick={add} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">
              Add
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="rounded-xl border bd overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 bg-white/[0.03] border-b bd">
              <span className="text-xs font-semibold caps-label">Smart Extract</span>
              {smartDone && <span className="text-[11px] text-green-400 font-medium">Felder automatisch ausgefüllt</span>}
            </div>
            <textarea
              value={smartText}
              onChange={(e) => { setSmartText(e.target.value); setSmartDone(false) }}
              onPaste={(e) => {
                const pasted = e.clipboardData.getData('text')
                setTimeout(() => {
                  setSmartText(pasted)
                  const extracted = extractFromText(pasted)
                  setForm(prev => ({
                    ...prev,
                    ...(extracted.name && !prev.name ? { name: extracted.name } : {}),
                    ...(extracted.type ? { type: extracted.type } : {}),
                    ...(extracted.game ? { game: extracted.game } : {}),
                    ...(extracted.severity ? { severity: extracted.severity } : {}),
                    ...(extracted.signatures && !prev.signatures ? { signatures: extracted.signatures } : {}),
                    ...(extracted.version && !prev.version ? { version: extracted.version } : {}),
                  }))
                  setSmartDone(true)
                }, 0)
              }}
              rows={3}
              placeholder="Paste cheat info, description, or any text here — fields below are filled automatically…"
              className="bd tile txt w-full p-3 text-xs font-mono focus:outline-none resize-none bg-transparent"
            />
            <div className="px-3 py-2 flex justify-end border-t bd">
              <button
                onClick={runExtract}
                className="rounded-lg bg-sky-600/80 hover:bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white"
              >
                Extrahieren
              </button>
            </div>
          </div>

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
          <Field label="Version (optional)">
            <Input value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })} placeholder="e.g. 4.2+" />
          </Field>
          <Field label="Related Cheats (comma separated names, optional)">
            <Input value={Array.isArray(form.relatedTo) ? form.relatedTo.join(', ') : form.relatedTo}
              onChange={(e) => setForm({ ...form, relatedTo: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
              placeholder="e.g. Vape V4, Novoline" />
          </Field>
        </div>
      </Modal>

      {/* Feature 1: Edit Entry Modal */}
      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit Entry"
        footer={
          <>
            <button onClick={() => setEditOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">
              Cancel
            </button>
            <button onClick={saveEdit} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">
              Save
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name">
            <Input autoFocus value={editForm.name || ''} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} placeholder="e.g. Skillclient" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Type">
              <Select value={editForm.type || 'Free Client'} onChange={(v) => setEditForm({ ...editForm, type: v })} options={TYPES.map((t) => ({ value: t, label: t }))} />
            </Field>
            <Field label="Game">
              <Select value={editForm.game || 'MINECRAFT'} onChange={(v) => setEditForm({ ...editForm, game: v })} options={ALL_GAMES.map((g) => ({ value: g, label: g }))} />
            </Field>
          </div>
          <Field label="Severity">
            <Select value={editForm.severity || 'Medium'} onChange={(v) => setEditForm({ ...editForm, severity: v })} options={SEVERITIES.map((s) => ({ value: s, label: s }))} />
          </Field>
          <Field label="Signatures (comma separated)">
            <Input value={editForm.signatures || ''} onChange={(e) => setEditForm({ ...editForm, signatures: e.target.value })} placeholder="domain.gg, package.name, loader.exe" />
          </Field>
          <Field label="Notes">
            <Input value={editForm.notes || ''} onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })} placeholder="Detection guidance" />
          </Field>
          <Field label="Version (optional)">
            <Input value={editForm.version || ''} onChange={(e) => setEditForm({ ...editForm, version: e.target.value })} placeholder="e.g. 4.2+" />
          </Field>
          <Field label="Related Cheats (comma separated names, optional)">
            <Input value={editForm.relatedTo || ''}
              onChange={(e) => setEditForm({ ...editForm, relatedTo: e.target.value })}
              placeholder="e.g. Vape V4, Novoline" />
          </Field>
        </div>
      </Modal>

      <Modal
        open={bulkOpen}
        onClose={() => setBulkOpen(false)}
        title="Bulk import cheats"
        footer={
          <button
            onClick={() => {
              try {
                const parsed = JSON.parse(bulkText)
                const arr = Array.isArray(parsed) ? parsed : [parsed]
                const cheats = arr
                  .filter((c) => c && c.name)
                  .map((c) => ({
                    name: String(c.name),
                    type: c.type || 'Custom',
                    game: c.game || 'FIVEM',
                    severity: c.severity || 'Medium',
                    signatures: Array.isArray(c.signatures) ? c.signatures : String(c.signatures || '').split(',').map((s) => s.trim()).filter(Boolean),
                    notes: c.notes || '',
                  }))
                if (cheats.length === 0) {
                  toast({ type: 'error', title: 'Nothing to import', body: 'JSON had no usable entries.' })
                  return
                }
                dispatch({ type: 'bulk-add-cheats', cheats })
                toast({ type: 'success', title: 'Imported', body: `${cheats.length} cheats added` })
                setBulkText('')
                setBulkOpen(false)
              } catch (e) {
                toast({ type: 'error', title: 'Invalid JSON', body: e.message })
              }
            }}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-500"
          >
            Import
          </button>
        }
      >
        <div className="space-y-3 text-sm">
          <p className="muted">
            Paste a JSON array. Each item needs at least <code className="txt">name</code>; supports{' '}
            <code className="txt">type</code>, <code className="txt">game</code>,{' '}
            <code className="txt">severity</code>, <code className="txt">signatures</code> (array or comma-separated string),{' '}
            <code className="txt">notes</code>.
          </p>
          <textarea
            value={bulkText}
            onChange={(e) => setBulkText(e.target.value)}
            rows={12}
            placeholder='[{"name":"Vape V5","type":"Paid Client","game":"MINECRAFT","severity":"Critical","signatures":["vape.gg","v5_loader"],"notes":""}]'
            className="bd tile txt w-full rounded-lg border p-3 font-mono text-xs focus:outline-none"
          />
        </div>
      </Modal>
    </div>
  )
}
