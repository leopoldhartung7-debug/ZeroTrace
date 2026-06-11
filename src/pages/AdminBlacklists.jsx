import { useState } from 'react'
import { Ban, Plus, Trash2, Cpu, MessageSquare, AtSign } from 'lucide-react'
import { PageHeader, Card, Input } from '../components/kit.jsx'
import Tabs from '../components/Tabs.jsx'
import { useStore, logAdminAction } from '../store.jsx'

const LISTS = {
  hwids: { label: 'HWID Bans', icon: Cpu, placeholder: 'FNV-32 HWID (e.g. 7A3B91C4)', validate: (v) => /^[0-9a-f]{8}$/i.test(v) ? null : 'Must be 8 hex chars' },
  discordIds: { label: 'Discord ID Bans', icon: MessageSquare, placeholder: '17-20 digit Discord user ID', validate: (v) => /^\d{17,20}$/.test(v) ? null : 'Must be 17-20 digits' },
  emailDomains: { label: 'Email Domain Bans', icon: AtSign, placeholder: 'domain.com or *.tempmail.org', validate: (v) => /^(\*\.)?[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) ? null : 'Invalid domain' },
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleDateString() : '—'
}

function BlacklistTab({ listKey }) {
  const { state, dispatch } = useStore()
  const list = (state.blacklists || {})[listKey] || []
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [err, setErr] = useState('')
  const meta = LISTS[listKey]

  const add = () => {
    const trimmed = value.trim()
    if (!trimmed) return
    const e = meta.validate(trimmed)
    if (e) { setErr(e); return }
    dispatch({ type: 'add-blacklist', list: listKey, value: trimmed, reason: reason.trim() })
    logAdminAction(dispatch, state, 'blacklist-add', `${listKey}:${trimmed}`, reason)
    setValue(''); setReason(''); setErr('')
  }

  const remove = (v) => {
    dispatch({ type: 'remove-blacklist', list: listKey, value: v })
    logAdminAction(dispatch, state, 'blacklist-remove', `${listKey}:${v}`)
  }

  const clearAll = () => {
    if (list.length === 0) return
    if (!window.confirm(`Clear all ${list.length} entries from this blacklist? This cannot be undone.`)) return
    dispatch({ type: 'clear-blacklist', list: listKey })
    logAdminAction(dispatch, state, 'blacklist-clear', `${listKey}:${list.length} entries`)
  }

  return (
    <div>
      <Card className="p-4">
        <p className="caps-label mb-3">Add new entry</p>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={value}
            onChange={(e) => { setValue(e.target.value); setErr('') }}
            placeholder={meta.placeholder}
            className="flex-1"
          />
          <Input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (optional)"
            className="flex-1"
          />
          <button onClick={add} className="bg-sky-600 hover:bg-sky-700 flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white">
            <Plus size={14} /> Add
          </button>
        </div>
        {err && <p className="mt-2 text-xs text-red-500">{err}</p>}
      </Card>

      {list.length > 0 && (
        <div className="mt-4 flex items-center justify-between">
          <p className="muted text-xs">{list.length} {list.length === 1 ? 'entry' : 'entries'}</p>
          <button
            onClick={clearAll}
            className="inline-flex items-center gap-1.5 rounded-md border border-red-600/40 px-3 py-1.5 text-xs font-medium text-red-500 hover:bg-red-600/10"
          >
            <Trash2 size={13} /> Clear all
          </button>
        </div>
      )}

      <Card className="mt-2 p-0">
        {list.length === 0 ? (
          <p className="muted py-12 text-center text-sm">No entries on this list.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="caps-label bd border-b">
                  <th className="px-4 py-3">Value</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3">Added</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {list.map((e) => (
                  <tr key={e.value} className="bd border-b last:border-0">
                    <td className="txt break-all px-4 py-3 font-mono text-xs">{e.value}</td>
                    <td className="muted px-4 py-3 text-xs">{e.reason || '—'}</td>
                    <td className="muted px-4 py-3 text-xs">{fmt(e.addedAt)}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => remove(e.value)}
                        className="bd inline-flex items-center gap-1 rounded-md border border-red-600/40 px-2 py-1 text-xs text-red-500 hover:bg-red-600/10"
                      >
                        <Trash2 size={12} /> Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

export default function AdminBlacklists() {
  const [tab, setTab] = useState('hwids')
  return (
    <div>
      <PageHeader
        icon={Ban}
        kicker="Moderation"
        title="Blacklists"
        subtitle="Block HWIDs, Discord IDs and email domains from registering or scanning."
      />
      <Tabs
        tabs={[
          { label: 'hwids', icon: Cpu },
          { label: 'discordIds', icon: MessageSquare },
          { label: 'emailDomains', icon: AtSign },
        ].map((t) => ({ ...t, label: LISTS[t.label].label.replace(/ Bans$/, '') })) }
        active={LISTS[tab].label.replace(/ Bans$/, '')}
        onChange={(label) => {
          const k = Object.keys(LISTS).find((x) => LISTS[x].label.replace(/ Bans$/, '') === label)
          if (k) setTab(k)
        }}
      />
      <div className="mt-6">
        <BlacklistTab listKey={tab} />
      </div>
    </div>
  )
}
