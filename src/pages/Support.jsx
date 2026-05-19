import { useState } from 'react'
import { LifeBuoy, Plus, MessageSquare } from 'lucide-react'
import { PageHeader, Card, Badge, EmptyState, Accordion, Field, Input, Textarea } from '../components/kit.jsx'
import { Modal, Select, useToast } from '../components/ui.jsx'
import { useStore } from '../store.jsx'

const FAQ = [
  { q: 'How do scan pins work?', a: 'Create a pin, share the 8-character code with the user, then run the scan to get a verdict (Clean / Suspicious / Cheating).' },
  { q: 'Is my data sent anywhere?', a: 'No. This dashboard is fully client-side — all pins, scans and files stay in your browser localStorage.' },
  { q: 'What files can the String Extractor handle?', a: 'Any binary: .exe, .jar, .dll and .sys are typical. It extracts ASCII and UTF-16LE strings.' },
  { q: 'How accurate is Suspicious Detection?', a: 'It uses a YARA-lite engine matching string and hex patterns. Treat results as indicators, not proof.' },
  { q: 'Can I add my own cheat signatures?', a: 'Yes — open the Cheat Database and click "Add Entry" to store custom clients and signatures.' },
]

export default function Support() {
  const { state, dispatch } = useStore()
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({ subject: '', category: 'General', priority: 'Normal', message: '' })

  const submit = () => {
    if (!form.subject.trim() || !form.message.trim())
      return toast({ type: 'error', title: 'Subject and message required' })
    dispatch({ type: 'add-ticket', ticket: { ...form, subject: form.subject.trim() } })
    toast({ type: 'success', title: 'Ticket submitted', body: form.subject })
    setForm({ subject: '', category: 'General', priority: 'Normal', message: '' })
    setOpen(false)
  }

  return (
    <div>
      <PageHeader
        icon={LifeBuoy}
        kicker="Get help & open tickets"
        title="Support"
        subtitle="Browse FAQs or open a support ticket."
        actions={
          <button onClick={() => setOpen(true)} className="flex items-center gap-2 rounded-xl bg-teal-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-teal-500">
            <Plus size={18} /> New Ticket
          </button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <h3 className="txt mb-4 text-lg font-semibold">Frequently Asked Questions</h3>
          <Accordion items={FAQ} />
        </Card>

        <Card className="p-6">
          <h3 className="txt mb-4 text-lg font-semibold">My Tickets ({state.tickets.length})</h3>
          {state.tickets.length === 0 ? (
            <EmptyState icon={MessageSquare} title="No tickets yet" hint="Open a ticket and it will be tracked here." />
          ) : (
            <div className="space-y-3">
              {state.tickets.map((t) => (
                <div key={t.id} className="tile rounded-lg border p-4">
                  <div className="flex items-center justify-between">
                    <p className="txt text-sm font-medium">{t.subject}</p>
                    <Badge tone={t.status}>{t.status}</Badge>
                  </div>
                  <p className="muted mt-1 text-xs">
                    {t.id} · {t.category} · {t.priority} · {new Date(t.createdAt).toLocaleDateString()}
                  </p>
                  <p className="muted mt-2 text-sm">{t.message}</p>
                  {t.status === 'Open' && (
                    <button
                      onClick={() => dispatch({ type: 'update-ticket', id: t.id, status: 'Resolved' })}
                      className="mt-3 text-xs font-medium text-teal-500 hover:text-teal-400"
                    >
                      Mark as resolved
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="New Support Ticket"
        footer={
          <>
            <button onClick={() => setOpen(false)} className="bd txt rounded-lg border px-4 py-2 text-sm">Cancel</button>
            <button onClick={submit} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-500">Submit</button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Subject">
            <Input autoFocus value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} placeholder="Short summary" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Category">
              <Select value={form.category} onChange={(v) => setForm({ ...form, category: v })} options={['General', 'Bug', 'Billing', 'Detection'].map((x) => ({ value: x, label: x }))} />
            </Field>
            <Field label="Priority">
              <Select value={form.priority} onChange={(v) => setForm({ ...form, priority: v })} options={['Low', 'Normal', 'High', 'Urgent'].map((x) => ({ value: x, label: x }))} />
            </Field>
          </div>
          <Field label="Message">
            <Textarea rows={4} value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} placeholder="Describe your issue…" />
          </Field>
        </div>
      </Modal>
    </div>
  )
}
