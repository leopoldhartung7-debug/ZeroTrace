import {
  BookOpen, FileText, ShieldCheck, Terminal, Video, GraduationCap,
  Keyboard, ArrowUpRight,
} from 'lucide-react'
import { PageHeader, Card } from '../components/kit.jsx'

const GUIDES = [
  { icon: GraduationCap, title: 'Screenshare Basics', desc: 'A step-by-step checklist for a proper screenshare session.', tag: 'Guide' },
  { icon: ShieldCheck, title: 'Detecting Ghost Clients', desc: 'How to spot native and Java ghost clients with strings & artifacts.', tag: 'Guide' },
  { icon: Terminal, title: 'Useful CMD Commands', desc: 'ipconfig /displaydns, prefetch, USN journal and more.', tag: 'Reference' },
  { icon: FileText, title: 'YARA Rule Writing', desc: 'Write effective string and hex patterns for the scanner.', tag: 'Reference' },
  { icon: Video, title: 'Video Walkthroughs', desc: 'Watch real screenshare investigations end to end.', tag: 'Video' },
  { icon: BookOpen, title: 'Cheat Encyclopedia', desc: 'Background on common clients, modules and behaviours.', tag: 'Wiki' },
]

const CMDS = [
  ['ipconfig /displaydns', 'Dump resolved domains (DNS cache)'],
  ['tree /f %temp%', 'List temp files recursively'],
  ['wmic process get name,executablepath', 'Running processes & paths'],
  ['powershell Get-ChildItem -Recurse', 'Recursive file listing'],
  ['fsutil usn readjournal C:', 'Read the USN change journal'],
]

export default function Resources() {
  return (
    <div>
      <PageHeader
        icon={BookOpen}
        kicker="Guides, references & tools"
        title="Resources"
        subtitle="Everything you need to run effective anti-cheat investigations."
      />

      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {GUIDES.map((g) => (
          <Card key={g.title} className="group cursor-pointer p-6 transition-transform hover:-translate-y-1">
            <div className="flex items-start justify-between">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 text-white shadow-lg shadow-blue-600/20">
                <g.icon size={20} />
              </div>
              <ArrowUpRight size={18} className="muted transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </div>
            <p className="caps-label mt-5">{g.tag}</p>
            <h3 className="txt mt-1 text-base font-semibold">{g.title}</h3>
            <p className="muted mt-2 text-sm">{g.desc}</p>
          </Card>
        ))}
      </div>

      <Card className="mt-6 p-6">
        <div className="mb-4 flex items-center gap-2">
          <Keyboard size={18} className="muted" />
          <h3 className="txt text-lg font-semibold">Quick Command Reference</h3>
        </div>
        <div className="space-y-2">
          {CMDS.map(([cmd, desc]) => (
            <div key={cmd} className="tile flex flex-col gap-1 rounded-lg border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <code className="txt font-mono text-xs">{cmd}</code>
              <span className="muted text-xs">{desc}</span>
            </div>
          ))}
        </div>
        <p className="muted mt-4 text-xs">
          Tip: press <kbd className="bd rounded border px-1.5 py-0.5">Ctrl/⌘ K</kbd> anywhere to open the command palette.
        </p>
      </Card>
    </div>
  )
}
