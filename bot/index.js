/* ZeroTrace — Discord Server / Role Checker bot.
 *
 * Invite this bot to the cheat / reselling Discords you want to monitor.
 * It exposes a tiny HTTP API the ZeroTrace dashboard calls:
 *
 *   GET  /check?id=<discordUserId>    header: x-api-key: <API_KEY>
 *   GET  /health
 *   GET  /scanner?pin=<4-8 digits>   → ZeroTrace-<pin>.zip download
 *   POST /report                     → receive & store a ZeroTrace scan result
 *   GET  /result?pin=<PIN>           → retrieve stored result for the dashboard
 *
 * For every guild the bot is in it checks whether the given user ID is a
 * member and, if so, returns their roles, nickname and join date.
 * Real data straight from the Discord API — nothing is fabricated.
 *
 * /scanner streams a ready-made ZIP (ZeroTrace.exe + a zerotrace.pin file)
 * so a plain link like  https://<bot-host>/scanner?pin=4821  is a one-click
 * download with the PIN already baked in. The exe is fetched from
 * SCANNER_EXE_URL (the dashboard's hosted ZeroTrace.exe).
 */

import { createServer } from 'node:http'
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { createHmac } from 'node:crypto'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  Client, GatewayIntentBits, ApplicationCommandOptionType, MessageFlags,
} from 'discord.js'

// ---- scan-result store (persisted as JSON files in ./reports/) --------
const __dirname = dirname(fileURLToPath(import.meta.url))
const REPORTS_DIR = join(__dirname, 'reports')
try { mkdirSync(REPORTS_DIR, { recursive: true }) } catch { /* already exists */ }

function storeReport(pin, payload) {
  writeFileSync(join(REPORTS_DIR, pin.toUpperCase() + '.json'), JSON.stringify(payload), 'utf8')
}

function loadReport(pin) {
  const f = join(REPORTS_DIR, pin.toUpperCase() + '.json')
  if (!existsSync(f)) return null
  try { return JSON.parse(readFileSync(f, 'utf8')) } catch { return null }
}

// Read the full POST body as a string.
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

// Verify HMAC-SHA256 sent by the scanner (optional — absent = skip check).
function verifyHmac(body, pin, header) {
  if (!header) return true
  const expected = 'sha256=' + createHmac('sha256', pin).update(body).digest('hex')
  return header === expected
}

// Convert the scanner's ScanReport JSON into the dashboard import-scan payload.
function toPayload(report, clientIp) {
  const findings = Array.isArray(report.Findings) ? report.Findings : []
  const detections = findings.map((f) => ({
    name: f.Title || f.Module || 'Unknown',
    severity: f.Risk || 'Low',
    detail: [f.Reason, f.Location ? 'Location: ' + f.Location : ''].filter(Boolean).join(' | '),
  }))

  const hasCritHigh = findings.some((f) => f.Risk === 'Critical' || f.Risk === 'High')
  const hasMedium = findings.some((f) => f.Risk === 'Medium')
  const verdict = hasCritHigh ? 'Cheating' : hasMedium ? 'Suspicious' : 'Clean'

  const sys = report.System || {}
  const inv = report.Inventory || {}
  const ip = clientIp || (Array.isArray(sys.IpAddresses) ? sys.IpAddresses[0] : '') || ''

  return {
    code: report.Pin || '',
    verdict,
    detections,
    game: sys.Game || 'FIVEM',
    host: report.MachineName || '',
    os: sys.System || report.OsVersion || '',
    ip,
    bootTime: sys.BootTime || '',
    installDate: sys.InstallDate || '',
    hardware: sys.HardwareStats || null,
    processes: (inv.Processes || []).map((p) => ({
      pid: p.Pid, name: p.Name, path: p.Path || '', signed: p.Signed ?? null,
    })),
    drivers: (inv.Drivers || []).map((d) => ({
      name: d.Name, publisher: '', signed: d.Signed ?? null,
    })),
    vm: inv.Vm ? { detected: inv.Vm.Detected, vendor: inv.Vm.Verdict, signals: inv.Vm.Indicators || [] } : null,
    usb: (inv.UsbDevices || []).map((u) => ({
      device: u.Name, serial: u.Serial || '', action: 'Seen', time: '', contents: [],
    })),
    scannedAt: report.FinishedUtc ? new Date(report.FinishedUtc).getTime() : Date.now(),
    discordServers: [],
  }
}

// ---- minimal .env loader (no extra dependency) -----------------------
try {
  for (const line of readFileSync(new URL('./.env', import.meta.url), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '')
  }
} catch { /* no .env file — rely on real environment variables */ }

const TOKEN = process.env.DISCORD_TOKEN
const API_KEY = process.env.API_KEY || ''
const PORT = Number(process.env.PORT) || 8787
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*'
const OWNER_IDS = (process.env.OWNER_IDS || '').split(',').map((s) => s.trim()).filter(Boolean)
// Where the hosted ZeroTrace.exe lives (same build the dashboard serves).
const SCANNER_EXE_URL =
  process.env.SCANNER_EXE_URL ||
  'https://leopoldhartung7-debug.github.io/ZeroTrace/ZeroTrace.exe'

if (!TOKEN) {
  console.error('DISCORD_TOKEN is missing. Copy .env.example to .env and fill it in.')
  process.exit(1)
}

const DISCORD_EPOCH = 1420070400000
const CHEAT_KW = ['cheat', 'hack', 'spoofer', 'loader', 'menu', 'modmenu', 'mod menu',
  'aimbot', ' esp', 'unlock', 'crack', 'leak', 'bypass', 'inject', 'exploit', 'rage']
const RESELL_KW = ['resell', 'reseller', 'reselling', 'shop', 'store', 'market',
  'sellix', 'sales', 'verkauf', 'sellauth', 'plug', 'services']
const classify = (name) => {
  const n = (name || '').toLowerCase()
  if (CHEAT_KW.some((k) => n.includes(k))) return 'cheat'
  if (RESELL_KW.some((k) => n.includes(k))) return 'reselling'
  return 'clean'
}

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
})

let ready = false
client.once('ready', async () => {
  ready = true
  console.log(`Logged in as ${client.user.tag} — in ${client.guilds.cache.size} servers.`)
  try {
    await client.application.commands.set([
      {
        name: 'einladen',
        description: 'Liefert den OAuth2-Einladungslink für diesen Bot.',
      },
      {
        name: 'server',
        description: 'Listet alle Server, in denen der Bot bereits ist.',
      },
      {
        name: 'verlassen',
        description: 'Lässt den Bot einen Server verlassen.',
        options: [
          {
            type: ApplicationCommandOptionType.String,
            name: 'serverid',
            description: 'Server-ID, die der Bot verlassen soll',
            required: true,
          },
        ],
      },
    ])
    console.log('Slash commands registered.')
  } catch (e) {
    console.error('Failed to register slash commands:', e?.message || e)
  }
})

function isOwner(interaction) {
  if (OWNER_IDS.length === 0) return true
  return OWNER_IDS.includes(interaction.user.id)
}

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return
  const ephemeral = { flags: MessageFlags.Ephemeral }

  if (interaction.commandName === 'einladen') {
    const url =
      `https://discord.com/api/oauth2/authorize?client_id=${client.user.id}` +
      `&scope=bot+applications.commands&permissions=0`
    return interaction.reply({
      content:
        `🔗 **Einladungslink:**\n${url}\n\n` +
        'Öffne den Link, wähle den Cheat-/Reselling-Server aus deiner Liste und tippe auf **Autorisieren**. Du brauchst dort „Server verwalten"-Rechte.',
      ...ephemeral,
    })
  }

  if (interaction.commandName === 'server') {
    if (!isOwner(interaction))
      return interaction.reply({ content: '⛔ Nur der Bot-Eigentümer darf das.', ...ephemeral })
    const guilds = [...client.guilds.cache.values()]
    if (guilds.length === 0)
      return interaction.reply({ content: 'Bot ist in keinem Server.', ...ephemeral })
    const lines = guilds.map((g) => {
      const flag = classify(g.name)
      const tag = flag === 'cheat' ? '🔴 Cheat' : flag === 'reselling' ? '🟠 Reselling' : '⚪'
      return `${tag} · **${g.name}** · ID \`${g.id}\` · ${g.memberCount} Mitglieder`
    })
    return interaction.reply({
      content: `📋 **Server (${guilds.length}):**\n${lines.join('\n').slice(0, 1900)}`,
      ...ephemeral,
    })
  }

  if (interaction.commandName === 'verlassen') {
    if (!isOwner(interaction))
      return interaction.reply({ content: '⛔ Nur der Bot-Eigentümer darf das.', ...ephemeral })
    const id = interaction.options.getString('serverid', true).trim()
    const guild = client.guilds.cache.get(id)
    if (!guild)
      return interaction.reply({ content: `Bot ist nicht in Server \`${id}\`.`, ...ephemeral })
    try {
      const name = guild.name
      await guild.leave()
      return interaction.reply({ content: `👋 Server **${name}** verlassen.`, ...ephemeral })
    } catch (e) {
      return interaction.reply({ content: `Fehler: ${e?.message || e}`, ...ephemeral })
    }
  }
})

async function checkUser(userId) {
  const createdAt = new Date(Number((BigInt(userId) >> 22n)) + DISCORD_EPOCH).toISOString()
  const results = []
  for (const [, guild] of client.guilds.cache) {
    const entry = {
      guild: guild.name,
      guildId: guild.id,
      flag: classify(guild.name),
      member: false,
      nick: null,
      roles: [],
      joinedAt: null,
    }
    try {
      const m = await guild.members.fetch({ user: userId, force: true })
      entry.member = true
      entry.nick = m.nickname || null
      entry.joinedAt = m.joinedAt ? m.joinedAt.toISOString() : null
      entry.roles = m.roles.cache
        .filter((r) => r.name !== '@everyone')
        .map((r) => r.name)
    } catch (e) {
      if (e?.code !== 10007 && e?.code !== 10013) {
        entry.error = String(e?.message || e)
      }
    }
    results.push(entry)
  }
  const found = results.filter((r) => r.member)
  return {
    id: userId,
    createdAt,
    totalServers: client.guilds.cache.size,
    found: found.length,
    results,
  }
}

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': ALLOW_ORIGIN,
    'Access-Control-Allow-Headers': 'x-api-key, content-type, x-zerotrace-signature',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  })
  res.end(JSON.stringify(body))
}

// ---- minimal store-only ZIP builder (no dependency) ------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

function crc32(buf) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

// files: [{ name, data: Buffer }] → Buffer (uncompressed/store ZIP)
function makeZip(files) {
  const parts = []
  const central = []
  let offset = 0
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8')
    const data = f.data
    const crc = crc32(data)
    const local = Buffer.alloc(30 + name.length)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0, 6)
    local.writeUInt16LE(0, 8) // store
    local.writeUInt16LE(0, 10)
    local.writeUInt16LE(0x21, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    name.copy(local, 30)
    parts.push(local, data)

    const cen = Buffer.alloc(46 + name.length)
    cen.writeUInt32LE(0x02014b50, 0)
    cen.writeUInt16LE(20, 4)
    cen.writeUInt16LE(20, 6)
    cen.writeUInt16LE(0, 8)
    cen.writeUInt16LE(0, 10)
    cen.writeUInt16LE(0, 12)
    cen.writeUInt16LE(0x21, 14)
    cen.writeUInt32LE(crc, 16)
    cen.writeUInt32LE(data.length, 20)
    cen.writeUInt32LE(data.length, 24)
    cen.writeUInt16LE(name.length, 28)
    cen.writeUInt32LE(offset, 42)
    name.copy(cen, 46)
    central.push(cen)
    offset += local.length + data.length
  }
  const cd = Buffer.concat(central)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(files.length, 8)
  end.writeUInt16LE(files.length, 10)
  end.writeUInt32LE(cd.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...parts, cd, end])
}

// Cache the fetched exe so we don't re-download it on every request.
let exeCache = null
async function getScannerExe() {
  if (exeCache) return exeCache
  const res = await fetch(SCANNER_EXE_URL, { cache: 'no-store' })
  if (!res.ok) throw new Error(`exe fetch HTTP ${res.status}`)
  exeCache = Buffer.from(await res.arrayBuffer())
  return exeCache
}

createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {})
  const url = new URL(req.url, 'http://localhost')

  if (url.pathname === '/health') {
    return send(res, 200, { ok: true, ready, servers: ready ? client.guilds.cache.size : 0 })
  }

  if (url.pathname === '/scanner') {
    const pin = (url.searchParams.get('pin') || '').trim()
    if (!/^\d{4,8}$/.test(pin)) return send(res, 400, { error: 'Invalid PIN (4-8 digits)' })
    try {
      const exe = await getScannerExe()
      const zip = makeZip([
        { name: 'ZeroTrace.exe', data: exe },
        { name: 'zerotrace.pin', data: Buffer.from(pin, 'utf8') },
      ])
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="ZeroTrace-${pin}.zip"`,
        'Access-Control-Allow-Origin': ALLOW_ORIGIN,
        'Content-Length': zip.length,
      })
      return res.end(zip)
    } catch (e) {
      return send(res, 502, { error: `Could not build scanner: ${String(e?.message || e)}` })
    }
  }

  // ---- POST /report — scanner sends completed scan result ---------------
  if (url.pathname === '/report' && req.method === 'POST') {
    try {
      const body = await readBody(req)
      const report = JSON.parse(body)
      const pin = (report.Pin || '').trim()
      if (!pin) return send(res, 400, { error: 'Missing Pin in report' })

      const sig = req.headers['x-zerotrace-signature']
      if (!verifyHmac(body, pin, sig)) return send(res, 401, { error: 'Invalid signature' })

      const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim()
      const payload = toPayload(report, clientIp)
      storeReport(pin, payload)

      console.log(`[report] stored PIN ${pin.toUpperCase()} — ${payload.verdict}, ${payload.detections.length} detection(s)`)
      return send(res, 200, { ok: true, pin: pin.toUpperCase(), detections: payload.detections.length, verdict: payload.verdict })
    } catch (e) {
      return send(res, 400, { error: String(e?.message || e) })
    }
  }

  // ---- GET /result?pin=X — dashboard fetches stored result -------------
  if (url.pathname === '/result') {
    const pin = (url.searchParams.get('pin') || '').trim()
    if (!pin) return send(res, 400, { error: 'Missing pin parameter' })
    const payload = loadReport(pin)
    if (!payload) return send(res, 404, { error: 'No result stored for this PIN' })
    return send(res, 200, payload)
  }

  if (url.pathname === '/check') {
    if (API_KEY && req.headers['x-api-key'] !== API_KEY) {
      return send(res, 401, { error: 'Invalid API key' })
    }
    if (!ready) return send(res, 503, { error: 'Bot not ready yet' })
    const id = (url.searchParams.get('id') || '').trim()
    if (!/^\d{17,20}$/.test(id)) return send(res, 400, { error: 'Invalid Discord ID' })
    try {
      return send(res, 200, await checkUser(id))
    } catch (e) {
      return send(res, 500, { error: String(e?.message || e) })
    }
  }

  return send(res, 404, { error: 'Not found' })
}).listen(PORT, () => console.log(`Checker API listening on :${PORT}`))

client.login(TOKEN)
