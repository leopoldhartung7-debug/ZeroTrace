/* ZeroTrace — Discord Server / Role Checker bot.
 *
 * Invite this bot to the cheat / reselling Discords you want to monitor.
 * It exposes a tiny HTTP API the ZeroTrace dashboard calls:
 *
 *   GET /check?id=<discordUserId>     header: x-api-key: <API_KEY>
 *   GET /health
 *
 * For every guild the bot is in it checks whether the given user ID is a
 * member and, if so, returns their roles, nickname and join date.
 * Real data straight from the Discord API — nothing is fabricated.
 */

import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import {
  Client, GatewayIntentBits, ApplicationCommandOptionType, MessageFlags,
} from 'discord.js'

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
    'Access-Control-Allow-Headers': 'x-api-key, content-type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
  })
  res.end(JSON.stringify(body))
}

createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {})
  const url = new URL(req.url, 'http://localhost')

  if (url.pathname === '/health') {
    return send(res, 200, { ok: true, ready, servers: ready ? client.guilds.cache.size : 0 })
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
