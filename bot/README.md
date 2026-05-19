# Ocean — Discord Server / Role Checker Bot

A small Discord bot + HTTP API. Invite it to the cheat / reselling Discords
you want to monitor. When you run a **Discord ID** check in the Ocean
dashboard (Forensic Tools), the dashboard asks this bot which of those
servers the user ID is in, and what roles they hold. All data comes
straight from the Discord API — nothing is invented.

> Why a bot? Discord does **not** let a website look up an arbitrary
> account's servers. The only legitimate way is a bot that is itself a
> member of those servers and uses the official API. That bot needs a
> persistent backend — it cannot run on GitHub Pages.

## 1. Create the bot

1. https://discord.com/developers/applications → **New Application**.
2. **Bot** tab → **Reset Token** → copy the token.
3. Still on the **Bot** tab → enable **Server Members Intent**
   (Privileged Gateway Intents). This is required to look up members.
4. **OAuth2 → URL Generator**: scope `bot`, no privileged permissions
   needed (read-only member lookup). Use the generated URL to invite the
   bot to each cheat / reselling server you want covered.

## 2. Configure

```bash
cd bot
cp .env.example .env
# edit .env: DISCORD_TOKEN, API_KEY (a long random string), PORT, ALLOW_ORIGIN
npm install
npm start
```

`ALLOW_ORIGIN` should be your dashboard origin (e.g.
`https://<user>.github.io`) or `*`.

## 3. Host it

It must run 24/7. Any small host works: a VPS, Railway, Render, Fly.io,
a Raspberry Pi, etc. Make the chosen `PORT` reachable over HTTPS
(put it behind a reverse proxy / the host's TLS).

## 4. Connect the dashboard

In the dashboard: **Account → Integrations → Discord Server Bot**

- **Bot API URL**: the public base URL (e.g. `https://yourhost.example`)
- **API Key**: the same `API_KEY` you put in `.env`

Then go to **Forensic Tools → Discord ID**, enter a Discord ID and run
the check. Live membership + roles per server are shown and (if a
webhook is configured) forwarded to it.

## API

```
GET /health
GET /check?id=<discordUserId>      header: x-api-key: <API_KEY>
```

`/check` response:

```json
{
  "id": "145481082291945490",
  "createdAt": "2016-...",
  "totalServers": 12,
  "found": 2,
  "results": [
    { "guild": "Some Cheat Hub", "guildId": "...", "flag": "cheat",
      "member": true, "nick": "x", "roles": ["Customer","Buyer"],
      "joinedAt": "2024-..." }
  ]
}
```

Notes: lookups are rate-limited by Discord; checking many servers takes a
moment. Only use this on servers you are legitimately invited to, for
consent-based anti-cheat / screenshare review.
