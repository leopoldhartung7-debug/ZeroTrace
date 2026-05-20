/* Tiny TOTP implementation (RFC 6238, SHA-1, 6 digits, 30s step). */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function generateBase32Secret(bytes = 20) {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  let bits = 0
  let value = 0
  let out = ''
  for (let i = 0; i < arr.length; i++) {
    value = (value << 8) | arr[i]
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}

function base32Decode(s) {
  const clean = s.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  const out = []
  let bits = 0
  let value = 0
  for (const c of clean) {
    const idx = B32.indexOf(c)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(out)
}

async function hmacSha1(keyBytes, counterBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, counterBytes)
  return new Uint8Array(sig)
}

function counterBytes(counter) {
  const buf = new Uint8Array(8)
  let n = BigInt(counter)
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return buf
}

export async function totp(secret, time = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(time / 1000 / step)
  const keyBytes = base32Decode(secret)
  const hmac = await hmacSha1(keyBytes, counterBytes(counter))
  const offset = hmac[hmac.length - 1] & 0xf
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  return String(code % 10 ** digits).padStart(digits, '0')
}

export async function verifyTotp(secret, token, window = 1) {
  const now = Date.now()
  const target = (token || '').trim()
  for (let w = -window; w <= window; w++) {
    const code = await totp(secret, now + w * 30000)
    if (code === target) return true
  }
  return false
}

export function otpauthUrl(secret, label = 'ZeroTrace', issuer = 'ZeroTrace') {
  const enc = (s) => encodeURIComponent(s)
  return `otpauth://totp/${enc(issuer)}:${enc(label)}?secret=${secret}&issuer=${enc(issuer)}&digits=6&period=30`
}
