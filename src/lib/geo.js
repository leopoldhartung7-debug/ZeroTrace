/* Best-effort IP geolocation using ipapi.co's free no-key tier. */

export async function lookupIp(ip) {
  if (!ip || ip === '—') return null
  try {
    const resp = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`)
    if (!resp.ok) return null
    const j = await resp.json()
    if (j.error) return null
    return {
      country: j.country_name || j.country || null,
      city: j.city || null,
      region: j.region || null,
      isp: j.org || j.asn || null,
      timezone: j.timezone || null,
    }
  } catch {
    return null
  }
}
