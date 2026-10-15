// /api/subdomains — enumerate subdomains passively via crt.sh (Certificate Transparency)
export async function onRequest(context) {
  const q = new URL(context.request.url);
  const domain = (q.searchParams.get('domain') || '').trim().toLowerCase();
  if (!domain || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
    return json(400, { error: 'domain tidak valid' });
  }
  try {
    const r = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { 'user-agent': 'CyberLab/1.0 subfinder' } }
    );
    if (!r.ok) return json(502, { error: 'crt.sh gagal: ' + r.status });
    const arr = await r.json();
    const set = new Set();
    for (const e of (arr || [])) {
      const names = String(e.name_value || '').split('\n');
      for (let n of names) {
        n = n.trim().toLowerCase();
        if (n.startsWith('*.')) n = n.slice(2); // buang marker wildcard cert
        if (n === domain || n.endsWith('.' + domain)) set.add(n);
      }
    }
    const subs = [...set].sort();
    return json(200, { domain, count: subs.length, subdomains: subs.slice(0, 1000) });
  } catch (e) {
    return json(502, { error: 'Gagal: ' + e.message });
  }
}
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=600' }
  });
}