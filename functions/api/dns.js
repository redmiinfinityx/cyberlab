// /api/dns — proxy DNS query via Cloudflare DNS-over-HTTPS (JSON)
export async function onRequest(context) {
  const q = new URL(context.request.url);
  const domain = (q.searchParams.get('domain') || '').trim();
  const type = (q.searchParams.get('type') || 'A').trim().toUpperCase();
  if (!domain) return json(400, { error: 'parameter domain wajib' });
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(domain)) {
    return json(400, { error: 'domain tidak valid' });
  }
  if (!/^(A|AAAA|MX|TXT|NS|CNAME|SOA|ANY)$/.test(type)) return json(400, { error: 'type tidak valid' });
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      { headers: { accept: 'application/dns-json' } }
    );
    if (!r.ok) return json(502, { error: 'DoH gagal: ' + r.status });
    const d = await r.json();
    return json(200, { domain, type, answers: d.Answer || [] });
  } catch (e) {
    return json(502, { error: 'Gagal: ' + e.message });
  }
}
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' }
  });
}