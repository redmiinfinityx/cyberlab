// /api/subdomains — aggregate passive subdomain sources (CT + passive DNS), no active brute-force
const SRC = 'CyberLab/1.0 subfinder';

async function collect(domain) {
  const set = new Set();
  const add = (raw) => {
    for (let n of String(raw || '').split(/\s+/)) {
      n = n.trim().toLowerCase().replace(/^[*.]*/, '');
      if (n === domain || n.endsWith('.' + domain)) set.add(n);
    }
  };

  const jobs = [];
  // 1. Certificate Transparency
  jobs.push((async () => {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { 'user-agent': SRC } });
    if (!r.ok) return;
    const arr = await r.json();
    for (const e of (arr || [])) add(String(e.name_value || '').replace(/\n/g, ' '));
  })());
  // 2. Anubis (passive, aggregates CT + others)
  jobs.push((async () => {
    const r = await fetch(`https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`,
      { headers: { 'user-agent': SRC } });
    if (!r.ok) return;
    const arr = await r.json();
    add(arr.join ? arr.join(' ') : '');
  })());
  // 3. AlienVault OTX passive DNS
  jobs.push((async () => {
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
      { headers: { 'user-agent': SRC, accept: 'application/json' } });
    if (!r.ok) return;
    const j = await r.json();
    for (const rec of (j.passive_dns || [])) add(String(rec.hostname || ''));
  })());

  await Promise.allSettled(jobs); // satu sumber gagal tidak menggagalkan yang lain
  return [...set].sort((a, b) => a.length - b.length || (a < b ? -1 : 1));
}

export async function onRequest(context) {
  const q = new URL(context.request.url);
  const domain = (q.searchParams.get('domain') || '').trim().toLowerCase();
  if (!domain || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
    return json(400, { error: 'domain tidak valid' });
  }
  try {
    const subs = await collect(domain);
    return json(200, { domain, count: subs.length, subdomains: subs.slice(0, 2000), sources: ['crt.sh', 'anubis', 'alienvault-otx'] });
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