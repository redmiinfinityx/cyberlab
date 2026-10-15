// /api/check — fetch target, reports status, redirect chain, TLS, security headers
export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url).searchParams.get('url') || '';
  if (!/^https?:\/\//i.test(url)) {
    return json(400, { error: 'URL harus http/https' });
  }
  let parsed;
  try { parsed = new URL(url); } catch (_) { return json(400, { error: 'URL tidak valid' }); }
  if (parsed.hostname === 'localhost' || parsed.hostname.endsWith('.internal') ||
      /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(parsed.hostname)) {
    return json(403, { error: 'URL internal dilarang (SSRF guard)' });
  }

  const redirects = [];
  let final = url;
  let status = 0, statusText = '', httpProtocol = '', tls = '', server = '';
  let headers = [], cert = '';
  let responseObj = null;

  try {
    let resp = await fetch(url, { redirect: 'manual', headers: { 'user-agent': 'CyberLab/1.0 (+https://cyberlab.rdmbot.my.id)' } });
    let loop = 0;
    // follow a bounded redirect chain manually so we can expose every hop
    while (resp.status >= 300 && resp.status < 400 && resp.headers.get('location') && loop < 6) {
      const loc = new URL(resp.headers.get('location'), url).toString();
      redirects.push(resp.status + ' → ' + loc);
      url = loc;
      resp = await fetch(url, { redirect: 'manual', headers: { 'user-agent': 'CyberLab/1.0' } });
      loop++;
    }
    final = url;
    status = resp.status; statusText = resp.statusText || '';
    if (resp.cf) {
      tls = resp.cf.tlsVersion || '';
      httpProtocol = resp.cf.httpProtocol || '';
    }
    server = resp.headers.get('server') || '';

    const names = ['content-security-policy','strict-transport-security','x-frame-options',
      'x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy'];
    headers = names.map(n => ({ name: n, missing: !resp.headers.get(n) }));
    responseObj = resp;
  } catch (e) {
    return json(502, { error: 'Gagal fetch: ' + e.message });
  }

  if (responseObj.cf && responseObj.cf.tlsCipher) {
    cert = 'Cipher: ' + responseObj.cf.tlsCipher;
  }
  return json(200, {
    final, status, statusText, tls, httpProtocol, server, redirects, headers, cert
  });
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
}