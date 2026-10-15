/* CyberLab — all client-side except /api/check */
const navMap = ['analyzer','generator','hash','crypto','encode','urlcheck'];

/* ---------- tabs ---------- */
function buildNav(){
  const nav = document.getElementById('nav');
  const labels = {
    analyzer:'Password Analyzer', generator:'Generator', hash:'Hash',
    crypto:'Crypto', encode:'Encode', urlcheck:'URL Check'
  };
  navMap.forEach(k=>{
    const b = document.createElement('button');
    b.textContent = labels[k];
    b.dataset.k = k;
    if(k==='analyzer') b.classList.add('on');
    b.onclick = ()=>switchTab(k);
    nav.appendChild(b);
  });
}
function switchTab(k){
  navMap.forEach(x=>document.getElementById('tab-'+x).classList.toggle('active', x===k));
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on', b.dataset.k===k));
}

/* ---------- analyzer ---------- */
const pwEl = document.getElementById('pw');
const pwEye = document.getElementById('pw-eye');
const esc = s=>String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function crackTime(bits){
  if(bits<28)  return 'instan';
  if(bits<35)  return 'detik';
  if(bits<59)  return 'menit — jam';
  if(bits<82)  return 'hari — bulan';
  if(bits<112) return 'tahun — abad';
  return 'praktis tak pecah';
}
function analyzePw(){
  const v = pwEl.value;
  const bar = document.getElementById('meter-bar');
  const out = document.getElementById('pw-out');
  if(!v){ bar.style.width='0'; bar.style.background='var(--bad)'; out.innerHTML=''; return; }
  const len = v.length;
  const upper=/[A-Z]/.test(v), lower=/[a-z]/.test(v), digit=/\d/.test(v),
        sym = /[^A-Za-z0-9]/.test(v), repeated=/(.)\1{2,}/.test(v);
  const pool = (upper?26:0)+(lower?26:0)+(digit?10:0)+(sym?33:0);
  let score = 0, bits = len*Math.log2(Math.max(pool,1));
  if(len>=12) score+=25; else if(len>=8) score+=15;
  score += (upper&&lower?10:0) + (digit?10:0) + (sym?12:0);
  score += Math.min(20, bits*0.15);
  if(repeated) score = Math.min(score, 45); // pola lemah
  score = Math.min(100, Math.round(score));
  const grade = score>=80?['Sangat Kuat','ok']:score>=60?['Kuat','ok']
        :score>=40?['Sedang','warn']:['Lemah','bad'];
  bar.style.width = score+'%';
  bar.style.background = score>=60?'var(--ok)':score>=40?'var(--warn)':'var(--bad)';
  const found=[]; if(upper)found.push('huruf besar'); if(lower)found.push('huruf kecil');
  if(digit)found.push('angka'); if(sym)found.push('simbol');
  out.innerHTML =
    `<div class="kv"><span>Skor</span><b>${score}/100 · <span class="tag ${grade[1]}">${grade[0]}</span></b></div>`+
    `<div class="kv"><span>Panjang</span><b>${len} karakter</b></div>`+
    `<div class="kv"><span>Ruang karakter</span><b>${Math.round(pool)} (${found.join(', ')||'—'})</b></div>`+
    `<div class="kv"><span>Estimasi retas (offline)</span><b>${esc(crackTime(bits))}</b></div>`+
    (repeated?`<div class="err">⚠ Pola berulang terdeteksi — membuat password mudah ditebak.</div>`:'');
}
function toggleShow(id){
  const el = document.getElementById(id);
  el.type = el.type==='password'?'text':'password';
  pwEye.textContent = el.type==='password'?'Tampilkan':'Sembunyikan';
}
pwEl.addEventListener('input', analyzePw);

/* ---------- generator ---------- */
function cryptoRand(n){
  const a = new Uint32Array(n);
  crypto.getRandomValues(a);
  return Array.from(a);
}
function genPw(){
  const len = Math.min(64, Math.max(4, +document.getElementById('glen').value||16));
  const sets = [];
  if(document.getElementById('gupper').checked) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if(document.getElementById('glower').checked) sets.push('abcdefghijkmnopqrstuvwxyz');
  if(document.getElementById('gdigit').checked) sets.push('23456789');
  if(document.getElementById('gsym').checked)   sets.push('!@#$%^&*');
  if(!sets.length){ document.getElementById('gen-out').textContent = 'Pilih minimal satu set karakter.'; return; }
  const all = sets.join('');
  const rnd = cryptoRand(len);
  const chars = rnd.map(r=>all[r%all.length]);
  // jamin minimal satu dari tiap kelas
  let idx=0;
  sets.forEach(s=>{ if(idx<len){ chars[idx]=s[rnd[idx]%s.length]; idx++; } });
  const pw = chars.join('');
  document.getElementById('gen-out').innerHTML =
    `Password:<br><b style="color:var(--acc);font-size:18px">${esc(pw)}</b><br>`+
    `<button class="ghost" onclick="copyText('${esc(pw)}')">Salin</button>`;
}
async function copyText(t){
  try{ await navigator.clipboard.writeText(t); }catch{}
}

/* ---------- hash ---------- */
function utf8(s){ return new TextEncoder().encode(s); }
function toHex(b){ return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''); }
async function pbkdf(seed){
  const key = await crypto.subtle.importKey('raw', utf8(seed), 'PBKDF2', false, ['deriveKey','deriveBits']);
  return crypto.subtle.deriveBits({name:'PBKDF2',salt:utf8('CyberLab'),iterations:100000,hash:'SHA-256'}, key, 256);
}
async function hashIt(){
  const data = document.getElementById('hash-in').value;
  const out = document.getElementById('hash-out');
  if(!data){ out.textContent='Masukkan data dulu.'; return; }
  let result;
  try{
    if(document.getElementById('hhmac').checked){
      const k = document.getElementById('hmac-key').value || 'secret';
      const key = await crypto.subtle.importKey('raw', utf8(k), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
      result = toHex(await crypto.subtle.sign('HMAC', key, utf8(data)));
    }else{
      const algo = ['hsha256','hsha384','hsha512','hsha1'].find(id=>document.getElementById(id).checked);
      const name  = algo==='hsha1'?'SHA-1':algo.slice(1).toUpperCase().replace('SHA','SHA-');
      result = toHex(await crypto.subtle.digest(name, utf8(data)));
    }
  }catch(e){ out.innerHTML = `<span class="err">Gagal: ${esc(e.message)}</span>`; return; }
  out.textContent = result;
}
document.querySelectorAll('input[name=algo]').forEach(r=>r.onchange=()=>{
  document.getElementById('hmac-key-wrap').style.display = r.id==='hhmac'?'block':'none';
});

/* ---------- crypto (AES-GCM + PBKDF2) ---------- */
async function getCryptoKey(pass){
  const bits = await pbkdf(pass);
  return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt','decrypt']);
}
const b64enc = b=>btoa(String.fromCharCode.apply(null,new Uint8Array(b)));
function utf8Bytes(s){ return new TextEncoder().encode(s); }
function b64ToBuf(s){
  const bin = atob(s.replace(/\s/g,''));
  const a = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i);
  return a;
}
async function crypt(encryp){
  const out = document.getElementById('crypto-out');
  const pass = document.getElementById('crypto-pass').value;
  const data = document.getElementById('crypto-in').value;
  if(!pass){ out.textContent='Isi kata sandi.'; return; }
  if(!data){ out.textContent='Isi aksi isi — input kosong.'; return; }
  try{
    const key = await getCryptoKey(pass);
    if(encryp){
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, utf8Bytes(data));
      out.innerHTML = 'Ciphertext (format: iv.base64:dat.base64 · simpan keduanya):<br>'+
        `<code style="color:var(--acc)">${esc(b64enc(iv))}.${esc(b64enc(ct))}</code>`;
    }else{
      if(!data.includes('.')){ out.innerHTML='<span class="err">Format salah. Harus <i>iv.base64:dat.base64</i>.</span>'; return; }
      const [ivb,cb] = data.trim().split('.');
      const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:b64ToBuf(ivb)}, key, b64ToBuf(cb));
      out.innerHTML = 'Plaintext:<br><code style="color:var(--ok)">'+esc(new TextDecoder().decode(pt))+'</code>';
    }
  }catch(e){
    out.innerHTML = `<span class="err">Gagal: ${esc(e.message)} (kata sandi salah / data korup?)</span>`;
  }
}

/* ---------- encode/decode ---------- */
function utf8ToB64(s){ return btoa(unescape(encodeURIComponent(s))); }
function b64ToUtf8(s){ return decodeURIComponent(escape(atob(s.trim()))); }
function hexEncode(s){ return Array.from(utf8Bytes(s)).map(x=>x.toString(16).padStart(2,'0')).join(''); }
function hexDecode(s){
  const t = s.replace(/\s/g,'');
  if(t.length%2) throw new Error('Hex harus panjang genap');
  const a = new Uint8Array(t.length/2);
  for(let i=0;i<a.length;i++) a[i]=parseInt(t.substr(i*2,2),16);
  return new TextDecoder().decode(a);
}
function enc(mode){
  const v = document.getElementById('enc-in').value;
  const out = document.getElementById('enc-out');
  try{
    const map = {b64:()=>utf8ToB64(v), url:()=>encodeURIComponent(v), hex:()=>hexEncode(v)};
    out.textContent = map[mode]();
  }catch(e){ out.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
function dec(mode){
  const v = document.getElementById('enc-in').value;
  const out = document.getElementById('enc-out');
  try{
    const map = {b64:()=>b64ToUtf8(v), url:()=>decodeURIComponent(v), hex:()=>hexDecode(v)};
    out.textContent = map[mode]();
  }catch(e){ out.innerHTML = `<span class="err">Decode gagal: ${esc(e.message)}</span>`; }
}

/* ---------- URL check (via Pages Function) ---------- */
const SEC_HEADERS = ['content-security-policy','strict-transport-security','x-frame-options',
  'x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy'];
function norm(u){
  if(!/^https?:\/\//i.test(u)) u = 'https://'+u;
  return u;
}
async function urlCheck(){
  const out = document.getElementById('url-out');
  const btn = document.querySelector('#tab-urlcheck .row>button');
  const url = norm(document.getElementById('url-in').value);
  btn.classList.add('wait'); btn.disabled = true;
  out.innerHTML = 'Memeriksa…';
  try{
    const r = await fetch('/api/check?url='+encodeURIComponent(url));
    const d = await r.json();
    if(!r.ok) throw new Error(d.error || r.status);
    let h = `<div class="kv"><span>URL target</span><b>${esc(d.final)}</b></div>`;
    h += `<div class="kv"><span>Status HTTP</span><b class="tag ${d.status<400?'ok':'warn'}">${d.status} ${esc(d.statusText)}</b></div>`;
    h += `<div class="kv"><span>TLS</span><b>${esc(d.tls)}</b></div>`;
    h += `<div class="kv"><span>Protokol</span><b>${esc(d.httpProtocol)}</b></div>`;
    h += `<div class="kv"><span>Server</span><b>${esc(d.server||'—')}</b></div>`;
    h += `<div class="kv"><span>Redirect hop</span><b>${'<span class="tag '+(d.redirects.length?'warn':'ok')+'">'+d.redirects.length+'</span>'}</b></div>`;
    if(d.redirects.length) h += `<div class="kv"><span>Rantai</span><b style="font-size:11px;color:var(--muted)">${esc(d.redirects.join(' → '))}</b></div>`;
    h += '<h3 style="margin-top:14px;font-size:14px">Security Headers</h3><div class="grid">';
    d.headers.forEach(sec=>{
      const good = !sec.missing;
      h += `<div class="sec"><span class="tag ${good?'ok':'bad'}">${good?'ADA':'MISSING'}</span><code>${sec.name}</code></div>`;
    });
    h += '</div>';
    if(d.cert){ h += `<div class="kv" style="margin-top:10px"><span>Certificate</span><b>${esc(d.cert)}</b></div>`; }
    out.innerHTML = h;
  }catch(e){
    out.innerHTML = `<span class="err">Gagal periksa: ${esc(e.message)}</span>`;
  }
  btn.classList.remove('wait'); btn.disabled = false;
}

buildNav(); analyzePw();