// index.js — Node 20, deploy auf render.com als Web Service
// Proxied Roblox /v2/login + 2FA + optional Arkose captcha-solve via CapSolver.
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const UA = 'Roblox/WinInet';
const CAPSOLVER_KEY = process.env.CAPSOLVER_KEY || ''; // optional, für auto-solve

// Roblox rotiert CSRF alle ~15min -> immer frisch holen
async function getCsrf() {
    const r = await axios.post('https://auth.roblox.com/v2/login',
        {}, { headers: { 'User-Agent': UA }, validateStatus: () => true });
    return r.headers['x-csrf-token'];
}

// cap-solver: schickt den arkose public key + page url, kriegt blob zurück
async function solveArkose(publicKey, pageUrl) {
    if (!CAPSOLVER_KEY) throw new Error('no capsolver key');
    const create = await axios.post('https://api.capsolver.com/createTask', {
        clientKey: CAPSOLVER_KEY,
        task: {
            type: 'FunCaptchaTaskProxyLess',
            websiteURL: pageUrl,
            websitePublicKey: publicKey
        }
    });
    if (!create.data?.taskId) throw new Error('capsolver create failed');
    const taskId = create.data.taskId;

    for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const res = await axios.post('https://api.capsolver.com/getTaskResult', {
            clientKey: CAPSOLVER_KEY, taskId
        });
        if (res.data?.status === 'ready') return res.data.solution.token;
        if (res.data?.status === 'failed' || res.data?.errorId) throw new Error('capsolver failed');
    }
    throw new Error('capsolver timeout');
}

app.post('/login', async (req, res) => {
    const { username, password, captchaToken, pageUrl, autoSolve } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'missing fields' });
    try {
        const csrf = await getCsrf();

        // captcha blob bestimmen: entweder vom browser-widget, oder auto-solve
        let blob = captchaToken || '';
        if (!blob && autoSolve && CAPSOLVER_KEY) {
            // roblox login public key (arkose) — die ist öffentlich bekannt
            blob = await solveArkose('9F35E182-C93C-EBCC-A31D-CF8ED317B996',
                pageUrl || 'https://www.roblox.com/login');
        }

        const payload = {
            ctype: 'Username',
            cvalue: username,
            password
        };
        if (blob) {
            payload.captchaToken = blob;
            payload.captchaProvider = 'PROVIDER_ARKOSE_LABS';
        }

        const r = await axios.post('https://auth.roblox.com/v2/login', payload, {
            headers: { 'x-csrf-token': csrf, 'User-Agent': UA },
            validateStatus: () => true
        });

        const setCookie = r.headers['set-cookie'] || [];
        const authCookie = setCookie.find(c => c.startsWith('.ROBLOSECURITY='));

        if (r.status === 200 && authCookie) {
            return res.json({ success: true, cookie: authCookie.split(';')[0] });
        }

        const err0 = r.data?.errors?.[0];
        // captcha gefordert -> nochmal, mit flag dass frontend widget zeigen soll
        if (err0 && /captcha/i.test(err0.message || '')) {
            return res.json({ needsCaptcha: true, error: r.data });
        }
        // 2FA gefordert
        if (err0 && /TwoStep|2FA|verification/i.test(err0.message || '')) {
            const mediaType = /authenticator/i.test(err0.message) ? 'Authenticator' : 'Email';
            return res.json({ needs2FA: true, mediaType, ticket: err0.metadata?.ticket });
        }

        return res.json({ success: false, error: r.data });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

app.post('/verify2fa', async (req, res) => {
    const { ticket, code } = req.body;
    if (!ticket || !code) return res.status(400).json({ error: 'missing fields' });
    try {
        const csrf = await getCsrf();
        const r = await axios.post('https://auth.roblox.com/v2/login',
            { ctype: 'Username', cvalue: '', password: '', ticket, code },
            { headers: { 'x-csrf-token': csrf, 'User-Agent': UA },
              validateStatus: () => true });

        const setCookie = r.headers['set-cookie'] || [];
        const authCookie = setCookie.find(c => c.startsWith('.ROBLOSECURITY='));
        if (authCookie) return res.json({ success: true, cookie: authCookie.split(';')[0] });
        return res.json({ success: false, error: r.data });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

// optionaler standalone captcha-endpoint für auto-solve ohne user
app.post('/solve-captcha', async (req, res) => {
    try {
        const blob = await solveArkose('9F35E182-C93C-EBCC-A31D-CF8ED317B996',
            req.body.pageUrl || 'https://www.roblox.com/login');
        res.json({ success: true, token: blob });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/', (_req, res) => res.send('ok'));
app.listen(process.env.PORT || 3000, () => console.log('listening'));
