const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;
const VALID_TOKEN = '7e8b839f2048991a';

app.use(cors());
app.use(express.json());

// In-memory sessions storage
const sessions = new Map();
const screenRequests = new Map();

// Periodic cleanup
setInterval(() => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, session] of sessions.entries()) {
        if (session.lastHeartbeat < cutoff) {
            sessions.delete(id);
        }
    }
}, 60000);

// 1. Heartbeat from HeavyRustLauncher
app.post('/api/heartbeat', (req, res) => {
    const { steamId, nickname, hwid, token, gamePid } = req.body || {};

    if (token !== VALID_TOKEN) {
        return res.status(403).json({ status: 'error', message: 'Invalid token' });
    }

    if (!steamId) {
        return res.status(400).json({ status: 'error', message: 'Missing steamId' });
    }

    let screenRequested = false;
    if (screenRequests.has(steamId) || (hwid && screenRequests.has(hwid))) {
        screenRequested = true;
        screenRequests.delete(steamId);
        if (hwid) screenRequests.delete(hwid);
    }

    sessions.set(String(steamId), {
        steamId: String(steamId),
        nickname: nickname || 'Player',
        hwid: hwid || '',
        ip: req.ip || req.connection.remoteAddress || '127.0.0.1',
        gamePid: gamePid || 0,
        lastHeartbeat: Date.now()
    });

    res.json({ status: 'ok', valid: true, request_screen: screenRequested });
});

// 2. Check player (GET /api/check?steamid=...)
app.get('/api/check', (req, res) => {
    const steamId = String(req.query.steamid || '');
    const session = sessions.get(steamId);

    if (session && (Date.now() - session.lastHeartbeat) <= 35000) {
        const secondsAgo = Math.round((Date.now() - session.lastHeartbeat) / 1000);
        res.json({ steamId, valid: true, nickname: session.nickname, hwid: session.hwid, secondsAgo });
    } else {
        res.json({ steamId, valid: false, message: 'No active launcher session found' });
    }
});

// 3. Single player check on join for HeavyAC.cs (POST /internal_player_state)
app.post('/internal_player_state', (req, res) => {
    const list = Array.isArray(req.body) ? req.body : [req.body];
    const first = list[0] || {};
    const id = String(first.userId || first.userid || '');
    const session = sessions.get(id);
    const isValid = session && (Date.now() - session.lastHeartbeat) <= 35000;
    res.json({
        userId: id,
        valid: Boolean(isValid),
        hban: false,
        hbanMessage: '',
        hwid: (session && session.hwid) || ''
    });
});

// 4. Bulk check for HeavyAC.cs (POST /internal_players_check)
app.post('/internal_players_check', (req, res) => {
    const playerList = Array.isArray(req.body) ? req.body : [];
    const results = playerList.map(p => {
        const id = String(p.userId || p.userid || '');
        const session = sessions.get(id);
        const isValid = session && (Date.now() - session.lastHeartbeat) <= 35000;
        return {
            userId: id,
            valid: Boolean(isValid),
            hban: false,
            hbanMessage: '',
            hwid: (session && session.hwid) || ''
        };
    });
    res.json(results);
});

// 4. Admin screen request (POST /api/screen_request)
app.post('/api/screen_request', (req, res) => {
    const { target } = req.body || {};
    if (target) {
        screenRequests.set(String(target), Date.now());
        return res.json({ status: 'ok', message: 'Screenshot request queued' });
    }
    res.status(400).json({ status: 'error', message: 'Missing target' });
});

// 5. Active players list (GET /api/players)
app.get('/api/players', (req, res) => {
    const now = Date.now();
    const list = Array.from(sessions.values()).map(s => ({
        steamId: s.steamId,
        nickname: s.nickname,
        hwid: s.hwid,
        ip: s.ip,
        active: (now - s.lastHeartbeat) <= 35000,
        secondsAgo: Math.round((now - s.lastHeartbeat) / 1000)
    }));
    res.json(list);
});

// 6. Web Dashboard
app.get(['/', '/index.html', '/admin'], (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heavy Rust — AntiCheat Master Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0D1117; --bg-card: #161B22; --bg-header: #21262D;
            --border-color: rgba(255, 255, 255, 0.1); --cyan-neon: #00E5FF;
            --green-active: #00E676; --red-alert: #FF1744; --text-main: #F0F6FC; --text-muted: #8B949E;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Outfit', sans-serif; background: var(--bg-base); color: var(--text-main); padding: 30px 20px; display: flex; justify-content: center; }
        .container { width: 100%; max-width: 1100px; display: flex; flex-direction: column; gap: 24px; }
        .header { display: flex; align-items: center; justify-content: space-between; padding: 24px 28px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; }
        .logo-box h1 { font-size: 24px; font-weight: 800; color: var(--cyan-neon); text-transform: uppercase; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 14px; padding: 20px; }
        .stat-card .label { font-size: 13px; color: var(--text-muted); text-transform: uppercase; }
        .stat-card .val { font-size: 28px; font-weight: 700; color: var(--cyan-neon); margin-top: 6px; }
        .table-wrap { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: var(--bg-header); padding: 14px 18px; font-size: 13px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
        td { padding: 14px 18px; font-size: 14px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        tr:hover { background: rgba(0, 229, 255, 0.03); }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge-active { background: rgba(0, 230, 118, 0.15); color: var(--green-active); }
        .badge-offline { background: rgba(255, 23, 68, 0.15); color: var(--red-alert); }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; box-shadow: 0 0 8px currentColor; }
        .btn-screen { background: rgba(0, 229, 255, 0.1); color: var(--cyan-neon); border: 1px solid var(--cyan-neon); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }
        .btn-screen:hover { background: var(--cyan-neon); color: #000; }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-box">
                <h1>🛡️ Heavy Rust Auth Server</h1>
                <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">Центральный сервер аутентификации лаунчера и античита</p>
            </div>
            <div class="badge badge-active"><span class="pulse-dot"></span> СЕРВЕР АКТИВЕН</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Игроков с лаунчером онлайн</div><div id="onlineCount" class="val">0</div></div>
            <div class="stat-card"><div class="label">Всего сессий в памяти</div><div id="totalCount" class="val">0</div></div>
            <div class="stat-card"><div class="label">Статус защиты сервера</div><div class="val" style="color: var(--green-active);">СТРОГИЙ ВХОД</div></div>
        </div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Статус</th><th>Никнейм</th><th>SteamID64</th><th>HWID Аппаратуры</th><th>Пульс (сек. назад)</th><th>Действие</th></tr></thead>
                <tbody id="playersTbody"><tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 30px;">Загрузка данных...</td></tr></tbody>
            </table>
        </div>
    </div>
    <script>
        async function fetchPlayers() {
            try {
                const res = await fetch('/api/players');
                const players = await res.json();
                const tbody = document.getElementById('playersTbody');
                const active = players.filter(p => p.active);
                document.getElementById('onlineCount').innerText = active.length;
                document.getElementById('totalCount').innerText = players.length;
                if (players.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 30px;">В данный момент никто не запустил лаунчер.</td></tr>';
                    return;
                }
                tbody.innerHTML = players.map(p => \`
                    <tr>
                        <td><span class="badge \${p.active ? 'badge-active' : 'badge-offline'}"><span class="pulse-dot"></span> \${p.active ? 'В ИГРЕ' : 'ВЫШЕЛ'}</span></td>
                        <td style="font-weight: 600;">\${escapeHtml(p.nickname)}</td>
                        <td class="mono">\${p.steamId}</td>
                        <td class="mono" style="font-size:11px; color:var(--text-muted);">\${p.hwid || 'N/A'}</td>
                        <td>\${p.secondsAgo} сек.</td>
                        <td><button class="btn-screen" onclick="requestScreen('\${p.steamId}')">📸 Скриншот</button></td>
                    </tr>
                \`).join('');
            } catch (e) { console.error(e); }
        }
        async function requestScreen(steamId) {
            try {
                await fetch('/api/screen_request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: steamId }) });
                alert('Запрос скриншота для ' + steamId + ' отправлен! Снимок поступит в Discord.');
            } catch (e) { alert('Ошибка: ' + e); }
        }
        function escapeHtml(t) { return (t || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
        fetchPlayers();
        setInterval(fetchPlayers, 3000);
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`[HeavyRustAuth] Server listening on port ${PORT}`);
});
