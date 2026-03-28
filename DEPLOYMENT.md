# Lumen Cortex — Deployment Architecture

> **Note:** Never call this project "Hexstrike" in external-facing content.

## Deployment Environments

### 🌐 Render (Production)
- **URL:** https://lumen-cortex.onrender.com
- **Service ID:** `srv-d6n67tngi27c73c89s70`
- **Plan:** Starter ($7/mo, 512MB RAM)
- **Start command:** `node --max-old-space-size=450 server.js`
- **Key env vars:**
  - `RENDER_SERVICE_ID` — set automatically by Render (triggers `isRender` detection)
  - `RENDER=true` — belt-and-suspenders guard
  - `DATABASE_URL=` — **must be empty** (overrides local .env; no Postgres on Render)

**Runs:** Core API, Ad Blocker analysis, web endpoints  
**Does NOT run:** Network monitoring, device monitoring, tcpdump-based features

---

### 🖥️ Mac Mini (Local Dev — Elim)
- **Location:** `/Users/jimmysmacmini/.openclaw/workspace/lumen-cortex/`
- **PM2 process:** `lumen-cortex`
- **Database:** Local Postgres (`lumen_cortex_v2`)
- **Runs:** Everything including local-only monitors

---

### 🖥️ Mac Studio (Local Dev — Unc Lumen)
- **Location:** `/Users/jimmysmacstudio/...`
- **Database:** Local Postgres
- **Runs:** Everything including local-only monitors

---

## Local-Only Features (guarded by `if (!isRender)`)

These features use system-level tools unavailable in cloud environments:

| Feature | Why blocked on Render |
|---|---|
| `internetMonitor.startMonitoring()` | Pings home network IPs — irrelevant in cloud |
| `deviceMonitor.startGlobalMonitor()` | Runs `sudo tcpdump` — no sudo, no interfaces on Render |

**Guard pattern:**
```js
const isRender = process.env.RENDER_SERVICE_ID || process.env.RENDER;
if (!isRender) {
  internetMonitor.startMonitoring();
  // ...
}
```

---

## Known Issues & Fixes

### 2025-07-14 — 502 Bad Gateway on Render
**Root causes:**
1. `.env` had `DATABASE_URL` pointing to `localhost:5432` → connection hang on startup
2. `deviceMonitor.startGlobalMonitor()` ran `sudo tcpdump` via setTimeout → hard crash (no sudo on Render)

**Fixes:**
- Set `DATABASE_URL=` (empty) in Render env vars
- Wrapped both monitors in `if (!isRender)` guards
- Added `--max-old-space-size=450` to start command for memory safety

---

## Deployment Checklist

Before deploying to Render:
- [ ] `DATABASE_URL=` is empty in Render env vars
- [ ] Any new background processes use `if (!isRender)` guard if they use system tools
- [ ] Memory usage stays under ~400MB (512MB plan limit)
- [ ] Test locally with `RENDER=true node server.js` to simulate cloud env
