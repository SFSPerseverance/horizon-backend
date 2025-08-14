# Horizon Backend (Render + GitHub Pages)

This is a minimal Node/Express backend that lets your website generate a 6‑digit code and your Roblox game verify it.

## What it does
- `POST /api/create-verification` — creates/refreshes a 6‑digit code for a Roblox `userId` (TTL is configurable).
- `POST /api/verify` — **called from Roblox** to mark the code as used (requires `x-admin-token` header).
- `GET /api/verify-status?user=USERID` — website polls this to see if the account is verified.

---

## 1) Create a new GitHub repo
1. Create a repo, e.g. `horizon-backend`.
2. Add all files from this folder.
3. Commit & push.

```bash
git init
git add .
git commit -m "init backend"
git branch -M main
git remote add origin https://github.com/<you>/horizon-backend.git
git push -u origin main
```

## 2) Create a PostgreSQL instance on Render
1. In Render, **New** → **PostgreSQL**.
2. Choose Free (for dev), name it, create.
3. After it's provisioned, copy the **External Connection** string (starts with `postgres://`).

## 3) Deploy a Web Service on Render
1. In Render, **New** → **Web Service** → **Build & deploy from a Git repository**.
2. Connect to your `horizon-backend` repo.
3. Environment: **Node**.
4. Build command: `npm ci`  (Render runs this automatically if you leave it blank).
5. Start command: `node server.js`
6. Add environment variables:
   - `DATABASE_URL` = (your Render Postgres external connection string)
   - `CORS_ORIGIN` = `https://<your-gh-username>.github.io` (and/or your custom domain), comma‑separated for multiples.
   - `ADMIN_TOKEN` = a long random secret (you’ll also paste this into Roblox)
   - `DEBUG_RETURN_CODE` = `true` while testing, `false` in production
   - `CODE_TTL_MINUTES` = `10` (or your choice)
7. Deploy. After it turns **Live**, note the service URL, e.g. `https://horizon-backend.onrender.com`.

## 4) Wire the website to the backend
In your `script.js`, replace the client‑side simulation with real calls:

```js
const API_BASE = "https://<your-render-service>.onrender.com";

// After validating username/password in handleSignup():
const resp = await fetch(`${API_BASE}/api/create-verification`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId: username })
});
const json = await resp.json();
if (!json.ok) { showMessage('Server error creating verification', 'error'); return; }
// Optionally show code if DEBUG_RETURN_CODE=true on server (hide in production)
const verificationCode = json.code || '------';
showVerificationForm(username, verificationCode);

// In the "Check verification" button handler:
const statusResp = await fetch(`${API_BASE}/api/verify-status?user=${encodeURIComponent(username)}`);
const statusJson = await statusResp.json();
if (statusJson.ok && statusJson.verified) {
  // ... finish signup and close modal ...
}
```

> Tip: Remove any `localStorage` user storage for verification and rely on the server instead.

## 5) Roblox game script
Use `RequestAsync` so you can send the `x-admin-token` header.

```lua
local HttpService = game:GetService("HttpService")
HttpService.HttpEnabled = true  -- Game Settings > Security > Allow HTTP Requests must be ON

local BACKEND = "https://<your-render-service>.onrender.com"
local ADMIN_TOKEN = "<same-as-on-render>"

local function verifyCode(userId, code)
    local req = {
        Url = BACKEND .. "/api/verify",
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["x-admin-token"] = ADMIN_TOKEN
        },
        Body = HttpService:JSONEncode({ userId = tostring(userId), code = tostring(code) })
    }
    local ok, res = pcall(function() return HttpService:RequestAsync(req) end)
    if not ok then warn("HTTP error", res) return false end
    if not res.Success then warn("HTTP failed", res.StatusCode, res.StatusMessage) return false end
    local data = HttpService:JSONDecode(res.Body)
    return data.ok and data.verified == true
end

-- Example usage from a LocalScript on a Submit button:
-- local userId = game.Players.LocalPlayer.UserId
-- local success = verifyCode(userId, codeFromTextbox)
-- if success then print("Verified!") else warn("Invalid / expired code") end
```

## 6) Test the flow
1. On your website, sign up with your Roblox UserId. The site calls `/api/create-verification`.
2. In Roblox, enter the code and press Submit. The game calls `/api/verify` with your token.
3. On the website, click **Check verification**. It polls `/api/verify-status` and should finish signup.

## 7) Security notes
- Set `DEBUG_RETURN_CODE=false` once you confirm everything works so the code is not revealed to the browser.
- Keep `ADMIN_TOKEN` secret. If leaked, rotate it on Render and in your Roblox script.
- Consider adding rate limits per user/IP and bot protection on the website.
- You can also tie the verification to a short-lived session id generated at signup.

---

Happy flying ✈️
