// server.js (your original file + login/register API)
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { z } from 'zod';
import { initDb, upsertCode, verifyCode, getStatus, pruneExpired } from './db.js';
import aircraftService from './aircraftService.js';

import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const TTL_MIN = Number(process.env.CODE_TTL_MINUTES || '10');
const DEBUG_RETURN_CODE = String(process.env.DEBUG_RETURN_CODE || 'false').toLowerCase() === 'true';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const rawOrigins = (process.env.CORS_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
const allowedOrigins = new Set(rawOrigins);

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(express.json({ limit: '100kb' }));

// CORS: allow your front-end origins. Roblox server->server calls won't send Origin, so they'll be allowed.
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.size === 0) return cb(null, true); // allow all if not set
    return cb(null, allowedOrigins.has(origin));
  }
}));

// Basic rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Separate rate limiter for aircraft updates (more lenient for game servers)
const aircraftLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300, // Allow more requests for real-time updates
  standardHeaders: true,
  legacyHeaders: false,
});

app.get('/health', (_req, res) => res.json({ ok: true }));

// Helpers
const SignupSchema = z.object({
  userId: z.string().regex(/^\d{1,20}$/)
});

const AircraftSchema = z.object({
  id: z.string(),
  callsign: z.string().optional(),
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  heading: z.number().min(0).max(360),
  altitude: z.number().optional(),
  speed: z.number().optional(),
  aircraft_type: z.string().optional()
});

const AircraftArraySchema = z.array(AircraftSchema);

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/* =========================
   New: simple user store fallback + password hashing helpers
   - If your ./db.js exposes user functions (createUser, getUserById, verifyUserPassword),
     the endpoints will use those. Otherwise we use a local file-based store at ./data/users.json
   ========================= */

const DATA_DIR = path.resolve('./data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// In-memory token store (simple). For production, consider JWT or persistent session store.
const tokenStore = new Map();

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}$${derived}`;
}

function verifyPassword(stored, password) {
  if (!stored || typeof stored !== 'string') return false;
  const [salt, derived] = stored.split('$');
  if (!salt || !derived) return false;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  // constant-time compare
  return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(derived, 'hex'));
}

async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (e) {
    // ignore
  }
}

async function readLocalUsers() {
  await ensureDataDir();
  try {
    const txt = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(txt || '{}');
  } catch (e) {
    return {}; // no file / empty
  }
}

async function writeLocalUsers(obj) {
  await ensureDataDir();
  await fs.writeFile(USERS_FILE, JSON.stringify(obj, null, 2), 'utf8');
}

async function localGetUser(userId) {
  const users = await readLocalUsers();
  return users[userId] || null;
}
async function localCreateUser(userId, password) {
  const users = await readLocalUsers();
  if (users[userId]) throw new Error('exists');
  users[userId] = {
    id: userId,
    passwordHash: hashPassword(password),
    createdAt: (new Date()).toISOString(),
    verified: false
  };
  await writeLocalUsers(users);
  return users[userId];
}
async function localSetVerified(userId, v = true) {
  const users = await readLocalUsers();
  if (!users[userId]) return false;
  users[userId].verified = !!v;
  await writeLocalUsers(users);
  return true;
}

/* =========================
   Routes: verification / aircraft (existing)
   ========================= */

// Create or refresh a verification code for a user.
// Front-end (GitHub Pages) should call this on signup.
app.post('/api/create-verification', async (req, res) => {
  try {
    const { userId } = SignupSchema.parse(req.body);
    const code = generateCode();
    const row = await upsertCode(userId, code, TTL_MIN);
    // In production, do NOT return the code to the browser. You might send it via DM/email, or only display in-game.
    res.json({ ok: true, ttlMinutes: TTL_MIN, ...(DEBUG_RETURN_CODE ? { code: row.code } : {}) });
  } catch (e) {
    console.error(e);
    res.status(400).json({ ok: false, error: 'invalid_input' });
  }
});

// Roblox server calls this to mark the code used.
// Must include header x-admin-token: <ADMIN_TOKEN>
app.post('/api/verify', async (req, res) => {
  try {
    const token = req.header('x-admin-token') || '';
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const bodySchema = z.object({
      userId: z.string().regex(/^\d{1,20}$/),
      code: z.string().regex(/^\d{6}$/)
    });
    const { userId, code } = bodySchema.parse(req.body);
    const ok = await verifyCode(userId, code);

    // If using local fallback users, mark them verified here too
    if (ok) {
      try {
        // if db.js provides a createUser/getUserById/verifyUser implementation, you may want to hook into it.
        // As a fallback, update local store.
        await localSetVerified(userId, true);
      } catch (e) {
        // ignore
      }
    }

    res.json({ ok: true, verified: ok });
  } catch (e) {
    console.error(e);
    res.status(400).json({ ok: false, error: 'invalid_input' });
  }
});

// Front-end polls this to know if verification completed.
app.get('/api/verify-status', async (req, res) => {
  try {
    const userId = String(req.query.user || '');
    if (!/^\d{1,20}$/.test(userId)) {
      return res.status(400).json({ ok: false, error: 'invalid_user' });
    }
    const status = await getStatus(userId);
    // getStatus is expected to return something like { verified: boolean }
    res.json({ ok: true, ...status });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* =========================
   NEW: Register (create user) endpoint
   POST /api/users
   Body: { userId: string (digits), password: string }
   Responds with ok + needsVerification; if DEBUG_RETURN_CODE returns the verification code.
   Also creates a verification code via upsertCode() so your verification pipeline keeps working.
   ========================= */
const RegisterSchema = z.object({
  userId: z.string().regex(/^\d{1,20}$/),
  password: z.string().min(6)
});

app.post('/api/users', async (req, res) => {
  try {
    const { userId, password } = RegisterSchema.parse(req.body);

    // Try to use DB-level createUser if available
    let createdUser = null;
    try {
      // If your db.js exports createUser, call it (expected interface: createUser(userId, passwordHash) or similar)
      // We'll check for exported function dynamically
      const dbModule = await import('./db.js');
      if (typeof dbModule.createUser === 'function') {
        // attempt to create user in DB (let DB handle hashing or storage)
        createdUser = await dbModule.createUser(userId, password);
      }
    } catch (e) {
      // ignore, fallback to local file store
    }

    if (!createdUser) {
      // fallback local create (throws if already exists)
      try {
        createdUser = await localCreateUser(userId, password);
      } catch (e) {
        if (e.message === 'exists') {
          return res.status(409).json({ ok: false, error: 'user_exists' });
        }
        throw e;
      }
    }

    // create verification code (so the same verification pipeline works)
    try {
      const code = generateCode();
      const row = await upsertCode(userId, code, TTL_MIN);
      const payload = { ok: true, needsVerification: true };
      if (DEBUG_RETURN_CODE) payload.code = row.code;
      return res.json(payload);
    } catch (e) {
      console.warn('upsertCode failed after user create:', e);
      return res.json({ ok: true, needsVerification: true });
    }
  } catch (e) {
    console.error('User register error:', e);
    res.status(400).json({ ok: false, error: 'invalid_input' });
  }
});

/* =========================
   NEW: Login endpoint
   POST /api/login
   Body: { userId, password }
   Returns: { ok:true, token, user } on success. If not verified returns 403 with error 'not_verified'.
   ========================= */
const LoginSchema = z.object({
  userId: z.string().regex(/^\d{1,20}$/),
  password: z.string().min(1)
});

app.post('/api/login', async (req, res) => {
  try {
    const { userId, password } = LoginSchema.parse(req.body);

    // 1) Try DB-level verification if db.js provides an accessor
    let userRecord = null;
    let dbUsed = false;
    try {
      const dbModule = await import('./db.js');
      if (typeof dbModule.getUserById === 'function') {
        userRecord = await dbModule.getUserById(userId);
        dbUsed = true;
      } else if (typeof dbModule.findUser === 'function') {
        userRecord = await dbModule.findUser(userId);
        dbUsed = true;
      }
    } catch (e) {
      // ignore, fallback to local
    }

    // 2) If no db user, fallback to local file
    if (!userRecord) {
      userRecord = await localGetUser(userId);
    }

    if (!userRecord) {
      return res.status(401).json({ ok: false, error: 'invalid_credentials' });
    }

    // If DB exposes verifyUserPassword we prefer it (maybe DB stores bcrypt)
    let passwordOk = false;
    try {
      const dbModule = await import('./db.js');
      if (typeof dbModule.verifyUserPassword === 'function') {
        passwordOk = await dbModule.verifyUserPassword(userId, password);
      }
    } catch (e) {
      // ignore
    }

    // fallback to comparing local passwordHash
    if (!passwordOk) {
      if (userRecord.passwordHash) {
        passwordOk = verifyPassword(userRecord.passwordHash, password);
      } else if (!dbUsed && userRecord.password) {
        // legacy plain password field (not recommended) - support during migration
        passwordOk = (userRecord.password === password);
      } else {
        // if no way to verify password, reject
        passwordOk = false;
      }
    }

    if (!passwordOk) {
      return res.status(401).json({ ok: false, error: 'invalid_credentials' });
    }

    // 3) Check verification status: prefer getStatus() from your db logic
    let verified = false;
    try {
      const status = await getStatus(userId);
      if (status && status.verified) verified = true;
    } catch (e) {
      // ignore; fallback to local user record's verified field
    }

    if (!verified) {
      // fallback local store check
      if (userRecord.verified) verified = true;
    }

    if (!verified) {
      return res.status(403).json({ ok: false, error: 'not_verified' });
    }

    // 4) success: mint a simple token and return
    const token = randomToken();
    tokenStore.set(token, { userId, issuedAt: Date.now() });

    // build returned user object (keep minimal)
    const user = { id: userId, name: userRecord.name || (userRecord.id || userId), email: userRecord.email || null };

    return res.json({ ok: true, token, user });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(400).json({ ok: false, error: 'invalid_input' });
  }
});

/* =========================
   Existing Aircraft routes (left intact)
   ========================= */

// Roblox server posts aircraft data here
// Must include header x-admin-token: <ADMIN_TOKEN>
app.post('/api/aircraft', aircraftLimiter, async (req, res) => {
  try {
    const token = req.header('x-admin-token') || '';
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    const aircraftArray = AircraftArraySchema.parse(req.body);
    const result = aircraftService.updateAircraft(aircraftArray);
    
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('Aircraft update error:', e);
    if (e instanceof z.ZodError) {
      res.status(400).json({ ok: false, error: 'invalid_aircraft_data', details: e.errors });
    } else {
      res.status(500).json({ ok: false, error: 'server_error' });
    }
  }
});

// Frontend can get current aircraft data (optional, WebSocket is preferred)
app.get('/api/aircraft', async (req, res) => {
  try {
    const aircraft = aircraftService.getAllAircraft();
    res.json({ 
      ok: true, 
      aircraft, 
      count: aircraft.length,
      connectedClients: aircraftService.getConnectedClientsCount()
    });
  } catch (e) {
    console.error('Get aircraft error:', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Aircraft service status endpoint
app.get('/api/aircraft/status', async (req, res) => {
  try {
    res.json({
      ok: true,
      aircraftCount: aircraftService.getAircraftCount(),
      connectedClients: aircraftService.getConnectedClientsCount()
    });
  } catch (e) {
    console.error('Aircraft status error:', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Optional: tiny cron-like pruning (best to run a separate cron job in production)
setInterval(() => {
  pruneExpired().catch(console.error);
}, 5 * 60 * 1000);

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  aircraftService.shutdown();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  aircraftService.shutdown();
  process.exit(0);
});

initDb().then(() => {
  const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    
    // Initialize aircraft tracking service
    aircraftService.initialize(server);
  });
}).catch(err => {
  console.error('DB init failed', err);
  process.exit(1);
});
