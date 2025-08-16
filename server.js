import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { z } from 'zod';
import { initDb, upsertCode, verifyCode, getStatus, pruneExpired } from './db.js';
import aircraftService from './aircraftService.js';

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
    res.json({ ok: true, ...status });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ===== AIRCRAFT TRACKING ROUTES =====

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