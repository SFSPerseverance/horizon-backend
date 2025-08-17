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
   - If your ./db.js exposes user functions (create
