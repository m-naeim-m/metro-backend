const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 8000;

// ============ Middleware ============
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '4kb' }));

// Rate limiter for OTP
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { message: 'rate_limited' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============ Helpers ============
function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function generateOtp(length = 6) {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += Math.floor(Math.random() * 10).toString();
  }
  return code;
}

function generateToken() {
  return sha256(`${Date.now()}${Math.random()}`);
}

function validPhone(value) {
  return /^09\d{9}$/.test(value);
}

function jsonResponse(res, statusCode, body) {
  return res.status(statusCode).json(body);
}

function isAdmin(req) {
  const configured = (process.env.ADMIN_REPORT_TOKEN || '').trim();
  return configured.length > 0 && req.headers.authorization === `Bearer ${configured}`;
}

function adminUnauthorized(res) {
  return jsonResponse(res, 401, { message: 'admin_unauthorized' });
}

function extractToken(req) {
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') ? auth.substring(7) : '';
}

// ============ Data Store ============
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = process.env.REPORT_DATA_FILE || path.join(DATA_DIR, 'auth_reports.json');

const records = {};
const sessions = {};
const requestCount = {};
const users = {};
const offlineSubscriptions = {};
const offlineActivationCodes = {};
const adsConfig = {};

let mapKeys = [];
let mapKeyIndex = 0;

function loadReportData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (raw.users) { Object.keys(users).forEach(k => delete users[k]); Object.assign(users, raw.users); }
    if (raw.offlineSubscriptions) { Object.keys(offlineSubscriptions).forEach(k => delete offlineSubscriptions[k]); Object.assign(offlineSubscriptions, raw.offlineSubscriptions); }
    if (raw.offlineActivationCodes) { Object.keys(offlineActivationCodes).forEach(k => delete offlineActivationCodes[k]); Object.assign(offlineActivationCodes, raw.offlineActivationCodes); }
    if (raw.adsConfig) { Object.keys(adsConfig).forEach(k => delete adsConfig[k]); Object.assign(adsConfig, raw.adsConfig); }
    console.log('Data loaded');
  } catch (err) {
    console.error('Data load failed:', err.message);
  }
}

function saveReportData() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmpFile = DATA_FILE + '.tmp';
    fs.writeFileSync(tmpFile, JSON.stringify({ users, offlineSubscriptions, offlineActivationCodes, adsConfig }));
    if (fs.existsSync(DATA_FILE)) fs.unlinkSync(DATA_FILE);
    fs.renameSync(tmpFile, DATA_FILE);
  } catch (err) {
    console.error('Data save failed:', err.message);
  }
}

// ============ SMS ============
async function sendSms(phone, code) {
  const baseUrl = (process.env.MELIPAYAMAK_BASE_URL || 'https://rest.payamak-panel.com').replace(/\/+$/, '');
  const username = (process.env.MELIPAYAMAK_USERNAME || '').trim();
  const password = (process.env.MELIPAYAMAK_PASSWORD || '').trim();
  const patternValue = (process.env.MELIPAYAMAK_PATTERN || '').trim();
  const bodyId = parseInt(patternValue);

  if (!username || !password || !patternValue || isNaN(bodyId) || !phone || !code) {
    throw new Error('sms_config_incomplete');
  }

  const response = await fetch(`${baseUrl}/api/SendSMS/BaseServiceNumber`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ username, password, to: phone, bodyId, text: code }),
    timeout: 30000,
  });

  const responseBody = await response.text();
  console.log('Melipayamak:', response.status);

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`sms_failed status=${response.status} body=${responseBody}`);
  }
}

// ============ Map Proxy ============
function getNextMapKey() {
  if (mapKeys.length === 0) return '';
  const key = mapKeys[mapKeyIndex % mapKeys.length];
  mapKeyIndex = (mapKeyIndex + 1) % mapKeys.length;
  return key;
}

async function mapRequest(targetUrl) {
  if (mapKeys.length === 0) throw new Error('map_keys_not_configured');
  let lastStatus = 503;
  for (let i = 0; i < mapKeys.length; i++) {
    const key = getNextMapKey();
    const response = await fetch(targetUrl, {
      headers: { 'x-api-key': key, 'Authorization': `Bearer ${key}`, 'Accept': '*/*' },
      timeout: 20000,
    });
    lastStatus = response.status;
    if (response.status !== 401 && response.status !== 403 && response.status !== 429) {
      return response;
    }
  }
  throw new Error(`map_all_keys_failed status=${lastStatus}`);
}

// ================================================================
//                         ROUTES
// ================================================================

// ====================== HEALTH ======================
app.get('/health', (req, res) => {
  jsonResponse(res, 200, { status: 'ok', message: 'OTP backend is running' });
});

// ====================== AUTH ======================

// POST /auth/request-otp
app.post('/auth/request-otp', otpLimiter, async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    if (!validPhone(phoneNumber)) return jsonResponse(res, 400, { message: 'invalid_phone' });

    const now = Date.now();
    if (!requestCount[phoneNumber]) requestCount[phoneNumber] = [];
    requestCount[phoneNumber] = requestCount[phoneNumber].filter(t => now - t < 3600000);
    if (requestCount[phoneNumber].length >= 5) return jsonResponse(res, 429, { message: 'rate_limited' });
    requestCount[phoneNumber].push(now);

    const code = generateOtp(6);
    const requestId = generateToken();
    const expiresAt = new Date(now + 3 * 60 * 1000);

    records[phoneNumber] = { phone: phoneNumber, hash: sha256(code), expiresAt, attempts: 0, requestId };

    try {
      await sendSms(phoneNumber, code);
    } catch (err) {
      delete records[phoneNumber];
      return jsonResponse(res, 502, { message: 'sms_failed' });
    }

    jsonResponse(res, 200, { message: 'ok', requestId, expiresAt: expiresAt.toISOString() });
  } catch (err) {
    jsonResponse(res, 500, { message: 'internal_error' });
  }
});

// POST /auth/resend-otp
app.post('/auth/resend-otp', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    const record = records[phoneNumber];
    if (!record) return jsonResponse(res, 404, { message: 'not_found' });

    const code = generateOtp(6);
    record.hash = sha256(code);
    record.expiresAt = new Date(Date.now() + 3 * 60 * 1000);
    record.attempts = 0;

    try { await sendSms(phoneNumber, code); }
    catch (err) { return jsonResponse(res, 502, { message: 'sms_failed' }); }

    jsonResponse(res, 200, { message: 'ok', requestId: record.requestId, expiresAt: record.expiresAt.toISOString() });
  } catch (err) {
    jsonResponse(res, 500, { message: 'internal_error' });
  }
});

// POST /auth/verify-otp
app.post('/auth/verify-otp', async (req, res) => {
  try {
    const { phoneNumber, code, requestId } = req.body;
    const record = records[phoneNumber];

    if (!record || record.requestId !== requestId) return jsonResponse(res, 400, { message: 'invalid_request' });
    if (new Date() > record.expiresAt) return jsonResponse(res, 400, { message: 'expired' });
    if (record.attempts >= 5) return jsonResponse(res, 429, { message: 'too_many_attempts' });

    record.attempts++;
    if (sha256(code) !== record.hash) return jsonResponse(res, 401, { message: 'invalid_code' });

    Object.keys(sessions).forEach(t => { if (sessions[t].phoneNumber === phoneNumber) delete sessions[t]; });

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    sessions[token] = { phoneNumber, expiresAt: expiresAt.toISOString() };

    users[phoneNumber] = {
      phoneNumber,
      registeredAt: users[phoneNumber]?.registeredAt || new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };

    saveReportData();
    delete records[phoneNumber];

    jsonResponse(res, 200, { session: { token, phoneNumber, expiresAt: expiresAt.toISOString() } });
  } catch (err) {
    jsonResponse(res, 500, { message: 'internal_error' });
  }
});

// GET /auth/me
app.get('/auth/me', (req, res) => {
  const token = extractToken(req);
  const session = sessions[token];
  if (!session) return jsonResponse(res, 401, { message: 'unauthorized' });
  jsonResponse(res, 200, { session: { token, ...session } });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  const token = extractToken(req);
  delete sessions[token];
  jsonResponse(res, 200, { message: 'ok' });
});

// ====================== SMS ======================

// POST /sms/send-otp  (client-side SMS send, separate from auth flow)
app.post('/sms/send-otp', async (req, res) => {
  try {
    const { phoneNumber, code, senderNumber, patternBodyId } = req.body;
    if (!phoneNumber || !code) return jsonResponse(res, 400, { message: 'invalid_request' });

    await sendSms(phoneNumber, code);
    jsonResponse(res, 200, { message: 'ok' });
  } catch (err) {
    jsonResponse(res, 502, { message: 'sms_failed' });
  }
});

// ====================== SUBSCRIPTIONS ======================

// POST /subscriptions/offline/activate
app.post('/subscriptions/offline/activate', (req, res) => {
  const { phoneNumber, code } = req.body;
  if (!validPhone(phoneNumber) || !code) return jsonResponse(res, 400, { message: 'invalid_activation' });

  const record = offlineActivationCodes[sha256(code.toUpperCase())];
  if (!record || record.phoneNumber !== phoneNumber || record.used) {
    return jsonResponse(res, 401, { message: 'invalid_activation' });
  }

  const validUntil = new Date(record.validUntil);
  if (isNaN(validUntil.getTime()) || validUntil <= new Date()) {
    return jsonResponse(res, 401, { message: 'activation_expired' });
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + record.durationDays * 24 * 60 * 60 * 1000);
  record.used = true;

  offlineSubscriptions[phoneNumber] = {
    phoneNumber,
    status: 'approved',
    startedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    activationMethod: 'backend_activation_code',
    updatedAt: now.toISOString(),
  };

  saveReportData();
  jsonResponse(res, 200, { subscription: offlineSubscriptions[phoneNumber] });
});

// POST /subscriptions/offline
app.post('/subscriptions/offline', (req, res) => {
  const token = extractToken(req);
  const session = sessions[token];
  if (!session) return jsonResponse(res, 401, { message: 'unauthorized' });

  const { subscription } = req.body;
  if (!subscription || typeof subscription !== 'object') return jsonResponse(res, 400, { message: 'invalid_subscription' });

  const phone = session.phoneNumber;
  offlineSubscriptions[phone] = { ...subscription, phoneNumber: phone, updatedAt: new Date().toISOString() };
  saveReportData();
  jsonResponse(res, 200, { message: 'ok' });
});

// ====================== ADS CONFIG ======================

// GET /config/ads
app.get('/config/ads', (req, res) => {
  jsonResponse(res, 200, {
    appId: adsConfig.appId || process.env.TAPSELL_APP_ID || '',
    bannerZoneId: adsConfig.bannerZoneId || process.env.TAPSELL_BANNER_ZONE_ID || '',
    interstitialZoneId: adsConfig.interstitialZoneId || process.env.TAPSELL_INTERSTITIAL_ZONE_ID || '',
  });
});

// POST /admin/config/ads
app.post('/admin/config/ads', (req, res) => {
  if (!isAdmin(req)) return adminUnauthorized(res);
  const { appId, bannerZoneId, interstitialZoneId } = req.body;
  if (appId) adsConfig.appId = appId;
  if (bannerZoneId) adsConfig.bannerZoneId = bannerZoneId;
  if (interstitialZoneId) adsConfig.interstitialZoneId = interstitialZoneId;
  saveReportData();
  jsonResponse(res, 200, { message: 'ok' });
});

// ====================== MAP PROXY ======================

// GET /map/tiles/:z/:x/:y.png
app.get('/map/tiles/:z/:x/:y.png', async (req, res) => {
  try {
    const { z, x, y } = req.params;
    const targetUrl = `https://map.ir/shiveh/xyz/1.0.0/Shiveh:Shiveh@EPSG:3857@png/${z}/${x}/${y}.png`;
    const response = await mapRequest(targetUrl);
    const buffer = await response.buffer();
    res.set({ 'Content-Type': response.headers.get('content-type') || 'image/png', 'Cache-Control': 'public, max-age=300' });
    res.send(buffer);
  } catch (err) {
    jsonResponse(res, 503, { message: 'map_unavailable' });
  }
});

// GET /map/foot
app.get('/map/foot', async (req, res) => {
  const { origin, destination } = req.query;
  if (!origin || !destination) return jsonResponse(res, 400, { message: 'invalid_map_request' });
  try {
    const response = await mapRequest(`https://map.ir/routes/foot/v1/driving/${origin};${destination}`);
    const body = await response.text();
    res.set({ 'Content-Type': response.headers.get('content-type') || 'application/json', 'Cache-Control': 'public, max-age=300' });
    res.send(body);
  } catch (err) {
    jsonResponse(res, 503, { message: 'map_unavailable' });
  }
});

// ====================== ADMIN ======================

// POST /admin/offline-activation-codes
app.post('/admin/offline-activation-codes', (req, res) => {
  if (!isAdmin(req)) return adminUnauthorized(res);
  const { phoneNumber, code, durationDays, validUntil } = req.body;
  if (!validPhone(phoneNumber) || !code || !durationDays || durationDays <= 0 || !validUntil) {
    return jsonResponse(res, 400, { message: 'invalid_activation_code' });
  }
  offlineActivationCodes[sha256(code.toUpperCase())] = {
    phoneNumber, codeHash: sha256(code.toUpperCase()),
    durationDays: parseInt(durationDays), validUntil: new Date(validUntil).toISOString(), used: false,
  };
  saveReportData();
  jsonResponse(res, 201, { message: 'ok' });
});

// GET /admin/reports/users
app.get('/admin/reports/users', (req, res) => {
  if (!isAdmin(req)) return adminUnauthorized(res);
  const list = Object.values(users).sort((a, b) => (b.lastLoginAt || '').localeCompare(a.lastLoginAt || ''));
  jsonResponse(res, 200, { users: list, count: list.length });
});

// GET /admin/reports/offline-subscriptions
app.get('/admin/reports/offline-subscriptions', (req, res) => {
  if (!isAdmin(req)) return adminUnauthorized(res);
  const now = new Date();
  const subs = Object.values(offlineSubscriptions).map(item => {
    const copy = { ...item };
    const expiresAt = new Date(copy.expiresAt);
    copy.isActive = expiresAt > now && copy.status === 'approved';
    copy.remainingSeconds = expiresAt > now ? Math.floor((expiresAt - now) / 1000) : 0;
    return copy;
  }).sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  jsonResponse(res, 200, { subscriptions: subs, count: subs.length, activeCount: subs.filter(s => s.isActive).length });
});

// ====================== CATCH ALL ======================
app.use((req, res) => {
  jsonResponse(res, 404, { message: 'not_found' });
});

// ====================== ERROR HANDLER ======================
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  jsonResponse(res, 500, { message: 'internal_error' });
});

// ================================================================
//                         START
// ================================================================
mapKeys = (process.env.MAP_IR_API_KEYS || process.env.MAP_IR_API_KEY || '').split(',').map(k => k.trim()).filter(k => k);
adsConfig.appId = (process.env.TAPSELL_APP_ID || '').trim();
adsConfig.bannerZoneId = (process.env.TAPSELL_BANNER_ZONE_ID || '').trim();
adsConfig.interstitialZoneId = (process.env.TAPSELL_INTERSTITIAL_ZONE_ID || '').trim();

loadReportData();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Metro Backend running on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   OTP:    POST /auth/request-otp`);
  console.log(`   Verify: POST /auth/verify-otp`);
  console.log(`   Admin:  GET  /admin/reports/users\n`);
});
