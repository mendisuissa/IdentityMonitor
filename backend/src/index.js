require('dotenv').config();
require('isomorphic-fetch');

const express = require('express');
const http    = require('http');
const cors    = require('cors');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const AzureTableSessionStore = require('./services/azureTableSessionStore');
const cron    = require('node-cron');
const path    = require('path');
const fs      = require('fs');
const remediationRouter = require('./routes/remediation');
const auditRoutes   = require('./routes/audit');
const deviceActionsRoutes = require('./routes/deviceActions');

const authRoutes    = require('./routes/auth');
const usersRoutes   = require('./routes/users');
const signinsRoutes = require('./routes/signins');
const alertsRoutes  = require('./routes/alerts');
const mockRoutes    = require('./routes/mock');
const webhookRoutes = require('./routes/webhook');
const pimRoutes     = require('./routes/pim');
const reportsRoutes = require('./routes/reports');
const tenantRoutes  = require('./routes/tenant');
const weeklyDigest  = require('./services/weeklyDigest');
const workflowStore = require('./services/workflowStore');
const alertsStore   = require('./services/alertsStore');

const auditLog        = require('./services/auditLog');
const anomalyService  = require('./services/anomalyService');
const wsService       = require('./services/wsService');
const jobRunner       = require('./services/jobRunner');
const tableStorage    = require('./services/tableStorage');
const webhookService  = require('./services/webhookService');
const telegramService = require('./services/telegramService');
const automationService = require('./services/automationService');
const deviceActionMonitor = require('./services/deviceActionMonitor');
const tenantRegistry = require('./services/tenantRegistry');
const autoRemediationService = require('./services/autoRemediationService');
const defenderVulnerabilityRoutes = require('./routes/defenderVulnerabilities');
const mspRoutes = require('./routes/msp');
const identityRoutes = require('./routes/identity');
const superadminRoutes = require('./routes/superadmin');
const billingRoutes    = require('./routes/billing');
const internalRoutes   = require('./routes/internal');

const rateLimit = require('express-rate-limit');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 3001;
const MOCK   = process.env.MOCK_MODE === 'true';

app.set('trust proxy', 1);
app.use(express.json());

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Auth endpoints: 20 requests per 15 min per IP (brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skip: () => MOCK,
});
// General API: 300 requests per 15 min per IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skip: () => MOCK,
});
// Remediation/action endpoints: 30 per 15 min (prevent abuse)
const actionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skip: () => MOCK,
});
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));

// Sessions
const sessionDir = process.env.NODE_ENV === 'production'
  ? '/home/sessions'
  : path.join(__dirname, '../../sessions');
if (!fs.existsSync(sessionDir)) fs.mkdirSync(sessionDir, { recursive: true });

const SESSION_TTL_SEC = 24 * 60 * 60; // 24 hours
app.use(session({
  // Use Azure Table Storage for sessions in production (fast, persistent across restarts).
  // Fall back to FileStore in dev when Azure Tables is not configured.
  store: process.env.AZURE_STORAGE_CONNECTION_STRING
    ? new AzureTableSessionStore({ ttl: SESSION_TTL_SEC })
    : new FileStore({ path: sessionDir, ttl: SESSION_TTL_SEC, retries: 1, logFn: () => {} }),
  secret: (() => {
    if (!process.env.SESSION_SECRET) {
      if (process.env.NODE_ENV === 'production') {
        console.error('[FATAL] SESSION_SECRET env var is not set. Refusing to start in production.');
        process.exit(1);
      }
      return 'priv-monitor-dev-secret-DO-NOT-USE-IN-PROD';
    }
    return process.env.SESSION_SECRET;
  })(),
  resave: false,
  saveUninitialized: false,
  rolling: true, // extend session on every request — keeps active users logged in
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   SESSION_TTL_SEC * 1000,
    sameSite: 'strict'
  }
}));

// ── Global request timeout — abort any request that hasn't responded in 30s ──
// Exception: auto-remediation trigger can take several minutes (up to maxRun × API time)
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health') {
    const isLongRunning = req.path.includes('/auto-remediation/trigger');
    const isDefender   = req.path.includes('/defender/');
    const timeoutMs = isLongRunning ? 5 * 60 * 1000 : isDefender ? 90 * 1000 : 30000;
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(503).json({ error: 'Request timeout' });
      }
    }, timeoutMs);
    res.on('finish', () => clearTimeout(timer));
    res.on('close',  () => clearTimeout(timer));
  }
  next();
});

// Re-populate tenant registry from session after backend restarts.
// Sessions survive via FileStore/Azure but _tenants is in-memory — this bridges the gap.
app.use((req, res, next) => {
  if (req.session?.tenant?.tenantId) {
    tenantRegistry.registerTenant(req.session.tenant);
  }
  next();
});

// API Routes
app.use('/api/auth',         authLimiter,   authRoutes);
app.use('/api/users',        apiLimiter,    usersRoutes);
app.use('/api/signins',      apiLimiter,    signinsRoutes);
app.use('/api/alerts',       apiLimiter,    alertsRoutes);
app.use('/api/mock',                        mockRoutes);
app.use('/api/webhook',                     webhookRoutes);
app.use('/api/pim',          apiLimiter,    pimRoutes);
app.use('/api/reports',      apiLimiter,    reportsRoutes);
app.use('/api/tenant',       apiLimiter,    tenantRoutes);
app.use('/api/remediation',  actionLimiter, remediationRouter);
app.use('/api/audit',        apiLimiter,    auditRoutes);
app.use('/api/device-actions', actionLimiter, deviceActionsRoutes);
app.use('/api/defender',     apiLimiter,    defenderVulnerabilityRoutes);
app.use('/api/msp',          apiLimiter,    mspRoutes);
app.use('/api/identity',     apiLimiter,    identityRoutes);
app.use('/api/superadmin',   apiLimiter,    superadminRoutes);
app.use('/api/billing',      apiLimiter,    billingRoutes);

// Gumroad webhook alias — matches the URL configured in Gumroad Ping settings
// Accepts both /api/billing/gumroad-webhook and /api/webhooks/gumroad
app.post('/api/webhooks/gumroad', express.urlencoded({ extended: true }), (req, res, next) => {
  // Rewrite to billing route and forward
  req.url = '/gumroad-webhook' + (req._parsedUrl?.search || '');
  billingRoutes(req, res, next);
});

// Settings route
try {
  const settingsRoutes = require('./routes/settings');
  app.use('/api/settings', settingsRoutes);
} catch(e) { /* optional */ }

app.use('/api/internal', internalRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), version: require('../package.json').version });
});

// GET /api/health-deep — supervisor-only endpoint, requires SUPERVISOR_SECRET header
app.get('/api/health-deep', (req, res) => {
  const secret = process.env.SUPERVISOR_SECRET;
  if (secret && req.headers['x-supervisor-secret'] !== secret) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const autoRem = require('./services/autoRemediationService');
    const remStats = autoRem.getRunStats();
    const tenantCount = (() => {
      try { return tenantRegistry.getAllTenantIds().length; } catch { return null; }
    })();
    res.json({
      status:      'ok',
      timestamp:   new Date().toISOString(),
      version:     require('../package.json').version,
      tenantCount,
      autoRemediation: {
        enabled:            autoRem.isEnabled(),
        lastRunAt:          remStats.lastRunAt,
        runsLast24h:        remStats.runsLast24h,
        failedLast24h:      remStats.failedLast24h,
        successLast24h:     remStats.successLast24h,
        recentErrors:       remStats.recentErrors,
        recentFailedActions: remStats.recentFailedActions,
      },
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// GET /api/posture — Composite security posture score for the current tenant
app.get('/api/posture', (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

    const { calculatePostureScore } = require('./services/postureScore');
    const tenantHealth = tenantRegistry.getTenantHealth(tenantId);
    const onboarding   = tenantRegistry.getOnboarding(tenantId);
    const settings     = require('./services/settingsService').getSettings(tenantId);

    // Calculate posture score (pimData can be null — will default to 50)
    const posture = calculatePostureScore(tenantId, tenantHealth, null);

    res.json({
      ...posture,
      tenant: {
        tenantId,
        tenantName: req.session.tenant.tenantName,
        onboarding: {
          connected:          true,
          permissionsGranted: onboarding.permissionsGranted || !!tenantHealth.graphPermissionsOk,
          firstScanDone:      onboarding.firstScanDone      || !!tenantHealth.lastSuccessfulScan,
          alertChannelTested: onboarding.alertChannelTested || !!tenantHealth.mailDeliveryOk,
          webhookActive:      onboarding.webhookActive      || !!tenantHealth.webhookActive,
          workHoursSet:       onboarding.workHoursSet       || !!(Array.isArray(settings.businessHours) ? settings.businessHours.some(h => h.enabled) : settings.businessHours?.startHour != null)
        },
        health: {
          graphPermissionsOk:   tenantHealth.graphPermissionsOk  ?? null,
          signInLogsAvailable:  tenantHealth.signInLogsAvailable ?? null,
          webhookActive:        tenantHealth.webhookActive        ?? false,
          webhookExpiresAt:     tenantHealth.webhookExpiresAt     || null,
          lastSuccessfulScan:   tenantHealth.lastSuccessfulScan   || null,
          lastScanAlertCount:   tenantHealth.lastScanAlertCount   || 0,
          baselineBuilt:        tenantHealth.baselineBuilt        ?? false,
          privilegedUserCount:  tenantHealth.privilegedUserCount  || 0,
          mailDeliveryOk:       tenantHealth.mailDeliveryOk       ?? null,
          telegramOk:           tenantHealth.telegramOk           ?? null,
        }
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// /health alias — must come BEFORE static files so SPA catch-all doesn't intercept it
app.get('/health', (req, res) => res.redirect(307, '/api/health'));

// Serve React frontend
const publicDir = path.join(__dirname, '..', 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
    res.sendFile(path.join(publicDir, 'index.html'));
  });
  console.log('[Static] Serving frontend from /public');
}

// WebSocket — attach to same HTTP server
wsService.init(server);

// ─── Startup Tasks ────────────────────────────────────────────────────────
async function startup() {
  // Init Azure Table Storage
  if (process.env.AZURE_STORAGE_CONNECTION_STRING) {
    try {
      await tableStorage.initTables();
      console.log('[Storage] Azure Table Storage initialized');
    } catch (err) {
      console.error('[Storage] Init failed:', err.message);
    }
  } else {
    console.warn('[Storage] AZURE_STORAGE_CONNECTION_STRING not set — using in-memory store');
  }

  // Startup Telegram message intentionally removed — Azure restarts triggered too many notifications.

  // Load alerts from Azure Tables into memory
  try {
    const tenantIds = tenantRegistry.getAllTenantIds();
    for (const tenantId of tenantIds) {
      await alertsStore.loadFromAzure(tenantId);
      await workflowStore.warmCache(tenantId);
      await auditLog.warmCache(tenantId);
    }
  } catch (err) {
    console.warn('[Startup] warmCache error:', err.message);
  }

  // Start background job runner (anomaly scans, webhook renewal, weekly digests)
  if (!MOCK) jobRunner.init();

  // Start auto-remediation cron (runs only if AUTO_REMEDIATION_ENABLED=true)
  autoRemediationService.start();
}

// ─── Scheduled Jobs ───────────────────────────────────────────────────────
if (!MOCK) {
  // Workflow/SLA automation sweep — every 15 min
  cron.schedule('*/15 * * * *', async () => {
    try {
      const results = automationService.runAutomationSweep();
      console.log('[CRON] Automation summary:', JSON.stringify(results));
    } catch (err) {
      console.error('[CRON] Automation failed:', err.message);
    }
  });

  // Device action monitor — check Intune for wipe/delete/reset every 5 minutes
  cron.schedule('*/5 * * * *', async () => {
    try {
      await deviceActionMonitor.runDeviceActionCheck();
    } catch (err) {
      console.error('[CRON] Device action monitor failed:', err.message);
    }
  });

  // Anomaly detection + alert notifications + webhooks + weekly digests
  // are all owned by jobRunner (initialized in startup)
}

server.listen(PORT, async () => {
  console.log('\n  ⬡ Privileged Identity Monitor v2.0');
  console.log('  Mode:     ' + (MOCK ? '🟡 MOCK' : '🟢 LIVE'));
  console.log('  Port:     ' + PORT);
  console.log('  Webhooks: ' + (process.env.WEBHOOK_NOTIFICATION_URL ? '✅ ' + process.env.WEBHOOK_NOTIFICATION_URL : '❌ Not configured'));
  console.log('  Telegram: ' + (process.env.TELEGRAM_BOT_TOKEN ? '✅ Configured' : '❌ Not configured'));
  console.log('  Storage:  ' + (process.env.AZURE_STORAGE_CONNECTION_STRING ? '✅ Azure Tables' : '⚠️  In-memory'));
  console.log('  WS:       ✅ ws://localhost:' + PORT + '/ws\n');
  await startup();
});
