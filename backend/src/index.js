require('dotenv').config();
require('isomorphic-fetch');

const express = require('express');
const http    = require('http');
const cors    = require('cors');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
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

const anomalyService  = require('./services/anomalyService');
const wsService       = require('./services/wsService');
const jobRunner       = require('./services/jobRunner');
const tableStorage    = require('./services/tableStorage');
const webhookService  = require('./services/webhookService');
const telegramService = require('./services/telegramService');
const automationService = require('./services/automationService');
const deviceActionMonitor = require('./services/deviceActionMonitor');
const tenantRegistry = require('./services/tenantRegistry');
const defenderVulnerabilityRoutes = require('./routes/defenderVulnerabilities');
const mspRoutes = require('./routes/msp');
const identityRoutes = require('./routes/identity');
const superadminRoutes = require('./routes/superadmin');
const billingRoutes    = require('./routes/billing');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 3001;
const MOCK   = process.env.MOCK_MODE === 'true';

app.set('trust proxy', 1);
app.use(express.json());
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
  store: new FileStore({ path: sessionDir, ttl: SESSION_TTL_SEC, retries: 1, logFn: () => {} }),
  secret: process.env.SESSION_SECRET || 'priv-monitor-dev-secret',
  resave: false,
  saveUninitialized: false,
  rolling: true, // extend session on every request — keeps active users logged in
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   SESSION_TTL_SEC * 1000,
    sameSite: 'lax'
  }
}));

// API Routes
app.use('/api/auth',    authRoutes);
app.use('/api/users',   usersRoutes);
app.use('/api/signins', signinsRoutes);
app.use('/api/alerts',  alertsRoutes);
app.use('/api/mock',    mockRoutes);
app.use('/api/webhook', webhookRoutes);
app.use('/api/pim',     pimRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/tenant',  tenantRoutes);
app.use('/api/remediation', remediationRouter);
app.use('/api/audit',     auditRoutes);
app.use('/api/device-actions', deviceActionsRoutes);
app.use('/api/defender',  defenderVulnerabilityRoutes);
app.use('/api/msp',       mspRoutes);
app.use('/api/identity',  identityRoutes);
app.use('/api/superadmin', superadminRoutes);
app.use('/api/billing',   billingRoutes);

// Settings route
try {
  const settingsRoutes = require('./routes/settings');
  app.use('/api/settings', settingsRoutes);
} catch(e) { /* optional */ }

app.get('/api/health', (req, res) => {
  res.json({
    status:        'ok',
    timestamp:     new Date().toISOString(),
    mockMode:      MOCK,
    version:       '2.0.0',
    activeTenants: tenantRegistry.getActiveTenants().length,
    features:      { webhooks: !!process.env.WEBHOOK_NOTIFICATION_URL, telegram: !!process.env.TELEGRAM_BOT_TOKEN, tableStorage: !!process.env.AZURE_STORAGE_CONNECTION_STRING }
  });
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
          workHoursSet:       onboarding.workHoursSet       || !!(settings.businessHours?.some(h => h.enabled))
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

  // Telegram startup message
  if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    try {
      await telegramService.sendMessage('🟢 *Privileged Identity Monitor* started\nMode: ' + (MOCK ? 'MOCK' : 'LIVE'));
    } catch (err) { /* ignore */ }
  }

  // Load alerts from Azure Tables into memory
  try {
    const tenantIds = tenantRegistry.getAllTenantIds();
    for (const tenantId of tenantIds) {
      await alertsStore.loadFromAzure(tenantId);
      await workflowStore.warmCache(tenantId);
    }
  } catch (err) {
    console.warn('[Startup] warmCache error:', err.message);
  }

  // Start background job runner (anomaly scans, webhook renewal, weekly digests)
  if (!MOCK) jobRunner.init();
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
