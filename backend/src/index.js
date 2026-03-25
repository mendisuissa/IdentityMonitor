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
const tableStorage    = require('./services/tableStorage');
const webhookService  = require('./services/webhookService');
const telegramService = require('./services/telegramService');
const automationService = require('./services/automationService');
const tenantRegistry = require('./services/tenantRegistry');
const defenderVulnerabilityRoutes = require('./routes/defenderVulnerabilities');
const auditRoutes = require('./routes/audit');

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

app.use(session({
  store: new FileStore({ path: sessionDir, ttl: 28800, retries: 1, logFn: () => {} }),
  secret: process.env.SESSION_SECRET || 'priv-monitor-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   8 * 60 * 60 * 1000,
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
app.use('/api/defender', defenderVulnerabilityRoutes);
app.use('/api/audit',   auditRoutes);

// Settings route
try {
  const settingsRoutes = require('./routes/settings');
  app.use('/api/settings', settingsRoutes);
} catch(e) { /* optional */ }

app.get('/api/health', (req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    mockMode:  MOCK,
    version:   '2.0.0',
    features:  { webhooks: !!process.env.WEBHOOK_NOTIFICATION_URL, telegram: !!process.env.TELEGRAM_BOT_TOKEN, tableStorage: !!process.env.AZURE_STORAGE_CONNECTION_STRING }
  });
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
}

// ─── Scheduled Jobs ───────────────────────────────────────────────────────
if (!MOCK) {
  // Scan every 15 min (fallback for tenants without webhooks)
  cron.schedule('*/15 * * * *', async () => {
    console.log('[CRON] Running scheduled automation sweep...');
    try {
      const results = automationService.runAutomationSweep();
      console.log('[CRON] Automation summary:', JSON.stringify(results));
    } catch (err) {
      console.error('[CRON] Automation failed:', err.message);
    }
  });

  // Weekly digest — every Sunday at 8am
  cron.schedule('0 8 * * 0', async () => {
    console.log('[CRON] Sending weekly security digests...');
    try {
      const tenantIds = tenantRegistry.getAllTenantIds();
      for (const tenantId of tenantIds) {
        await weeklyDigest.generateAndSend(tenantId);
      }
    } catch (err) {
      console.error('[CRON] Weekly digest failed:', err.message);
    }
  });

  // Renew webhook subscriptions daily at 3am
  cron.schedule('0 3 * * *', async () => {
    console.log('[CRON] Renewing webhook subscriptions...');
    try {
      await webhookService.renewAllExpiring(tenantRegistry.getAllTenantIds());
    } catch (err) {
      console.error('[CRON] Webhook renewal failed:', err.message);
    }
  });
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
