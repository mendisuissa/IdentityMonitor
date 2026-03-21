// mockData.js — realistic mock data for demo / testing
// Activated when MOCK_MODE=true in .env

const MOCK_USERS = [
  {
    id: 'mock-user-001',
    displayName: 'Alex Johnson',
    userPrincipalName: 'alex.johnson@contoso.com',
    mail: 'alex.johnson@contoso.com',
    accountEnabled: true,
    roles: ['Global Administrator'],
    alertCount: 2,
    riskLevel: 'critical'
  },
  {
    id: 'mock-user-002',
    displayName: 'Sarah Mitchell',
    userPrincipalName: 'sarah.mitchell@contoso.com',
    mail: 'sarah.mitchell@contoso.com',
    accountEnabled: true,
    roles: ['Intune Administrator', 'Cloud Device Administrator'],
    alertCount: 1,
    riskLevel: 'high'
  },
  {
    id: 'mock-user-003',
    displayName: 'David Chen',
    userPrincipalName: 'david.chen@contoso.com',
    mail: 'david.chen@contoso.com',
    accountEnabled: true,
    roles: ['Global Administrator', 'Privileged Role Administrator'],
    alertCount: 0,
    riskLevel: 'clean'
  },
  {
    id: 'mock-user-004',
    displayName: 'Emma Torres',
    userPrincipalName: 'emma.torres@contoso.com',
    mail: 'emma.torres@contoso.com',
    accountEnabled: true,
    roles: ['Intune Administrator'],
    alertCount: 1,
    riskLevel: 'medium'
  },
  {
    id: 'mock-user-005',
    displayName: 'James Wilson',
    userPrincipalName: 'james.wilson@contoso.com',
    mail: 'james.wilson@contoso.com',
    accountEnabled: false,
    roles: ['Global Administrator'],
    alertCount: 0,
    riskLevel: 'clean'
  }
];

function randomPast(hoursAgo) {
  return new Date(Date.now() - hoursAgo * 3600000).toISOString();
}

const MOCK_SIGN_INS = [
  {
    id: 'signin-001',
    createdDateTime: randomPast(0.5),
    userDisplayName: 'Alex Johnson',
    userPrincipalName: 'alex.johnson@contoso.com',
    userId: 'mock-user-001',
    ipAddress: '185.220.101.45',
    location: { city: 'Moscow', countryOrRegion: 'Russia', geoCoordinates: { latitude: 55.75, longitude: 37.61 } },
    deviceDetail: { deviceId: 'unknown-device-xyz', displayName: 'Unknown-PC', operatingSystem: 'Windows 11', browser: 'Chrome' },
    status: { errorCode: 0 },
    appDisplayName: 'Microsoft Azure Portal',
    riskLevelAggregated: 'high'
  },
  {
    id: 'signin-002',
    createdDateTime: randomPast(1),
    userDisplayName: 'Alex Johnson',
    userPrincipalName: 'alex.johnson@contoso.com',
    userId: 'mock-user-001',
    ipAddress: '192.168.1.100',
    location: { city: 'Tel Aviv', countryOrRegion: 'Israel', geoCoordinates: { latitude: 32.08, longitude: 34.78 } },
    deviceDetail: { deviceId: 'device-aad-001', displayName: 'ALEX-LAPTOP', operatingSystem: 'Windows 11', browser: 'Edge' },
    status: { errorCode: 0 },
    appDisplayName: 'Microsoft Intune',
    riskLevelAggregated: 'none'
  },
  {
    id: 'signin-003',
    createdDateTime: randomPast(2),
    userDisplayName: 'Sarah Mitchell',
    userPrincipalName: 'sarah.mitchell@contoso.com',
    userId: 'mock-user-002',
    ipAddress: '203.0.113.88',
    location: { city: 'Singapore', countryOrRegion: 'Singapore', geoCoordinates: { latitude: 1.35, longitude: 103.82 } },
    deviceDetail: { deviceId: 'device-aad-002', displayName: 'SARAH-WORKSTATION', operatingSystem: 'macOS', browser: 'Safari' },
    status: { errorCode: 0 },
    appDisplayName: 'Microsoft 365 Admin Center',
    riskLevelAggregated: 'medium'
  },
  {
    id: 'signin-004',
    createdDateTime: randomPast(3),
    userDisplayName: 'David Chen',
    userPrincipalName: 'david.chen@contoso.com',
    userId: 'mock-user-003',
    ipAddress: '10.0.0.45',
    location: { city: 'New York', countryOrRegion: 'United States', geoCoordinates: { latitude: 40.71, longitude: -74.00 } },
    deviceDetail: { deviceId: 'device-aad-003', displayName: 'DAVID-SURFACE', operatingSystem: 'Windows 11', browser: 'Edge' },
    status: { errorCode: 0 },
    appDisplayName: 'Microsoft Entra ID',
    riskLevelAggregated: 'none'
  },
  {
    id: 'signin-005',
    createdDateTime: randomPast(4),
    userDisplayName: 'Emma Torres',
    userPrincipalName: 'emma.torres@contoso.com',
    userId: 'mock-user-004',
    ipAddress: '198.51.100.12',
    location: { city: 'London', countryOrRegion: 'United Kingdom', geoCoordinates: { latitude: 51.51, longitude: -0.13 } },
    deviceDetail: { deviceId: 'new-device-444', displayName: null, operatingSystem: 'iOS', browser: 'Mobile Safari' },
    status: { errorCode: 0 },
    appDisplayName: 'Microsoft Intune',
    riskLevelAggregated: 'none'
  },
  {
    id: 'signin-006',
    createdDateTime: randomPast(5),
    userDisplayName: 'Alex Johnson',
    userPrincipalName: 'alex.johnson@contoso.com',
    userId: 'mock-user-001',
    ipAddress: '192.168.1.100',
    location: { city: 'Tel Aviv', countryOrRegion: 'Israel', geoCoordinates: { latitude: 32.08, longitude: 34.78 } },
    deviceDetail: { deviceId: 'device-aad-001', displayName: 'ALEX-LAPTOP', operatingSystem: 'Windows 11', browser: 'Edge' },
    status: { errorCode: 50126, failureReason: 'Invalid username or password' },
    appDisplayName: 'Azure Portal',
    riskLevelAggregated: 'none'
  },
  {
    id: 'signin-007',
    createdDateTime: randomPast(0.3),
    userDisplayName: 'Alex Johnson',
    userPrincipalName: 'alex.johnson@contoso.com',
    userId: 'mock-user-001',
    ipAddress: '103.21.244.0',
    location: { city: 'Tokyo', countryOrRegion: 'Japan', geoCoordinates: { latitude: 35.68, longitude: 139.69 } },
    deviceDetail: { deviceId: 'unknown-device-jp', displayName: 'Unknown', operatingSystem: 'Windows 10', browser: 'Chrome' },
    status: { errorCode: 0 },
    appDisplayName: 'Azure Portal',
    riskLevelAggregated: 'high'
  }
];

function getMockAlerts() {
  const now = Date.now();
  return [
    {
      id: 'alert-impossible-travel-001',
      userId: 'mock-user-001',
      userDisplayName: 'Alex Johnson',
      userPrincipalName: 'alex.johnson@contoso.com',
      roles: ['Global Administrator'],
      signInId: 'signin-007',
      signInTime: new Date(now - 0.3 * 3600000).toISOString(),
      ipAddress: '103.21.244.0',
      country: 'Japan',
      city: 'Tokyo',
      deviceName: 'Unknown',
      deviceOs: 'Windows 10',
      appName: 'Azure Portal',
      anomalyType: 'IMPOSSIBLE_TRAVEL',
      anomalyLabel: 'Impossible Travel',
      severity: 'critical',
      detail: '9,200 km in 0.7 hours — physically impossible (Tel Aviv → Tokyo)',
      status: 'open',
      detectedAt: new Date(now - 18 * 60000).toISOString(),
      actionsTriggered: [
        { action: 'admin_email_sent', timestamp: new Date(now - 18 * 60000).toISOString() },
        { action: 'sessions_revoked', timestamp: new Date(now - 17 * 60000).toISOString() },
        { action: 'user_notified', timestamp: new Date(now - 17 * 60000).toISOString() }
      ]
    },
    {
      id: 'alert-new-country-001',
      userId: 'mock-user-001',
      userDisplayName: 'Alex Johnson',
      userPrincipalName: 'alex.johnson@contoso.com',
      roles: ['Global Administrator'],
      signInId: 'signin-001',
      signInTime: new Date(now - 0.5 * 3600000).toISOString(),
      ipAddress: '185.220.101.45',
      country: 'Russia',
      city: 'Moscow',
      deviceName: 'Unknown-PC',
      deviceOs: 'Windows 11',
      appName: 'Microsoft Azure Portal',
      anomalyType: 'NEW_COUNTRY',
      anomalyLabel: 'New Country Detected',
      severity: 'high',
      detail: 'Sign-in from new country: Russia',
      status: 'open',
      detectedAt: new Date(now - 30 * 60000).toISOString(),
      actionsTriggered: [
        { action: 'admin_email_sent', timestamp: new Date(now - 30 * 60000).toISOString() },
        { action: 'sessions_revoked', timestamp: new Date(now - 29 * 60000).toISOString() }
      ]
    },
    {
      id: 'alert-new-country-002',
      userId: 'mock-user-002',
      userDisplayName: 'Sarah Mitchell',
      userPrincipalName: 'sarah.mitchell@contoso.com',
      roles: ['Intune Administrator', 'Cloud Device Administrator'],
      signInId: 'signin-003',
      signInTime: new Date(now - 2 * 3600000).toISOString(),
      ipAddress: '203.0.113.88',
      country: 'Singapore',
      city: 'Singapore',
      deviceName: 'SARAH-WORKSTATION',
      deviceOs: 'macOS',
      appName: 'Microsoft 365 Admin Center',
      anomalyType: 'NEW_COUNTRY',
      anomalyLabel: 'New Country Detected',
      severity: 'high',
      detail: 'Sign-in from new country: Singapore',
      status: 'open',
      detectedAt: new Date(now - 2 * 3600000).toISOString(),
      actionsTriggered: [
        { action: 'admin_email_sent', timestamp: new Date(now - 2 * 3600000).toISOString() }
      ]
    },
    {
      id: 'alert-unknown-device-004',
      userId: 'mock-user-004',
      userDisplayName: 'Emma Torres',
      userPrincipalName: 'emma.torres@contoso.com',
      roles: ['Intune Administrator'],
      signInId: 'signin-005',
      signInTime: new Date(now - 4 * 3600000).toISOString(),
      ipAddress: '198.51.100.12',
      country: 'United Kingdom',
      city: 'London',
      deviceName: null,
      deviceOs: 'iOS',
      appName: 'Microsoft Intune',
      anomalyType: 'UNKNOWN_DEVICE',
      anomalyLabel: 'Unrecognized Device',
      severity: 'medium',
      detail: 'Unrecognized device: unknown iOS device',
      status: 'open',
      detectedAt: new Date(now - 4 * 3600000).toISOString(),
      actionsTriggered: [
        { action: 'admin_email_sent', timestamp: new Date(now - 4 * 3600000).toISOString() }
      ]
    }
  ];
}

function getMockStats(alerts) {
  const open = alerts.filter(a => a.status === 'open');
  return {
    total: alerts.length,
    open: open.length,
    critical: open.filter(a => a.severity === 'critical').length,
    high: open.filter(a => a.severity === 'high').length,
    medium: open.filter(a => a.severity === 'medium').length,
    low: open.filter(a => a.severity === 'low').length,
    resolvedToday: alerts.filter(a => a.status === 'resolved').length
  };
}

module.exports = { MOCK_USERS, MOCK_SIGN_INS, getMockAlerts, getMockStats };
