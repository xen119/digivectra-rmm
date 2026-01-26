const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const WebSocket = require('ws');
const archiver = require('archiver');

const CERT_DIR = path.join(__dirname, 'certs');
const PORT = process.env.PORT ? Number(process.env.PORT) : 8443;
const USERS_CONFIG_PATH = path.join(__dirname, 'config', 'users.json');
const AGENT_DOWNLOAD_DIR = process.env.AGENT_DOWNLOAD_DIR
  ? path.resolve(process.env.AGENT_DOWNLOAD_DIR)
  : path.join(__dirname, '..', 'AgentPublished');
const AGENT_BUILD_FALLBACK_DIR = path.join(__dirname, '..', 'Agent', 'bin', 'Debug', 'net8.0-windows');

const certPath = path.join(CERT_DIR, 'server.crt');
const keyPath = path.join(CERT_DIR, 'server.key');

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.error('TLS certificate not found.');
  console.error(`Place server.crt and server.key in ${CERT_DIR}`);
  process.exit(1);
}

const PUBLIC_DIR = path.join(__dirname, 'public');
const server = https.createServer({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
});

const DEFAULT_GROUP = 'Ungrouped';
const DATA_DIR = path.join(__dirname, 'data');
const MONITORING_CONFIG_PATH = path.join(DATA_DIR, 'monitoring.json');
const FIREWALL_BASELINE_PATH = path.join(DATA_DIR, 'firewall-baseline.json');
const NAVIGATION_CONFIG_PATH = path.join(DATA_DIR, 'navigation.json');
const GROUPS_CONFIG_PATH = path.join(DATA_DIR, 'groups.json');
const AGENT_GROUP_ASSIGNMENTS_PATH = path.join(DATA_DIR, 'agent-groups.json');
const LICENSES_PATH = path.join(DATA_DIR, 'licenses.json');
const GENERAL_SETTINGS_PATH = path.join(DATA_DIR, 'settings.json');
const SNMP_SETTINGS_PATH = path.join(DATA_DIR, 'snmp-settings.json');
const SNMP_DISCOVERY_LOG_PATH = path.join(DATA_DIR, 'snmp-discoveries.json');
const SNMP_DISCOVERY_LOG_LIMIT = 200;
const NETWORK_SCANNER_LOG_PATH = path.join(DATA_DIR, 'network-scans.json');
const NETWORK_SCANNER_LOG_LIMIT = 200;
const SNMP_HISTORY_FILENAME = 'snmp-discoveries.json';
const NETWORK_HISTORY_FILENAME = 'network-scans.json';
const DEFAULT_TENANT_ID = 'default';
const DEFAULT_TENANT = {
  id: DEFAULT_TENANT_ID,
  name: 'Default tenant',
  description: 'Global default tenant',
  domains: ['localhost', '127.0.0.1', '::1'],
};
const TENANTS_CONFIG_PATH = path.join(DATA_DIR, 'tenants.json');
const TENANT_DATA_ROOT = path.join(DATA_DIR, 'tenants');
const GLOBAL_TENANT_ID = 'global';
const VULNERABILITY_CONFIG_PATH = path.join(__dirname, 'config', 'vulnerability.json');
const VULNERABILITY_STORE_PATH = path.join(DATA_DIR, 'vulnerabilities.json');
const vulnerabilityIngestionJobs = new Map(); // sourceId -> { timer }
const VULNERABILITY_SOURCE_IMPLEMENTATIONS = {};
const DEFAULT_VULNERABILITY_SOURCE_DEFINITIONS = [
  {
    id: 'nvd',
    label: 'NVD (National Vulnerability Database)',
    description: 'Normalized CVEs collected from NVD.',
    type: 'nvd',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    ingestionMinutes: 1440,
    builtin: true,
  },
  {
    id: 'kev',
    label: 'KEV (Known Exploited Vulnerabilities)',
    description: 'CISA KEV catalog for actively exploited CVEs.',
    type: 'kev',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    ingestionMinutes: 1440,
    builtin: true,
  },
  {
    id: 'epss',
    label: 'EPSS (Exploit Prediction Scoring System)',
    description: 'First.org EPSS probability scores.',
    type: 'epss',
    url: 'https://api.first.org/data/v1/epss',
    ingestionMinutes: 60,
    builtin: true,
  },
];
const VALID_USER_ROLES = new Set(['viewer', 'operator', 'admin']);
const clients = new Map(); // socket -> info
const agents = new Map(); // id -> info (persist offline)
const clientsById = new Map(); // id -> { socket, info }
const shellStreams = new Map(); // id -> response
const shellOutputHistory = new Map(); // agentId -> [{ stream, timestamp, output }]
const SHELL_HISTORY_LIMIT = 200;
const screenSessions = new Map(); // sessionId -> session data
const groups = loadGroups();
const agentGroupAssignments = loadAgentGroupAssignments(groups);
const snmpDiscoverySettings = loadSnmpDiscoverySettings();
let tenants = loadTenants();
const tenantIndex = new Map();

function refreshTenantIndex() {
  tenantIndex.clear();
  for (const entry of tenants) {
    tenantIndex.set(entry.id, entry);
  }
  tenantIndex.set(GLOBAL_TENANT_ID, {
    id: GLOBAL_TENANT_ID,
    name: 'Global tenant',
    description: 'Global administrators have access to all tenants.',
    domains: [],
  });
}

refreshTenantIndex();
const licenseRecords = loadLicenses();
const licenseIndex = new Map(licenseRecords.map((entry) => [entry.code, entry]));
const screenLists = new Map(); // agentId -> { screens, updatedAt }
const screenListRequests = new Map(); // agentId -> { resolvers: [], timer }
const FILE_REQUEST_TIMEOUT_MS = 120_000;
const FILE_UPLOAD_CHUNK_BYTES = 256 * 1024;
const fileRequests = new Map(); // requestId -> { kind, agentId, resolve, reject, timer }
const SOFTWARE_REQUEST_TIMEOUT_MS = 60_000;
const softwareRequests = new Map(); // requestId -> { agentId, resolve, reject, timer }
const SERVICE_REQUEST_TIMEOUT_MS = 60_000;
const serviceRequests = new Map();
const patchApprovals = new Map(); // `${agentId}:${updateId}` -> { approvedAt }
const patchSchedules = new Map(); // scheduleId -> schedule data
const PATCH_SCHEDULE_TICK_MS = 5_000;
const PATCH_SCHEDULE_RETRY_MS = 15_000;
const patchHistory = [];
const PATCH_HISTORY_LIMIT = 200;
const PATCH_CATEGORY_ORDER = [
  'Security Updates',
  'Feature Updates',
  'Driver Updates',
  'Definition Updates',
  'Optional Updates',
  'Out-of-Band Updates',
  'Servicing Stack Updates',
  'Cumulative Updates',
  'Other Updates',
];
const MIN_SCREEN_SCALE = 0.35;
const MAX_SCREEN_SCALE = 1.0;
const DEFAULT_SCREEN_SCALE = 0.75;
const chatListeners = new Map(); // agentId -> Set<ServerResponse>
const chatHistories = new Map(); // agentId -> [{ sessionId, text, direction, agentName, timestamp }]
const chatNotificationCounts = new Map();
const CHAT_HISTORY_LIMIT = 200;
const agentChatLastTimestamp = new Map();
const snmpScanStreams = new Map(); // requestId -> { agentId, clients: Set<ServerResponse> }
const pendingSnmpScans = new Map(); // requestId -> { agentId, agentName, requestId, startedAt, devices: [] }
const snmpDiscoveryHistory = new Map();
const networkScannerStreams = new Map(); // requestId -> { agentId, clients: Set<ServerResponse> }
const pendingNetworkScannerScans = new Map(); // requestId -> { agentId, agentName, requestId, startedAt, devices: [] }
const networkScannerHistory = new Map();
const generalSettingsCache = new Map();
let generalSettings;

function dispatchSnmpEvent(agentId, requestId, eventName, payload) {
  captureSnmpEvent(agentId, requestId, eventName, payload);

  const entry = snmpScanStreams.get(requestId);
  if (!entry || entry.agentId !== agentId) {
    return;
  }

  const data = JSON.stringify(payload);
  for (const client of entry.clients) {
    client.write(`event: ${eventName}\n`);
    client.write(`data: ${data}\n\n`);
  }

  if (eventName === 'snmp-complete' || eventName === 'snmp-error') {
    snmpScanStreams.delete(requestId);
  }
}

function dispatchNetworkEvent(agentId, requestId, eventName, payload) {
  captureNetworkScannerEvent(agentId, requestId, eventName, payload);

  const entry = networkScannerStreams.get(requestId);
  if (!entry || entry.agentId !== agentId) {
    return;
  }

  const data = JSON.stringify(payload);
  for (const client of entry.clients) {
    client.write(`event: ${eventName}\n`);
    client.write(`data: ${data}\n\n`);
  }

  if (eventName === 'network-scanner-complete' || eventName === 'network-scanner-error') {
    networkScannerStreams.delete(requestId);
  }
}

const SCREEN_LIST_TTL_MS = 60_000;
const SCREEN_LIST_TIMEOUT_MS = 5_000;
const NAVIGATION_ITEMS = [
  {
    id: 'monitoring',
    label: 'Monitoring',
    href: 'monitoring.html',
    description: 'View active monitoring profiles, metrics, and alerts.',
  },
  {
    id: 'system-health',
    label: 'System Health',
    href: 'system-health.html',
    description: 'Review overall system health and diagnostics.',
  },
  {
    id: 'firewall-baseline',
    label: 'Firewall Baseline',
    href: 'firewall-baseline.html',
    description: 'Track baseline firewall policies and deviations.',
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    href: 'vulnerabilities.html',
    description: 'Browse the vulnerability catalog and CVE details.',
  },
  {
    id: 'patches',
    label: 'Patch Management',
    href: 'patches.html',
    description: 'Approve, schedule, and monitor Windows updates.',
  },
  {
    id: 'software-management',
    label: 'Software Inventory',
    href: 'software-management.html',
    description: 'Inspect software inventory, approvals, and actions.',
  },
  {
    id: 'snmp',
    label: 'SNMP Discovery',
    href: 'snmp.html',
    description: 'View recorded SNMP discovery results per agent.',
  },
  {
    id: 'network-scanner',
    label: 'Network Scanner',
    href: 'network.html',
    description: 'Scan the local subnets, resolve MAC addresses, and trigger Wake-on-LAN.',
  },
  {
    id: 'scripts',
    label: 'Scripts',
    href: 'scripts.html',
    description: 'Upload and execute remediation scripts.',
  },
  {
    id: 'scheduler',
    label: 'Scheduler',
    href: 'scheduler.html',
    description: 'Create recurring automation or patch campaigns.',
  },
  {
    id: 'ai-agent',
    label: 'AI Agent',
    href: 'ai-agent.html',
    description: 'Talk to an assistant that can review agents and take guided actions.',
  },
  {
    id: 'tenants',
    label: 'Tenants',
    href: 'tenants.html',
    description: 'Manage tenants, their domains, and metadata.',
  },
  {
    id: 'users',
    label: 'Users',
    href: 'users.html',
    description: 'Manage dashboard users, roles, and access.',
  },
  {
    id: 'compliance',
    label: 'Compliance',
    href: 'compliance.html',
    description: 'Track Windows security baselines and view compliance scores.',
  },
  {
    id: 'compliance-admin',
    label: 'Compliance Admin',
    href: 'compliance-admin.html',
    description: 'Edit compliance profiles and rule definitions.',
  },
  {
    id: 'gpo',
    label: 'GPO Management',
    href: 'gpo.html',
    description: 'Manage and deploy GPO templates to agents.',
  },
  {
    id: 'licenses',
    label: 'Licenses',
    href: 'licenses.html',
    description: 'Manage and revoke agent license keys.',
  },
];

const AI_HISTORY_PATH = path.join(DATA_DIR, 'ai-history.json');
const AI_HISTORY_LIMIT = 400;
const AI_SESSION_TTL_MS = 2 * 60 * 60_1000;
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';
const OPENAI_MODEL = process.env.OPENAI_MODEL ?? 'gpt-4o-mini';
const DEFAULT_AI_AGENT_SETTINGS = {
  systemPrompt:
    'You are the RMM operations assistant. Help administrators understand the fleet, surface risks, and take safe actions via the provided tools. Ask clarifying questions before acting, think step-by-step, and explain each outcome.',
  apiKey: null,
};
const DEFAULT_TECH_DIRECT_SETTINGS = {
  apiKey: null,
  apiSecret: null,
};
const AI_TOOL_INSTRUCTIONS = [
  'Use list_agents to review connected agents and their health.',
  'Use get_agent_details when you need historical context for a specific agent.',
  'Use assign_agent_group to move an agent between groups when an action is requested.',
  'Use get_agent_monitoring_history to surface recent monitoring events for the focal agent.',
  'Use get_agent_system_health to retrieve event statistics and log entries for that agent.',
  'Use get_agent_firewall_rules when you need to inspect what the endpoint firewall is doing.',
  'Use get_agent_vulnerabilities to see the latest vulnerability findings tied to the agent.',
  'Use get_agent_patch_history to understand which patch operations involved the agent.',
  'Use get_agent_software_inventory to review the agent’s reported applications.',
  'Use get_agent_scripts to list remediation scripts and any recent script activity for this agent.',
  'Use get_agent_compliance_report to read the assigned compliance profile and score for the agent.',
  'Use get_agent_license_info to confirm the license currently associated with the agent.',
  'Use run_agent_shell_command to execute shell commands and gather their output from the agent.',
  'Use get_agent_services and manage_agent_service to inspect and control Windows services on that agent.',
].join(' ');
const AI_TOOL_DEFINITIONS = [
  {
    name: 'list_agents',
    description: 'Return a short summary of agents that are connected to the platform.',
    parameters: {
      type: 'object',
      properties: {
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          description: 'Maximum number of agents to return.',
        },
      },
    },
  },
  {
    name: 'get_agent_details',
    description: 'Read detailed information about a single agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent to describe.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'assign_agent_group',
    description: 'Move an agent into a different group for targeting.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent to move.',
        },
        group: {
          type: 'string',
          description: 'Destination group name.',
        },
      },
      required: ['agent_id', 'group'],
    },
  },
  {
    name: 'get_agent_monitoring_history',
    description: 'Return recent monitoring events (alerts, script requests, remediation, etc.) for a single agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose monitoring history is requested.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          description: 'Maximum number of events to return (default 20).',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_system_health',
    description: 'Fetch the latest event statistics and log entries for a single agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose system health is requested.',
        },
        level: {
          type: 'string',
          enum: ['Information', 'Warning', 'Error'],
          description: 'Optional severity level for returned event entries.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_firewall_rules',
    description: 'Inspect the Windows firewall rules, profiles, and defaults configured on the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent to inspect.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_vulnerabilities',
    description: 'List vulnerability matches attributed to the agent including severity and affected component.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose vulnerabilities you need.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_patch_history',
    description: 'Review patch schedules or actions that were targeted at the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose patch history you need.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          description: 'Maximum number of patch events to return (default 20).',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_software_inventory',
    description: 'Gather the software inventory report that the agent recently sent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose software inventory is requested.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_scripts',
    description: 'List remediation scripts in the catalog plus the recent script activity for the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose script activity is requested.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 20,
          description: 'Maximum number of recent script events to return (default 5).',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_compliance_report',
    description: 'Retrieve the compliance profile, score, and results for the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose compliance report is requested.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'get_agent_license_info',
    description: 'Confirm which license key is assigned to that agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent whose license info is requested.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'run_agent_shell_command',
    description: 'Execute a shell command on the agent and collect the resulting output.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent to target.',
        },
        command: {
          type: 'string',
          description: 'The command string to execute.',
        },
        language: {
          type: 'string',
          enum: ['powershell', 'cmd'],
          description: 'The shell language to use (defaults to powershell).',
        },
      },
      required: ['agent_id', 'command'],
    },
  },
  {
    name: 'get_agent_services',
    description: 'List the Windows services running on the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent.',
        },
      },
      required: ['agent_id'],
    },
  },
  {
    name: 'manage_agent_service',
    description: 'Start, stop, or restart a specific service on the agent.',
    parameters: {
      type: 'object',
      properties: {
        agent_id: {
          type: 'string',
          description: 'Identifier of the agent.',
        },
        service_name: {
          type: 'string',
          description: 'Exact service name to manage.',
        },
        action: {
          type: 'string',
          enum: ['start', 'stop', 'restart'],
          description: 'Service action to perform.',
        },
      },
      required: ['agent_id', 'service_name', 'action'],
    },
  },
];
const AI_CONVERSATION_HISTORY_LIMIT = 20;
const AI_AGENT_SESSION_PREFIX = 'agent-chat:';
const AI_AGENT_USER = 'AI Assistant';
const AI_AGENT_ROLE = 'ai';
const AI_AGENT_RESPONSE_OPTIONS = {
  temperature: 0.3,
  max_tokens: 500,
};
const SNMP_AUTH_PROTOCOLS = ['SHA1', 'SHA256', 'SHA384', 'SHA512'];
const SNMP_PRIV_PROTOCOLS = ['DES', '3DES', 'AES', 'AES192', 'AES256'];
const SNMP_VERSION_KEYS = ['v1', 'v2c', 'v3'];
const DEFAULT_SNMP_VERSION = 'v3';

function createDefaultSnmpSettings() {
  return {
    v1: {
      port: 161,
      community: 'public',
      resolveNamesOnly: false,
    },
    v2c: {
      port: 161,
      community: 'public',
      resolveNamesOnly: false,
    },
    v3: {
      port: 161,
      username: '',
      authProtocol: 'SHA1',
      authPassword: '',
      privProtocol: 'AES',
      privPassword: '',
      resolveNamesOnly: false,
    },
  };
}

function sanitizeSnmpPort(value, fallback) {
  const candidate = Number(value);
  if (Number.isInteger(candidate) && candidate >= 1 && candidate <= 65535) {
    return candidate;
  }

  return fallback;
}

function pickSnmpProtocol(value, allowed, fallback) {
  if (typeof value !== 'string') {
    return fallback;
  }

  const normalized = value.trim().toUpperCase();
  return allowed.includes(normalized) ? normalized : fallback;
}

function normalizeSnmpVersionSettings(version, base, overrides) {
  const defaults = createDefaultSnmpSettings();
  const template = defaults[version] ?? {};
  const baseValues = (typeof base === 'object' && base !== null) ? base : {};
  const result = { ...template, ...baseValues };

  if (!overrides || typeof overrides !== 'object') {
    return result;
  }

  if ('port' in overrides) {
    result.port = sanitizeSnmpPort(overrides.port, result.port);
  }

  if (version === 'v1' || version === 'v2c') {
    if ('community' in overrides && typeof overrides.community === 'string') {
      result.community = overrides.community.trim();
    }
    if ('resolveNamesOnly' in overrides) {
      result.resolveNamesOnly = Boolean(overrides.resolveNamesOnly);
    }
  } else if (version === 'v3') {
    if ('username' in overrides && typeof overrides.username === 'string') {
      result.username = overrides.username.trim();
    }
    if ('authProtocol' in overrides) {
      result.authProtocol = pickSnmpProtocol(overrides.authProtocol, SNMP_AUTH_PROTOCOLS, result.authProtocol);
    }
    if ('authPassword' in overrides && typeof overrides.authPassword === 'string') {
      result.authPassword = overrides.authPassword;
    }
    if ('privProtocol' in overrides) {
      result.privProtocol = pickSnmpProtocol(overrides.privProtocol, SNMP_PRIV_PROTOCOLS, result.privProtocol);
    }
    if ('privPassword' in overrides && typeof overrides.privPassword === 'string') {
      result.privPassword = overrides.privPassword;
    }
    if ('resolveNamesOnly' in overrides) {
      result.resolveNamesOnly = Boolean(overrides.resolveNamesOnly);
    }
  }

  return result;
}

function mergeSnmpSettings(base = {}, overrides = {}) {
  const merged = {};
  let mutated = false;

  for (const version of SNMP_VERSION_KEYS) {
    const baseVersion = base[version];
    if (Object.prototype.hasOwnProperty.call(overrides, version)) {
      merged[version] = normalizeSnmpVersionSettings(version, baseVersion, overrides[version] ?? {});
      mutated = true;
    } else {
      merged[version] = normalizeSnmpVersionSettings(version, baseVersion, null);
    }
  }

  return mutated ? merged : null;
}

function buildSnmpResponse(snmp) {
  const source = (typeof snmp === 'object' && snmp !== null) ? snmp : createDefaultSnmpSettings();
  const defaults = createDefaultSnmpSettings();
  const payload = {};
  for (const version of SNMP_VERSION_KEYS) {
    payload[version] = {
      ...defaults[version],
      ...(source[version] ?? {}),
    };
  }
  return payload;
}

function getSnmpConfigForVersion(version, settings = generalSettings) {
  const normalized = typeof version === 'string' && version.trim()
    ? version.trim().toLowerCase()
    : 'v3';
  if (!SNMP_VERSION_KEYS.includes(normalized)) {
    return null;
  }

  const entry = (settings?.snmp?.[normalized] ?? createDefaultSnmpSettings()[normalized]) ?? null;
  if (!entry) {
    return null;
  }

  if (normalized === 'v3') {
    if (!entry.username) {
      return null;
    }

    return {
      username: entry.username,
      authProtocol: entry.authProtocol ?? 'SHA1',
      authPassword: entry.authPassword || null,
      privProtocol: entry.privProtocol ?? 'AES',
      privPassword: entry.privPassword || null,
      resolveNamesOnly: Boolean(entry.resolveNamesOnly),
      port: entry.port,
    };
  }

  return {
    community: entry.community ?? 'public',
    resolveNamesOnly: Boolean(entry.resolveNamesOnly),
    port: entry.port,
  };
}

const DEFAULT_GENERAL_SETTINGS = {
  screenConsentRequired: true,
  autoRespondToAgentChat: false,
  aiAgent: {
    ...DEFAULT_AI_AGENT_SETTINGS,
  },
  techDirect: {
    ...DEFAULT_TECH_DIRECT_SETTINGS,
  },
  snmp: createDefaultSnmpSettings(),
  snmpVersion: DEFAULT_SNMP_VERSION,
};
const TECH_DIRECT_WARRANTY_ENDPOINT = 'https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements';
const TECH_DIRECT_WARRANTY_TTL_MS = 6 * 60 * 60 * 1000;
const TECH_DIRECT_TOKEN_ENDPOINT = 'https://apigtwb2c.us.dell.com/auth/oauth/v2/token';
const TECH_DIRECT_TOKEN_MIN_TTL_MS = 60_000;
const techDirectTokenCache = new Map(); // tenantId -> { token, expiresAt }
generalSettings = loadGeneralSettings();
const aiHistory = loadAiHistory();
const aiConversations = new Map();

const DEFAULT_COMPLIANCE_CONFIG = {
  defaultProfileId: null,
  assignments: {},
  profiles: [],
};

const COMPLIANCE_CONFIG_PATH = path.join(DATA_DIR, 'compliance.json');
const complianceStatusByAgent = new Map();
let complianceConfig = loadComplianceConfig();
let complianceProfilesById = new Map();
const GPO_CONFIG_PATH = path.join(DATA_DIR, 'gpo-policies.json');
let gpoConfig = loadGpoConfig();
let gpoProfilesById = new Map();
refreshComplianceCache();
refreshGpoCache();
const SESSION_TTL_MS = 30 * 60_1000;
const SSO_SECRET = process.env.SSO_SECRET ?? 'CHANGE_ME-SSO-KEY';
const SSO_WINDOW_MS = 5 * 60_1000;
const REMEDIATION_DIR = path.join(__dirname, 'scripts', 'remediation');
const SOFTWARE_UNINSTALL_INTERVAL_MS = 60 * 60_1000;
const softwareApprovals = new Map(); // softwareId -> { state: 'approved'|'rejected'|'pending' }
const softwareUninstallQueue = new Map(); // softwareId -> { pending: Set<agentId>, lastAttempt: Map<agentId, timestamp> }
const softwareUninstallLog = [];
const SOFTWARE_UNINSTALL_LOG_LIMIT = 200;
const SERVICE_ACTION_TIMEOUT_MS = 30_000;
const serviceActionRequests = new Map();
const FIREWALL_REQUEST_TIMEOUT_MS = 30_000;
const firewallRequests = new Map();
const EVENT_STATS_TIMEOUT_MS = 30_000;
const EVENT_ENTRIES_TIMEOUT_MS = 30_000;
const eventStatsRequests = new Map();
const eventEntriesRequests = new Map();
const agentEventStatsCache = new Map();
const agentEventEntriesCache = new Map();

let USERS_CONFIG = loadUsersConfig();
const monitoringEvents = new Set();
const monitoringConfig = loadMonitoringConfig();
const firewallBaselines = loadFirewallBaselines();
const vulnerabilityConfig = loadVulnerabilityConfig();
ensureDefaultVulnerabilitySources();
const vulnerabilityStore = loadVulnerabilityStore();
const monitoringHistory = [];
const MONITORING_HISTORY_LIMIT = 100;
const agentMetrics = new Map(); // agentId -> [{ timestamp, cpuPercent?, ramPercent? }]
const alertStates = new Map(); // `${agentId}:${profileId}:${ruleId}` -> boolean
const agentAlertStatus = new Map(); // agentId -> boolean
const agentProfileStatus = new Map(); // agentId -> Map<profileId, boolean>
const sessions = new Map();
const roleWeight = { viewer: 0, operator: 1, admin: 2 };
const assetVulnerabilityCache = new Map();
const navigationVisibility = loadNavigationVisibility();

server.on('request', async (req, res) => {
  const requestedUrl = new URL(req.url ?? '/', `https://${req.headers.host ?? 'localhost'}`);
  const pathname = requestedUrl.pathname;

  if (pathname.startsWith('/auth/')) {
    handleAuthRoute(req, res, pathname, requestedUrl);
    return;
  }

  const chatReadMatch = pathname.match(/^\/chat\/([^/]+)\/read$/);
  if (chatReadMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = chatReadMatch[1];
    clearChatNotification(agentId);
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname === '/login.html' || pathname === '/login.js') {
    serveStaticAsset(req, res, pathname);
    return;
  }

  const session = getSessionFromRequest(req);
  if (!session) {
    respondUnauthorized(req, res);
    return;
  }

  req.userSession = session;

  if (pathname === '/clients' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const sessionUser = req.userSession?.user;
    const accessibleAgents = Array.from(agents.values())
      .filter((info) => sessionHasTenantAccess(sessionUser, info.tenantId ?? DEFAULT_TENANT_ID));
    const payload = accessibleAgents.map((info) => ({
      id: info.id,
      name: info.name,
      os: info.os,
      platform: info.platform,
      connectedAt: info.connectedAt,
      remoteAddress: info.remoteAddress,
      internalIp: info.internalIp ?? info.remoteAddress,
      externalIp: info.externalIp ?? info.remoteAddress,
      group: info.group ?? DEFAULT_GROUP,
      specs: info.specs ?? null,
      updatesSummary: info.updatesSummary ?? null,
      bsodSummary: info.bsodSummary ?? null,
      processSnapshot: info.processSnapshot ?? null,
      status: info.status ?? 'offline',
      lastSeen: info.lastSeen ?? null,
      loggedInUser: info.loggedInUser ?? null,
      pendingReboot: info.pendingReboot ?? false,
      monitoringEnabled: shouldMonitorAgent(info),
      monitoringAlert: agentAlertStatus.get(info.id) ?? false,
      monitoringProfiles: getAgentMonitoringProfiles(info),
      softwareSummary: info.softwareSummary ?? null,
      features: Array.isArray(info.features) ? info.features : [],
      snmpDiscoveryEnabled: isSnmpDiscoveryEnabled(info.id),
      bitlockerStatus: info.bitlockerStatus ?? null,
      avStatus: info.avStatus ?? null,
      warranty: info.warranty ?? null,
      chatNotifications: chatNotificationCounts.get(info.id) ?? 0,
      tenantId: info.tenantId ?? DEFAULT_TENANT_ID,
    }));
    return res.end(JSON.stringify(payload));
  }

  if (pathname === '/snmp/discoveries' && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const limitParam = Number(requestedUrl.searchParams.get('limit'));
    const agentFilter = requestedUrl.searchParams.get('agent')?.trim();
    const limit = Number.isFinite(limitParam) && limitParam > 0
      ? Math.min(limitParam, SNMP_DISCOVERY_LOG_LIMIT)
      : 50;

      const tenantId = getTenantIdForRequest(req);
      const tenantRecords = getSnmpHistoryForTenant(tenantId);
    const records = agentFilter
      ? tenantRecords.filter((record) => record.agentId === agentFilter)
      : tenantRecords;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ records: records.slice(0, limit) }));
  }

  if (pathname === '/snmp/discoveries/clear' && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const tenantId = getTenantIdForRequest(req);
    if (!clearSnmpDiscoveryHistory(tenantId)) {
      res.writeHead(500);
      return res.end('Unable to clear SNMP discovery history');
    }

    res.writeHead(204);
    return res.end();
  }

  if (pathname === '/network-scanner/discoveries' && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const limitParam = Number(requestedUrl.searchParams.get('limit'));
    const agentFilter = requestedUrl.searchParams.get('agent')?.trim();
    const limit = Number.isFinite(limitParam) && limitParam > 0
      ? Math.min(limitParam, NETWORK_SCANNER_LOG_LIMIT)
      : 50;

      const tenantId = getTenantIdForRequest(req);
      const tenantRecords = getNetworkHistoryForTenant(tenantId);
    const records = agentFilter
      ? tenantRecords.filter((record) => record.agentId === agentFilter)
      : tenantRecords;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ records: records.slice(0, limit) }));
  }

  if (pathname === '/network-scanner/discoveries/clear' && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const tenantId = getTenantIdForRequest(req);
    if (!clearNetworkScannerHistory(tenantId)) {
      res.writeHead(500);
      return res.end('Unable to clear network scanner history');
    }

    res.writeHead(204);
    return res.end();
  }

    if (pathname === '/snmp/defaults' && req.method === 'GET') {
      if (!ensureRole(req, res, 'viewer')) {
        return;
      }

      const tenantId = getTenantIdForRequest(req);
      const tenantSettings = getGeneralSettingsForTenant(tenantId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ snmp: buildSnmpResponse(tenantSettings.snmp) }));
    }

  if (pathname === '/groups' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ groups: Array.from(groups).sort() }));
    return;
  }

  if (pathname === '/groups' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const { name } = JSON.parse(body);
        const normalized = normalizeGroupName(name);
        if (!normalized) {
          res.writeHead(400);
          return res.end('Invalid group name');
        }

        groups.add(normalized);
        persistGroups();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ name: normalized }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/groups' && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    collectBody(req, (body) => {
      try {
        const { name } = JSON.parse(body);
        const normalized = normalizeGroupName(name);
        if (!normalized || normalized === DEFAULT_GROUP) {
          res.writeHead(400);
          return res.end('Invalid group name');
        }
        if (!groups.has(normalized)) {
          res.writeHead(404);
          return res.end('Group not found');
        }

        groups.delete(normalized);
        persistGroups();

        for (const entry of clientsById.values()) {
          if ((entry.info.group ?? DEFAULT_GROUP) === normalized) {
            entry.info.group = DEFAULT_GROUP;
          }
        }

        for (const [agentId, groupName] of agentGroupAssignments) {
          if (groupName === normalized) {
            agentGroupAssignments.set(agentId, DEFAULT_GROUP);
          }
        }

        persistAgentGroupAssignments();
        res.writeHead(204);
        res.end();
      } catch (error) {
        console.error('Failed to delete group', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/groups/assign' && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    collectBody(req, (body) => {
      try {
        const { agentId, group } = JSON.parse(body);
        const entry = clientsById.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const normalized = normalizeGroupName(group);
        const assignedGroup = assignAgentToGroup(agentId, normalized);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ group: assignedGroup }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const usersGetMatch = pathname === '/users' && req.method === 'GET';
  if (usersGetMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const requester = req.userSession?.user;
    const requestedTenant = requestedUrl.searchParams.get('tenantId')?.trim();
    const tenantId = requester?.isGlobal
      ? (requestedTenant || DEFAULT_TENANT_ID)
      : getSessionTenantId(requester);

    const payload = USERS_CONFIG.filter((entry) => {
      const entryTenant = typeof entry.tenantId === 'string' && entry.tenantId.trim()
        ? entry.tenantId.trim()
        : DEFAULT_TENANT_ID;
      if (requester?.isGlobal) {
        return entryTenant === tenantId;
      }
      return entryTenant === tenantId;
    }).map((entry) => ({
      username: entry.username,
      role: entry.role,
      totpSecret: entry.totpSecret,
      createdAt: entry.createdAt ?? null,
      tenantId: entry.tenantId ?? DEFAULT_TENANT_ID,
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ users: payload, tenantId }));
    return;
  }

  const usersCreateMatch = pathname === '/users' && req.method === 'POST';
  if (usersCreateMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, async (body) => {
      try {
        const data = JSON.parse(body);
        const username = (data.username ?? '').toString().trim();
        const password = (data.password ?? '').toString();
        const role = (data.role ?? 'viewer').toString().trim();
        const totpSecret = (data.totp ?? authenticator.generateSecret()).toString().trim();
        if (!username || !password || !role) {
          res.writeHead(400);
          return res.end('Username, password and role are required');
        }

        if (USERS_CONFIG.some((entry) => entry.username === username)) {
          res.writeHead(409);
          return res.end('Username already exists');
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const tenantId = resolveTenantForNewUser(req, data.tenantId);
        const newUser = {
          username,
          role,
          passwordHash,
          totpSecret,
          createdAt: Date.now(),
          tenantId,
        };
        USERS_CONFIG.push(newUser);
        persistUsersConfig();

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          username: newUser.username,
          role: newUser.role,
          totpSecret: newUser.totpSecret,
          createdAt: newUser.createdAt,
          tenantId: newUser.tenantId,
        }));
      } catch (error) {
        console.error('Unable to create user', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const licenseListMatch = pathname === '/licenses' && req.method === 'GET';
  if (licenseListMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const sessionUser = req.userSession?.user;
    const requestedTenantId = requestedUrl.searchParams.get('tenantId')?.trim() || '';
    const resolvedHostTenant = getTenantIdForRequest(req);
    const sessionTenant = getSessionTenantId(sessionUser);
    const tenantId = sessionUser?.isGlobal
      ? (requestedTenantId || resolvedHostTenant || DEFAULT_TENANT_ID)
      : sessionTenant;
    const records = licenseRecords
      .filter((entry) => {
        const entryTenant = typeof entry.tenantId === 'string' && entry.tenantId.trim()
          ? entry.tenantId.trim()
          : DEFAULT_TENANT_ID;
        return entryTenant === tenantId;
      });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      licenses: records.map((entry) => ({
        code: entry.code,
        assignedAgentId: entry.assignedAgentId ?? null,
        assignedAgentName: entry.assignedAgentId ? agents.get(entry.assignedAgentId)?.name ?? null : null,
        agentStatus: entry.assignedAgentId ? agents.get(entry.assignedAgentId)?.status ?? null : null,
        createdAt: entry.createdAt,
        assignedAt: entry.assignedAt,
        revokedAt: entry.revokedAt,
        lastUsedAt: entry.lastUsedAt,
        active: !entry.revokedAt,
        tenantId: entry.tenantId ?? DEFAULT_TENANT_ID,
      })),
      tenantId,
    }));
    return;
  }

  const licenseCreateMatch = pathname === '/licenses' && req.method === 'POST';
  if (licenseCreateMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const tenantId = getTenantIdForRequest(req);

    collectBody(req, (body) => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const tenantId = resolveLicenseTenant(req, payload?.tenantId);
        const record = {
          code: generateLicenseCode(),
          createdAt: new Date().toISOString(),
          revokedAt: null,
          lastUsedAt: null,
          tenantId,
        };
        licenseRecords.push(record);
        licenseIndex.set(record.code, record);
        persistLicenses();

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ license: record }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid license request');
      }
    });

    return;
  }

  const licenseRevokeMatch = pathname === '/licenses/revoke' && req.method === 'POST';
  if (licenseRevokeMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const code = typeof payload?.code === 'string' ? payload.code.trim() : '';
        if (!code) {
          res.writeHead(400);
          return res.end('License code is required');
        }

        const record = getLicenseRecord(code);
        if (!record) {
          res.writeHead(404);
          return res.end('License not found');
        }

        if (record.revokedAt) {
          res.writeHead(400);
          return res.end('License already revoked');
        }

        record.revokedAt = new Date().toISOString();
        persistLicenses();
        disconnectAgentsByLicense(code);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ license: record }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const licenseUnassignMatch = pathname === '/licenses/unassign' && req.method === 'POST';
  if (licenseUnassignMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const code = typeof payload?.code === 'string' ? payload.code.trim() : '';
        if (!code) {
          res.writeHead(400);
          return res.end('License code is required');
        }

        const record = getLicenseRecord(code);
        if (!record) {
          res.writeHead(404);
          return res.end('License not found');
        }

        if (!record.assignedAgentId) {
          res.writeHead(400);
          return res.end('License is not assigned to any agent');
        }

        notifyAgentLicenseUnassigned(code);
        unassignLicense(code);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ license: record }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const navigationSettingsMatch = pathname === '/settings/navigation';
  if (navigationSettingsMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ items: getNavigationPayload() }));
    return;
  }

  if (navigationSettingsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const updates = Array.isArray(payload.items) ? payload.items : [];
        updateNavigationVisibility(updates);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ items: getNavigationPayload() }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const generalSettingsMatch = pathname === '/settings/general';
    if (generalSettingsMatch && req.method === 'GET') {
      if (!ensureRole(req, res, 'admin')) {
        return;
      }

      const tenantId = getTenantIdForRequest(req);
      const tenantSettings = getGeneralSettingsForTenant(tenantId);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        screenConsentRequired: Boolean(tenantSettings?.screenConsentRequired !== false),
        autoRespondToAgentChat: Boolean(tenantSettings?.autoRespondToAgentChat),
        techDirectConfigured: Boolean(
          tenantSettings?.techDirect?.apiKey && tenantSettings?.techDirect?.apiSecret,
        ),
        snmp: buildSnmpResponse(tenantSettings?.snmp),
        snmpVersion: tenantSettings?.snmpVersion ?? DEFAULT_SNMP_VERSION,
      }));
      return;
    }

  if (generalSettingsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const tenantId = getTenantIdForRequest(req);
        const currentSettings = getGeneralSettingsForTenant(tenantId);
        const updates = {};
        if ('screenConsentRequired' in payload) {
          if (typeof payload.screenConsentRequired !== 'boolean') {
            res.writeHead(400);
            return res.end('screenConsentRequired must be true or false');
          }
          updates.screenConsentRequired = payload.screenConsentRequired;
        }
        if ('autoRespondToAgentChat' in payload) {
          if (typeof payload.autoRespondToAgentChat !== 'boolean') {
            res.writeHead(400);
            return res.end('autoRespondToAgentChat must be true or false');
          }
          updates.autoRespondToAgentChat = payload.autoRespondToAgentChat;
        }
        const techDirectUpdates = {};
        if ('techDirectApiKey' in payload) {
          const key = typeof payload.techDirectApiKey === 'string' ? payload.techDirectApiKey.trim() : '';
          techDirectUpdates.apiKey = key ? key : null;
        }
        if ('techDirectApiSecret' in payload) {
          const secret = typeof payload.techDirectApiSecret === 'string' ? payload.techDirectApiSecret.trim() : '';
          techDirectUpdates.apiSecret = secret ? secret : null;
        }
        const techDirectChanged = Object.keys(techDirectUpdates).length > 0;
        if (techDirectChanged) {
          const current = {
            ...DEFAULT_TECH_DIRECT_SETTINGS,
            ...(currentSettings.techDirect ?? {}),
          };
          updates.techDirect = {
            ...current,
            ...techDirectUpdates,
          };
        }
        if (Object.prototype.hasOwnProperty.call(payload, 'snmp')) {
          const snmpPayload = payload.snmp;
          if (snmpPayload && typeof snmpPayload === 'object') {
            const snmpUpdate = mergeSnmpSettings(currentSettings.snmp, snmpPayload);
            if (snmpUpdate) {
              updates.snmp = snmpUpdate;
            }
          }
        }
        if (Object.prototype.hasOwnProperty.call(payload, 'snmpVersion')) {
          const versionValue = typeof payload.snmpVersion === 'string'
            ? payload.snmpVersion.trim().toLowerCase()
            : '';
          if (!versionValue || !SNMP_VERSION_KEYS.includes(versionValue)) {
            res.writeHead(400);
            return res.end('Invalid SNMP version');
          }
          updates.snmpVersion = versionValue;
        }
        if (!Object.keys(updates).length) {
          res.writeHead(400);
          return res.end('No valid settings to update.');
        }

        const updatedSettings = {
          ...currentSettings,
          ...updates,
        };
        persistGeneralSettings(tenantId, updatedSettings);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          screenConsentRequired: Boolean(updatedSettings.screenConsentRequired !== false),
          autoRespondToAgentChat: Boolean(updatedSettings.autoRespondToAgentChat),
          techDirectConfigured: Boolean(
            updatedSettings?.techDirect?.apiKey && updatedSettings?.techDirect?.apiSecret,
          ),
          snmp: buildSnmpResponse(updatedSettings.snmp),
          snmpVersion: updatedSettings?.snmpVersion ?? DEFAULT_SNMP_VERSION,
        }));
        if (techDirectChanged) {
          clearTechDirectTokenCache(tenantId);
          void refreshDellWarrantyForAllAgents({ force: true });
        }
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

    const tenantInfoMatch = pathname === '/tenants/current';
    if (tenantInfoMatch && req.method === 'GET') {
      if (!ensureRole(req, res, 'viewer')) {
        return;
      }

  res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      tenant: getTenantPayload(req),
      isGlobal: Boolean(req.userSession?.user?.isGlobal),
    }));
    return;
  }

  const aiSettingsMatch = pathname === '/settings/ai';
    if (aiSettingsMatch && req.method === 'GET') {
      if (!ensureRole(req, res, 'admin')) {
        return;
      }

      const tenantId = getTenantIdForRequest(req);
      const tenantSettings = getGeneralSettingsForTenant(tenantId);

      const payload = {
        systemPrompt: tenantSettings.aiAgent?.systemPrompt ?? DEFAULT_AI_AGENT_SETTINGS.systemPrompt,
        apiKeyConfigured: Boolean(tenantSettings.aiAgent?.apiKey),
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }

    const tenantsListMatch = pathname === '/tenants' && req.method === 'GET';
    if (tenantsListMatch) {
      if (!ensureRole(req, res, 'admin')) {
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tenants }));
      return;
    }

    if (pathname === '/tenants' && req.method === 'POST') {
      if (!ensureRole(req, res, 'admin')) {
        return;
      }

      collectBody(req, (body) => {
        try {
          const payload = JSON.parse(body);
          const normalized = normalizeTenantPayload(payload);
          if (!normalized?.id) {
            res.writeHead(400);
            return res.end('Tenant id is required');
          }
          if (findTenantById(normalized.id)) {
            res.writeHead(409);
            return res.end('Tenant already exists');
          }

          const updated = [...tenants, normalized];
          if (!commitTenantList(updated)) {
            res.writeHead(500);
            return res.end('Unable to persist tenant');
          }

          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ tenant: normalized }));
        } catch (error) {
          res.writeHead(400);
          res.end('Invalid tenant payload');
        }
      });

      return;
    }

    const tenantOpMatch = pathname.match(/^\/tenants\/([^/]+)$/);
    if (tenantOpMatch) {
      if (!ensureRole(req, res, 'admin')) {
        return;
      }

      const targetId = typeof tenantOpMatch[1] === 'string' ? tenantOpMatch[1].trim() : '';
      if (!targetId) {
        res.writeHead(400);
        res.end('Tenant id is required');
        return;
      }

      if (req.method === 'PUT') {
        collectBody(req, (body) => {
          try {
            const payload = JSON.parse(body);
            const tenant = findTenantById(targetId);
            if (!tenant) {
              res.writeHead(404);
              return res.end('Tenant not found');
            }
            const updates = {};
            if (typeof payload.name === 'string' && payload.name.trim()) {
              updates.name = payload.name.trim();
            }
            if (typeof payload.description === 'string') {
              updates.description = payload.description.trim();
            }
            if (payload.domains !== undefined) {
              updates.domains = parseTenantDomains(payload.domains);
            }
            if (!Object.keys(updates).length) {
              res.writeHead(400);
              return res.end('No tenant fields to update');
            }

            const updated = tenants.map((entry) => {
              if (entry.id === targetId) {
                return { ...entry, ...updates };
              }
              return entry;
            });

            if (!commitTenantList(updated)) {
              res.writeHead(500);
              return res.end('Unable to persist tenant update');
            }

            const refreshed = findTenantById(targetId);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ tenant: refreshed }));
          } catch (error) {
            res.writeHead(400);
            res.end('Invalid tenant payload');
          }
        });

        return;
      }

      if (req.method === 'DELETE') {
        if (targetId === DEFAULT_TENANT_ID) {
          res.writeHead(400);
          return res.end('Default tenant cannot be removed');
        }

        const existing = findTenantById(targetId);
        if (!existing) {
          res.writeHead(404);
          return res.end('Tenant not found');
        }

        const updated = tenants.filter((entry) => entry.id !== targetId);
        if (!commitTenantList(updated)) {
          res.writeHead(500);
          return res.end('Unable to delete tenant');
        }

        res.writeHead(204);
        return res.end();
      }
    }

  if (aiSettingsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const tenantId = getTenantIdForRequest(req);
        const currentSettings = getGeneralSettingsForTenant(tenantId);
        const systemPrompt = typeof payload.systemPrompt === 'string'
          ? payload.systemPrompt
          : currentSettings.aiAgent?.systemPrompt ?? DEFAULT_AI_AGENT_SETTINGS.systemPrompt;
        const updatedAiAgent = {
          ...currentSettings.aiAgent,
          systemPrompt,
        };

        if (payload.apiKey !== undefined) {
          const key = typeof payload.apiKey === 'string' ? payload.apiKey.trim() : '';
          updatedAiAgent.apiKey = key ? key : null;
        }

        const updatedSettings = {
          ...currentSettings,
          aiAgent: updatedAiAgent,
        };
        persistGeneralSettings(tenantId, updatedSettings);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          systemPrompt: updatedAiAgent.systemPrompt,
          apiKeyConfigured: Boolean(updatedAiAgent.apiKey),
        }));
      } catch (error) {
        console.error('Unable to update AI settings', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const aiSessionMatch = pathname === '/ai/session';
  if (aiSessionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const sessionId = createAiSession();
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ sessionId }));
    return;
  }

  const aiHistoryMatch = pathname === '/ai/history';
  if (aiHistoryMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const limit = Number.parseInt(requestedUrl.searchParams.get('limit') ?? '', 10) || 50;
    const history = getRecentAiHistory({ limit });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ history }));
    return;
  }

  const aiMessageMatch = pathname === '/ai/message';
  if (aiMessageMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, async (body) => {
      try {
        const payload = JSON.parse(body);
        const text = typeof payload.text === 'string' ? payload.text.trim() : '';
        if (!text) {
          res.writeHead(400);
          res.end('Message text is required');
          return;
        }

        const tenantId = getTenantIdForRequest(req);
        const tenantSettings = getGeneralSettingsForTenant(tenantId);

        const sessionId = typeof payload.sessionId === 'string' && payload.sessionId.trim()
          ? payload.sessionId.trim()
          : createAiSession();
        const session = getAiConversation(sessionId);
        const sessionUser = req.userSession?.user?.username ?? 'server';

        recordAiHistory({
          sessionId,
          user: sessionUser,
          type: 'prompt',
          text,
        });

        const baseMessages = buildAiMessages(session, text, [], tenantSettings);
        const {
          assistantMessage,
          toolDetails,
          functionCallMessage,
          functionResultMessage,
        } = await callAiWithToolLoop(baseMessages, {}, tenantSettings);
        const assistantContent = assistantMessage?.content ?? '';

        if (toolDetails) {
          recordAiHistory({
            sessionId,
            user: sessionUser,
            type: 'tool',
            tool: toolDetails.name,
            arguments: toolDetails.arguments,
            result: toolDetails.result,
            error: toolDetails.error,
          });
        }

        recordAiHistory({
          sessionId,
          user: sessionUser,
          type: 'response',
          text: assistantContent,
        });

        const sessionEntries = [
          { role: 'user', content: text },
          ...(functionCallMessage && functionResultMessage ? [functionCallMessage, functionResultMessage] : []),
          { role: 'assistant', content: assistantContent },
        ];
        appendSessionMessages(session, sessionEntries);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          sessionId,
          message: assistantContent,
          toolCall: toolDetails,
        }));
      } catch (error) {
        console.error('AI message failed', error);
        res.writeHead(502);
        res.end('AI service unavailable');
      }
    });

    return;
  }
  const complianceProfilesMatch = pathname === '/compliance/profiles';
  if (complianceProfilesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      defaultProfileId: complianceConfig.defaultProfileId ?? null,
      profiles: Array.isArray(complianceConfig.profiles) ? complianceConfig.profiles : [],
      assignments: complianceConfig.assignments ?? {},
    }));
    return;
  }

  if (complianceProfilesMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const sanitizedProfiles = sanitizeProfilesPayload(payload);
        if (!sanitizedProfiles.length) {
          res.writeHead(400);
          return res.end('At least one profile is required');
        }
        const defaultProfileId = typeof payload?.defaultProfileId === 'string' && payload.defaultProfileId.trim()
          ? payload.defaultProfileId.trim()
          : sanitizedProfiles[0].id;

        complianceConfig.profiles = sanitizedProfiles;
        complianceConfig.defaultProfileId = defaultProfileId;
        persistComplianceConfig();
        refreshComplianceCache();
        broadcastComplianceDefinitions({ runNow: true });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          defaultProfileId,
          profiles: sanitizedProfiles,
        }));
      } catch (error) {
        console.error('Unable to save compliance definitions', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const complianceDevicesMatch = pathname === '/compliance/devices' && req.method === 'GET';
  if (complianceDevicesMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const statuses = [];
    for (const [agentId, summary] of complianceStatusByAgent) {
      const agentInfo = clientsById.get(agentId)?.info ?? agents.get(agentId) ?? null;
      statuses.push({
        agentId,
        agentName: agentInfo?.name ?? 'Unknown',
        agentStatus: agentInfo?.status ?? 'offline',
        assignedProfileId: getAssignedComplianceProfileId(agentId),
        profileId: summary.profileId,
        profileLabel: summary.profileLabel,
        score: summary.score,
        evaluatedAt: summary.updatedAt,
        passWeight: summary.passWeight,
        failWeight: summary.failWeight,
        notApplicableWeight: summary.notApplicableWeight,
        totalWeight: summary.totalWeight,
        results: summary.results,
      });
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ statuses }));
    return;
  }

  const complianceAssignmentsMatch = pathname === '/compliance/assignments';
  if (complianceAssignmentsMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ assignments: complianceConfig.assignments ?? {} }));
    return;
  }

  if (complianceAssignmentsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' && payload.agentId.trim()
          ? payload.agentId.trim()
          : null;
        const profileId = typeof payload?.profileId === 'string' && payload.profileId.trim()
          ? payload.profileId.trim()
          : null;
        if (!agentId) {
          res.writeHead(400);
          return res.end('agentId is required');
        }
        if (profileId && !getComplianceProfile(profileId)) {
          res.writeHead(400);
          return res.end('Unknown profile');
        }

        complianceConfig.assignments = complianceConfig.assignments ?? {};
        if (profileId) {
          complianceConfig.assignments[agentId] = profileId;
        } else {
          delete complianceConfig.assignments[agentId];
        }
        persistComplianceConfig();
        broadcastComplianceDefinitions({ targetAgentId: agentId, runNow: true });

        res.writeHead(204);
        return res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const complianceRunMatch = pathname === '/compliance/run' && req.method === 'POST';
  if (complianceRunMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' && payload.agentId.trim()
          ? payload.agentId.trim()
          : null;
        requestComplianceRun(agentId);
        res.writeHead(202);
        res.end('Compliance run triggered');
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const gpoProfilesMatch = pathname === '/gpo/profiles';
  if (gpoProfilesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      defaultProfileId: gpoConfig.defaultProfileId ?? null,
      profiles: Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : [],
      assignments: gpoConfig.assignments ?? {},
    }));
    return;
  }

  if (gpoProfilesMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const sanitizedProfiles = sanitizeGpoProfilesPayload(payload);
        if (!sanitizedProfiles.length) {
          res.writeHead(400);
          return res.end('At least one GPO profile is required');
        }
        const defaultProfileId = typeof payload?.defaultProfileId === 'string' && payload.defaultProfileId.trim()
          ? payload.defaultProfileId.trim()
          : sanitizedProfiles[0].id;

        gpoConfig.profiles = sanitizedProfiles;
        gpoConfig.defaultProfileId = defaultProfileId;
        persistGpoConfig();
        refreshGpoCache();
        broadcastGpoDefinitions({ runNow: true });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          defaultProfileId,
          profiles: sanitizedProfiles,
        }));
      } catch (error) {
        console.error('Unable to save GPO definitions', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const gpoAssignmentsMatch = pathname === '/gpo/assignments';
  if (gpoAssignmentsMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ assignments: gpoConfig.assignments ?? {} }));
    return;
  }

  if (gpoAssignmentsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' && payload.agentId.trim()
          ? payload.agentId.trim()
          : null;
        const profileId = typeof payload?.profileId === 'string' && payload.profileId.trim()
          ? payload.profileId.trim()
          : null;
        if (!agentId) {
          res.writeHead(400);
          return res.end('agentId is required');
        }
        if (profileId && !getGpoProfile(profileId)) {
          res.writeHead(400);
          return res.end('Unknown GPO profile');
        }

        gpoConfig.assignments = gpoConfig.assignments ?? {};
        if (profileId) {
          gpoConfig.assignments[agentId] = profileId;
        } else {
          delete gpoConfig.assignments[agentId];
        }
        persistGpoConfig();
        broadcastGpoDefinitions({ targetAgentId: agentId, runNow: true });

        res.writeHead(204);
        return res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const gpoRunMatch = pathname === '/gpo/run' && req.method === 'POST';
  if (gpoRunMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' && payload.agentId.trim()
          ? payload.agentId.trim()
          : null;
        requestGpoRun(agentId);
        res.writeHead(202);
        res.end('GPO apply triggered');
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const agentDownloadMatch = pathname === '/agent/download' && req.method === 'GET';
  if (agentDownloadMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentDir = resolveAgentPackageDir();
    if (!agentDir) {
      res.writeHead(500);
      res.end('Agent package directory not found. Publish the agent first.');
      return;
    }

    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto
      ? String(forwardedProto).split(',')[0].trim()
      : (req.socket.encrypted || req.connection?.encrypted ? 'https' : 'http');
    const wssScheme = protocol === 'https' ? 'wss' : 'ws';
    const hostHeader = req.headers.host ?? `localhost:${PORT}`;
    const endpoint = `${wssScheme}://${hostHeader}`;
    const archive = archiver('zip', { zlib: { level: 9 } });
    const fileName = `rmm-agent-${Date.now()}.zip`;
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${fileName}"`,
    });

    archive.on('error', (error) => {
      console.error('Agent download creation failed', error);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end('Unable to create agent package.');
      } else {
        res.destroy(error);
      }
    });

    archive.pipe(res);
    archive.directory(agentDir, false);
    const launcherLines = [
      '@echo off',
      'setlocal',
      'cd /d "%~dp0"',
      `dotnet Agent.dll ${endpoint}`,
      'endlocal',
    ];
    archive.append(launcherLines.join('\r\n'), { name: 'run-agent.bat' });
    archive.append(JSON.stringify({ endpoint, dashboard: `${protocol}://${hostHeader}` }, null, 2), { name: 'server.json' });
    archive.finalize();
    return;
  }

  const shellStreamMatch = pathname.match(/^\/shell\/([^/]+)$/);
  if (shellStreamMatch && req.method === 'GET') {
    const agentId = shellStreamMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    shellStreams.set(agentId, res);
    res.on('close', () => {
      shellStreams.delete(agentId);
      sendControl(entry.socket, 'stop-shell');
    });

    sendControl(entry.socket, 'start-shell');
    return;
  }

  const shellInputMatch = pathname.match(/^\/shell\/([^/]+)\/input$/);
  if (shellInputMatch && req.method === 'POST') {
    const agentId = shellInputMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      sendControl(entry.socket, 'shell-input', { input: body });
      res.writeHead(204);
      res.end();
    });

    return;
  }

  const screenListMatch = pathname.match(/^\/screen\/([^/]+)\/screens$/);
  if (screenListMatch && req.method === 'GET') {
    const agentId = screenListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const cached = screenLists.get(agentId);
    if (cached && Date.now() - cached.updatedAt < SCREEN_LIST_TTL_MS) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ screens: cached.screens }));
      return;
    }

    requestScreenList(agentId, entry.socket)
      .then((screens) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ screens }));
      })
      .catch(() => {
        res.writeHead(504);
        res.end('Failed to retrieve screen list');
      });

    return;
  }

  const screenOfferMatch = pathname.match(/^\/screen\/([^/]+)\/offer$/);
  if (screenOfferMatch && req.method === 'GET') {
    const sessionId = screenOfferMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      console.warn(`Offer requested for unknown session ${sessionId}`);
      res.writeHead(404);
      return res.end('Session not found');
    }

    console.log(`Offer requested for session ${sessionId} (agent ${session.agentName}) - ready=${Boolean(session.offer)}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const payloadBase = {
      sessionId,
      agentId: session.agentId,
      agentName: session.agentName,
    };

    if (!session.offer) {
      return res.end(JSON.stringify({ ...payloadBase, ready: false }));
    }

    res.end(JSON.stringify({ ...payloadBase, ...session.offer, ready: true }));
    return;
  }

  const screenEventsMatch = pathname.match(/^\/screen\/([^/]+)\/events$/);
  if (screenEventsMatch && req.method === 'GET') {
    const sessionId = screenEventsMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    session.sseClients.add(res);

    console.log(`Screen events client added for session ${sessionId} (agent ${session.agentName})`);
    sendScreenEvent(session, 'status', {
      sessionId,
      agentId: session.agentId,
      agentName: session.agentName,
      state: session.offer ? 'offer-ready' : 'waiting-offer',
      screenId: session.screenId,
      screenName: getScreenName(session.agentId, session.screenId),
    });

    res.on('close', () => {
      session.sseClients.delete(res);
      console.log(`Screen events disconnected for session ${sessionId}`);
      sendControl(session.socket, 'stop-screen', { sessionId });
      screenSessions.delete(sessionId);
    });

    if (session.offer) {
      sendScreenEvent(session, 'offer', session.offer);
    }

    for (const candidate of session.agentCandidates) {
      sendScreenEvent(session, 'candidate', candidate);
    }

    return;
  }

  const snmpEventsMatch = pathname.match(/^\/clients\/([^/]+)\/snmp\/([^/]+)\/events$/);
  if (snmpEventsMatch && req.method === 'GET') {
    const agentId = snmpEventsMatch[1];
    const requestId = snmpEventsMatch[2];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    let stream = snmpScanStreams.get(requestId);
    if (stream && stream.agentId !== agentId) {
      res.writeHead(409);
      res.end('Request ID already bound to a different agent');
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    if (!stream) {
      stream = { agentId, clients: new Set() };
      snmpScanStreams.set(requestId, stream);
    }

    stream.clients.add(res);
    res.on('close', () => {
      stream.clients.delete(res);
      if (stream.clients.size === 0) {
        snmpScanStreams.delete(requestId);
      }
    });

    return;
  }

  const networkScannerEventsMatch = pathname.match(/^\/clients\/([^/]+)\/network-scanner\/([^/]+)\/events$/);
  if (networkScannerEventsMatch && req.method === 'GET') {
    const agentId = networkScannerEventsMatch[1];
    const requestId = networkScannerEventsMatch[2];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    let stream = networkScannerStreams.get(requestId);
    if (stream && stream.agentId !== agentId) {
      res.writeHead(409);
      res.end('Request ID already bound to a different agent');
      return;
    }

    if (!stream) {
      stream = { agentId, clients: new Set() };
      networkScannerStreams.set(requestId, stream);
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write('\n');

    stream.clients.add(res);
      res.on('close', () => {
        stream.clients.delete(res);
        if (stream.clients.size === 0) {
          networkScannerStreams.delete(requestId);
        }
      });

    return;
  }

  const screenRequestMatch = pathname === '/screen/request' && req.method === 'POST';
  if (screenRequestMatch) {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = payload.agentId;
        const requestedScreenId = typeof payload.screenId === 'string' && payload.screenId.trim()
          ? payload.screenId.trim()
          : null;
        console.log(`Received screen request for agent ${agentId}`);
        const entry = clientsById.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const requestedScale = extractScale(payload?.scale);
        const sessionId = uuidv4();
        screenSessions.set(sessionId, {
          agentId,
          socket: entry.socket,
          agentName: entry.info.name,
          sseClients: new Set(),
          offer: null,
          agentCandidates: [],
          screenId: requestedScreenId,
          scale: requestedScale,
        });

        const tenantId = getTenantIdForRequest(req);
        const tenantSettings = getGeneralSettingsForTenant(tenantId);
        console.log(`Sending start-screen to agent ${agentId} for session ${sessionId}`);
        sendControl(entry.socket, 'start-screen', {
          sessionId,
          screenId: requestedScreenId,
          scale: requestedScale,
          requireConsent: Boolean(tenantSettings?.screenConsentRequired !== false),
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const chatEventsMatch = pathname.match(/^\/chat\/([^/]+)\/events$/);
  if (chatEventsMatch && req.method === 'GET') {
    const agentId = chatEventsMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    addChatListener(agentId, res);
    flushChatHistory(agentId, res);
    res.on('close', () => {
      removeChatListener(agentId, res);
    });

    return;
  }

  const chatMessageMatch = pathname.match(/^\/chat\/([^/]+)\/message$/);
  if (chatMessageMatch && req.method === 'POST') {
    const agentId = chatMessageMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const text = typeof payload?.text === 'string' ? payload.text.trim() : '';
        if (!text) {
          res.writeHead(400);
          res.end('Message text is required');
          return;
        }

        const sessionId = uuidv4();
        const sessionUser = req.userSession?.user?.username ?? 'server';
        const sessionRole = req.userSession?.user?.role ?? 'user';
        const chatEvent = {
          sessionId,
          agentId,
          agentName: entry.info.name,
          direction: 'server',
          text,
          timestamp: new Date().toISOString(),
          user: sessionUser,
          role: sessionRole,
        };

        recordChatHistory(agentId, chatEvent);
        dispatchChatEvent(agentId, chatEvent);
        sendControl(entry.socket, 'chat-request', { sessionId, text, user: sessionUser, role: sessionRole });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const updatesDataMatch = pathname.match(/^\/updates\/([^/]+)\/data$/);
  if (updatesDataMatch && req.method === 'GET') {
    const agentId = updatesDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ summary: entry.info.updatesSummary ?? null }));
    return;
  }

  const updatesRefreshMatch = pathname.match(/^\/updates\/([^/]+)\/refresh$/);
  if (updatesRefreshMatch && req.method === 'POST') {
    const agentId = updatesRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'request-updates');
    res.writeHead(202);
    res.end();
    return;
  }

  const updatesInstallMatch = pathname.match(/^\/updates\/([^/]+)\/install$/);
  if (updatesInstallMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    const agentId = updatesInstallMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        if (!Array.isArray(payload?.ids)) {
          res.writeHead(400);
          return res.end('Invalid request');
        }

        const ids = payload.ids
          .filter((entryId) => typeof entryId === 'string' && entryId.trim())
          .map((entryId) => entryId.trim());

        if (ids.length === 0) {
          res.writeHead(400);
          return res.end('No updates selected');
        }

        console.log(`Installing ${ids.length} updates on agent ${agentId}`);
        sendControl(entry.socket, 'install-updates', { ids });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  const patchesMatch = pathname === '/patches' && req.method === 'GET';
  if (patchesMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    const patches = buildPatchCatalog();
    res.end(JSON.stringify({
      patches,
      summary: buildPatchSummary(patches),
    }));
    return;
  }

  const patchSchedulesMatch = pathname === '/patches/schedules' && req.method === 'GET';
  if (patchSchedulesMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ schedules: serializeSchedules(Array.from(patchSchedules.values())) }));
    return;
  }

  const patchApproveMatch = pathname === '/patches/approve' && req.method === 'POST';
  if (patchApproveMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' ? payload.agentId.trim() : '';
        const updateId = typeof payload?.updateId === 'string' ? payload.updateId.trim() : '';
        if (!agentId || !updateId) {
          res.writeHead(400);
          return res.end('Agent and update ID required');
        }

        const entry = agents.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const approved = payload?.approved !== false;
        const key = `${agentId}:${updateId}`;
        if (approved) {
          patchApprovals.set(key, { approvedAt: Date.now() });
        } else {
          patchApprovals.delete(key);
        }

        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const patchScheduleMatch = pathname === '/patches/schedule' && req.method === 'POST';
  if (patchScheduleMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const patchIds = Array.isArray(payload?.patchIds)
          ? payload.patchIds.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim())
          : [];
        const agentIds = Array.isArray(payload?.agentIds)
          ? payload.agentIds.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim())
          : [];

        if (patchIds.length === 0) {
          res.writeHead(400);
          return res.end('At least one patch must be selected');
        }

        const runAtValue = payload?.runAt;
        let runAt = typeof runAtValue === 'number' ? runAtValue : Date.parse(runAtValue ?? '');
        if (Number.isNaN(runAt)) {
          runAt = Date.now();
        }
        if (runAt < Date.now()) {
          runAt = Date.now();
        }

        const repeatMsValue = Number(payload?.repeatMs);
        const repeatMs = Number.isFinite(repeatMsValue) && repeatMsValue > 0 ? repeatMsValue : 0;

        const missingApprovals = [];
        if (agentIds.length > 0) {
          for (const agentId of agentIds) {
            for (const patchId of patchIds) {
              if (!isPatchApproved(agentId, patchId)) {
                missingApprovals.push({ agentId, patchId });
              }
            }
          }

          if (missingApprovals.length > 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
              error: 'All agents must approve the selected patches before scheduling',
              missing: missingApprovals,
            }));
          }
        }

        const schedule = {
          id: uuidv4(),
          name: typeof payload?.name === 'string' && payload.name.trim()
            ? payload.name.trim()
            : `Patch run ${new Date().toISOString()}`,
          patchIds,
          agentIds,
          category: typeof payload?.category === 'string' && payload.category.trim()
            ? payload.category.trim()
            : null,
          dynamic: agentIds.length === 0,
          runAt,
          repeatMs,
          nextRun: runAt,
          lastRun: null,
          createdAt: Date.now(),
          pendingAgents: new Set(agentIds),
        };

        patchSchedules.set(schedule.id, schedule);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(serializeSchedule(schedule)));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const snmpDiscoveryMatch = pathname.match(/^\/clients\/([^/]+)\/snmp\/discovery$/);
  if (snmpDiscoveryMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = snmpDiscoveryMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const tenantId = getTenantIdForRequest(req);

    collectBody(req, (body) => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const enabled = typeof payload.enabled === 'boolean' ? payload.enabled : null;
        if (enabled === null) {
          res.writeHead(400);
          return res.end('Enabled must be true or false');
        }

        if (!setSnmpDiscoveryEnabled(agentId, enabled)) {
          res.writeHead(500);
          return res.end('Failed to persist SNMP discovery setting');
        }

        entry.info.snmpDiscoveryEnabled = enabled;
        agents.set(agentId, entry.info);
        res.writeHead(204);
        res.end();
      } catch (error) {
        console.error('Failed to update SNMP discovery setting', error);
        res.writeHead(400);
        res.end('Invalid SNMP discovery request');
      }
    });

    return;
  }

  const snmpScanMatch = pathname.match(/^\/clients\/([^/]+)\/snmp\/scan$/);
  if (snmpScanMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = snmpScanMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    if (!isSnmpDiscoveryEnabled(agentId)) {
      res.writeHead(403);
      return res.end('SNMP discovery disabled for this agent');
    }

    collectBody(req, (body) => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const tenantId = getTenantIdForRequest(req);
        const tenantSettings = getGeneralSettingsForTenant(tenantId);
        const versionValue = typeof payload.version === 'string' && payload.version.trim()
          ? payload.version.trim().toLowerCase()
          : (tenantSettings?.snmpVersion ?? DEFAULT_SNMP_VERSION);

          const snmpConfig = getSnmpConfigForVersion(versionValue, tenantSettings);
          if (!snmpConfig) {
            res.writeHead(400);
            return res.end('SNMP defaults are not configured for the selected version');
          }

          const requestId = typeof payload.requestId === 'string' && payload.requestId.trim()
            ? payload.requestId.trim()
            : uuidv4();

        const message = {
          requestId,
          snmp: snmpConfig,
          version: versionValue,
          timeoutMs: typeof payload.timeoutMs === 'number' ? payload.timeoutMs : undefined,
          maxConcurrency: typeof payload.maxConcurrency === 'number' ? payload.maxConcurrency : undefined,
          hostsPerSubnet: typeof payload.hostsPerSubnet === 'number' ? payload.hostsPerSubnet : undefined,
        };

        beginSnmpDiscoveryRecord(agentId, entry.info.name ?? 'unknown', requestId, tenantId);

        sendControl(entry.socket, 'start-snmp-scan', message);
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ requestId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid SNMP scan payload');
      }
    });

    return;
  }

  const networkScannerScanMatch = pathname.match(/^\/clients\/([^/]+)\/network-scanner\/scan$/);
  if (networkScannerScanMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = networkScannerScanMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const tenantId = getTenantIdForRequest(req);

    collectBody(req, (body) => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const requestId = typeof payload.requestId === 'string' && payload.requestId.trim()
          ? payload.requestId.trim()
          : uuidv4();

        const servicePorts = Array.isArray(payload?.servicePorts)
          ? payload.servicePorts
            .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535)
          : undefined;
        const tcpPorts = Array.isArray(payload?.tcpPorts)
          ? payload.tcpPorts
            .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535)
          : servicePorts;
        const udpPorts = Array.isArray(payload?.udpPorts)
          ? payload.udpPorts
            .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535)
          : undefined;

        const message = {
          requestId,
          timeoutMs: typeof payload.timeoutMs === 'number' ? payload.timeoutMs : undefined,
          maxConcurrency: typeof payload.maxConcurrency === 'number' ? payload.maxConcurrency : undefined,
          hostsPerSubnet: typeof payload.hostsPerSubnet === 'number' ? payload.hostsPerSubnet : undefined,
          tcpPorts,
          udpPorts,
        };

        beginNetworkScannerRecord(agentId, entry.info.name ?? 'unknown', requestId, tenantId);

        sendControl(entry.socket, 'start-network-scanner', message);
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ requestId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid network scanner payload');
      }
    });

    return;
  }

  const networkScannerWakeMatch = pathname.match(/^\/clients\/([^/]+)\/network-scanner\/wake$/);
  if (networkScannerWakeMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = networkScannerWakeMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const macAddress = typeof payload.macAddress === 'string' && payload.macAddress.trim()
          ? payload.macAddress.trim()
          : '';
        if (!macAddress) {
          res.writeHead(400);
          return res.end('MAC address is required');
        }

        const targetIp = typeof payload.targetIp === 'string' && payload.targetIp.trim()
          ? payload.targetIp.trim()
          : undefined;

        const requestId = uuidv4();
        sendControl(entry.socket, 'wake-on-lan', {
          requestId,
          macAddress,
          targetIp,
        });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ requestId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid Wake-on-LAN payload');
      }
    });

    return;
  }

  const clientActionMatch = pathname.match(/^\/clients\/([^/]+)\/action$/);
  if (clientActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = clientActionMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const action = typeof payload?.action === 'string' ? payload.action.trim() : '';
        if (!action) {
          res.writeHead(400);
          return res.end('Action required');
        }

        sendControl(entry.socket, 'invoke-action', { action });
        logPatchEvent({
          timestamp: new Date().toISOString(),
          type: 'action',
          agentId,
          action,
          scheduleId: payload?.scheduleId ?? null,
        });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  const deleteScheduleMatch = pathname.match(/^\/patches\/schedules\/([^/]+)$/);
  if (deleteScheduleMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const scheduleId = deleteScheduleMatch[1];
    if (patchSchedules.has(scheduleId)) {
      patchSchedules.delete(scheduleId);
      logPatchEvent({
        timestamp: new Date().toISOString(),
        type: 'schedule-deleted',
        scheduleId,
      });
      res.writeHead(204);
      return res.end();
    }

    res.writeHead(404);
    res.end('Schedule not found');
    return;
  }

  const historyMatch = pathname === '/patches/history' && req.method === 'GET';
  if (historyMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ history: patchHistory.slice() }));
    return;
  }

  const bsodDataMatch = pathname.match(/^\/bsod\/([^/]+)\/data$/);
  if (bsodDataMatch && req.method === 'GET') {
    const agentId = bsodDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ summary: entry.info.bsodSummary ?? null }));
    return;
  }

  const bsodRefreshMatch = pathname.match(/^\/bsod\/([^/]+)\/refresh$/);
  if (bsodRefreshMatch && req.method === 'POST') {
    const agentId = bsodRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'request-bsod');
    res.writeHead(202);
    res.end();
    return;
  }

  const processDataMatch = pathname.match(/^\/processes\/([^/]+)\/data$/);
  if (processDataMatch && req.method === 'GET') {
    const agentId = processDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ snapshot: entry.info.processSnapshot ?? null }));
    return;
  }

  const processRefreshMatch = pathname.match(/^\/processes\/([^/]+)\/refresh$/);
  if (processRefreshMatch && req.method === 'POST') {
    const agentId = processRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'list-processes');
    res.writeHead(202);
    res.end();
    return;
  }

  const processKillMatch = pathname.match(/^\/processes\/([^/]+)\/kill$/);
  if (processKillMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    const agentId = processKillMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const pid = Number(payload?.processId);
        if (!Number.isInteger(pid) || pid <= 0) {
          res.writeHead(400);
          return res.end('Invalid process id');
        }

        sendControl(entry.socket, 'kill-process', { processId: pid });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  if (pathname === '/monitoring/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    monitoringEvents.add(res);
    res.on('close', () => monitoringEvents.delete(res));
    return;
  }

  if (pathname === '/monitoring/events/history' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const queryAgentId = requestedUrl.searchParams.get('agentId')?.trim();
    const queryProfileId = requestedUrl.searchParams.get('profileId')?.trim();
    const limitParam = parseInt(requestedUrl.searchParams.get('limit') ?? '', 10);
    const limit = Number.isNaN(limitParam) || limitParam <= 0 ? 200 : limitParam;
    let entries = monitoringHistory;
    if (queryAgentId) {
      entries = entries.filter((entry) => entry.payload?.agentId === queryAgentId);
    }
    if (queryProfileId) {
      entries = entries.filter((entry) => entry.payload?.profileId === queryProfileId);
    }
    res.end(JSON.stringify(entries.slice(-limit)));
    return;
  }

  if (pathname === '/monitoring/profiles' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.monitoringProfiles));
    return;
  }

  if (pathname === '/monitoring/profiles' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        if (!name) {
          res.writeHead(400);
          return res.end('Profile name required');
        }

        const profile = {
          id: uuidv4(),
          name,
          description: typeof payload?.description === 'string' ? payload.description.trim() : '',
          alertProfileId: typeof payload?.alertProfileId === 'string' ? payload.alertProfileId.trim() : null,
          assignedAgents: [],
          assignedGroups: [],
          rules: [],
        };

        const rules = Array.isArray(payload?.rules) ? payload.rules : [payload?.rule].filter(Boolean);
        for (const entry of rules) {
          if (entry?.metric && typeof entry?.threshold === 'number') {
            profile.rules.push({
              id: uuidv4(),
              metric: entry.metric,
              threshold: entry.threshold,
              windowSeconds: typeof entry?.windowSeconds === 'number' ? entry.windowSeconds : 30,
              comparison: entry?.comparison || 'gte',
            });
          }
        }

        if (profile.rules.length === 0) {
          res.writeHead(400);
          return res.end('At least one rule is required');
        }

        monitoringConfig.monitoringProfiles.push(profile);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const profileAssignMatch = pathname.match(/^\/monitoring\/profiles\/([^/]+)\/assign$/);
  if (profileAssignMatch && req.method === 'POST') {
    const profileId = profileAssignMatch[1];
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const targetType = payload?.targetType;
        const rawTargetId = typeof payload?.targetId === 'string' ? payload.targetId.trim() : '';
        const targetId = targetType === 'group' ? normalizeGroupName(rawTargetId) : rawTargetId;
        if (!targetType || !targetId) {
          res.writeHead(400);
          return res.end('Invalid assignment');
        }

        if (targetType === 'agent') {
          if (!profile.assignedAgents.includes(targetId)) {
            profile.assignedAgents.push(targetId);
          }
          notifyAgentMonitoring(targetId);
        } else if (targetType === 'group') {
          if (!profile.assignedGroups.includes(targetId)) {
            profile.assignedGroups.push(targetId);
          }
          notifyGroupMonitoring(targetId);
        } else {
          res.writeHead(400);
          return res.end('Unknown target type');
        }

        saveMonitoringConfig();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

  return;
}

  const profileDeleteMatch = pathname.match(/^\/monitoring\/profiles\/([^/]+)$/);
  if (profileDeleteMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = profileDeleteMatch[1];
    const index = monitoringConfig.monitoringProfiles.findIndex((entry) => entry.id === profileId);
    if (index === -1) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    const [removed] = monitoringConfig.monitoringProfiles.splice(index, 1);
    clearMonitoringProfileState(profileId);
    saveMonitoringConfig();

    const affectedAgents = new Set(removed.assignedAgents ?? []);
    for (const entry of clientsById.values()) {
      const groupName = entry.info.group ?? DEFAULT_GROUP;
      if ((removed.assignedGroups ?? []).includes(groupName)) {
        affectedAgents.add(entry.info.id);
      }
    }
    for (const agentId of affectedAgents) {
      notifyAgentMonitoring(agentId);
    }

    res.writeHead(204);
    return res.end();
  }

  if (pathname === '/alert-profiles' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.alertProfiles));
    return;
  }

  if (pathname === '/alert-profiles' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        if (!name) {
          res.writeHead(400);
          return res.end('Alert profile name required');
        }

        const profile = {
          id: uuidv4(),
          name,
          emails: Array.isArray(payload?.emails) ? payload.emails.filter((email) => typeof email === 'string' && email.trim()) : [],
          dashboard: Boolean(payload?.dashboard),
          remediationScript: typeof payload?.remediationScript === 'string' ? payload.remediationScript.trim() : null,
        };

        monitoringConfig.alertProfiles.push(profile);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (profileAssignMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = profileAssignMatch[1];
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const targetType = payload?.targetType;
        const rawTargetId = typeof payload?.targetId === 'string' ? payload.targetId.trim() : '';
        const targetId = targetType === 'group' ? normalizeGroupName(rawTargetId) : rawTargetId;
        if (!targetType || !targetId) {
          res.writeHead(400);
          return res.end('Invalid assignment');
        }

        if (targetType === 'agent') {
          profile.assignedAgents = (profile.assignedAgents ?? []).filter((id) => id !== targetId);
          notifyAgentMonitoring(targetId);
        } else if (targetType === 'group') {
          profile.assignedGroups = (profile.assignedGroups ?? []).filter((id) => id !== targetId);
          notifyGroupMonitoring(targetId);
        } else {
          res.writeHead(400);
          return res.end('Unknown target type');
        }

        saveMonitoringConfig();
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/remediation/scripts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.remediationScripts));
    return;
  }

  if (pathname === '/scripts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.remediationScripts));
    return;
  }

  const scriptContentMatch = pathname.match(/^\/scripts\/([^/]+)\/content$/);
  if (scriptContentMatch && req.method === 'GET') {
    const scriptName = scriptContentMatch[1];
    const script = getScriptByName(scriptName);
    if (!script) {
      res.writeHead(404);
      return res.end('Script not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name: script.name, content: readScriptContent(script) }));
    return;
  }

  if (pathname === '/scripts' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        const description = typeof payload?.description === 'string' ? payload.description.trim() : '';
        const language = typeof payload?.language === 'string' ? payload.language.toLowerCase() : 'powershell';
        const content = typeof payload?.content === 'string' ? payload.content : '';

        if (!name || !content) {
          res.writeHead(400);
          return res.end('Name and content are required');
        }

        if (getScriptByName(name)) {
          res.writeHead(409);
          return res.end('Script name already exists');
        }

        ensureRemediationDirectory();
        const fileName = sanitizeScriptFileName(name, language);
        fs.writeFileSync(path.join(REMEDIATION_DIR, fileName), content, 'utf-8');

        const scriptEntry = {
          name,
          description,
          language,
          file: fileName,
        };

        monitoringConfig.remediationScripts.push(scriptEntry);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(scriptEntry));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/scripts/run' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const scriptName = typeof payload?.scriptName === 'string' ? payload.scriptName.trim() : '';
        const agentIds = Array.isArray(payload?.agentIds) ? payload.agentIds : [];

        const script = getScriptByName(scriptName);
        if (!script || agentIds.length === 0) {
          res.writeHead(400);
          return res.end('Script name and agent list are required');
        }

        const missing = [];
        const triggered = [];
        for (const agentId of agentIds) {
          const entry = clientsById.get(agentId);
          if (!entry) {
            missing.push(agentId);
            continue;
          }

          runRemediation(entry.info, entry.socket, script.name, {
            type: 'script-run',
            metric: script.language,
            message: `Manual run of ${script.name}`,
          });
          triggered.push(agentId);
        }

        sendMonitoringEvent('script-run', {
          type: 'script-run',
          scriptName: script.name,
          agentIds: triggered,
          timestamp: new Date().toISOString(),
        });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ triggered, missing }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const fileListMatch = pathname.match(/^\/files\/([^/]+)\/list$/);
  if (fileListMatch && req.method === 'GET') {
    const agentId = fileListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const requestedPath = requestedUrl.searchParams.get('path') ?? '';
    requestAgentFileList(entry, requestedPath)
      .then((result) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      })
      .catch((error) => {
        console.error('File list request failed', error);
        res.writeHead(504);
        res.end('File list request timed out');
      });

    return;
  }

  const fileDownloadMatch = pathname.match(/^\/files\/([^/]+)\/download$/);
  if (fileDownloadMatch && req.method === 'GET') {
    const agentId = fileDownloadMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const requestedPath = requestedUrl.searchParams.get('path');
    if (!requestedPath) {
      res.writeHead(400);
      return res.end('Path is required');
    }

    requestAgentFileDownload(entry, requestedPath)
      .then((result) => {
        if (!result || typeof result.data !== 'string' || !result.name) {
          res.writeHead(502);
          return res.end('Invalid download response');
        }

        const buffer = Buffer.from(result.data, 'base64');
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(result.name)}"`,
        });
        res.end(buffer);
      })
      .catch((error) => {
        console.error('File download failed', error);
        res.writeHead(504);
        res.end('File download timed out');
      });

    return;
  }

  const fileUploadMatch = pathname.match(/^\/files\/([^/]+)\/upload$/);
  if (fileUploadMatch && req.method === 'POST') {
    const agentId = fileUploadMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const destinationPath = typeof payload?.path === 'string' ? payload.path.trim() : '';
        const data = typeof payload?.data === 'string' ? payload.data.trim() : '';
        if (!destinationPath || !data) {
          res.writeHead(400);
          return res.end('Path and data are required');
        }

        requestAgentFileUpload(entry, destinationPath, data)
          .then((response) => {
            res.writeHead(response.success ? 202 : 400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: response.success,
              message: response.message ?? '',
            }));
          })
          .catch((error) => {
            console.error('File upload failed', error);
            res.writeHead(400);
            res.end('Upload request timed out');
          });
      } catch (error) {
        console.error('File upload failed', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareListMatch = pathname.match(/^\/software\/([^/]+)\/list$/);
  if (softwareListMatch && req.method === 'GET') {
    const agentId = softwareListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const filterText = (requestedUrl.searchParams.get('filter') ?? '').trim().toLowerCase();
    const sourceFilter = (requestedUrl.searchParams.get('source') ?? '').trim().toLowerCase();
    const pageValue = Number(requestedUrl.searchParams.get('page') ?? '1');
    const sizeValue = Number(requestedUrl.searchParams.get('pageSize') ?? '25');
    const page = Math.max(Math.floor(pageValue) || 1, 1);
    const pageSize = Math.min(Math.max(Math.floor(sizeValue) || 25, 5), 200);

        requestAgentSoftwareList(entry)
          .then((result) => {
            const allEntries = Array.isArray(result.entries) ? result.entries : [];
        const filtered = allEntries.filter((item) => {
          if (!filterText) {
            return true;
          }
          const haystack = `${item.name ?? ''} ${item.version ?? ''} ${item.publisher ?? ''} ${item.source ?? ''}`.toLowerCase();
          return haystack.includes(filterText);
        }).filter((item) => {
          if (!sourceFilter) {
            return true;
          }
          return (item.source ?? '').toLowerCase().includes(sourceFilter);
        });

        filtered.sort((a, b) => (a.name ?? '').localeCompare(b.name ?? '', 'en', { sensitivity: 'base' }));
        const total = filtered.length;
        const offset = (page - 1) * pageSize;
        const paged = filtered.slice(offset, offset + pageSize);

        res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              agentId,
              total,
              page,
              pageSize,
              entries: paged,
              retrievedAt: result.retrievedAt,
            }));
          })
      .catch((error) => {
        console.error('Software list request failed', error);
        res.writeHead(504);
        res.end('Software request timed out');
      });
    return;
  }

  const softwareUninstallMatch = pathname.match(/^\/software\/([^/]+)\/uninstall$/);
  if (softwareUninstallMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = softwareUninstallMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const softwareId = typeof payload?.softwareId === 'string' ? payload.softwareId.trim() : '';
        if (!softwareId) {
          res.writeHead(400);
          return res.end('softwareId is required');
        }

        const requestId = uuidv4();
        sendControl(entry.socket, 'uninstall-software', {
          requestId,
          softwareId,
          source: typeof payload?.source === 'string' ? payload.source : 'registry',
          uninstallCommand: typeof payload?.uninstallCommand === 'string' ? payload.uninstallCommand : null,
          packageFullName: typeof payload?.packageFullName === 'string' ? payload.packageFullName : null,
          productCode: typeof payload?.productCode === 'string' ? payload.productCode : null,
        });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ requestId, success: true, message: 'Uninstall requested.' }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareInventoryMatch = pathname === '/software' && req.method === 'GET';
  if (softwareInventoryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    try {
      await refreshSoftwareEntriesFromAgents();
    } catch (error) {
      console.warn('Software inventory refresh failed', error);
    }

    const snapshot = buildSoftwareCatalog();
    const pendingUninstalls = Array.from(softwareUninstallQueue.values()).reduce((sum, queue) => sum + queue.pending.size, 0);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      software: snapshot.list,
      summary: {
        totalSoftware: snapshot.list.length,
        totalAgents: snapshot.agentCount,
        rejectedPairs: snapshot.rejectedPairs,
        pendingUninstalls,
      },
    }));
  }

  const softwareApprovalMatch = pathname === '/software/approval' && req.method === 'POST';
  if (softwareApprovalMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, async (body) => {
      try {
        const payload = JSON.parse(body);
        const softwareId = (payload?.softwareId ?? '').toString().trim();
        const action = (payload?.action ?? '').toString().trim().toLowerCase();
        if (!softwareId || (action !== 'approve' && action !== 'reject')) {
          res.writeHead(400);
          return res.end('softwareId and valid action are required');
        }

        const state = action === 'reject' ? 'rejected' : 'approved';
        softwareApprovals.set(softwareId, { state });
        if (state === 'rejected') {
          queueRejectedSoftwareNow(softwareId);
        } else {
          softwareUninstallQueue.delete(softwareId);
        }

        res.writeHead(204);
        res.end();
      } catch (error) {
        console.error('Software approval failed', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareLogsMatch = pathname === '/software/logs' && req.method === 'GET';
  if (softwareLogsMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ logs: softwareUninstallLog.slice(0, SOFTWARE_UNINSTALL_LOG_LIMIT) }));
    return;
  }

  const ruleLibraryMatch = pathname === '/firewall/rule-library' && req.method === 'GET';
  if (ruleLibraryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const requestedAgentId = requestedUrl.searchParams.get('agent');
    let entry = requestedAgentId ? clientsById.get(requestedAgentId) : null;
    if (!entry) {
      entry = Array.from(clientsById.values()).find((client) => client.socket.readyState === WebSocket.OPEN) ?? null;
    }

    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    requestAgentFirewallRules(entry)
      .then((payload) => {
        const rules = Array.isArray(payload.rules) ? payload.rules : [];
        const unique = new Map();
        for (const rule of rules) {
          if (!rule?.name) {
            continue;
          }
          if (!unique.has(rule.name)) {
            unique.set(rule.name, { name: rule.name, enabled: Boolean(rule.enabled) });
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          agentId: entry.info.id,
          agentName: entry.info.name,
          rules: Array.from(unique.values()),
        }));
      })
      .catch((error) => {
        console.error('Rule library request failed', error);
        res.writeHead(504, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unable to load rule library' }));
      });

    return;
  }

  const firewallRulesMatch = pathname.match(/^\/firewall\/([^/]+)\/rules$/);
  if (firewallRulesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = firewallRulesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    try {
      const result = await requestAgentFirewallRules(entry);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        firewallEnabled: result.firewallEnabled ?? null,
        profiles: result.profiles ?? null,
        defaultInboundAction: result.defaultInboundAction ?? null,
        defaultOutboundAction: result.defaultOutboundAction ?? null,
        rules: Array.isArray(result.rules) ? result.rules : [],
      }));
    } catch (error) {
      console.error('Firewall rules request failed', error);
      const message = typeof error?.message === 'string' ? error.message : '';
      if (message.includes('unsupported')) {
        res.writeHead(501, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Firewall unsupported' }));
      } else {
        res.writeHead(504, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Firewall request timed out' }));
      }
    }

    return;
  }

  const firewallRuleActionMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/action$/);
  if (firewallRuleActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleActionMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.ruleName === 'string' ? payload.ruleName.trim() : '';
        const enabled = payload?.enabled === true;
        if (!ruleName) {
          res.writeHead(400);
          return res.end('ruleName is required');
        }

        if (entry.socket.readyState !== WebSocket.OPEN) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Agent offline' }));
          return;
        }

        requestAgentFirewallAction(entry, { type: 'rule', ruleName, enabled })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule update requested',
            }));
          })
        .catch((error) => {
          console.error('Firewall rule update failed', error);
          const message = typeof error?.message === 'string' ? error.message : '';
          if (message.includes('unsupported')) {
            res.writeHead(501, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Firewall unsupported' }));
          } else {
            res.writeHead(504, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Firewall request timed out' }));
          }
        });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const firewallRuleAddMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/add$/);
  if (firewallRuleAddMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleAddMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.name === 'string' ? payload.name.trim() : '';
        const direction = payload?.direction === 'outbound' ? 'outbound' : 'inbound';
        const action = payload?.action === 'block' ? 'block' : 'allow';
        const protocol = typeof payload?.protocol === 'string' ? payload.protocol : 'any';
        const localPorts = typeof payload?.localPorts === 'string' ? payload.localPorts : '';
        const remotePorts = typeof payload?.remotePorts === 'string' ? payload.remotePorts : '';
        const application = typeof payload?.application === 'string' ? payload.application : '';

        if (!ruleName) {
          res.writeHead(400);
          return res.end('Rule name is required');
        }

        requestAgentFirewallAction(entry, {
          type: 'add-rule',
          ruleName,
          direction,
          action,
          protocol,
          localPorts,
          remotePorts,
          applicationName: application,
        })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule add requested',
            }));
          })
          .catch((error) => {
            console.error('Firewall rule add failed', error);
            const message = typeof error?.message === 'string' ? error.message : '';
            if (message.includes('unsupported')) {
              res.writeHead(501, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall unsupported' }));
            } else {
              res.writeHead(504, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall request timed out' }));
            }
          });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const firewallRuleDeleteMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/delete$/);
  if (firewallRuleDeleteMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleDeleteMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.ruleName === 'string' ? payload.ruleName.trim() : '';
        if (!ruleName) {
          res.writeHead(400);
          return res.end('Rule name is required');
        }

        requestAgentFirewallAction(entry, {
          type: 'delete-rule',
          ruleName,
        })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule removal requested',
            }));
          })
          .catch((error) => {
            console.error('Firewall rule removal failed', error);
            const message = typeof error?.message === 'string' ? error.message : '';
            if (message.includes('unsupported')) {
              res.writeHead(501, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall unsupported' }));
            } else {
              res.writeHead(504, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall request timed out' }));
            }
          });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }
  const firewallStateMatch = pathname.match(/^\/firewall\/([^/]+)\/state$/);
  if (firewallStateMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallStateMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const profile = typeof payload?.profile === 'string' ? payload.profile.toLowerCase() : 'all';
        const enabled = payload?.enabled === true;
        if (entry.socket.readyState !== WebSocket.OPEN) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Agent offline' }));
          return;
        }

        requestAgentFirewallAction(entry, { type: 'state', profile, enabled })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Firewall state updated',
            }));
          })
            .catch((error) => {
              console.error('Firewall state update failed', error);
              const message = typeof error?.message === 'string' ? error.message : '';
              if (message.includes('unsupported')) {
                res.writeHead(501, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Firewall unsupported' }));
              } else {
                res.writeHead(504, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Firewall request timed out' }));
              }
            });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

  return;
}

  const baselineListMatch = pathname === '/firewall/baseline' && req.method === 'GET';
  if (baselineListMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ profiles: firewallBaselines }));
    return;
  }

  const baselineCreateMatch = pathname === '/firewall/baseline' && req.method === 'POST';
  if (baselineCreateMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = (payload?.name ?? '').toString().trim();
        const description = (payload?.description ?? '').toString().trim();
        const rules = Array.isArray(payload?.rules)
          ? payload.rules.map((rule) => ({
            ruleName: (rule?.ruleName ?? '').toString().trim(),
            enabled: Boolean(rule?.enabled),
          })).filter((rule) => rule.ruleName)
          : [];

        if (!name) {
          res.writeHead(400);
          return res.end('Profile name is required');
        }

        const profile = {
          id: uuidv4(),
          name,
          description,
          rules,
          assignedAgents: [],
          assignedGroups: [],
          createdAt: new Date().toISOString(),
        };
        firewallBaselines.push(profile);
        persistFirewallBaselines();

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const baselineAssignMatch = pathname.match(/^\/firewall\/baseline\/([^/]+)\/assign$/);
  if (baselineAssignMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = baselineAssignMatch[1];
    const profile = firewallBaselines.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Baseline not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agents = Array.isArray(payload?.agents) ? payload.agents : [];
        const groups = Array.isArray(payload?.groups) ? payload.groups : [];
        profile.assignedAgents = Array.from(new Set(agents.filter((id) => typeof id === 'string' && id.trim())));
        profile.assignedGroups = Array.from(new Set(groups.filter((name) => typeof name === 'string' && name.trim())));
        persistFirewallBaselines();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, profile }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const baselineApplyMatch = pathname.match(/^\/firewall\/baseline\/([^/]+)\/apply$/);
  if (baselineApplyMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = baselineApplyMatch[1];
    const profile = firewallBaselines.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Baseline not found');
    }

    const targetAgentIds = getBaselineTargetAgentIds(profile);
    const agentEntries = targetAgentIds
      .map((agentId) => clientsById.get(agentId))
      .filter((entry) => entry && entry.socket.readyState === WebSocket.OPEN);

    if (!agentEntries.length) {
      res.writeHead(400);
      return res.end('No connected agents available for this profile');
    }

    const applyPromises = [];
    for (const entry of agentEntries) {
      for (const rule of profile.rules) {
        if (!rule.ruleName) {
          continue;
        }

        applyPromises.push(
          requestAgentFirewallAction(entry, {
            type: 'rule',
            ruleName: rule.ruleName,
            enabled: Boolean(rule.enabled),
          }).catch(() => null),
        );
      }
    }

    Promise.allSettled(applyPromises)
      .then(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Baseline push requested',
          targetCount: agentEntries.length,
        }));
      })
      .catch(() => {
        res.writeHead(500);
        res.end('Unable to dispatch baseline');
      });

    return;
  }

  const vulnerabilityStatusMatch = pathname === '/vulnerabilities/status' && req.method === 'GET';
  if (vulnerabilityStatusMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getVulnerabilityStatus()));
    return;
  }

  const vulnerabilitySourcesBase = '/vulnerabilities/sources';
  const vulnerabilitySourcesMatch = pathname === vulnerabilitySourcesBase;
  if (vulnerabilitySourcesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const sources = (Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [])
      .map((entry) => formatSourceForClient(entry));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ sources }));
    return;
  }

  if (vulnerabilitySourcesMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const rawId = (payload.id ?? '').toString().trim().toLowerCase();
        if (!rawId || !/^[a-z0-9_-]+$/.test(rawId)) {
          res.writeHead(400);
          return res.end('Invalid source id');
        }
        if (getVulnerabilitySource(rawId)) {
          res.writeHead(409);
          return res.end('Source already exists');
        }
        const label = (payload.label ?? rawId).toString().trim();
        if (!label) {
          res.writeHead(400);
          return res.end('Label is required');
        }
        const source = {
          id: rawId,
          label,
          description: (payload.description ?? '').toString().trim(),
          type: (payload.type ?? 'custom').toString().trim(),
          url: (payload.url ?? '').toString().trim(),
          ingestionMinutes: Number.isFinite(Number(payload.ingestionMinutes))
            ? Math.max(1, Math.floor(Number(payload.ingestionMinutes)))
            : 60,
          enabled: payload.enabled === undefined ? true : Boolean(payload.enabled),
          builtin: false,
          lastIngested: null,
        };
        vulnerabilityConfig.sources = Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [];
        vulnerabilityConfig.sources.push(source);
        persistVulnerabilityConfig();
        rescheduleSourceIngestion(source.id);

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ source: formatSourceForClient(source) }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const vulnerabilitySourceIdMatch = pathname.match(/^\/vulnerabilities\/sources\/([^/]+)$/);
  if (vulnerabilitySourceIdMatch && req.method === 'PATCH') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const sourceId = vulnerabilitySourceIdMatch[1];
    const source = getVulnerabilitySource(sourceId);
    if (!source) {
      res.writeHead(404);
      res.end('Source not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        let mutated = false;
        if (payload.label !== undefined) {
          const label = `${payload.label}`.trim();
          if (label) {
            source.label = label;
            mutated = true;
          }
        }
        if (payload.description !== undefined) {
          source.description = `${payload.description}`.trim();
          mutated = true;
        }
        if (payload.url !== undefined) {
          source.url = `${payload.url}`.trim();
          mutated = true;
        }
        if (payload.type !== undefined) {
          source.type = `${payload.type}`.trim();
          mutated = true;
        }
        if (payload.ingestionMinutes !== undefined) {
          const minutes = Number(payload.ingestionMinutes);
          if (Number.isFinite(minutes) && minutes > 0) {
            source.ingestionMinutes = Math.max(1, Math.floor(minutes));
            mutated = true;
          }
        }
        if (payload.enabled !== undefined) {
          source.enabled = Boolean(payload.enabled);
          mutated = true;
        }

        if (mutated) {
          persistVulnerabilityConfig();
        }

        rescheduleSourceIngestion(source.id);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ source: formatSourceForClient(source) }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (vulnerabilitySourceIdMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const sourceId = vulnerabilitySourceIdMatch[1];
    const source = getVulnerabilitySource(sourceId);
    if (!source) {
      res.writeHead(404);
      res.end('Source not found');
      return;
    }
    if (source.builtin) {
      res.writeHead(400);
      res.end('Builtin sources cannot be removed; disable instead.');
      return;
    }

    vulnerabilityConfig.sources = (Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [])
      .filter((entry) => entry.id !== sourceId);
    persistVulnerabilityConfig();
    cancelSourceIngestion(sourceId);

    res.writeHead(204);
    res.end();
    return;
  }

  const vulnerabilityQueryMatch = pathname === '/vulnerabilities' && req.method === 'GET';
  if (vulnerabilityQueryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const query = requestedUrl.searchParams.get('q')?.trim().toLowerCase() ?? '';
    const limit = Number(requestedUrl.searchParams.get('limit')) || 50;
    const results = searchVulnerabilities(query, limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: results.total, items: results.items }));
    return;
  }

  const vulnerabilityRawMatch = pathname === '/vulnerabilities/raw' && req.method === 'GET';
  if (vulnerabilityRawMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    try {
      ensureDataDirectory();
      let raw = [];
      if (fs.existsSync(VULNERABILITY_STORE_PATH)) {
        let serialized = fs.readFileSync(VULNERABILITY_STORE_PATH, 'utf-8');
        if (serialized.charCodeAt(0) === 0xfeff) {
          serialized = serialized.slice(1);
        }
        raw = JSON.parse(serialized);
      }
      const params = requestedUrl.searchParams;
      const limit = Math.min(Math.max(Number(params.get('limit')) || 150, 10), 500);
      const offset = Math.max(Number(params.get('offset')) || 0, 0);
      const requestedSource = (params.get('source') ?? '').trim().toLowerCase();

      const availableSources = (Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [])
        .map((entry) => formatSourceForClient(entry));
      const normalizedRaw = Array.isArray(raw) ? raw.map((item) => (Array.isArray(item) && item.length >= 2 ? item[1] : item)) : [];

      const sourceTotals = {};
      for (const entry of normalizedRaw) {
        const entrySources = entry?.sources ?? {};
        for (const [key, value] of Object.entries(entrySources)) {
          if (value) {
            const normalizedKey = key.toLowerCase();
            sourceTotals[normalizedKey] = (sourceTotals[normalizedKey] ?? 0) + 1;
          }
        }
      }
      for (const source of availableSources) {
        const normalizedId = source.id?.toString().toLowerCase() ?? '';
        if (normalizedId && sourceTotals[normalizedId] === undefined) {
          sourceTotals[normalizedId] = 0;
        }
      }

      let filtered = normalizedRaw;
      if (requestedSource) {
        filtered = filtered.filter((entry) => {
          const entrySources = entry?.sources ?? {};
          return Object.entries(entrySources).some(([key, value]) => value && key.toString().toLowerCase() === requestedSource);
        });
      }

      filtered = filtered
        .slice()
        .sort((a, b) => (b?.cveId ?? '').localeCompare(a?.cveId ?? ''));

      const total = filtered.length;
      const slice = filtered.slice(offset, offset + limit);
      const entries = slice
        .map((entry) => ({
          cveId: entry?.cveId ?? null,
          description: entry?.description ?? '',
          cvss: entry?.cvss ?? null,
          lastUpdated: entry?.lastUpdated ?? null,
          sources: entry?.sources ?? {},
          cpes: Array.isArray(entry?.cpes) ? entry.cpes : [],
          kbArticleIDs: Array.isArray(entry?.kbArticleIDs) ? entry.kbArticleIDs : [],
          link: entry?.cveId ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(entry.cveId)}` : null,
          target: formatCveTargetLabel(entry),
        }));

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        total,
        offset,
        limit,
        entries,
        sources: availableSources,
        sourceTotals,
        requestedSource: requestedSource || 'all',
      }));
    } catch (error) {
      console.error('Unable to serve raw vulnerability data', error);
      res.writeHead(500);
      res.end('Unable to read vulnerability data');
    }

    return;
  }

  const vulnerabilityAssetMatch = pathname.match(/^\/vulnerabilities\/asset\/([^/]+)$/);
  if (vulnerabilityAssetMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = vulnerabilityAssetMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    const results = evaluateAssetVulnerabilities(entry.info);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ agentId, total: results.length, vulnerabilities: results }));
    return;
  }

  const systemHealthMatch = pathname === '/system-health/agents' && req.method === 'GET';
  if (systemHealthMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentInfos = Array.from(agents.values());
    const statsPromises = agentInfos.map(async (info) => {
      const clientEntry = clientsById.get(info.id);
      if (clientEntry?.socket?.readyState === WebSocket.OPEN) {
        try {
          const result = await requestAgentEventStats(clientEntry);
          const record = {
            stats: typeof result.stats === 'object' && result.stats !== null ? result.stats : {},
            since: typeof result.since === 'string' ? result.since : new Date().toISOString(),
            retrievedAt: new Date().toISOString(),
          };
          agentEventStatsCache.set(info.id, record);
          return formatSystemHealthPayload(info, record.stats, record.since, record.retrievedAt, { source: 'live' });
        } catch (error) {
          const cache = agentEventStatsCache.get(info.id);
          return formatSystemHealthPayload(info, cache?.stats ?? null, cache?.since ?? null, cache?.retrievedAt ?? null, {
            offline: true,
            error: error?.message ?? 'Event stats request failed',
          });
        }
      }

      const cache = agentEventStatsCache.get(info.id);
      return formatSystemHealthPayload(info, cache?.stats ?? null, cache?.since ?? null, cache?.retrievedAt ?? null, { offline: true });
    });

    try {
      const payload = await Promise.all(statsPromises);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        agents: payload,
        summary: {
          totalAgents: agentInfos.length,
          retrievedAt: new Date().toISOString(),
        },
      }));
    } catch (error) {
      console.error('System health stats failed', error);
      res.writeHead(500);
      res.end('Unable to gather event log stats');
    }

    return;
  }

  const systemHealthAgentMatch = pathname.match(/^\/system-health\/agent\/([^/]+)$/);
  if (systemHealthAgentMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = systemHealthAgentMatch[1];
    const agentInfo = agents.get(agentId) ?? clientsById.get(agentId)?.info ?? null;
    const clientEntry = clientsById.get(agentId);
    let record = agentEventStatsCache.get(agentId);
    let offline = true;
    let errorMessage = null;

    if (clientEntry?.socket?.readyState === WebSocket.OPEN) {
      try {
        const result = await requestAgentEventStats(clientEntry);
        record = {
          stats: typeof result.stats === 'object' && result.stats !== null ? result.stats : {},
          since: typeof result.since === 'string' ? result.since : new Date().toISOString(),
          retrievedAt: new Date().toISOString(),
        };
        agentEventStatsCache.set(agentId, record);
        offline = false;
      } catch (error) {
        offline = true;
        errorMessage = error?.message ?? 'Event stats request failed';
      }
    }

    if (!record) {
      record = {
        stats: null,
        since: null,
        retrievedAt: null,
      };
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      agentId,
      name: agentInfo?.name ?? agentId,
      os: agentInfo?.os ?? agentInfo?.platform ?? 'unknown',
      platform: agentInfo?.platform ?? null,
      status: agentInfo?.status ?? (clientEntry ? 'online' : 'offline'),
      loggedInUser: agentInfo?.loggedInUser ?? null,
      group: agentInfo?.group ?? DEFAULT_GROUP,
      pendingReboot: Boolean(agentInfo?.pendingReboot),
      eventStats: record.stats,
      since: record.since,
      retrievedAt: record.retrievedAt,
      offline,
      error: errorMessage,
    }));

    return;
  }

  const systemHealthEntriesMatch = pathname.match(/^\/system-health\/([^/]+)\/entries$/);
  if (systemHealthEntriesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = systemHealthEntriesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent unavailable' }));
      return;
    }

    const requestedLevel = (requestedUrl.searchParams.get('level') ?? '').trim();
    const level = requestedLevel || 'Information';

    try {
      const result = await requestAgentEventEntries(entry, level);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        agentId,
        level: result.level ?? level,
        entries: Array.isArray(result.entries) ? result.entries : [],
        retrievedAt: new Date().toISOString(),
      }));
    } catch (error) {
      res.writeHead(504, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error?.message ?? 'Event entries request timed out' }));
    }

    return;
  }

  const agentServicesMatch = pathname.match(/^\/agent\/([^/]+)\/services$/);
  if (agentServicesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = agentServicesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    requestAgentServiceList(entry)
      .then((services) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ services }));
      })
      .catch(() => {
        res.writeHead(504);
        res.end('Unable to retrieve services');
      });

    return;
  }

  const agentServiceActionMatch = pathname.match(/^\/agent\/([^/]+)\/service\/([^/]+)\/action$/);
  if (agentServiceActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = agentServiceActionMatch[1];
    const serviceName = decodeURIComponent(agentServiceActionMatch[2]);
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, async (body) => {
      try {
        const payload = JSON.parse(body);
        const action = (payload?.action ?? '').toString().trim().toLowerCase();
        if (!['start', 'stop', 'restart'].includes(action)) {
          res.writeHead(400);
          return res.end('Invalid action');
        }

        const result = await performServiceAction(entry, serviceName, action);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: Boolean(result.success),
          message: result.message ?? 'Action completed',
        }));
      } catch (error) {
        console.error('Service action failed', error);
        res.writeHead(500);
        res.end('Service action failed');
      }
    });

    return;
  }

  const screenAnswerMatch = pathname.match(/^\/screen\/([^/]+)\/answer$/);
  if (screenAnswerMatch && req.method === 'POST') {
    const sessionId = screenAnswerMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        sendControl(session.socket, 'screen-answer', {
          sessionId,
          sdp: payload.sdp,
          sdpType: payload.type,
        });
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid SDP');
      }
    });

    return;
  }

  const screenCandidateMatch = pathname.match(/^\/screen\/([^/]+)\/candidate$/);
  if (screenCandidateMatch && req.method === 'POST') {
    const sessionId = screenCandidateMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        sendControl(session.socket, 'screen-candidate', {
          sessionId,
          candidate: payload.candidate,
          sdpMid: payload.sdpMid,
          sdpMLineIndex: payload.sdpMLineIndex,
        });
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid candidate');
      }
    });

    return;
  }

  const screenStopMatch = pathname.match(/^\/screen\/([^/]+)\/stop$/);
  if (screenStopMatch && req.method === 'POST') {
    const sessionId = screenStopMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    sendControl(session.socket, 'stop-screen', { sessionId });
    screenSessions.delete(sessionId);
    res.writeHead(204);
    res.end();
    return;
  }

  const filePath = pathname === '/' ? '/index.html' : pathname;
  const resolved = path.join(PUBLIC_DIR, decodeURIComponent(filePath));
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(resolved, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end('Not found');
    }

    const ext = path.extname(resolved);
    const mime = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (socket, request) => {
  const remote = request.socket.remoteAddress ?? 'unknown';
  const forwarded = request.headers['x-forwarded-for'];
  const externalIp = typeof forwarded === 'string'
    ? forwarded.split(',')[0].trim()
    : remote;
  const id = uuidv4();
  let info = {
    id,
    socket,
    name: `unnamed (${remote})`,
    remoteAddress: remote,
    internalIp: null,
    externalIp,
    connectedAt: new Date().toISOString(),
    os: 'unknown',
    platform: 'unknown',
    group: DEFAULT_GROUP,
    status: 'online',
    lastSeen: null,
    specs: null,
    updatesSummary: null,
    bsodSummary: null,
    processSnapshot: null,
    loggedInUser: 'Unknown',
    pendingReboot: false,
    softwareSummary: null,
    features: [],
    snmpDiscoveryEnabled: isSnmpDiscoveryEnabled(id),
    bitlockerStatus: null,
    avStatus: null,
    license: null,
    tenantId: DEFAULT_TENANT_ID,
    identified: false,
  };

  {
    const storedGroup = agentGroupAssignments.get(info.id);
    if (storedGroup) {
      info.group = storedGroup;
      groups.add(storedGroup);
    }
  }

  clients.set(socket, info);
  agents.set(id, info);
  clientsById.set(id, { socket, info });

  console.log(`Client connected from ${remote}`);
  socket.send('Welcome to the secure WebSocket server!');

  socket.on('message', (data) => {
    const payload = data.toString();
    console.log(`Received: ${payload}`);

    try {
      const parsed = JSON.parse(payload);
      if (parsed?.type === 'chat-response') {
        const text = typeof parsed.text === 'string' ? parsed.text.trim() : '';
        if (text.length > 0) {
          const chatEvent = {
            sessionId: typeof parsed.sessionId === 'string' && parsed.sessionId.trim()
              ? parsed.sessionId.trim()
              : uuidv4(),
            agentId: info.id,
            agentName: info.name,
            direction: 'agent',
            text,
            timestamp: new Date().toISOString(),
            user: info.loggedInUser ?? info.name,
            role: 'agent',
          };

          recordChatHistory(info.id, chatEvent);
          dispatchChatEvent(info.id, chatEvent);
          scheduleAiAgentResponse(info, chatEvent);
        }
        return;
      }

      if (parsed?.type === 'hello' && typeof parsed.name === 'string' && parsed.name.trim()) {
        const licenseCode = typeof parsed.license === 'string'
          ? parsed.license.trim()
          : '';
        const licenseRecord = licenseCode ? getLicenseRecord(licenseCode) : null;
        if (!licenseRecord || licenseRecord.revokedAt) {
          sendControl(socket, 'license-result', { success: false, message: 'License invalid or revoked' });
          socket.close(1008, 'invalid license');
          return;
        }
        const requestedId = typeof parsed.agentId === 'string' && parsed.agentId.trim()
          ? parsed.agentId.trim()
          : info.id;
        if (licenseRecord.assignedAgentId && licenseRecord.assignedAgentId !== requestedId) {
          sendControl(socket, 'license-result', { success: false, message: 'License already assigned to another agent' });
          socket.close(1008, 'license already assigned');
          return;
        }
        assignLicenseToAgent(licenseCode, requestedId);
        if (requestedId !== info.id) {
          clientsById.delete(info.id);
          agents.delete(info.id);
          const existing = agents.get(requestedId);
          if (existing) {
            info = existing;
          } else {
            info = { ...info, id: requestedId };
          }
          const assignedGroup = agentGroupAssignments.get(requestedId);
          if (assignedGroup) {
            info.group = assignedGroup;
            groups.add(assignedGroup);
          } else if (!info.group) {
            info.group = DEFAULT_GROUP;
          }
          agents.set(requestedId, info);
        }

        info.name = parsed.name.trim();
        if (typeof parsed.os === 'string' && parsed.os.trim()) {
          info.os = parsed.os.trim();
          evaluateAssetVulnerabilities(info);
        }
        if (typeof parsed.platform === 'string' && parsed.platform.trim()) {
          info.platform = parsed.platform.trim();
        }
        if (typeof parsed.loggedInUser === 'string' && parsed.loggedInUser.trim()) {
          info.loggedInUser = parsed.loggedInUser.trim();
        }
        if (typeof parsed.internalIp === 'string') {
          const trimmed = parsed.internalIp.trim();
          if (trimmed) {
            info.internalIp = trimmed;
          }
        } else if (parsed.internalIp === null) {
          info.internalIp = null;
        }
        if (typeof parsed.externalIp === 'string') {
          const trimmed = parsed.externalIp.trim();
          if (trimmed) {
            info.externalIp = trimmed;
          }
        } else if (parsed.externalIp === null) {
          info.externalIp = null;
        }
        info.license = licenseCode;
        info.tenantId = getLicenseTenantId(licenseRecord);
        info.identified = true;
        info.snmpDiscoveryEnabled = isSnmpDiscoveryEnabled(info.id);
        markLicenseUsed(licenseCode);
        sendControl(socket, 'license-result', { success: true });
        if (parsed.specs != null) {
          info.specs = parsed.specs;
          void maybeRefreshWarranty(info);
        }
        if (Array.isArray(parsed.features)) {
          info.features = parsed.features.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
        }

        info.bitlockerStatus = normalizeBitlockerStatus(parsed.bitlockerStatus);
        info.avStatus = normalizeAvStatus(parsed.avStatus);
        if (typeof parsed.pendingReboot === 'boolean') {
          info.pendingReboot = parsed.pendingReboot;
        }

        info.status = 'online';
        info.lastSeen = null;
        console.log(`Identified client as ${info.name}`);
        info.socket = socket;
        clients.set(socket, info);
        clientsById.set(info.id, { socket, info });
        notifyMonitoringState({ socket, info });
        sendComplianceDefinitions(socket, info.id, true);
        sendGpoDefinitions(socket, info.id, true);
      } else if (parsed?.type === 'shell-output') {
        emitShellOutput(info.id, parsed);
      } else if (parsed?.type === 'screen-offer') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          session.offer = {
            sdp: parsed.sdp,
            sdpType: parsed.sdpType,
          };
          console.log(`Stored screen offer for ${parsed.sessionId} (agent ${session.agentName})`);
          sendScreenEvent(session, 'offer', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            ...session.offer,
            screenId: session.screenId,
            screenName: getScreenName(session.agentId, session.screenId),
          });
          sendScreenEvent(session, 'status', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            state: 'offer-ready',
            screenId: session.screenId,
            screenName: getScreenName(session.agentId, session.screenId),
          });
        }
      } else if (parsed?.type === 'screen-candidate') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          const candidate = {
            candidate: parsed.candidate,
            sdpMid: parsed.sdpMid,
            sdpMLineIndex: parsed.sdpMLineIndex,
          };
          session.agentCandidates.push(candidate);
          console.log(`Stored screen candidate for ${parsed.sessionId}`);
          sendScreenEvent(session, 'candidate', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            ...candidate,
          });
        }
      } else if (parsed?.type === 'screen-error') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          console.log(`Screen error from agent ${session.agentName}: ${parsed.message}`);
          sendScreenEvent(session, 'error', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            message: parsed.message,
          });
        }
      } else if (parsed?.type === 'updates-summary') {
      info.updatesSummary = parsed.summary ?? null;
      if (typeof parsed.pendingReboot === 'boolean') {
        info.pendingReboot = parsed.pendingReboot;
      }
      } else if (parsed?.type === 'bsod-summary') {
        info.bsodSummary = parsed.summary ?? null;
      } else if (parsed?.type === 'update-install-result') {
        console.log(`Update install result from ${info.name}: success=${parsed.success}, message="${parsed.message}", rebootRequired=${parsed.rebootRequired}`);
        info.pendingReboot = Boolean(parsed.rebootRequired);
        const scheduleId = typeof parsed.scheduleId === 'string' && parsed.scheduleId.trim()
          ? parsed.scheduleId.trim()
          : null;
        if (scheduleId) {
          const schedule = patchSchedules.get(scheduleId);
          logPatchEvent({
            timestamp: new Date().toISOString(),
            type: 'result',
            scheduleId,
            scheduleName: schedule?.name ?? null,
            agentId: info.id,
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
            rebootRequired: Boolean(parsed.rebootRequired),
            patchIds: schedule?.patchIds ?? [],
          });
        }
        } else if (parsed?.type === 'process-list') {
          info.processSnapshot = parsed.snapshot ?? null;
        } else if (parsed?.type === 'process-kill-result') {
        console.log(`Process kill result from ${info.name}: pid=${parsed.processId}, success=${parsed.success}, message=${parsed.message ?? 'n/a'}`);
      } else if (parsed?.type === 'file-list' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'file-download-result' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'file-upload-result' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
    } else if (parsed?.type === 'software-list' && typeof parsed.requestId === 'string') {
      const pending = completeSoftwareRequest(parsed.requestId);
      if (pending) {
        const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
        const retrievedAt = typeof parsed.retrievedAt === 'string' ? parsed.retrievedAt : new Date().toISOString();
        pending.resolve({ entries, retrievedAt });
        info.softwareSummary = {
          totalCount: entries.length,
          lastUpdated: retrievedAt,
        };
      }
      } else if (parsed?.type === 'service-list' && typeof parsed.requestId === 'string') {
        const pending = completeServiceRequest(parsed.requestId);
        if (pending) {
          pending.resolve(Array.isArray(parsed.services) ? parsed.services : []);
        }
      } else if (parsed?.type === 'service-action-result' && typeof parsed.requestId === 'string') {
        const pending = completeServiceActionRequest(parsed.requestId);
        if (pending) {
          pending.resolve({
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
            serviceName: parsed.serviceName ?? '',
            action: parsed.action ?? '',
          });
        }
      } else if (parsed?.type === 'firewall-rules' && typeof parsed.requestId === 'string') {
        const pending = completeFirewallRequest(parsed.requestId);
        if (pending && pending.kind === 'rules') {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'firewall-action-result' && typeof parsed.requestId === 'string') {
        const pending = completeFirewallRequest(parsed.requestId);
        if (pending && pending.kind === 'action') {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'event-stats' && typeof parsed.requestId === 'string') {
        const pending = completeEventStatsRequest(parsed.requestId);
        if (pending) {
          const stats = typeof parsed.stats === 'object' && parsed.stats !== null ? parsed.stats : {};
          const since = typeof parsed.since === 'string' ? parsed.since : new Date().toISOString();
          const record = {
            stats,
            since,
            retrievedAt: new Date().toISOString(),
          };
          agentEventStatsCache.set(info.id, record);
          pending.resolve({
            stats: record.stats,
            since: record.since,
            retrievedAt: record.retrievedAt,
          });
        }
      } else if (parsed?.type === 'event-entries' && typeof parsed.requestId === 'string') {
        const pending = completeEventEntriesRequest(parsed.requestId);
        if (pending) {
          const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
          const normalizedLevel = typeof parsed.level === 'string' ? parsed.level : 'Information';
          agentEventEntriesCache.set(info.id, {
            entries: entries.slice(0, 100),
            level: normalizedLevel,
            retrievedAt: new Date().toISOString(),
          });
          pending.resolve({
            entries,
            level: normalizedLevel,
          });
        }
    } else if (parsed?.type === 'software-operation-result') {
          handleSoftwareOperationResult(info, parsed);
        } else if (parsed?.type === 'action-result') {
          logPatchEvent({
            timestamp: new Date().toISOString(),
            type: 'result',
            agentId: info.id,
            action: parsed.action ?? null,
            scheduleId: parsed.scheduleId ?? null,
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
          });
        } else if (parsed?.type === 'screen-list' && Array.isArray(parsed.screens)) {
        const normalized = parsed.screens.map((screen, index) => ({
          id: typeof screen.id === 'string' && screen.id.trim() ? screen.id.trim() : `display-${index + 1}`,
          name: typeof screen.name === 'string' && screen.name.trim() ? screen.name.trim() : `Display ${index + 1}`,
          width: typeof screen.width === 'number' ? screen.width : null,
          height: typeof screen.height === 'number' ? screen.height : null,
          x: typeof screen.x === 'number' ? screen.x : null,
          y: typeof screen.y === 'number' ? screen.y : null,
          primary: Boolean(screen.primary),
        }));

        screenLists.set(info.id, { screens: normalized, updatedAt: Date.now() });
        fulfillScreenListRequest(info.id, normalized);
      } else if (parsed?.type === 'monitoring-metrics') {
        handleMonitoringMetrics(info, socket, parsed);
      } else if ((parsed?.type === 'snmp-scan-result' || parsed?.type === 'snmp-scan-complete' || parsed?.type === 'snmp-scan-error') && typeof parsed.requestId === 'string') {
        const agentId = typeof parsed.agentId === 'string' ? parsed.agentId : info.id;
        const eventType = parsed.type === 'snmp-scan-result'
          ? 'snmp-result'
          : parsed.type === 'snmp-scan-complete'
            ? 'snmp-complete'
            : 'snmp-error';
        dispatchSnmpEvent(agentId, parsed.requestId, eventType, parsed);
      } else if ((parsed?.type === 'network-scanner-result' || parsed?.type === 'network-scanner-complete' || parsed?.type === 'network-scanner-error') && typeof parsed.requestId === 'string') {
        const agentId = typeof parsed.agentId === 'string' ? parsed.agentId : info.id;
        const eventType = parsed.type;
        dispatchNetworkEvent(agentId, parsed.requestId, eventType, parsed);
      } else if (parsed?.type === 'network-scanner-wake-result') {
        const agentId = typeof parsed.agentId === 'string' ? parsed.agentId : info.id;
        const requestId = typeof parsed.requestId === 'string' ? parsed.requestId : uuidv4();
        dispatchNetworkEvent(agentId, requestId, 'network-scanner-wake-result', parsed);
      } else if (parsed?.type === 'remediation-result') {
        sendMonitoringEvent('remediation-result', {
          type: 'remediation-result',
          agentId: info.id,
          agentName: info.name,
          requestId: parsed.requestId,
          success: Boolean(parsed.success),
          message: parsed.message ?? '',
          scriptName: parsed.scriptName ?? '',
          timestamp: new Date().toISOString(),
        });
        } else if (parsed?.type === 'compliance-report') {
          handleComplianceReport(info.id, parsed);
        } else if (parsed?.type === 'gpo-result') {
          console.log(`GPO apply result from ${info.id}: ${parsed.success ? 'success' : 'failure'} - ${parsed.message ?? 'no details'}`);
        }
    } catch (error) {
      // ignore invalid JSON and continue echoing
    }

    socket.send(`Echo: ${payload}`);
  });

  socket.on('close', () => {
    info.status = 'offline';
    info.lastSeen = new Date().toISOString();
    clients.delete(socket);
    clientsById.delete(id);
    if (!info.identified) {
      agents.delete(id);
      agentGroupAssignments.delete(id);
    }
    shellStreams.delete(id);
    shellOutputHistory.delete(id);
    screenLists.delete(id);
    cancelScreenListRequest(id, new Error('agent disconnected'));
    agentProfileStatus.delete(id);
    for (const [requestId, request] of softwareRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        softwareRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of eventStatsRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        eventStatsRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of eventEntriesRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        eventEntriesRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of firewallRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        firewallRequests.delete(requestId);
      }
    }
    for (const [sessionId, session] of screenSessions) {
      if (session.agentId === id) {
        sendScreenEvent(session, 'closed', { reason: 'agent disconnected' });
        screenSessions.delete(sessionId);
      }
    }
    console.log(`Client disconnected: ${info.name}`);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`HTTPS server listening on https://localhost:${PORT}`);
    console.log(`WebSocket endpoint available at wss://localhost:${PORT}`);
    console.log('Agent dashboard available via the root path');
    startVulnerabilityIngestion();
    broadcastComplianceDefinitions({ runNow: true });
  });
}

module.exports = {
  ingestNvdFeed,
  ingestKevCatalog,
  ingestEpssScores,
};

function sendControl(socket, type, additional = {}) {
  if (socket.readyState !== WebSocket.OPEN) {
    console.log(`Cannot send ${type}; socket state ${socket.readyState}`);
    return;
  }

  const message = JSON.stringify({ type, ...additional });
  console.log(`sendControl ${type} -> ${message}`);
  socket.send(message);
}

function emitShellOutput(agentId, data) {
  const stream = shellStreams.get(agentId);
  if (!stream) {
    return;
  }

  const entry = {
    output: data.output,
    stream: data.stream,
    timestamp: new Date().toISOString(),
  };
  const history = shellOutputHistory.get(agentId) ?? [];
  history.push(entry);
  if (history.length > SHELL_HISTORY_LIMIT) {
    history.shift();
  }
  shellOutputHistory.set(agentId, history);
  notifyShellOutputWaiters(agentId);

  const payload = {
    output: data.output,
    stream: data.stream,
    timestamp: entry.timestamp,
  };

  stream.write('event: shell\n');
  stream.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function collectBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    callback(body);
  });
}

function sendScreenEvent(session, eventName, data) {
  const payload = JSON.stringify(data);
  console.log(`dispatching ${eventName} for ${session.agentId}`);
  for (const res of session.sseClients) {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${payload}\n\n`);
  }
}

function isPatchApproved(agentId, updateId) {
  if (!agentId || !updateId) {
    return false;
  }

  return patchApprovals.has(`${agentId}:${updateId}`);
}

function buildPatchCatalog() {
  const catalog = new Map();

  for (const info of agents.values()) {
    const summary = info.updatesSummary;
    if (!summary?.categories?.length) {
      continue;
    }

    for (const category of summary.categories) {
      const updates = Array.isArray(category.updates) ? category.updates : [];
      for (const update of updates) {
        const updateId = typeof update?.id === 'string' && update.id.trim() ? update.id.trim() : '';
        if (!updateId) {
          continue;
        }

        let entry = catalog.get(updateId);
        if (!entry) {
          entry = {
            id: updateId,
            title: update.title ?? 'Unnamed update',
            description: update.description ?? '',
            categories: new Map(),
            kbArticleIDs: new Set(),
            agents: new Map(),
          };
          catalog.set(updateId, entry);
        }

        if (category?.name) {
          entry.categories.set(category.name, category.purpose ?? '');
        }

        if (Array.isArray(update.kbArticleIDs)) {
          for (const kb of update.kbArticleIDs) {
            if (typeof kb === 'string' && kb.trim()) {
              entry.kbArticleIDs.add(kb.trim());
            }
          }
        }

        const agentKey = info.id ?? '';
        if (!agentKey) {
          continue;
        }

        let agentRecord = entry.agents.get(agentKey);
        if (!agentRecord) {
          agentRecord = {
            agentId: agentKey,
            agentName: info.name ?? agentKey,
            status: info.status ?? 'offline',
            group: info.group ?? DEFAULT_GROUP,
            approved: false,
            pendingReboot: Boolean(info.pendingReboot),
          };
          entry.agents.set(agentKey, agentRecord);
        }

        agentRecord.status = info.status ?? 'offline';
        agentRecord.pendingReboot = Boolean(info.pendingReboot);
        agentRecord.group = info.group ?? DEFAULT_GROUP;
        agentRecord.approved = isPatchApproved(agentKey, updateId);
      }
    }
  }

  return Array.from(catalog.values()).map((entry) => ({
    id: entry.id,
    title: entry.title,
    description: entry.description,
    categories: Array.from(entry.categories.entries()).map(([name, purpose]) => ({ name, purpose })),
    kbArticleIDs: Array.from(entry.kbArticleIDs),
    agents: Array.from(entry.agents.values()),
    primaryCategory: selectPrimaryCategory(entry.categories),
  }));
}

function buildPatchSummary(patches) {
  const agentIds = new Set();
  let approvedCount = 0;
  let pendingCount = 0;
  let rebootCount = 0;
  for (const patch of patches) {
    for (const agent of patch.agents) {
      agentIds.add(agent.agentId);
      if (agent.approved) {
        approvedCount += 1;
      } else {
        pendingCount += 1;
      }
      if (agent.pendingReboot) {
        rebootCount += 1;
      }
    }
  }

  return {
    totalPatches: patches.length,
    totalAgents: agentIds.size,
    approvedPairs: approvedCount,
    pendingApprovals: pendingCount,
    pendingReboots: rebootCount,
  };
}

function collectApprovedAgentsForPatches(patchIds) {
  const patchSet = new Set(patchIds);
  const targets = new Map();
  for (const key of patchApprovals.keys()) {
    const separator = key.indexOf(':');
    if (separator === -1) {
      continue;
    }

    const agentId = key.slice(0, separator);
    const updateId = key.slice(separator + 1);
    if (!patchSet.has(updateId)) {
      continue;
    }

    const updates = targets.get(agentId) ?? new Set();
    updates.add(updateId);
    targets.set(agentId, updates);
  }
  return targets;
}

function getSoftwareCatalogKey(software) {
  if (!software) {
    return 'unknown';
  }

  const idPart = typeof software.id === 'string' && software.id.trim();
  if (idPart) {
    return idPart.trim();
  }

  const namePart = (software.name ?? '').toString().trim() || 'unknown';
  const versionPart = (software.version ?? '').toString().trim();
  const publisherPart = (software.publisher ?? '').toString().trim();
  return `${namePart}::${versionPart}::${publisherPart}`;
}

function getSoftwareState(softwareId) {
  const record = softwareApprovals.get(softwareId);
  return record?.state ?? 'pending';
}

function buildSoftwareCatalog() {
  const catalog = new Map();
  const agentSet = new Set();
  for (const { info } of clientsById.values()) {
    const agentId = info.id;
    if (!agentId) {
      continue;
    }

    agentSet.add(agentId);
    const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
    entries.forEach((softwareItem) => {
      const softwareId = softwareItem.__catalogId ?? getSoftwareCatalogKey(softwareItem);
      softwareItem.__catalogId = softwareId;
      let record = catalog.get(softwareId);
      if (!record) {
        record = {
          id: softwareId,
          name: softwareItem.name ?? 'Unknown',
          version: softwareItem.version ?? '',
          publisher: softwareItem.publisher ?? '',
          source: softwareItem.source ?? '',
          agents: new Map(),
        };
        catalog.set(softwareId, record);
      }

      record.agents.set(agentId, {
        agentId,
        agentName: info.name ?? agentId,
        status: info.status ?? 'offline',
        source: softwareItem.source ?? '',
        version: softwareItem.version ?? '',
        publisher: softwareItem.publisher ?? '',
        installDate: softwareItem.installDate ?? '',
        location: softwareItem.location ?? '',
        uninstallCommand: softwareItem.uninstallCommand ?? '',
        packageFullName: softwareItem.packageFullName ?? '',
        productCode: softwareItem.productCode ?? '',
        softwareId: softwareId,
      });
    });
  }

  const list = Array.from(catalog.values()).map((entry) => {
    const status = getSoftwareState(entry.id);
    return {
      id: entry.id,
      name: entry.name,
      version: entry.version,
      publisher: entry.publisher,
      source: entry.source,
      status,
      agents: Array.from(entry.agents.values()),
      agentCount: entry.agents.size,
    };
  });

  updateSoftwareUninstallQueue(list);
  return {
    list,
    agentCount: agentSet.size,
    rejectedPairs: list.reduce((total, software) => {
      if (software.status === 'rejected') {
        return total + software.agentCount;
      }
      return total;
    }, 0),
  };
}

function updateSoftwareUninstallQueue(softwareList) {
  const rejectedSet = new Set();

  softwareList.forEach((software) => {
    if (software.status !== 'rejected') {
      softwareUninstallQueue.delete(software.id);
      return;
    }

    rejectedSet.add(software.id);
    let queue = softwareUninstallQueue.get(software.id);
    if (!queue) {
      queue = { pending: new Set(), lastAttempt: new Map() };
    }

    const currentAgents = new Set();
    software.agents.forEach((agent) => {
      queue.pending.add(agent.agentId);
      currentAgents.add(agent.agentId);
    });

    for (const agentId of Array.from(queue.pending)) {
      if (!currentAgents.has(agentId)) {
        queue.pending.delete(agentId);
      }
    }

    if (queue.pending.size === 0) {
      return softwareUninstallQueue.delete(software.id);
    }

    softwareUninstallQueue.set(software.id, queue);
  });

  for (const softwareId of Array.from(softwareUninstallQueue.keys())) {
    if (!rejectedSet.has(softwareId)) {
      softwareUninstallQueue.delete(softwareId);
    }
  }
}

async function refreshSoftwareEntriesFromAgents() {
  const clients = Array.from(clientsById.values());
  await Promise.allSettled(clients.map(async (entry) => {
    if (entry.socket.readyState !== WebSocket.OPEN) {
      return;
    }

    try {
      const result = await requestAgentSoftwareList(entry);
      const normalized = Array.isArray(result.entries)
        ? result.entries.map((item) => {
            const clone = { ...item };
            clone.__catalogId = getSoftwareCatalogKey(clone);
            return clone;
          })
        : [];
      entry.info.softwareEntries = normalized;
      entry.info.softwareRetrievedAt = result.retrievedAt;
      evaluateAssetVulnerabilities(entry.info);
    } catch (error) {
      console.warn('Software refresh failed for', entry.info.id, error);
    }
  }));
}

function logSoftwareEvent(entry) {
  softwareUninstallLog.unshift(entry);
  if (softwareUninstallLog.length > SOFTWARE_UNINSTALL_LOG_LIMIT) {
    softwareUninstallLog.pop();
  }
}

function handleSoftwareOperationResult(info, parsed) {
  const softwareId = parsed.softwareId;
  if (!softwareId) {
    return;
  }

  const queue = softwareUninstallQueue.get(softwareId);
  if (!queue) {
    return;
  }

  if (parsed.success) {
    queue.pending.delete(info.id);
    queue.lastAttempt.delete(info.id);
    logSoftwareEvent({
      timestamp: new Date().toISOString(),
      type: 'uninstall-success',
      softwareId,
      agentId: info.id,
      agentName: info.name,
      softwareName: parsed.softwareName ?? '',
      message: parsed.message ?? 'Uninstall completed',
    });
  } else {
    queue.lastAttempt.set(info.id, Date.now());
    logSoftwareEvent({
      timestamp: new Date().toISOString(),
      type: 'uninstall-failure',
      softwareId,
      agentId: info.id,
      agentName: info.name,
      softwareName: parsed.softwareName ?? '',
      message: parsed.message ?? 'Uninstall failed',
    });
  }

  if (!queue.pending.size) {
    softwareUninstallQueue.delete(softwareId);
  } else {
    // ensure we attempt again soon
    setTimeout(processSoftwareUninstalls, 5_000);
  }
}

function findAgentSoftwareEntry(info, softwareId) {
  const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  return entries.find((item) => (item.__catalogId ?? getSoftwareCatalogKey(item)) === softwareId) ?? null;
}

function queueRejectedSoftwareNow(softwareId) {
  const queue = softwareUninstallQueue.get(softwareId) ?? { pending: new Set(), lastAttempt: new Map() };
  queue.pending.clear();
  for (const { info } of clientsById.values()) {
    const softwareEntry = findAgentSoftwareEntry(info, softwareId);
    if (softwareEntry && info.id) {
      queue.pending.add(info.id);
    }
  }

  if (!queue.pending.size) {
    return softwareUninstallQueue.delete(softwareId);
  }

  softwareUninstallQueue.set(softwareId, queue);
  processSoftwareUninstalls();
}

  function processSoftwareUninstalls() {
  if (!softwareUninstallQueue.size) {
    return;
  }

  for (const [softwareId, queue] of Array.from(softwareUninstallQueue.entries())) {
    if (!queue.pending.size) {
      softwareUninstallQueue.delete(softwareId);
      continue;
    }

    for (const agentId of Array.from(queue.pending)) {
      const entry = clientsById.get(agentId);
      if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
        continue;
      }

        const softwareEntry = findAgentSoftwareEntry(entry.info, softwareId);
        if (!softwareEntry) {
          queue.pending.delete(agentId);
          continue;
        }

        const hasPackageFullName = typeof softwareEntry.packageFullName === 'string' && softwareEntry.packageFullName.trim().length > 0;
        const hasUninstallCommand = typeof softwareEntry.uninstallCommand === 'string' && softwareEntry.uninstallCommand.trim().length > 0;
        const hasProductCode = typeof softwareEntry.productCode === 'string' && softwareEntry.productCode.trim().length > 0;

        if (!hasPackageFullName && !hasUninstallCommand && !hasProductCode) {
          queue.pending.delete(agentId);
          logSoftwareEvent({
            timestamp: new Date().toISOString(),
            type: 'uninstall-failure',
            softwareId,
            agentId,
            agentName: entry.info.name,
            softwareName: softwareEntry.name ?? '',
            message: 'No uninstall payload available (missing appx name, command, and product code).',
          });
          continue;
        }

        const requestId = uuidv4();
        const payload = {
          requestId,
          softwareId,
          source: hasPackageFullName ? 'appx' : 'registry',
          uninstallCommand: hasUninstallCommand ? softwareEntry.uninstallCommand?.trim() ?? null : null,
          packageFullName: hasPackageFullName ? softwareEntry.packageFullName?.trim() ?? null : null,
          productCode: hasProductCode ? softwareEntry.productCode?.trim() ?? null : null,
        };

        sendControl(entry.socket, 'uninstall-software', payload);
        logSoftwareEvent({
          timestamp: new Date().toISOString(),
          type: 'uninstall-attempt',
          softwareId,
          agentId,
          agentName: entry.info.name,
          softwareName: softwareEntry.name ?? '',
          message: 'Automatic uninstall requested',
        });
    }

    if (queue.pending.size === 0) {
      softwareUninstallQueue.delete(softwareId);
    }
  }
}

function resolveAgentPackageDir() {
  if (fs.existsSync(AGENT_DOWNLOAD_DIR)) {
    return AGENT_DOWNLOAD_DIR;
  }

  if (fs.existsSync(AGENT_BUILD_FALLBACK_DIR)) {
    return AGENT_BUILD_FALLBACK_DIR;
  }

  return null;
}

function selectPrimaryCategory(categoryMap) {
  for (const canonical of PATCH_CATEGORY_ORDER) {
    if (categoryMap.has(canonical)) {
      return { name: canonical, purpose: categoryMap.get(canonical) ?? '' };
    }
  }

  for (const [name, purpose] of categoryMap.entries()) {
    return { name, purpose: purpose ?? '' };
  }

  return null;
}

function serializeSchedule(schedule) {
  return {
    id: schedule.id,
    name: schedule.name,
    patchIds: schedule.patchIds,
    agentIds: Array.isArray(schedule.agentIds) ? schedule.agentIds : [],
    category: schedule.category ?? null,
    dynamic: Boolean(schedule.dynamic ?? (!Array.isArray(schedule.agentIds) || schedule.agentIds.length === 0)),
    createdAt: schedule.createdAt,
    nextRun: schedule.nextRun,
    lastRun: schedule.lastRun,
    repeatMs: schedule.repeatMs > 0 ? schedule.repeatMs : null,
    pendingAgents: Array.from(schedule.pendingAgents),
  };
}

function serializeSchedules(schedules) {
  return schedules.map((schedule) => serializeSchedule(schedule));
}

function logPatchEvent(entry) {
  patchHistory.unshift(entry);
  if (patchHistory.length > PATCH_HISTORY_LIMIT) {
    patchHistory.pop();
  }
}

function processPatchSchedules() {
  const now = Date.now();
  for (const schedule of Array.from(patchSchedules.values())) {
    if (schedule.nextRun > now) {
      continue;
    }

    const isDynamic = Boolean(schedule.dynamic || !Array.isArray(schedule.agentIds) || !schedule.agentIds.length);
    const targetEntries = [];

    if (isDynamic) {
      const dynamicTargets = collectApprovedAgentsForPatches(schedule.patchIds);
      dynamicTargets.forEach((patchSet, agentId) => {
        targetEntries.push({
          agentId,
          patchIds: Array.from(patchSet),
        });
      });
    } else {
      const referenceIds = schedule.repeatMs > 0
        ? schedule.agentIds
        : Array.from(schedule.pendingAgents);
      referenceIds.forEach((agentId) => {
        targetEntries.push({
          agentId,
          patchIds: schedule.patchIds.slice(),
        });
      });
    }

    if (!targetEntries.length) {
      schedule.nextRun = now + PATCH_SCHEDULE_RETRY_MS;
      continue;
    }

    let delivered = false;
    for (const target of targetEntries) {
      const entry = clientsById.get(target.agentId);
      if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
        continue;
      }

      const filteredIds = Array.from(new Set(target.patchIds)).filter(Boolean);
      if (!filteredIds.length) {
        continue;
      }

      console.log(`Triggering patch schedule ${schedule.name} (${schedule.id}) for agent ${target.agentId}`);
      sendControl(entry.socket, 'install-updates', { ids: filteredIds, scheduleId: schedule.id });
      logPatchEvent({
        timestamp: new Date().toISOString(),
        type: 'dispatch',
        scheduleId: schedule.id,
        scheduleName: schedule.name,
        agentId: target.agentId,
        patchIds: filteredIds,
      });
      delivered = true;
      if (!isDynamic && schedule.repeatMs === 0) {
        schedule.pendingAgents.delete(target.agentId);
      }
    }

    schedule.lastRun = now;
    if (schedule.repeatMs > 0) {
      if (!isDynamic) {
        schedule.pendingAgents = new Set(schedule.agentIds);
      }
      schedule.nextRun = now + schedule.repeatMs;
      continue;
    }

    if (isDynamic) {
      patchSchedules.delete(schedule.id);
      continue;
    }

    if (schedule.pendingAgents.size === 0) {
      patchSchedules.delete(schedule.id);
      continue;
    }

    schedule.nextRun = now + PATCH_SCHEDULE_RETRY_MS;
    if (!delivered) {
      console.log(`Patch schedule ${schedule.name} waiting for offline targets`);
    }
  }
}

setInterval(processPatchSchedules, PATCH_SCHEDULE_TICK_MS);
setInterval(processSoftwareUninstalls, SOFTWARE_UNINSTALL_INTERVAL_MS);

function addChatListener(agentId, res) {
  const listeners = chatListeners.get(agentId) ?? new Set();
  listeners.add(res);
  chatListeners.set(agentId, listeners);
}

function removeChatListener(agentId, res) {
  const listeners = chatListeners.get(agentId);
  if (!listeners) {
    return;
  }

  listeners.delete(res);
  if (listeners.size === 0) {
    chatListeners.delete(agentId);
  } else {
    chatListeners.set(agentId, listeners);
  }
}

function flushChatHistory(agentId, res) {
  const history = chatHistories.get(agentId) ?? [];
  for (const entry of history) {
    writeChatEvent(res, entry);
  }
}

function dispatchChatEvent(agentId, payload) {
  const listeners = chatListeners.get(agentId);
  if (!listeners || listeners.size === 0) {
    return;
  }

  const data = JSON.stringify(payload);
  for (const res of listeners) {
    res.write('event: chat\n');
    res.write(`data: ${data}\n\n`);
  }
}

function recordChatHistory(agentId, payload) {
  const history = chatHistories.get(agentId) ?? [];
  history.push({ ...payload });
  if (history.length > CHAT_HISTORY_LIMIT) {
    history.shift();
  }
  chatHistories.set(agentId, history);
  if (payload.direction === 'agent') {
    const messageTimestamp = Number.isFinite(Date.parse(payload.timestamp ?? '')) && payload.timestamp
      ? Date.parse(payload.timestamp ?? '')
      : Date.now();
    const previousTimestamp = agentChatLastTimestamp.get(agentId) ?? 0;
    if (messageTimestamp > previousTimestamp) {
      agentChatLastTimestamp.set(agentId, messageTimestamp);
      incrementChatNotification(agentId, messageTimestamp);
    }
  }
}

function writeChatEvent(res, payload) {
  res.write('event: chat\n');
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function normalizeGroupName(value) {
  if (typeof value !== 'string') {
    return DEFAULT_GROUP;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_GROUP;
}

function assignAgentToGroup(agentId, groupName) {
  const entry = clientsById.get(agentId);
  if (!entry) {
    return DEFAULT_GROUP;
  }

  const normalized = normalizeGroupName(groupName);
  entry.info.group = normalized;
  const alreadyKnown = groups.has(normalized);
  groups.add(normalized);
  if (!alreadyKnown) {
    persistGroups();
  }
  agentGroupAssignments.set(agentId, normalized);
  persistAgentGroupAssignments();
  return normalized;
}

function extractScale(raw) {
  let scale = DEFAULT_SCREEN_SCALE;
  if (typeof raw === 'number') {
    scale = raw;
  } else if (typeof raw === 'string') {
    const parsed = parseFloat(raw);
    if (!Number.isNaN(parsed)) {
      scale = parsed;
    }
  }

  return clampScreenScale(scale);
}

function clampScreenScale(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return DEFAULT_SCREEN_SCALE;
  }

  return Math.min(Math.max(value, MIN_SCREEN_SCALE), MAX_SCREEN_SCALE);
}

function requestScreenList(agentId, socket) {
  return new Promise((resolve, reject) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      reject(new Error('Agent unavailable'));
      return;
    }

    const existing = screenListRequests.get(agentId);
    if (existing) {
      existing.resolvers.push({ resolve, reject });
      return;
    }

    const resolvers = [{ resolve, reject }];
    const timer = setTimeout(() => {
      screenListRequests.delete(agentId);
      for (const entry of resolvers) {
        entry.reject(new Error('Screen list request timed out'));
      }
    }, SCREEN_LIST_TIMEOUT_MS);

    screenListRequests.set(agentId, { resolvers, timer });
    sendControl(socket, 'get-screen-list');
  });
}

function fulfillScreenListRequest(agentId, screens) {
  const pending = screenListRequests.get(agentId);
  if (!pending) {
    return;
  }

  clearTimeout(pending.timer);
  screenListRequests.delete(agentId);
  for (const entry of pending.resolvers) {
    entry.resolve(screens);
  }
}

function cancelScreenListRequest(agentId, reason) {
  const pending = screenListRequests.get(agentId);
  if (!pending) {
    return;
  }

  clearTimeout(pending.timer);
  screenListRequests.delete(agentId);
  for (const entry of pending.resolvers) {
    entry.reject(reason);
  }
}

function requestAgentFileList(entry, requestedPath) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('list', entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-files', { requestId, path: requestedPath ?? '' });
  });
}

function requestAgentFileDownload(entry, requestedPath) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('download', entry.info.id, resolve, reject);
    sendControl(entry.socket, 'download-file', { requestId, path: requestedPath });
  });
}

function requestAgentFileUpload(entry, destinationPath, base64Data) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('upload', entry.info.id, resolve, reject);
    const buffer = Buffer.from(base64Data, 'base64');
    const chunkCount = buffer.length === 0
      ? 1
      : Math.ceil(buffer.length / FILE_UPLOAD_CHUNK_BYTES);

    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * FILE_UPLOAD_CHUNK_BYTES;
      const end = Math.min(buffer.length, start + FILE_UPLOAD_CHUNK_BYTES);
      const chunk = buffer.slice(start, end);

      sendControl(entry.socket, 'upload-file-chunk', {
        requestId,
        path: destinationPath,
        chunkIndex: index,
        totalChunks: chunkCount,
        data: chunk.toString('base64'),
      });
    }

    sendControl(entry.socket, 'upload-file-complete', {
      requestId,
      path: destinationPath,
    });
  });
}

function requestAgentSoftwareList(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueSoftwareRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-software', { requestId });
  });
}

function enqueueFileRequest(kind, agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    fileRequests.delete(requestId);
    reject(new Error('File request timed out'));
  }, FILE_REQUEST_TIMEOUT_MS);

  fileRequests.set(requestId, { kind, agentId, resolve, reject, timer });
  return requestId;
}

function completeFileRequest(requestId) {
  const entry = fileRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  fileRequests.delete(requestId);
  return entry;
}

  function enqueueSoftwareRequest(agentId, resolve, reject) {
    const requestId = uuidv4();
    const timer = setTimeout(() => {
      softwareRequests.delete(requestId);
      reject(new Error('Software request timed out'));
    }, SOFTWARE_REQUEST_TIMEOUT_MS);

    softwareRequests.set(requestId, { agentId, resolve, reject, timer });
    return requestId;
  }

  function completeSoftwareRequest(requestId) {
    const entry = softwareRequests.get(requestId);
    if (!entry) {
      return null;
    }

  clearTimeout(entry.timer);
  softwareRequests.delete(requestId);
    return entry;
  }

  function enqueueServiceRequest(agentId, resolve, reject) {
    const requestId = uuidv4();
    const timer = setTimeout(() => {
      serviceRequests.delete(requestId);
      reject(new Error('Service request timed out'));
    }, SERVICE_REQUEST_TIMEOUT_MS);

    serviceRequests.set(requestId, { agentId, resolve, reject, timer });
    return requestId;
  }

  function completeServiceRequest(requestId) {
    const entry = serviceRequests.get(requestId);
    if (!entry) {
      return null;
    }

    clearTimeout(entry.timer);
    serviceRequests.delete(requestId);
    return entry;
  }

function enqueueServiceActionRequest(requestId, resolve, reject) {
  const timer = setTimeout(() => {
    serviceActionRequests.delete(requestId);
    reject(new Error('Service action timed out'));
  }, SERVICE_ACTION_TIMEOUT_MS);

    serviceActionRequests.set(requestId, { resolve, reject, timer });
  }

function completeServiceActionRequest(requestId) {
  const entry = serviceActionRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  serviceActionRequests.delete(requestId);
  return entry;
}

function enqueueFirewallRequest(agentId, kind, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    firewallRequests.delete(requestId);
    reject(new Error('Firewall request timed out'));
  }, FIREWALL_REQUEST_TIMEOUT_MS);

  firewallRequests.set(requestId, { agentId, kind, resolve, reject, timer });
  return requestId;
}

function completeFirewallRequest(requestId) {
  const entry = firewallRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  firewallRequests.delete(requestId);
  return entry;
}

function requestAgentEventStats(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueEventStatsRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'request-event-stats', { requestId });
  });
}

function requestAgentEventEntries(entry, level) {
  return new Promise((resolve, reject) => {
    const normalized = typeof level === 'string' && level.trim()
      ? `${level.charAt(0).toUpperCase()}${level.slice(1).toLowerCase()}`
      : 'Information';
    const requestId = enqueueEventEntriesRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'request-event-entries', { requestId, level: normalized });
  });
}

function enqueueEventStatsRequest(agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    eventStatsRequests.delete(requestId);
    reject(new Error('Event stats request timed out'));
  }, EVENT_STATS_TIMEOUT_MS);

  eventStatsRequests.set(requestId, { agentId, resolve, reject, timer });
  return requestId;
}

function completeEventStatsRequest(requestId) {
  const entry = eventStatsRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  eventStatsRequests.delete(requestId);
  return entry;
}

function enqueueEventEntriesRequest(agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    eventEntriesRequests.delete(requestId);
    reject(new Error('Event entries request timed out'));
  }, EVENT_ENTRIES_TIMEOUT_MS);

  eventEntriesRequests.set(requestId, { agentId, resolve, reject, timer });
  return requestId;
}

function completeEventEntriesRequest(requestId) {
  const entry = eventEntriesRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  eventEntriesRequests.delete(requestId);
  return entry;
}

function formatSystemHealthPayload(info, stats, since, retrievedAt, options = {}) {
  const agentId = info?.id ?? '';
  const status = info?.status ?? (clientsById.has(agentId) ? 'online' : 'offline');
  return {
    agentId,
    name: info?.name ?? agentId,
    status,
    os: info?.os ?? info?.platform ?? 'unknown',
    platform: info?.platform ?? null,
    group: info?.group ?? DEFAULT_GROUP,
    loggedInUser: info?.loggedInUser ?? null,
    pendingReboot: Boolean(info?.pendingReboot),
    lastSeen: info?.lastSeen ?? null,
    eventStats: stats ?? null,
    since: since ?? null,
    retrievedAt: retrievedAt ?? null,
    error: options.error ?? null,
    source: options.source ?? 'cache',
    offline: Boolean(options.offline) || status !== 'online',
  };
}

function handleAuthRoute(req, res, pathname, requestedUrl) {
  if (req.method === 'POST' && pathname === '/auth/login') {
    return handleLogin(req, res);
  }

  if (pathname === '/auth/logout') {
    const session = getSessionFromRequest(req);
    if (session) {
      sessions.delete(session.id);
    }

    clearSessionCookie(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: true }));
  }

  if (pathname === '/auth/me' && req.method === 'GET') {
    const session = getSessionFromRequest(req);
    if (!session) {
      res.writeHead(401);
      return res.end('Unauthorized');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ username: session.user.username, role: session.user.role }));
  }

  if (pathname === '/auth/sso') {
    return handleSso(req, res, requestedUrl);
  }

  res.writeHead(404);
  res.end('Not found');
}

function handleLogin(req, res) {
  collectBody(req, async (body) => {
    try {
      const data = JSON.parse(body.toString());
      const username = data.username?.toString().trim();
      const password = data.password?.toString();
      const totp = data.totp?.toString();
      if (!username || !password || !totp) {
        throw new Error('Missing credentials.');
      }

      const tenantId = getTenantIdForRequest(req);
      const user = findUserForTenant(username, tenantId);
      if (!user) {
        throw new Error('Invalid credentials.');
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match || !authenticator.check(totp, user.totpSecret)) {
        throw new Error('Invalid credentials.');
      }

      const session = createSession(user);
      setSessionCookie(res, session.id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ username: user.username, role: user.role }));
    } catch (error) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
  });
}

function handleSso(req, res, requestedUrl) {
  const username = requestedUrl.searchParams.get('username') ?? '';
  const timestamp = Number(requestedUrl.searchParams.get('ts'));
  const signature = requestedUrl.searchParams.get('sig');

  if (!username || !signature || Number.isNaN(timestamp)) {
    res.writeHead(400);
    return res.end('Invalid SSO request.');
  }

  if (Math.abs(Date.now() - timestamp) > SSO_WINDOW_MS) {
    res.writeHead(400);
    return res.end('SSO request expired.');
  }

  const expected = crypto.createHmac('sha256', SSO_SECRET).update(`${username}:${timestamp}`).digest('hex');
  if (expected !== signature) {
    res.writeHead(401);
    return res.end('Invalid SSO signature.');
  }

  const tenantId = getTenantIdForRequest(req);
  const user = findUserForTenant(username, tenantId);
  if (!user) {
    res.writeHead(401);
    return res.end('Unknown user.');
  }

  const session = createSession(user);
  setSessionCookie(res, session.id);
  res.writeHead(302, { Location: '/' });
  res.end();
}

function serveStaticAsset(req, res, pathname) {
  const filePath = pathname === '/login.html' ? '/login.html' : '/login.js';
  const resolved = path.join(PUBLIC_DIR, filePath);
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(resolved, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end('Not found');
    }

    const ext = path.extname(resolved);
    const mime = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

function setSessionCookie(res, sessionId) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  res.setHeader('Set-Cookie', `rmm-session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'rmm-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
}

function parseCookies(header) {
  if (!header) {
    return {};
  }

  return header.split(';').reduce((acc, cookie) => {
    const [key, ...valueParts] = cookie.split('=');
    if (!key) {
      return acc;
    }

    acc[key.trim()] = decodeURIComponent(valueParts.join('=').trim());
    return acc;
  }, {});
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies['rmm-session'];
  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }

  if (session.expires < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  session.expires = Date.now() + SESSION_TTL_MS;
  return session;
}

function agentSupports(info, feature) {
  if (!info || !feature) {
    return false;
  }

  const features = Array.isArray(info.features) ? info.features : [];
  return features.includes(feature);
}

function createSession(userEntry) {
  const sanitized = {
    username: userEntry.username,
    role: userEntry.role,
    tenantId: userEntry.tenantId ?? DEFAULT_TENANT_ID,
    isGlobal: userEntry.tenantId === GLOBAL_TENANT_ID,
  };
  const id = uuidv4();
  const session = { id, user: sanitized, expires: Date.now() + SESSION_TTL_MS };
  sessions.set(id, session);
  return session;
}

function respondUnauthorized(req, res) {
  const acceptHeader = req.headers.accept ?? '';
  if (acceptHeader.includes('text/html')) {
    res.writeHead(302, { Location: '/login.html' });
    res.end();
    return;
  }

  res.writeHead(401);
  res.end('Unauthorized');
}

function getSessionTenantId(sessionUser) {
  if (!sessionUser) {
    return DEFAULT_TENANT_ID;
  }
  if (sessionUser.tenantId === GLOBAL_TENANT_ID) {
    return GLOBAL_TENANT_ID;
  }
  return sessionUser.tenantId ?? DEFAULT_TENANT_ID;
}

function sessionHasTenantAccess(sessionUser, tenantId) {
  if (!sessionUser) {
    return false;
  }
  if (sessionUser.isGlobal) {
    return true;
  }
  const normalizedTenant = (typeof tenantId === 'string' && tenantId.trim())
    ? tenantId.trim()
    : DEFAULT_TENANT_ID;
  return sessionUser.tenantId === normalizedTenant;
}

function ensureRole(req, res, minRole) {
  const session = req.userSession;
  if (!session) {
    respondUnauthorized(req, res);
    return false;
  }

  const weight = roleWeight[session.user.role] ?? 0;
  if (weight < roleWeight[minRole]) {
    res.writeHead(403);
    res.end('Forbidden');
    return false;
  }

  return true;
}

function loadUsersConfig() {
  try {
    const raw = fs.readFileSync(USERS_CONFIG_PATH, 'utf-8');
    const data = JSON.parse(raw);
    const { list, mutated } = normalizeUsersPayload(data);
    if (mutated && Array.isArray(list)) {
      fs.writeFileSync(USERS_CONFIG_PATH, JSON.stringify(list, null, 2), 'utf-8');
    }
    return list;
  } catch (error) {
    console.error('Failed to load users config', error);
    return [];
  }
}

function requestAgentServiceList(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueServiceRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-services', { requestId });
  });
}

function requestAgentFirewallRules(entry) {
  if (!agentSupports(entry.info, 'firewall')) {
    return Promise.reject(new Error('Firewall feature unsupported by this agent'));
  }

  return new Promise((resolve, reject) => {
    const requestId = enqueueFirewallRequest(entry.info.id, 'rules', resolve, reject);
    sendControl(entry.socket, 'list-firewall', { requestId });
  });
}

function requestAgentFirewallAction(entry, payload) {
  if (!agentSupports(entry.info, 'firewall')) {
    return Promise.reject(new Error('Firewall feature unsupported by this agent'));
  }

  return new Promise((resolve, reject) => {
    const requestId = enqueueFirewallRequest(entry.info.id, 'action', resolve, reject);
    sendControl(entry.socket, 'firewall-action', { requestId, ...payload });
  });
}

function performServiceAction(entry, serviceName, action) {
  return new Promise((resolve, reject) => {
    const requestId = uuidv4();
    enqueueServiceActionRequest(requestId, resolve, reject);
    sendControl(entry.socket, 'manage-service', {
      requestId,
      serviceName,
      action,
    });
  });
}

function persistUsersConfig() {
  try {
    fs.writeFileSync(USERS_CONFIG_PATH, JSON.stringify(USERS_CONFIG, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to save users config', error);
    return false;
  }
}

function normalizeUsersPayload(payload) {
  const normalized = [];
  let mutated = false;
  const seen = new Set();
  const entries = Array.isArray(payload) ? payload : [];
  if (!Array.isArray(payload)) {
    mutated = true;
  }

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') {
      mutated = true;
      continue;
    }

    const usernameRaw = typeof entry.username === 'string' ? entry.username.trim() : '';
    if (!usernameRaw) {
      mutated = true;
      continue;
    }

    const usernameKey = usernameRaw.toLowerCase();
    if (seen.has(usernameKey)) {
      mutated = true;
      continue;
    }
    seen.add(usernameKey);

    const passwordHash = typeof entry.passwordHash === 'string' && entry.passwordHash.trim()
      ? entry.passwordHash.trim()
      : null;
    if (!passwordHash) {
      mutated = true;
      continue;
    }

    const roleRaw = typeof entry.role === 'string' ? entry.role.trim().toLowerCase() : '';
    const role = VALID_USER_ROLES.has(roleRaw) ? roleRaw : 'viewer';
    if (role !== roleRaw) {
      mutated = true;
    }

    const totpSecretRaw = typeof entry.totpSecret === 'string' ? entry.totpSecret.trim() : '';
    const totpSecret = totpSecretRaw || authenticator.generateSecret();
    if (!totpSecretRaw) {
      mutated = true;
    }

    const tenantIdRaw = typeof entry.tenantId === 'string' ? entry.tenantId.trim() : '';
    const tenantId = tenantIdRaw || DEFAULT_TENANT_ID;
    if (!tenantIdRaw) {
      mutated = true;
    }

    const createdAt = typeof entry.createdAt === 'number' ? entry.createdAt : Date.now();
    if (!('createdAt' in entry)) {
      mutated = true;
    }

    normalized.push({
      username: usernameRaw,
      passwordHash,
      role,
      totpSecret,
      tenantId,
      createdAt,
    });
  }

  return { list: normalized, mutated };
}

function findUserForTenant(username, tenantId) {
  if (!username) {
    return null;
  }
  const key = username.trim();
  if (!key) {
    return null;
  }

  const targetTenant = typeof tenantId === 'string' && tenantId.trim()
    ? tenantId.trim()
    : DEFAULT_TENANT_ID;

  return USERS_CONFIG.find((entry) => {
    if (entry.username !== key) {
      return false;
    }
    if (entry.tenantId === GLOBAL_TENANT_ID) {
      return true;
    }
    return entry.tenantId === targetTenant;
  }) ?? null;
}

function resolveTenantForNewUser(req, requestedTenantId) {
  const sessionUser = req.userSession?.user;
  const normalizedRequested = typeof requestedTenantId === 'string' && requestedTenantId.trim()
    ? requestedTenantId.trim()
    : null;

  if (sessionUser?.isGlobal) {
    if (normalizedRequested) {
      return normalizedRequested;
    }
    return DEFAULT_TENANT_ID;
  }

  return sessionUser?.tenantId ?? DEFAULT_TENANT_ID;
}

function getScreenName(agentId, screenId) {
  if (!screenId) {
    return null;
  }

  const stored = screenLists.get(agentId);
  return stored?.screens.find((screen) => screen.id === screenId)?.name ?? null;
}

function getAssignedProfiles(info) {
  if (!info) {
    return [];
  }

  const group = info.group ?? DEFAULT_GROUP;
  return monitoringConfig.monitoringProfiles.filter((profile) => {
    const agents = Array.isArray(profile.assignedAgents) ? profile.assignedAgents : [];
    const groups = Array.isArray(profile.assignedGroups) ? profile.assignedGroups : [];
    return agents.includes(info.id) || groups.includes(group);
  });
}

function getAgentMonitoringProfiles(info) {
  const profiles = getAssignedProfiles(info);
  if (!info || !info.id) {
    return profiles.map((profile) => ({
      id: profile.id,
      name: profile.name,
      alert: false,
      metrics: getRequiredMetricsForProfiles([profile]),
    }));
  }

  const statusMap = agentProfileStatus.get(info.id) ?? new Map();
  return profiles.map((profile) => ({
    id: profile.id,
    name: profile.name,
    alert: statusMap.get(profile.id) ?? false,
    metrics: getRequiredMetricsForProfiles([profile]),
  }));
}

function shouldMonitorAgent(info) {
  return getAssignedProfiles(info).length > 0;
}

function normalizeBitlockerStatus(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const protectionStatus = typeof payload.protectionStatus === 'string' && payload.protectionStatus.trim()
    ? payload.protectionStatus.trim()
    : null;
  const lockStatus = typeof payload.lockStatus === 'string' && payload.lockStatus.trim()
    ? payload.lockStatus.trim()
    : null;

  if (!protectionStatus && !lockStatus) {
    return null;
  }

  const volume = typeof payload.volume === 'string' && payload.volume.trim()
    ? payload.volume.trim()
    : 'Unknown';

  let percentage = null;
  if (typeof payload.percentageEncrypted === 'number' && Number.isFinite(payload.percentageEncrypted)) {
    percentage = clampPercentage(payload.percentageEncrypted);
  } else if (typeof payload.percentageEncrypted === 'string') {
    const parsed = Number(payload.percentageEncrypted);
    if (Number.isFinite(parsed)) {
      percentage = clampPercentage(parsed);
    }
  }

  const keyProtectors = Array.isArray(payload.keyProtectors)
    ? payload.keyProtectors
      .filter((entry) => typeof entry === 'string' && entry.trim())
      .map((entry) => entry.trim())
    : [];

  return {
    volume,
    protectionStatus: protectionStatus ?? 'Unknown',
    lockStatus: lockStatus ?? 'Unknown',
    percentageEncrypted: Number.isFinite(percentage) ? percentage : null,
    keyProtectors,
  };
}

function normalizeAvStatus(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const name = typeof payload.name === 'string' && payload.name.trim()
    ? payload.name.trim()
    : 'Unknown AV';
  const status = typeof payload.status === 'string' && payload.status.trim()
    ? payload.status.trim()
    : 'Unknown';
  const definition = typeof payload.definition === 'string' && payload.definition.trim()
    ? payload.definition.trim()
    : 'Definition status unknown';
  const productState = Number.isFinite(payload.ProductState)
    ? Number(payload.ProductState)
    : 0;

  return { name, status, definition, productState };
}

function clampPercentage(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  if (value < 0) {
    return 0;
  }

  if (value > 100) {
    return 100;
  }

  return value;
}

function notifyMonitoringState(entry) {
  if (!entry || !entry.socket || !entry.info) {
    return;
  }

  const profiles = getAssignedProfiles(entry.info);
  const enabled = profiles.length > 0;
  const metrics = getRequiredMetricsForProfiles(profiles);
  sendControl(entry.socket, 'monitoring-status', {
    enabled,
    profiles: profiles.map((profile) => profile.id),
    metrics,
  });
}

function notifyAgentMonitoring(agentId) {
  const entry = clientsById.get(agentId);
  if (!entry) {
    return;
  }

  notifyMonitoringState(entry);
}

function notifyGroupMonitoring(groupName) {
  for (const entry of clientsById.values()) {
    if ((entry.info.group ?? DEFAULT_GROUP) === groupName) {
      notifyMonitoringState(entry);
    }
  }
}

function ensureDataDirectory() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// Tenant storage helpers - ensures we can persist tenant-specific files
function sanitizeTenantId(tenantId) {
  if (typeof tenantId === 'string') {
    const candidate = tenantId.trim();
    if (candidate) {
      return candidate;
    }
  }

  return DEFAULT_TENANT_ID;
}

function ensureTenantStorageRoot() {
  ensureDataDirectory();
  if (!fs.existsSync(TENANT_DATA_ROOT)) {
    fs.mkdirSync(TENANT_DATA_ROOT, { recursive: true });
  }
}

function ensureTenantDataDir(tenantId) {
  ensureTenantStorageRoot();
  const safeTenantId = sanitizeTenantId(tenantId);
  const dir = path.join(TENANT_DATA_ROOT, safeTenantId);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function getTenantFilePath(tenantId, fileName) {
  const dir = ensureTenantDataDir(tenantId);
  return path.join(dir, fileName);
}

function loadTenantJson(tenantId, fileName, fallback = null) {
  try {
    const filePath = getTenantFilePath(tenantId, fileName);
    if (!fs.existsSync(filePath)) {
      return fallback;
    }

    let raw = fs.readFileSync(filePath, 'utf-8');
    if (raw.charCodeAt(0) === 0xfeff) {
      raw = raw.slice(1);
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error(`Failed to load tenant data (${fileName})`, error);
    return fallback;
  }
}

function persistTenantJson(tenantId, fileName, data) {
  try {
    const filePath = getTenantFilePath(tenantId, fileName);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error(`Failed to persist tenant data (${fileName})`, error);
    return false;
  }
}

function loadGroups() {
  ensureDataDirectory();
  let stored = [];
  try {
    if (fs.existsSync(GROUPS_CONFIG_PATH)) {
      let raw = fs.readFileSync(GROUPS_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load group config', error);
  }

  const set = new Set([DEFAULT_GROUP]);
  if (Array.isArray(stored)) {
    for (const candidate of stored) {
      const normalized = normalizeGroupName(candidate);
      if (normalized) {
        set.add(normalized);
      }
    }
  }

  persistGroups(set);
  return set;
}

function persistGroups(set = groups) {
  try {
    ensureDataDirectory();
    const payload = Array.from(set).sort();
    fs.writeFileSync(GROUPS_CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist group config', error);
    return false;
  }
}

function loadLicenses() {
  ensureDataDirectory();
  let stored = [];
  try {
    if (fs.existsSync(LICENSES_PATH)) {
      let raw = fs.readFileSync(LICENSES_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      const parsed = JSON.parse(raw);
      const normalized = normalizeLicensesPayload(parsed);
      if (normalized.mutated) {
        fs.writeFileSync(LICENSES_PATH, JSON.stringify(normalized.list, null, 2), 'utf-8');
      }
      return normalized.list;
    }
  } catch (error) {
    console.error('Failed to load license config', error);
  }

  return [];
}

function persistLicenses() {
  try {
    ensureDataDirectory();
    fs.writeFileSync(LICENSES_PATH, JSON.stringify(licenseRecords, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist licenses', error);
    return false;
  }
}

function generateLicenseCode() {
  return crypto.randomBytes(12).toString('hex');
}

function getLicenseRecord(code) {
  return licenseIndex.get(code);
}

function markLicenseUsed(code) {
  const record = getLicenseRecord(code);
  if (!record) {
    return;
  }

  record.lastUsedAt = new Date().toISOString();
  persistLicenses();
}

function getLicenseTenantId(record) {
  if (!record) {
    return DEFAULT_TENANT_ID;
  }
  const tenant = typeof record.tenantId === 'string' && record.tenantId.trim()
    ? record.tenantId.trim()
    : DEFAULT_TENANT_ID;
  return tenant;
}

function assignLicenseToAgent(code, agentId) {
  const record = getLicenseRecord(code);
  if (!record || record.revokedAt) {
    return false;
  }

  if (record.assignedAgentId && record.assignedAgentId !== agentId) {
    return false;
  }

  if (!record.assignedAgentId) {
    record.assignedAgentId = agentId;
    record.assignedAt = new Date().toISOString();
    persistLicenses();
  }

  return true;
}

function unassignLicense(code) {
  const record = getLicenseRecord(code);
  if (!record) {
    return false;
  }

  record.assignedAgentId = null;
  record.assignedAt = null;
  persistLicenses();
  return true;
}

function disconnectAgentsByLicense(code, reason = 'license revoked') {
  for (const entry of clientsById.values()) {
    if (entry.info.license !== code) {
      continue;
    }

    if (entry.socket.readyState === WebSocket.OPEN) {
      sendControl(entry.socket, 'license-revoked', { reason });
      entry.socket.close(4003, reason);
    }
  }
  const record = getLicenseRecord(code);
  if (record) {
    record.assignedAgentId = null;
    record.assignedAt = null;
    persistLicenses();
  }
}

function notifyAgentLicenseUnassigned(code, reason = 'license released') {
  const record = getLicenseRecord(code);
  if (!record?.assignedAgentId) {
    return;
  }

  const entry = clientsById.get(record.assignedAgentId);
  if (entry?.socket?.readyState === WebSocket.OPEN) {
    sendControl(entry.socket, 'license-unassigned', { reason });
    entry.socket.close(4003, 'license unassigned');
  }
}

function loadAgentGroupAssignments(groupsSet) {
  ensureDataDirectory();
  let stored = {};
  try {
    if (fs.existsSync(AGENT_GROUP_ASSIGNMENTS_PATH)) {
      let raw = fs.readFileSync(AGENT_GROUP_ASSIGNMENTS_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load agent group assignments', error);
  }

  const map = new Map();
  if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
    for (const [agentId, value] of Object.entries(stored)) {
      if (!agentId) {
        continue;
      }
      const normalized = normalizeGroupName(value);
      map.set(agentId, normalized);
      if (groupsSet && normalized) {
        groupsSet.add(normalized);
      }
    }
  }

  persistAgentGroupAssignments(map);
  return map;
}

function persistAgentGroupAssignments(map = agentGroupAssignments) {
  try {
    ensureDataDirectory();
    const payload = {};
    for (const [agentId, groupName] of map) {
      if (!agentId || !groupName) {
        continue;
      }
      payload[agentId] = groupName;
    }
    fs.writeFileSync(AGENT_GROUP_ASSIGNMENTS_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist agent group assignments', error);
    return false;
  }
}

function normalizeLicensesPayload(payload) {
  const normalized = [];
  let mutated = false;
  const entries = Array.isArray(payload) ? payload : [];
  if (!Array.isArray(payload)) {
    mutated = true;
  }

  for (const entry of entries) {
    if (!entry || typeof entry.code !== 'string') {
      mutated = true;
      continue;
    }

    const code = entry.code.trim();
    if (!code) {
      mutated = true;
      continue;
    }

    const createdAt = typeof entry.createdAt === 'string' ? entry.createdAt : new Date().toISOString();
    if (entry.createdAt !== createdAt) {
      mutated = true;
    }

    const revokedAt = typeof entry.revokedAt === 'string' ? entry.revokedAt : null;
    if (entry.revokedAt !== revokedAt) {
      mutated = true;
    }

    const lastUsedAt = typeof entry.lastUsedAt === 'string' ? entry.lastUsedAt : null;
    if (entry.lastUsedAt !== lastUsedAt) {
      mutated = true;
    }

    const assignedAgentId = typeof entry.assignedAgentId === 'string' ? entry.assignedAgentId : null;
    if (entry.assignedAgentId !== assignedAgentId) {
      mutated = true;
    }

    const assignedAt = typeof entry.assignedAt === 'string' ? entry.assignedAt : null;
    if (entry.assignedAt !== assignedAt) {
      mutated = true;
    }

    const tenantId = typeof entry.tenantId === 'string' && entry.tenantId.trim()
      ? entry.tenantId.trim()
      : DEFAULT_TENANT_ID;
    if (entry.tenantId !== tenantId) {
      mutated = true;
    }

    normalized.push({
      code,
      createdAt,
      revokedAt,
      lastUsedAt,
      assignedAgentId,
      assignedAt,
      tenantId,
    });
  }

  return { list: normalized, mutated };
}

function resolveLicenseTenant(req, requestedTenantId) {
  const sessionUser = req.userSession?.user;
  const normalized = typeof requestedTenantId === 'string' && requestedTenantId.trim()
    ? requestedTenantId.trim()
    : null;

  if (sessionUser?.isGlobal) {
    return normalized ?? DEFAULT_TENANT_ID;
  }

  return sessionUser?.tenantId ?? DEFAULT_TENANT_ID;
}

function loadSnmpDiscoverySettings() {
  ensureDataDirectory();
  let stored = {};
  try {
    if (fs.existsSync(SNMP_SETTINGS_PATH)) {
      let raw = fs.readFileSync(SNMP_SETTINGS_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load SNMP discovery settings', error);
  }

  const map = new Map();
  if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
    for (const [agentId, value] of Object.entries(stored)) {
      if (!agentId) {
        continue;
      }
      map.set(agentId, Boolean(value));
    }
  }

  persistSnmpDiscoverySettings(map);
  return map;
}

function persistSnmpDiscoverySettings(map = snmpDiscoverySettings) {
  try {
    ensureDataDirectory();
    const payload = {};
    for (const [agentId, enabled] of map) {
      if (!agentId) {
        continue;
      }
      payload[agentId] = Boolean(enabled);
    }
    fs.writeFileSync(SNMP_SETTINGS_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist SNMP discovery settings', error);
    return false;
  }
}

function isSnmpDiscoveryEnabled(agentId) {
  if (!agentId) {
    return true;
  }

  if (!snmpDiscoverySettings.has(agentId)) {
    return true;
  }

  return Boolean(snmpDiscoverySettings.get(agentId));
}

function setSnmpDiscoveryEnabled(agentId, enabled) {
  if (!agentId) {
    return false;
  }

  snmpDiscoverySettings.set(agentId, Boolean(enabled));
  return persistSnmpDiscoverySettings();
}

function captureSnmpEvent(agentId, requestId, eventName, payload) {
  if (!requestId || !eventName) {
    return;
  }

  if (eventName === 'snmp-result' && Array.isArray(payload?.devices)) {
    for (const device of payload.devices) {
      appendSnmpDeviceToRecord(requestId, device);
    }
    return;
  }

  if (eventName === 'snmp-complete') {
    finalizeSnmpDiscoveryRecord(requestId, {
      status: 'complete',
      scanned: Number.isFinite(payload?.scanned) ? payload.scanned : null,
      found: Number.isFinite(payload?.found) ? payload.found : null,
      durationMs: Number.isFinite(payload?.durationMs) ? payload.durationMs : null,
    });
    return;
  }

  if (eventName === 'snmp-error') {
    finalizeSnmpDiscoveryRecord(requestId, {
      status: 'error',
      scanned: Number.isFinite(payload?.scanned) ? payload.scanned : null,
      found: Number.isFinite(payload?.found) ? payload.found : null,
      durationMs: Number.isFinite(payload?.durationMs) ? payload.durationMs : null,
      message: typeof payload?.message === 'string' ? payload.message : null,
    });
    return;
  }
}

function appendSnmpDeviceToRecord(requestId, device) {
  const pending = pendingSnmpScans.get(requestId);
  if (!pending) {
    return;
  }

  if (!device || typeof device !== 'object') {
    return;
  }

  pending.devices.push({
    ip: typeof device.ip === 'string' ? device.ip : '',
    sysDescr: typeof device.sysDescr === 'string' ? device.sysDescr : '',
    sysName: typeof device.sysName === 'string' ? device.sysName : '',
    sysObjectId: typeof device.sysObjectId === 'string' ? device.sysObjectId : '',
    discoveredAt: new Date().toISOString(),
  });
}

function finalizeSnmpDiscoveryRecord(requestId, summary) {
  const pending = pendingSnmpScans.get(requestId);
  if (!pending) {
    return;
  }

  pendingSnmpScans.delete(requestId);

  const record = {
    requestId,
    agentId: pending.agentId,
    agentName: pending.agentName,
    status: summary.status ?? 'unknown',
    startedAt: pending.startedAt,
    completedAt: new Date().toISOString(),
    scanned: typeof summary.scanned === 'number' ? summary.scanned : null,
    found: typeof summary.found === 'number' ? summary.found : null,
    durationMs: typeof summary.durationMs === 'number' ? summary.durationMs : null,
    message: typeof summary.message === 'string' ? summary.message : null,
    devices: pending.devices,
    tenantId: typeof pending.tenantId === 'string' && pending.tenantId ? pending.tenantId : DEFAULT_TENANT_ID,
  };

  appendTenantHistoryRecord(
    snmpDiscoveryHistory,
    record.tenantId,
    SNMP_HISTORY_FILENAME,
    SNMP_DISCOVERY_LOG_LIMIT,
    SNMP_DISCOVERY_LOG_PATH,
    record
  );
}

function beginSnmpDiscoveryRecord(agentId, agentName, requestId, tenantId = DEFAULT_TENANT_ID) {
  if (!agentId || !requestId) {
    return;
  }

  pendingSnmpScans.set(requestId, {
    agentId,
    agentName: agentName ?? 'unknown',
    requestId,
    startedAt: new Date().toISOString(),
    devices: [],
    tenantId: typeof tenantId === 'string' && tenantId ? tenantId : DEFAULT_TENANT_ID,
  });
}

function captureNetworkScannerEvent(agentId, requestId, eventName, payload) {
  if (!requestId || !eventName) {
    return;
  }

  if (eventName === 'network-scanner-result' && Array.isArray(payload?.devices)) {
    for (const device of payload.devices) {
      appendNetworkHostToRecord(requestId, device);
    }
    return;
  }

  if (eventName === 'network-scanner-complete') {
    finalizeNetworkScannerRecord(requestId, {
      status: 'complete',
      scanned: Number.isFinite(payload?.scanned) ? payload.scanned : null,
      found: Number.isFinite(payload?.found) ? payload.found : null,
      durationMs: Number.isFinite(payload?.durationMs) ? payload.durationMs : null,
    });
    return;
  }

  if (eventName === 'network-scanner-error') {
    finalizeNetworkScannerRecord(requestId, {
      status: 'error',
      scanned: Number.isFinite(payload?.scanned) ? payload.scanned : null,
      found: Number.isFinite(payload?.found) ? payload.found : null,
      durationMs: Number.isFinite(payload?.durationMs) ? payload.durationMs : null,
      message: typeof payload?.message === 'string' ? payload.message : null,
    });
    return;
  }
}

function appendNetworkHostToRecord(requestId, device) {
  const pending = pendingNetworkScannerScans.get(requestId);
  if (!pending) {
    return;
  }

  if (!device || typeof device !== 'object') {
    return;
  }

  pending.devices.push({
    ip: typeof device.ip === 'string' ? device.ip : '',
    hostName: typeof device.hostName === 'string' ? device.hostName : '',
    macAddress: typeof device.macAddress === 'string' ? device.macAddress : '',
    services: Array.isArray(device.services) ? device.services.filter((entry) => typeof entry === 'string') : [],
    discoveredAt: new Date().toISOString(),
  });
}

function finalizeNetworkScannerRecord(requestId, summary) {
  const pending = pendingNetworkScannerScans.get(requestId);
  if (!pending) {
    return;
  }

  pendingNetworkScannerScans.delete(requestId);

  const record = {
    requestId,
    agentId: pending.agentId,
    agentName: pending.agentName,
    status: summary.status ?? 'unknown',
    startedAt: pending.startedAt,
    completedAt: new Date().toISOString(),
    scanned: typeof summary.scanned === 'number' ? summary.scanned : null,
    found: typeof summary.found === 'number' ? summary.found : null,
    durationMs: typeof summary.durationMs === 'number' ? summary.durationMs : null,
    message: typeof summary.message === 'string' ? summary.message : null,
    devices: pending.devices,
    tenantId: typeof pending.tenantId === 'string' && pending.tenantId ? pending.tenantId : DEFAULT_TENANT_ID,
  };

  appendTenantHistoryRecord(
    networkScannerHistory,
    record.tenantId,
    NETWORK_HISTORY_FILENAME,
    NETWORK_SCANNER_LOG_LIMIT,
    NETWORK_SCANNER_LOG_PATH,
    record
  );
}

function beginNetworkScannerRecord(agentId, agentName, requestId, tenantId = DEFAULT_TENANT_ID) {
  if (!agentId || !requestId) {
    return;
  }

  pendingNetworkScannerScans.set(requestId, {
    agentId,
    agentName: agentName ?? 'unknown',
    requestId,
    startedAt: new Date().toISOString(),
    devices: [],
    tenantId: typeof tenantId === 'string' && tenantId ? tenantId : DEFAULT_TENANT_ID,
  });
}

function clearSnmpDiscoveryHistory(tenantId) {
  return clearTenantHistory(snmpDiscoveryHistory, tenantId, SNMP_HISTORY_FILENAME);
}

function clearNetworkScannerHistory(tenantId) {
  return clearTenantHistory(networkScannerHistory, tenantId, NETWORK_HISTORY_FILENAME);
}

function normalizeHistoryRecords(stored, limit) {
  const normalized = [];
  if (!Array.isArray(stored)) {
    return normalized;
  }

  const maxEntries = Number.isFinite(limit) && limit > 0 ? limit : Number.POSITIVE_INFINITY;
  for (const record of stored) {
    if (!record || typeof record !== 'object') {
      continue;
    }

    const tenantId = typeof record.tenantId === 'string' && record.tenantId.trim()
      ? record.tenantId.trim()
      : DEFAULT_TENANT_ID;
    normalized.push({ ...record, tenantId });
    if (normalized.length >= maxEntries) {
      break;
    }
  }

  return normalized;
}

function loadLegacyHistoryRecords(filePath, limit) {
  ensureDataDirectory();
  try {
    if (!filePath || !fs.existsSync(filePath)) {
      return [];
    }
    let raw = fs.readFileSync(filePath, 'utf-8');
    if (raw.charCodeAt(0) === 0xfeff) {
      raw = raw.slice(1);
    }
    const parsed = JSON.parse(raw);
    return normalizeHistoryRecords(parsed, limit);
  } catch (error) {
    console.error('Failed to load legacy history', error);
    return [];
  }
}

function loadTenantHistoryRecords(map, tenantId, fileName, limit, legacyPath = null) {
  const normalizedTenantId = sanitizeTenantId(tenantId);
  if (map.has(normalizedTenantId)) {
    return map.get(normalizedTenantId);
  }

  let stored = loadTenantJson(normalizedTenantId, fileName, null);
  let records = [];
  if (stored !== null) {
    records = normalizeHistoryRecords(stored, limit);
  } else if (normalizedTenantId === DEFAULT_TENANT_ID && legacyPath) {
    records = loadLegacyHistoryRecords(legacyPath, limit);
  }

  map.set(normalizedTenantId, records);
  return records;
}

function appendTenantHistoryRecord(map, tenantId, fileName, limit, legacyPath, record) {
  const normalizedTenantId = sanitizeTenantId(tenantId);
  const records = loadTenantHistoryRecords(
    map,
    normalizedTenantId,
    fileName,
    limit,
    legacyPath
  );
  const entry = { ...record, tenantId: normalizedTenantId };
  records.unshift(entry);
  if (records.length > limit) {
    records.length = limit;
  }

  persistTenantJson(normalizedTenantId, fileName, records);
}

function clearTenantHistory(map, tenantId, fileName) {
  const normalizedTenantId = sanitizeTenantId(tenantId);
  map.set(normalizedTenantId, []);
  return persistTenantJson(normalizedTenantId, fileName, []);
}

function getSnmpHistoryForTenant(tenantId) {
  return loadTenantHistoryRecords(
    snmpDiscoveryHistory,
    tenantId,
    SNMP_HISTORY_FILENAME,
    SNMP_DISCOVERY_LOG_LIMIT,
    SNMP_DISCOVERY_LOG_PATH
  );
}

function getNetworkHistoryForTenant(tenantId) {
  return loadTenantHistoryRecords(
    networkScannerHistory,
    tenantId,
    NETWORK_HISTORY_FILENAME,
    NETWORK_SCANNER_LOG_LIMIT,
    NETWORK_SCANNER_LOG_PATH
  );
}

function resolveTenantFromHost(hostname) {
  const normalizedHost = typeof hostname === 'string' ? hostname.trim().toLowerCase() : '';
  if (!normalizedHost) {
    return tenantIndex.get(DEFAULT_TENANT_ID) ?? DEFAULT_TENANT;
  }

  for (const tenant of tenants) {
    const domains = Array.isArray(tenant.domains) ? tenant.domains : [];
    for (const domain of domains) {
      const normalizedDomain = typeof domain === 'string' ? domain.trim().toLowerCase() : '';
      if (!normalizedDomain) {
        continue;
      }
      if (normalizedDomain === normalizedHost) {
        return tenant;
      }
      if (normalizedDomain.startsWith('*.')) {
        const suffix = normalizedDomain.slice(2);
        if (suffix && (normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`))) {
          return tenant;
        }
      }
    }
  }

  return tenantIndex.get(DEFAULT_TENANT_ID) ?? DEFAULT_TENANT;
}

function getTenantFromRequest(req) {
  const hostHeader = typeof req.headers?.host === 'string' ? req.headers.host : '';
  const hostname = hostHeader.split(':')[0] ?? '';
  return resolveTenantFromHost(hostname);
}

function getTenantIdForRequest(req) {
  return getTenantFromRequest(req).id ?? DEFAULT_TENANT_ID;
}

function getTenantPayload(req) {
  const tenant = getTenantFromRequest(req);
  if (!tenant) {
    return { id: DEFAULT_TENANT_ID, name: DEFAULT_TENANT.name, domains: DEFAULT_TENANT.domains, description: DEFAULT_TENANT.description };
  }
  return {
    id: tenant.id,
    name: tenant.name,
    description: tenant.description ?? null,
    domains: Array.isArray(tenant.domains) ? tenant.domains : [],
  };
}

function loadTenants() {
  ensureDataDirectory();
  let stored = [];
  let mutated = false;
  try {
    if (fs.existsSync(TENANTS_CONFIG_PATH)) {
      let raw = fs.readFileSync(TENANTS_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load tenant configuration', error);
  }

  const normalized = [];
  if (Array.isArray(stored)) {
    for (const entry of stored) {
      if (!entry || typeof entry !== 'object') {
        continue;
      }
      const id = typeof entry.id === 'string' && entry.id.trim() ? entry.id.trim() : null;
      if (!id) {
        continue;
      }
      const name = typeof entry.name === 'string' && entry.name.trim()
        ? entry.name.trim()
        : DEFAULT_TENANT.name;
      const description = typeof entry.description === 'string' ? entry.description.trim() : '';
      const domains = Array.isArray(entry.domains)
        ? Array.from(new Set(entry.domains
          .map((domain) => (typeof domain === 'string' ? domain.trim().toLowerCase() : ''))
          .filter(Boolean)))
        : [];

      normalized.push({
        id,
        name,
        description,
        domains,
      });
    }
  }

  if (!normalized.some((tenant) => tenant.id === DEFAULT_TENANT_ID)) {
    normalized.unshift({ ...DEFAULT_TENANT });
    mutated = true;
  }

  if (!normalized.length) {
    normalized.push({ ...DEFAULT_TENANT });
    mutated = true;
  }

  if (mutated) {
    persistTenants(normalized);
  }

  return normalized;
}

function persistTenants(list) {
  try {
    ensureDataDirectory();
    const payload = Array.isArray(list) ? list : [];
    fs.writeFileSync(TENANTS_CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist tenant configuration', error);
    return false;
  }
}

function commitTenantList(updated) {
  const success = persistTenants(updated);
  if (!success) {
    return false;
  }

  tenants = loadTenants();
  refreshTenantIndex();
  return true;
}

function parseTenantDomains(value) {
  if (!value) {
    return [];
  }

  const items = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[;,\s]+/) : [];
  const normalized = [];
  for (const item of items) {
    const trimmed = typeof item === 'string' ? item.trim().toLowerCase() : '';
    if (trimmed) {
      normalized.push(trimmed);
    }
  }

  return Array.from(new Set(normalized));
}

function normalizeTenantPayload(payload, options = { requireId: true }) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const idRaw = typeof payload.id === 'string' ? payload.id.trim() : '';
  const id = options.requireId ? (idRaw || null) : idRaw;
  if (options.requireId && !id) {
    return null;
  }

  const nameRaw = typeof payload.name === 'string' ? payload.name.trim() : '';
  const name = nameRaw || (options.requireId ? id : DEFAULT_TENANT.name);
  const description = typeof payload.description === 'string' ? payload.description.trim() : '';
  const domains = parseTenantDomains(payload.domains);

  if (!id) {
    return { name, description, domains };
  }

  return {
    id,
    name,
    description,
    domains,
  };
}

function findTenantById(id) {
  const normalized = typeof id === 'string' ? id.trim() : '';
  if (!normalized) {
    return null;
  }
  return tenants.find((entry) => entry.id === normalized) ?? null;
}

function ensureRemediationDirectory() {
  if (!fs.existsSync(REMEDIATION_DIR)) {
    fs.mkdirSync(REMEDIATION_DIR, { recursive: true });
  }
}

function loadNavigationVisibility() {
  ensureDataDirectory();
  let stored = [];
  try {
    if (fs.existsSync(NAVIGATION_CONFIG_PATH)) {
      let raw = fs.readFileSync(NAVIGATION_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load navigation config', error);
  }

  const map = new Map();
  for (const item of NAVIGATION_ITEMS) {
    const entry = Array.isArray(stored)
      ? stored.find((candidate) => candidate.id === item.id)
      : null;
    const visible = entry && typeof entry.visible === 'boolean' ? entry.visible : true;
    map.set(item.id, visible);
  }

  persistNavigationVisibility(map);
  return map;
}

function persistNavigationVisibility(map) {
  try {
    ensureDataDirectory();
    const payload = NAVIGATION_ITEMS.map((item) => ({
      id: item.id,
      visible: map.get(item.id) ?? true,
    }));
    fs.writeFileSync(NAVIGATION_CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist navigation config', error);
    return false;
  }
}

function getNavigationPayload() {
  return NAVIGATION_ITEMS.map((item) => ({
    id: item.id,
    label: item.label,
    href: item.href,
    description: item.description,
    visible: navigationVisibility.get(item.id) ?? true,
  }));
}

function updateNavigationVisibility(entries) {
  if (!Array.isArray(entries)) {
    return false;
  }

  let mutated = false;
  for (const entry of entries) {
    const id = (entry?.id ?? '').toString();
    if (!id) {
      continue;
    }

    const known = NAVIGATION_ITEMS.find((item) => item.id === id);
    if (!known) {
      continue;
    }

    const visible = typeof entry.visible === 'boolean' ? entry.visible : null;
    if (visible === null) {
      continue;
    }

    const current = navigationVisibility.get(id) ?? true;
    if (current === visible) {
      continue;
    }

    navigationVisibility.set(id, visible);
    mutated = true;
  }

  if (mutated) {
    persistNavigationVisibility(navigationVisibility);
  }

  return mutated;
}

function loadLegacyGeneralSettings() {
    try {
      if (fs.existsSync(GENERAL_SETTINGS_PATH)) {
        let raw = fs.readFileSync(GENERAL_SETTINGS_PATH, 'utf-8');
        if (raw.charCodeAt(0) === 0xfeff) {
          raw = raw.slice(1);
        }
        return JSON.parse(raw);
      }
    } catch (error) {
      console.error('Failed to load legacy general settings', error);
    }
    return null;
  }

  function buildGeneralSettingsFromStored(stored) {
    const settings = {
      screenConsentRequired: true,
      autoRespondToAgentChat: DEFAULT_GENERAL_SETTINGS.autoRespondToAgentChat ?? false,
      aiAgent: {
        ...DEFAULT_AI_AGENT_SETTINGS,
      },
      techDirect: {
        ...DEFAULT_TECH_DIRECT_SETTINGS,
      },
      snmp: createDefaultSnmpSettings(),
      snmpVersion: DEFAULT_SNMP_VERSION,
    };

    if (!stored || typeof stored !== 'object') {
      return settings;
    }

    if (typeof stored.screenConsentRequired === 'boolean') {
      settings.screenConsentRequired = stored.screenConsentRequired;
    }
    if (typeof stored.autoRespondToAgentChat === 'boolean') {
      settings.autoRespondToAgentChat = stored.autoRespondToAgentChat;
    }
    if (stored.aiAgent && typeof stored.aiAgent === 'object') {
      const aiAgent = stored.aiAgent;
      if (typeof aiAgent.systemPrompt === 'string') {
        settings.aiAgent.systemPrompt = aiAgent.systemPrompt;
      }
      if (Object.prototype.hasOwnProperty.call(aiAgent, 'apiKey')) {
        if (typeof aiAgent.apiKey === 'string') {
          const trimmed = aiAgent.apiKey.trim();
          settings.aiAgent.apiKey = trimmed ? trimmed : null;
        } else if (aiAgent.apiKey === null) {
          settings.aiAgent.apiKey = null;
        }
      }
    }
    if (stored.techDirect && typeof stored.techDirect === 'object') {
      const techDirect = stored.techDirect;
      if (typeof techDirect.apiKey === 'string') {
        const trimmedKey = techDirect.apiKey.trim();
        settings.techDirect.apiKey = trimmedKey ? trimmedKey : null;
      } else if (techDirect.apiKey === null) {
        settings.techDirect.apiKey = null;
      }
      if (typeof techDirect.apiSecret === 'string') {
        const trimmedSecret = techDirect.apiSecret.trim();
        settings.techDirect.apiSecret = trimmedSecret ? trimmedSecret : null;
      } else if (techDirect.apiSecret === null) {
        settings.techDirect.apiSecret = null;
      }
    }
    if (typeof stored.snmpVersion === 'string') {
      const normalizedVersion = stored.snmpVersion.trim().toLowerCase();
      if (SNMP_VERSION_KEYS.includes(normalizedVersion)) {
        settings.snmpVersion = normalizedVersion;
      }
    }
    if (stored.snmp && typeof stored.snmp === 'object') {
      const mergedSnmp = mergeSnmpSettings(settings.snmp, stored.snmp);
      if (mergedSnmp) {
        settings.snmp = mergedSnmp;
      }
    }

    return settings;
  }

  function loadGeneralSettings(tenantId = DEFAULT_TENANT_ID) {
    const normalizedTenantId = sanitizeTenantId(tenantId);
    let stored = loadTenantJson(normalizedTenantId, 'settings.json');
    let foundFile = stored !== null;
    if (!foundFile && normalizedTenantId === DEFAULT_TENANT_ID) {
      stored = loadLegacyGeneralSettings();
      foundFile = stored !== null;
    }

    const settings = buildGeneralSettingsFromStored(stored);
    if (!foundFile) {
      persistTenantJson(normalizedTenantId, 'settings.json', settings);
    }

    generalSettingsCache.set(normalizedTenantId, settings);

    return settings;
  }

  function getGeneralSettingsForTenant(tenantId) {
    const normalized = sanitizeTenantId(tenantId);
    if (generalSettingsCache.has(normalized)) {
      return generalSettingsCache.get(normalized);
    }
    return loadGeneralSettings(normalized);
  }

  function persistGeneralSettings(tenantId, settings) {
    const normalizedTenantId = sanitizeTenantId(tenantId);
    if (!settings) {
      return false;
    }

    const result = persistTenantJson(normalizedTenantId, 'settings.json', settings);
    if (result) {
      generalSettingsCache.set(normalizedTenantId, settings);
      if (normalizedTenantId === DEFAULT_TENANT_ID) {
        generalSettings = settings;
      }
    }
    return result;
  }

function loadAiHistory() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(AI_HISTORY_PATH)) {
      let raw = fs.readFileSync(AI_HISTORY_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    }
  } catch (error) {
    console.error('Failed to load AI history', error);
  }
  return [];
}

function persistAiHistory() {
  try {
    ensureDataDirectory();
    fs.writeFileSync(AI_HISTORY_PATH, JSON.stringify(aiHistory, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist AI history', error);
    return false;
  }
}

function recordAiHistory(payload) {
  if (!payload || typeof payload !== 'object') {
    return;
  }

  aiHistory.push({
    id: uuidv4(),
    timestamp: Date.now(),
    ...payload,
  });
  while (aiHistory.length > AI_HISTORY_LIMIT) {
    aiHistory.shift();
  }

  persistAiHistory();
}

function getRecentAiHistory(options = {}) {
  const limit = Math.max(1, Math.min(options.limit || 50, AI_HISTORY_LIMIT));
  const slice = aiHistory.slice(-limit);
  return slice.reverse().map((entry) => ({ ...entry }));
}

function pruneAiSessions() {
  const now = Date.now();
  for (const [sessionId, session] of aiConversations.entries()) {
    if (!session || typeof session.lastUsed !== 'number') {
      aiConversations.delete(sessionId);
      continue;
    }
    if (now - session.lastUsed > AI_SESSION_TTL_MS) {
      aiConversations.delete(sessionId);
    }
  }
}

function createAiSession(providedId) {
  pruneAiSessions();
  const sessionId = typeof providedId === 'string' && providedId.trim()
    ? providedId.trim()
    : uuidv4();
  aiConversations.set(sessionId, {
    id: sessionId,
    messages: [],
    lastUsed: Date.now(),
  });
  return sessionId;
}

function getAiConversation(sessionId) {
  if (!sessionId) {
    return null;
  }
  pruneAiSessions();
  const existing = aiConversations.get(sessionId);
  if (existing) {
    existing.lastUsed = Date.now();
    return existing;
  }
  const newSession = {
    id: sessionId,
    messages: [],
    lastUsed: Date.now(),
  };
  aiConversations.set(sessionId, newSession);
  return newSession;
}

function appendSessionMessages(session, entries) {
  if (!session || !Array.isArray(entries)) {
    return;
  }

  for (const entry of entries) {
    if (!entry || !entry.role) {
      continue;
    }
    session.messages.push({ ...entry });
  }

  while (session.messages.length > AI_CONVERSATION_HISTORY_LIMIT) {
    session.messages.shift();
  }

  session.lastUsed = Date.now();
}

function buildAiMessages(session, userContent, extraSystemMessages = [], tenantSettings = generalSettings) {
  const systemPrompt = tenantSettings.aiAgent?.systemPrompt ?? DEFAULT_AI_AGENT_SETTINGS.systemPrompt;
  const history = Array.isArray(session?.messages) ? session.messages.slice() : [];
  return [
    { role: 'system', content: systemPrompt },
    { role: 'system', content: `Tool guidance: ${AI_TOOL_INSTRUCTIONS}` },
    ...extraSystemMessages,
    ...history,
    { role: 'user', content: userContent },
  ];
}

async function callOpenAi(messages, overrides = {}, tenantSettings = generalSettings) {
  const apiKey = tenantSettings.aiAgent?.apiKey;
  if (!apiKey) {
    throw new Error('OpenAI API key is not configured');
  }

  const payload = {
    model: OPENAI_MODEL,
    messages,
    temperature: 0.2,
    max_tokens: 700,
    functions: AI_TOOL_DEFINITIONS,
    function_call: 'auto',
    ...overrides,
  };

  if (!overrides.functions) {
    payload.functions = AI_TOOL_DEFINITIONS;
  }
  if (!overrides.function_call) {
    payload.function_call = 'auto';
  }

  const response = await fetch(OPENAI_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`OpenAI request failed (${response.status}) ${errorBody}`);
  }

  const data = await response.json();
  const choice = Array.isArray(data.choices) ? data.choices[0] : null;
  if (!choice) {
    throw new Error('OpenAI returned no choices');
  }
  return { choice, data };
}

async function callAiWithToolLoop(messages, overrides = {}, tenantSettings = generalSettings) {
  const initialResponse = await callOpenAi(messages, overrides, tenantSettings);
  let assistantMessage = initialResponse.choice?.message ?? null;
  let functionCallMessage = null;
  let functionResultMessage = null;
  let toolDetails = null;

  if (assistantMessage?.function_call) {
    const toolResult = await executeAiTool(assistantMessage.function_call);
    toolDetails = {
      name: assistantMessage.function_call.name,
      arguments: toolResult.arguments,
      result: toolResult.result,
      error: toolResult.error ?? null,
    };

    functionCallMessage = {
      role: 'assistant',
      content: null,
      function_call: assistantMessage.function_call,
    };
    functionResultMessage = {
      role: 'function',
      name: assistantMessage.function_call.name,
      content: JSON.stringify(
        toolResult.result ?? { error: toolResult.error ?? 'No result' }
      ),
    };

    const followUpMessages = [
      ...messages,
      functionCallMessage,
      functionResultMessage,
    ];
    const followUpResponse = await callOpenAi(
      followUpMessages,
      {
        ...overrides,
        function_call: 'none',
      },
      tenantSettings,
    );
    assistantMessage = followUpResponse.choice?.message ?? null;
  }

  return { assistantMessage, functionCallMessage, functionResultMessage, toolDetails };
}

function parseFunctionArguments(raw) {
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      return parsed;
    }
  } catch (error) {
    return null;
  }
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runAgentShellCommand(agentId, command, language = 'powershell', timeoutMs = 3000) {
  const entry = clientsById.get(agentId);
  if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
    return {
      error: 'Agent is not connected or offline.',
    };
  }

  const normalizedCommand = typeof command === 'string' ? command.trim() : '';
  if (!normalizedCommand) {
    return {
      error: 'command is required.',
    };
  }

  const resolvedLanguage = typeof language === 'string' && language.trim()
    ? language.trim()
    : 'powershell';
  const initialHistory = shellOutputHistory.get(agentId) ?? [];
  const startIndex = initialHistory.length;

  sendControl(entry.socket, 'start-shell', { language: resolvedLanguage });
  await sleep(100);
  sendControl(entry.socket, 'shell-input', { input: `${normalizedCommand}\n` });
  await sleep(timeoutMs);
  const history = shellOutputHistory.get(agentId) ?? [];
  const outputEntries = history.slice(startIndex);
  return {
    agentId,
    command: normalizedCommand,
    language: resolvedLanguage,
    output: outputEntries.slice(-20),
  };
}

async function fetchAgentServicesForTool(agentId) {
  const entry = clientsById.get(agentId);
  if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
    return {
      error: 'Agent is not connected or offline.',
    };
  }

  try {
    const services = await requestAgentServiceList(entry);
    return {
      agentId,
      services,
    };
  } catch (error) {
    return {
      error: error?.message ?? 'Unable to retrieve services.',
    };
  }
}

async function controlAgentService(agentId, serviceName, action) {
  const entry = clientsById.get(agentId);
  if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
    return {
      error: 'Agent is not connected or offline.',
    };
  }

  const normalizedAction = (action ?? '').toString().trim().toLowerCase();
  if (!['start', 'stop', 'restart'].includes(normalizedAction)) {
    return {
      error: 'Invalid action. Allowed values are start, stop, restart.',
    };
  }

  try {
    const result = await performServiceAction(entry, serviceName, normalizedAction);
    return {
      agentId,
      serviceName,
      action: normalizedAction,
      success: Boolean(result.success),
      message: result.message ?? '',
    };
  } catch (error) {
    return {
      error: error?.message ?? 'Service action failed.',
    };
  }
}

function resolveAgentEntry(agentId) {
  if (!agentId) {
    return null;
  }
  const connected = clientsById.get(agentId);
  if (connected) {
    return connected;
  }
  const cachedInfo = agents.get(agentId);
  if (!cachedInfo) {
    return null;
  }
  return { socket: null, info: cachedInfo };
}

function clampLimit(value, fallback = 10, min = 1, max = 100) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(Math.max(min, parsed), max);
}

function getAgentMonitoringHistory(agentId, limit = 20) {
  const normalizedLimit = clampLimit(limit, 20, 1, 50);
  const events = [];
  for (let index = monitoringHistory.length - 1; index >= 0 && events.length < normalizedLimit; index -= 1) {
    const entry = monitoringHistory[index];
    const payload = entry?.payload ?? {};
    const candidateId = payload.agentId
      ?? (typeof payload.agent === 'string' ? payload.agent : null)
      ?? payload.agent?.id
      ?? payload.agent?.agentId
      ?? null;
    if (!candidateId || candidateId !== agentId) {
      continue;
    }
    events.push({
      eventName: entry.eventName ?? null,
      timestamp: payload.timestamp ?? payload.updatedAt ?? payload.createdAt ?? null,
      summary: payload.summary ?? null,
      details: payload,
    });
  }
  return events;
}

function getAgentPatchHistory(agentId, limit = 20) {
  const normalizedLimit = clampLimit(limit, 20, 1, 50);
  const entries = [];
  for (const entry of patchHistory) {
    if (!entry || entry.agentId !== agentId) {
      continue;
    }
    entries.push(entry);
    if (entries.length >= normalizedLimit) {
      break;
    }
  }
  return entries;
}

function getAgentSoftwareInventory(agentId) {
  const entry = resolveAgentEntry(agentId);
  const info = entry?.info ?? null;
  if (!info) {
    return null;
  }
  const software = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  return {
    agentId,
    agentName: info.name ?? agentId,
    retrievedAt: info.softwareRetrievedAt ?? null,
    total: software.length,
    list: software.map((item) => ({
      name: item?.name ?? 'Unknown',
      version: item?.version ?? '',
      publisher: item?.publisher ?? '',
      installDate: item?.installDate ?? null,
      location: item?.location ?? null,
      source: item?.source ?? null,
    })),
  };
}

function getAgentScriptActivity(agentId, limit = 5) {
  const normalizedLimit = clampLimit(limit, 5, 1, 20);
  const activities = [];
  for (let index = monitoringHistory.length - 1; index >= 0 && activities.length < normalizedLimit; index -= 1) {
    const entry = monitoringHistory[index];
    const payload = entry?.payload ?? {};
    const candidateId = payload.agentId
      ?? (typeof payload.agent === 'string' ? payload.agent : null)
      ?? payload.agent?.id
      ?? payload.agent?.agentId
      ?? null;
    if (candidateId !== agentId) {
      continue;
    }
    if (!payload.scriptName) {
      continue;
    }
    activities.push({
      eventName: entry.eventName ?? null,
      scriptName: payload.scriptName,
      timestamp: payload.timestamp ?? payload.requestedAt ?? null,
      status: payload.status ?? null,
      details: payload,
    });
  }
  return activities;
}

function getAgentComplianceSummary(agentId) {
  if (!agentId) {
    return null;
  }
  const summary = complianceStatusByAgent.get(agentId);
  if (!summary) {
    return null;
  }
  const profile = getComplianceProfile(summary.profileId);
  return {
    ...summary,
    profile,
  };
}

function getAgentLicenseRecord(agentId) {
  if (!agentId) {
    return null;
  }
  const record = licenseRecords.find((entry) => entry.assignedAgentId === agentId) ?? null;
  if (!record) {
    return null;
  }
  return {
    ...record,
    status: record.revokedAt ? 'revoked' : 'assigned',
  };
}

function getAgentVulnerabilities(agentId) {
  const entry = resolveAgentEntry(agentId);
  const info = entry?.info ?? null;
  if (!info) {
    return null;
  }
  const results = evaluateAssetVulnerabilities(info);
  return {
    agentId,
    agentName: info.name ?? agentId,
    total: results.length,
    vulnerabilities: results,
  };
}

async function gatherAgentSystemHealth(agentId, level = 'Information') {
  const entry = clientsById.get(agentId);
  const info = entry?.info ?? agents.get(agentId) ?? null;
  const normalizedLevel = typeof level === 'string' && level.trim() ? level.trim() : 'Information';
  const response = {
    agentId,
    agentName: info?.name ?? agentId,
    online: Boolean(entry?.socket?.readyState === WebSocket.OPEN),
    stats: null,
    since: null,
    retrievedAt: null,
    entries: [],
    entryLevel: normalizedLevel,
    entriesRetrievedAt: null,
    errors: [],
  };

  const cachedStats = agentEventStatsCache.get(agentId);
  if (cachedStats) {
    response.stats = cachedStats.stats;
    response.since = cachedStats.since;
    response.retrievedAt = cachedStats.retrievedAt;
  }

  const cachedEntries = agentEventEntriesCache.get(agentId);
  if (cachedEntries) {
    response.entries = cachedEntries.entries;
    response.entryLevel = cachedEntries.level ?? response.entryLevel;
    response.entriesRetrievedAt = cachedEntries.retrievedAt ?? response.entriesRetrievedAt;
  }

  if (entry?.socket?.readyState === WebSocket.OPEN) {
    try {
      const stats = await requestAgentEventStats(entry);
      response.stats = stats.stats;
      response.since = stats.since;
      response.retrievedAt = stats.retrievedAt;
    } catch (error) {
      response.errors.push(`stats: ${error?.message ?? 'request failed'}`);
    }

    try {
      const entriesPayload = await requestAgentEventEntries(entry, normalizedLevel);
      response.entries = Array.isArray(entriesPayload.entries) ? entriesPayload.entries : [];
      response.entryLevel = entriesPayload.level ?? normalizedLevel;
      response.entriesRetrievedAt = new Date().toISOString();
      agentEventEntriesCache.set(agentId, {
        entries: response.entries.slice(0, 100),
        level: response.entryLevel,
        retrievedAt: response.entriesRetrievedAt,
      });
    } catch (error) {
      response.errors.push(`entries: ${error?.message ?? 'request failed'}`);
    }
  }

  return response;
}

async function fetchAgentFirewallRulesForAgent(agentId) {
  const entry = clientsById.get(agentId);
  if (!entry) {
    return { agentId, error: 'Agent not connected' };
  }
  if (!entry.socket || entry.socket.readyState !== WebSocket.OPEN) {
    return { agentId, error: 'Agent offline' };
  }
  try {
    const rules = await requestAgentFirewallRules(entry);
    return {
      agentId,
      firewallEnabled: rules.firewallEnabled ?? null,
      profiles: Array.isArray(rules.profiles) ? rules.profiles : null,
      defaultInboundAction: rules.defaultInboundAction ?? null,
      defaultOutboundAction: rules.defaultOutboundAction ?? null,
      rules: Array.isArray(rules.rules) ? rules.rules : [],
    };
  } catch (error) {
    return { agentId, error: error?.message ?? 'Firewall request failed' };
  }
}

function formatAgentSummary(info) {
  if (!info) {
    return null;
  }
  return {
    id: info.id,
    name: info.name ?? 'Unknown',
    status: info.status ?? 'offline',
    group: info.group ?? DEFAULT_GROUP,
    os: info.os ?? info.platform ?? 'Unknown',
    connectedAt: info.connectedAt ? new Date(info.connectedAt).toISOString() : null,
    lastSeen: info.lastSeen ? new Date(info.lastSeen).toISOString() : null,
    monitoringAlert: agentAlertStatus.get(info.id) ?? false,
    pendingReboot: Boolean(info.pendingReboot),
  };
}

function formatAgentDetails(info) {
  if (!info) {
    return null;
  }
  return {
    id: info.id,
    name: info.name ?? 'Unknown',
    status: info.status ?? 'offline',
    os: info.os ?? info.platform ?? 'Unknown',
    group: info.group ?? DEFAULT_GROUP,
    components: {
      monitoring: shouldMonitorAgent(info),
    },
    lastSeen: info.lastSeen ? new Date(info.lastSeen).toISOString() : null,
    connectedAt: info.connectedAt ? new Date(info.connectedAt).toISOString() : null,
    pendingReboot: Boolean(info.pendingReboot),
    specs: info.specs ?? null,
    features: Array.isArray(info.features) ? info.features : [],
    softwareSummary: info.softwareSummary ?? null,
  };
}

async function executeAiTool(functionCall) {
  if (!functionCall) {
    return {
      arguments: {},
      result: null,
      error: 'No function call was provided.',
    };
  }

  const args = parseFunctionArguments(functionCall.arguments);
  if (args === null) {
    return {
      arguments: null,
      result: null,
      error: 'Unable to decode function arguments.',
    };
  }

  switch (functionCall.name) {
    case 'list_agents': {
      const limit = Number.isFinite(Number(args?.limit))
        ? Math.min(50, Math.max(1, Number(args.limit)))
        : 20;
      const summaries = Array.from(clientsById.values())
        .map((entry) => formatAgentSummary(entry.info))
        .filter(Boolean)
        .slice(0, limit);
      return {
        arguments: args,
        result: { agents: summaries },
      };
    }
    case 'get_agent_details': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const liveEntry = clientsById.get(agentId);
      const targetInfo = liveEntry?.info ?? agents.get(agentId) ?? null;
      if (!targetInfo) {
        return {
          arguments: args,
          result: null,
          error: 'Agent not found.',
        };
      }
      return {
        arguments: args,
        result: { agent: formatAgentDetails(targetInfo) },
      };
    }
    case 'assign_agent_group': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      const groupName = typeof args?.group === 'string' ? args.group.trim() : '';
      if (!agentId || !groupName) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id and group are required.',
        };
      }
      const entry = clientsById.get(agentId);
      if (!entry) {
        return {
          arguments: args,
          result: null,
          error: 'Agent is not connected.',
        };
      }
      const previousGroup = entry.info.group ?? DEFAULT_GROUP;
      const assignedGroup = assignAgentToGroup(agentId, groupName);
      return {
        arguments: args,
        result: {
          agentId,
          previousGroup,
          group: assignedGroup,
        },
      };
    }
    case 'get_agent_monitoring_history': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const resolved = resolveAgentEntry(agentId);
      const events = getAgentMonitoringHistory(agentId, args?.limit);
      return {
        arguments: args,
        result: {
          agentId,
          agentName: resolved?.info?.name ?? agentId,
          events,
        },
      };
    }
    case 'get_agent_system_health': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const level = typeof args?.level === 'string' ? args.level : 'Information';
      const health = await gatherAgentSystemHealth(agentId, level);
      return {
        arguments: args,
        result: health,
      };
    }
    case 'get_agent_firewall_rules': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const firewall = await fetchAgentFirewallRulesForAgent(agentId);
      if (firewall.error) {
        return {
          arguments: args,
          result: firewall,
          error: firewall.error,
        };
      }
      return {
        arguments: args,
        result: firewall,
      };
    }
    case 'get_agent_vulnerabilities': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const payload = getAgentVulnerabilities(agentId);
      if (!payload) {
        return {
          arguments: args,
          result: null,
          error: 'Agent data is unavailable.',
        };
      }
      return {
        arguments: args,
        result: payload,
      };
    }
    case 'get_agent_patch_history': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const history = getAgentPatchHistory(agentId, args?.limit);
      return {
        arguments: args,
        result: {
          agentId,
          history,
        },
      };
    }
    case 'get_agent_software_inventory': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const inventory = getAgentSoftwareInventory(agentId);
      if (!inventory) {
        return {
          arguments: args,
          result: null,
          error: 'Agent software inventory is unavailable.',
        };
      }
      return {
        arguments: args,
        result: inventory,
      };
    }
    case 'get_agent_scripts': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const resolved = resolveAgentEntry(agentId);
      const activity = getAgentScriptActivity(agentId, args?.limit);
      const availableScripts = Array.isArray(monitoringConfig.remediationScripts)
        ? monitoringConfig.remediationScripts.map((entry) => ({
          name: entry.name,
          description: entry.description ?? '',
          language: entry.language ?? null,
        }))
        : [];
      return {
        arguments: args,
        result: {
          agentId,
          agentName: resolved?.info?.name ?? agentId,
          availableScripts,
          recentActivity: activity,
        },
      };
    }
    case 'get_agent_compliance_report': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const summary = getAgentComplianceSummary(agentId);
      if (!summary) {
        return {
          arguments: args,
          result: null,
          error: 'Compliance data is unavailable for that agent.',
        };
      }
      return {
        arguments: args,
        result: summary,
      };
    }
    case 'get_agent_license_info': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const license = getAgentLicenseRecord(agentId);
      return {
        arguments: args,
        result: {
          agentId,
          license,
        },
      };
    }
    case 'run_agent_shell_command': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const command = typeof args?.command === 'string' ? args.command : '';
      if (!command.trim()) {
        return {
          arguments: args,
          result: null,
          error: 'command is required.',
        };
      }
      const language = typeof args?.language === 'string' ? args.language : 'powershell';
      const payload = await runAgentShellCommand(agentId, command, language);
      if (payload.error) {
        return {
          arguments: args,
          result: payload,
          error: payload.error,
        };
      }
      return {
        arguments: args,
        result: payload,
      };
    }
    case 'get_agent_services': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      if (!agentId) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id is required.',
        };
      }
      const payload = await fetchAgentServicesForTool(agentId);
      if (payload.error) {
        return {
          arguments: args,
          result: payload,
          error: payload.error,
        };
      }
      return {
        arguments: args,
        result: payload,
      };
    }
    case 'manage_agent_service': {
      const agentId = typeof args?.agent_id === 'string' ? args.agent_id.trim() : '';
      const serviceName = typeof args?.service_name === 'string' ? args.service_name.trim() : '';
      const action = typeof args?.action === 'string' ? args.action : '';
      if (!agentId || !serviceName || !action) {
        return {
          arguments: args,
          result: null,
          error: 'agent_id, service_name, and action are required.',
        };
      }
      const payload = await controlAgentService(agentId, serviceName, action);
      if (payload.error) {
        return {
          arguments: args,
          result: payload,
          error: payload.error,
        };
      }
      return {
        arguments: args,
        result: payload,
      };
    }
    default:
      return {
        arguments: args,
        result: null,
        error: 'Requested tool is not implemented.',
      };
  }
}

async function respondToAgentWithAi(info, chatEvent) {
  if (!info?.id || !info.socket || info.socket.readyState !== WebSocket.OPEN) {
    return;
  }
  const tenantId = info?.tenantId ?? DEFAULT_TENANT_ID;
  const tenantSettings = getGeneralSettingsForTenant(tenantId);
  if (!tenantSettings.aiAgent?.apiKey) {
    console.log('AI auto reply skipped: API key missing');
    return;
  }
  if (!tenantSettings.autoRespondToAgentChat) {
    console.log('AI auto reply skipped: feature disabled');
    return;
  }

  console.log(`AI auto reply triggered for agent ${info.id}`);

  console.log('respondToAgentWithAi start', chatEvent.text);

  const sessionId = `${AI_AGENT_SESSION_PREFIX}${info.id}`;
  const conversation = getAiConversation(sessionId);
  const userContent = chatEvent.text;
  const agentDisplay = info.name ? `${info.name} (${info.id})` : info.id;
  const agentFocusInstruction = `Focus exclusively on agent ${agentDisplay}. Only provide information, guidance, and tool actions that target this agent.`;
  const messages = buildAiMessages(conversation, userContent, [
    { role: 'system', content: agentFocusInstruction },
  ], tenantSettings);

  try {
    const {
      assistantMessage,
      functionCallMessage,
      functionResultMessage,
      toolDetails,
    } = await callAiWithToolLoop(
      messages,
      { ...AI_AGENT_RESPONSE_OPTIONS },
      tenantSettings,
    );
    const reply = assistantMessage?.content?.trim() ?? '';
    if (!reply) {
      console.log('AI auto reply produced empty completion');
      return;
    }

    const sessionEntries = [
      { role: 'user', content: userContent },
      ...(functionCallMessage && functionResultMessage ? [functionCallMessage, functionResultMessage] : []),
      { role: 'assistant', content: reply },
    ];
    appendSessionMessages(conversation, sessionEntries);

    if (toolDetails) {
      recordAiHistory({
        sessionId,
        user: AI_AGENT_USER,
        type: 'tool',
        tool: toolDetails.name,
        arguments: toolDetails.arguments,
        result: toolDetails.result,
        error: toolDetails.error,
      });
    }

    const aiEvent = {
      sessionId: chatEvent.sessionId ?? uuidv4(),
      agentId: info.id,
      agentName: info.name,
      direction: 'server',
      text: reply,
      timestamp: new Date().toISOString(),
      user: AI_AGENT_USER,
      role: AI_AGENT_ROLE,
    };

    recordChatHistory(info.id, aiEvent);
    dispatchChatEvent(info.id, aiEvent);
    sendControl(info.socket, 'chat-request', {
      sessionId: aiEvent.sessionId,
      text: reply,
      user: AI_AGENT_USER,
      role: AI_AGENT_ROLE,
    });

    recordAiHistory({
      sessionId,
      user: AI_AGENT_USER,
      type: 'auto-response',
      agentId: info.id,
      text: reply,
    });
  } catch (error) {
    console.log('AI auto reply failed', error?.message ?? error);
    console.error('AI agent reply failed', error);

    const messageText = `Auto-reply failed: ${error?.message ?? (typeof error === 'string' ? error : 'Unknown error')}`;
    recordAiHistory({
      sessionId,
      user: AI_AGENT_USER,
      type: 'auto-response-error',
      agentId: info.id,
      text: messageText,
    });

    const fallbackEvent = {
      sessionId: chatEvent.sessionId ?? uuidv4(),
      agentId: info.id,
      agentName: info.name,
      direction: 'server',
      text: messageText,
      timestamp: new Date().toISOString(),
      user: AI_AGENT_USER,
      role: AI_AGENT_ROLE,
    };

    recordChatHistory(info.id, fallbackEvent);
    dispatchChatEvent(info.id, fallbackEvent);
    sendControl(info.socket, 'chat-request', {
      sessionId: fallbackEvent.sessionId,
      text: fallbackEvent.text,
      user: AI_AGENT_USER,
      role: AI_AGENT_ROLE,
    });
  }
}

function scheduleAiAgentResponse(info, chatEvent) {
  console.log(`Scheduling AI agent reply for ${info?.id}`);
  void respondToAgentWithAi(info, chatEvent);
}

function loadComplianceConfig() {
  ensureDataDirectory();
  let stored = null;
  try {
    if (fs.existsSync(COMPLIANCE_CONFIG_PATH)) {
      let raw = fs.readFileSync(COMPLIANCE_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load compliance config', error);
  }

  const normalize = (payload) => {
    const profiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
    const assignments = payload?.assignments && typeof payload.assignments === 'object' && !Array.isArray(payload.assignments)
      ? payload.assignments
      : {};
    const defaultProfileId = typeof payload?.defaultProfileId === 'string' && payload.defaultProfileId.trim()
      ? payload.defaultProfileId.trim()
      : (profiles[0]?.id ?? null);
    return {
      defaultProfileId,
      assignments,
      profiles,
    };
  };

  const config = normalize(stored ?? DEFAULT_COMPLIANCE_CONFIG);
  if (!stored) {
    try {
      fs.writeFileSync(COMPLIANCE_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to persist default compliance config', error);
    }
  }

  return config;
}

function loadGpoConfig() {
  ensureDataDirectory();
  let stored = null;
  try {
    if (fs.existsSync(GPO_CONFIG_PATH)) {
      let raw = fs.readFileSync(GPO_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load GPO config', error);
  }

  const normalize = (payload) => {
    const profiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
    const assignments = payload?.assignments && typeof payload.assignments === 'object' && !Array.isArray(payload.assignments)
      ? payload.assignments
      : {};
    const defaultProfileId = typeof payload?.defaultProfileId === 'string' && payload.defaultProfileId.trim()
      ? payload.defaultProfileId.trim()
      : (profiles[0]?.id ?? null);
    return {
      defaultProfileId,
      assignments,
      profiles,
    };
  };

  const config = normalize(stored ?? { defaultProfileId: null, assignments: {}, profiles: [] });
  if (!stored) {
    try {
      fs.writeFileSync(GPO_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to persist default GPO config', error);
    }
  }

  return config;
}

function persistGpoConfig() {
  ensureDataDirectory();
  try {
    fs.writeFileSync(GPO_CONFIG_PATH, JSON.stringify(gpoConfig, null, 2), 'utf-8');
  } catch (error) {
    console.error('Failed to persist GPO config', error);
  }
}


function sanitizeProfilesPayload(payload) {
  const profiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
  const normalized = [];
  for (const entry of profiles) {
    if (!entry || typeof entry !== 'object') {
      continue;
    }
    const id = typeof entry.id === 'string' && entry.id.trim()
      ? entry.id.trim()
      : null;
    if (!id) {
      continue;
    }
    const label = typeof entry.label === 'string' && entry.label.trim()
      ? entry.label.trim()
      : id;
    const description = typeof entry.description === 'string'
      ? entry.description.trim()
      : '';
    const weight = Number(entry.weight);
    const profileWeight = Number.isFinite(weight) && weight > 0 ? weight : 1;
    const rules = Array.isArray(entry.rules) ? entry.rules : [];
    const sanitizedRules = [];
    for (const rule of rules) {
      if (!rule || typeof rule !== 'object') {
        continue;
      }
      const ruleId = typeof rule.id === 'string' && rule.id.trim()
        ? rule.id.trim()
        : null;
      if (!ruleId) {
        continue;
      }
      const ruleType = typeof rule.type === 'string'
        ? rule.type.trim().toLowerCase()
        : 'registry';
      const ruleWeight = Number(rule.weight);
      const normalizedWeight = Number.isFinite(ruleWeight) && ruleWeight > 0 ? ruleWeight : 1;
      const operation = typeof rule.operation === 'string' && rule.operation.trim()
        ? rule.operation.trim().toLowerCase()
        : 'equals';
      const subject = (rule.subject && typeof rule.subject === 'object') ? rule.subject : {};
        const mappings = Array.isArray(rule.mappings) ? rule.mappings : [];
        const normalizedMappings = [];
        for (const mapping of mappings) {
          if (!mapping || typeof mapping !== 'object') {
            continue;
          }
          const standard = typeof mapping.standard === 'string' ? mapping.standard.trim() : null;
          const identifier = typeof mapping.id === 'string' ? mapping.id.trim() : null;
          if (!standard || !identifier) {
            continue;
          }
          normalizedMappings.push({ standard, id: identifier });
        }
        const remediationScript = typeof rule.remediationScript === 'string' && rule.remediationScript.trim()
          ? rule.remediationScript.trim()
          : null;

        sanitizedRules.push({
          id: ruleId,
          description: typeof rule.description === 'string' ? rule.description.trim() : '',
          type: ruleType,
          weight: normalizedWeight,
          operation,
          subject,
          mappings: normalizedMappings,
          remediationScript,
        });
      }

    normalized.push({
      id,
      label,
      description,
      weight: profileWeight,
      rules: sanitizedRules,
    });
  }

  return normalized;
}

function sanitizeGpoProfilesPayload(payload) {
  const profiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
  const normalized = [];
  for (const entry of profiles) {
    if (!entry || typeof entry !== 'object') {
      continue;
    }
    const id = typeof entry.id === 'string' && entry.id.trim() ? entry.id.trim() : null;
    if (!id) {
      continue;
    }
    const label = typeof entry.label === 'string' && entry.label.trim() ? entry.label.trim() : id;
    const description = typeof entry.description === 'string' ? entry.description.trim() : '';
    const template = typeof entry.template === 'string' ? entry.template : '';
    normalized.push({ id, label, description, template });
  }
  return normalized;
}

function persistComplianceConfig() {
  try {
    ensureDataDirectory();
    fs.writeFileSync(COMPLIANCE_CONFIG_PATH, JSON.stringify(complianceConfig, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist compliance config', error);
    return false;
  }
}

function refreshComplianceCache() {
  complianceProfilesById = new Map();
  const profiles = Array.isArray(complianceConfig.profiles) ? complianceConfig.profiles : [];
  for (const profile of profiles) {
    if (!profile?.id) {
      continue;
    }
    complianceProfilesById.set(profile.id, {
      ...profile,
      rules: Array.isArray(profile.rules) ? profile.rules : [],
    });
  }
}

function getComplianceProfile(profileId) {
  if (!profileId) {
    return null;
  }
  return complianceProfilesById.get(profileId) ?? null;
}

function getAssignedComplianceProfileId(agentId) {
  const assignment = (complianceConfig.assignments ?? {})[agentId];
  if (assignment && typeof assignment === 'string') {
    return assignment;
  }
  return complianceConfig.defaultProfileId ?? (complianceConfig.profiles?.[0]?.id ?? null);
}

function refreshGpoCache() {
  gpoProfilesById = new Map();
  const profiles = Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : [];
  for (const profile of profiles) {
    if (!profile?.id) {
      continue;
    }
    gpoProfilesById.set(profile.id, {
      ...profile,
      template: typeof profile.template === 'string' ? profile.template : '',
    });
  }
}

function getGpoProfile(profileId) {
  if (!profileId) {
    return null;
  }
  return gpoProfilesById.get(profileId) ?? null;
}

function getAssignedGpoProfileId(agentId) {
  const assignment = (gpoConfig.assignments ?? {})[agentId];
  if (assignment && typeof assignment === 'string') {
    return assignment;
  }
  return gpoConfig.defaultProfileId ?? (gpoConfig.profiles?.[0]?.id ?? null);
}

function getRuleWeight(profile, ruleId) {
  if (!profile || !Array.isArray(profile.rules)) {
    return 1;
  }
  const rule = profile.rules.find((entry) => entry?.id === ruleId);
  if (!rule) {
    return 1;
  }
  const weight = Number(rule.weight ?? 1);
  if (!Number.isFinite(weight) || weight <= 0) {
    return 1;
  }
  return weight;
}

function handleComplianceReport(agentId, payload) {
  if (!agentId) {
    return;
  }

  const profileId = typeof payload?.profileId === 'string' && payload.profileId.trim()
    ? payload.profileId.trim()
    : getAssignedComplianceProfileId(agentId);
  const profile = getComplianceProfile(profileId);
  const data = Array.isArray(payload?.results) ? payload.results : [];
  let passWeight = 0;
  let failWeight = 0;
  let notApplicableWeight = 0;
  const normalized = [];

  for (const entry of data) {
    const ruleId = typeof entry?.ruleId === 'string' && entry.ruleId.trim()
      ? entry.ruleId.trim()
      : null;
    if (!ruleId) {
      continue;
    }

    let status = typeof entry?.status === 'string' ? entry.status.trim().toLowerCase() : '';
    if (status !== 'pass' && status !== 'fail' && status !== 'not_applicable') {
      status = 'fail';
    }

    const weight = getRuleWeight(profile, ruleId);
    normalized.push({
      ruleId,
      status,
      weight,
      details: typeof entry?.details === 'string' ? entry.details : '',
    });

    if (status === 'pass') {
      passWeight += weight;
    } else if (status === 'fail') {
      failWeight += weight;
    } else {
      notApplicableWeight += weight;
    }
  }

  const applicableWeight = passWeight + failWeight;
  const score = applicableWeight > 0
    ? Math.round((passWeight / applicableWeight) * 1000) / 10
    : null;
  const updatedAt = typeof payload?.evaluatedAt === 'string' && payload.evaluatedAt
    ? payload.evaluatedAt
    : new Date().toISOString();

  const summary = {
    profileId,
    profileLabel: profile?.label ?? profileId ?? 'Unknown profile',
    passWeight,
    failWeight,
    notApplicableWeight,
    totalWeight: passWeight + failWeight + notApplicableWeight,
    score,
    results: normalized,
    updatedAt,
  };

  complianceStatusByAgent.set(agentId, summary);
  const entry = clientsById.get(agentId);
  if (entry) {
    entry.info.compliance = {
      profileId,
      score,
      updatedAt,
    };
  }
  console.log(`Compliance report received from ${agentId} (score ${score ?? 'n/a'})`);
}

function broadcastComplianceDefinitions({ runNow = false, targetAgentId } = {}) {
  if (targetAgentId) {
    const entry = clientsById.get(targetAgentId);
    if (entry) {
      sendComplianceDefinitions(entry.socket, targetAgentId, runNow);
    }
    return;
  }

  for (const [agentId, { socket }] of clientsById) {
    sendComplianceDefinitions(socket, agentId, runNow);
  }
}

function sendComplianceDefinitions(socket, agentId, runNow = false) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  const payload = {
    type: 'compliance-definitions',
    profiles: Array.isArray(complianceConfig.profiles) ? complianceConfig.profiles : [],
    defaultProfileId: complianceConfig.defaultProfileId ?? null,
    assignments: complianceConfig.assignments ?? {},
    assignedProfileId: getAssignedComplianceProfileId(agentId),
    runNow,
  };

  try {
    socket.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Unable to deliver compliance definitions', error);
  }
}

function requestComplianceRun(agentId = null) {
  if (agentId) {
    const entry = clientsById.get(agentId);
    if (entry) {
      sendComplianceRunRequest(entry.socket, agentId);
    }
    return;
  }

  for (const [id, entry] of clientsById) {
    sendComplianceRunRequest(entry.socket, id);
  }
}

function broadcastGpoDefinitions({ runNow = false, targetAgentId } = {}) {
  if (targetAgentId) {
    const entry = clientsById.get(targetAgentId);
    if (entry) {
      sendGpoDefinitions(entry.socket, targetAgentId, runNow);
    }
    return;
  }

  for (const [agentId, { socket }] of clientsById) {
    sendGpoDefinitions(socket, agentId, runNow);
  }
}

function sendGpoDefinitions(socket, agentId, runNow = false) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  const payload = {
    type: 'gpo-policies',
    profiles: Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : [],
    defaultProfileId: gpoConfig.defaultProfileId ?? null,
    assignments: gpoConfig.assignments ?? {},
    assignedProfileId: getAssignedGpoProfileId(agentId),
    runNow,
  };

  try {
    socket.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Unable to deliver GPO definitions', error);
  }
}

function requestGpoRun(agentId = null) {
  broadcastGpoDefinitions({ runNow: true, targetAgentId: agentId });
}

function sendComplianceRunRequest(socket, agentId) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  const payload = {
    type: 'run-compliance',
    profileId: getAssignedComplianceProfileId(agentId),
  };

  try {
    socket.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Unable to request compliance run', error);
  }
}

function loadMonitoringConfig() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(MONITORING_CONFIG_PATH)) {
      let raw = fs.readFileSync(MONITORING_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load monitoring config', error);
  }

  const defaultConfig = {
    monitoringProfiles: [],
    alertProfiles: [],
    remediationScripts: [],
  };
  fs.writeFileSync(MONITORING_CONFIG_PATH, JSON.stringify(defaultConfig, null, 2));
  return defaultConfig;
}

function ensureConfigDirectory() {
  const configDir = path.join(__dirname, 'config');
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
}

const DEFAULT_VULNERABILITY_CONFIG = {
  nvdApiKey: '',
  ingestionMinutes: {
    nvd: 1440,
    kev: 1440,
    epss: 60,
  },
  epssThreshold: 0.4,
  ignoredCves: [],
  sources: [],
};

function loadVulnerabilityConfig() {
  ensureConfigDirectory();
  try {
    if (fs.existsSync(VULNERABILITY_CONFIG_PATH)) {
      let raw = fs.readFileSync(VULNERABILITY_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load vulnerability config', error);
  }

  fs.writeFileSync(VULNERABILITY_CONFIG_PATH, JSON.stringify(DEFAULT_VULNERABILITY_CONFIG, null, 2));
  return { ...DEFAULT_VULNERABILITY_CONFIG };
}

function persistVulnerabilityConfig() {
  try {
    ensureConfigDirectory();
    fs.writeFileSync(VULNERABILITY_CONFIG_PATH, JSON.stringify(vulnerabilityConfig, null, 2));
    return true;
  } catch (error) {
    console.error('Failed to persist vulnerability config', error);
    return false;
  }
}

function loadVulnerabilityStore() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(VULNERABILITY_STORE_PATH)) {
      let raw = fs.readFileSync(VULNERABILITY_STORE_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return new Map(JSON.parse(raw));
    }
  } catch (error) {
    console.error('Failed to load vulnerability store', error);
  }

  const store = new Map();
  persistVulnerabilityStore(store);
  return store;
}

function persistVulnerabilityStore(store = vulnerabilityStore) {
  try {
    ensureDataDirectory();
    fs.writeFileSync(VULNERABILITY_STORE_PATH, JSON.stringify(Array.from(store.entries())), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist vulnerability store', error);
    return false;
  }
}

function capitalize(value) {
  if (!value) {
    return '';
  }
  return value[0].toUpperCase() + value.slice(1);
}

function getDefaultIngestionMinutes(sourceId) {
  const def = DEFAULT_VULNERABILITY_SOURCE_DEFINITIONS.find((entry) => entry.id === sourceId);
  const minutes = Number(def?.ingestionMinutes ?? 0);
  return Number.isFinite(minutes) && minutes > 0 ? minutes : 60;
}

function ensureDefaultVulnerabilitySources() {
  if (!Array.isArray(vulnerabilityConfig.sources)) {
    vulnerabilityConfig.sources = [];
  }

  let mutated = false;
  for (const definition of DEFAULT_VULNERABILITY_SOURCE_DEFINITIONS) {
    let existing = vulnerabilityConfig.sources.find((entry) => entry.id === definition.id);
    if (!existing) {
      const legacyKey = `last${capitalize(definition.id)}Ingest`;
      existing = {
        ...definition,
        enabled: definition.enabled ?? true,
        ingestionMinutes: definition.ingestionMinutes,
        lastIngested: vulnerabilityConfig[legacyKey] ?? null,
      };
      vulnerabilityConfig.sources.push(existing);
      mutated = true;
      continue;
    }

    let updated = false;
    if (!existing.label) {
      existing.label = definition.label;
      updated = true;
    }
    if (!existing.description) {
      existing.description = definition.description;
      updated = true;
    }
    if (!existing.url) {
      existing.url = definition.url;
      updated = true;
    }
    if (!existing.type) {
      existing.type = definition.type;
      updated = true;
    }
    if (!existing.ingestionMinutes) {
      existing.ingestionMinutes = definition.ingestionMinutes;
      updated = true;
    }
    if (existing.enabled === undefined) {
      existing.enabled = true;
      updated = true;
    }
    const legacyKey = `last${capitalize(definition.id)}Ingest`;
    if (!existing.lastIngested && vulnerabilityConfig[legacyKey]) {
      existing.lastIngested = vulnerabilityConfig[legacyKey];
      updated = true;
    }
    if (!existing.builtin) {
      existing.builtin = true;
      updated = true;
    }

    mutated = mutated || updated;
  }

  if (mutated) {
    persistVulnerabilityConfig();
  }
}

function getVulnerabilitySource(sourceId) {
  if (!Array.isArray(vulnerabilityConfig.sources)) {
    return null;
  }
  return vulnerabilityConfig.sources.find((entry) => entry.id === sourceId) ?? null;
}

function formatSourceForClient(source) {
  if (!source) {
    return null;
  }
  return {
    id: source.id,
    label: source.label ?? source.id,
    description: source.description ?? '',
    type: source.type ?? '',
    url: source.url ?? '',
    enabled: Boolean(source.enabled),
    ingestionMinutes: source.ingestionMinutes ?? getDefaultIngestionMinutes(source.id),
    lastIngested: source.lastIngested ?? null,
    builtin: Boolean(source.builtin),
  };
}

function getSourceIntervalMs(sourceId) {
  const source = getVulnerabilitySource(sourceId);
  const minutes = Number(source?.ingestionMinutes ?? getDefaultIngestionMinutes(sourceId));
  if (!Number.isFinite(minutes) || minutes <= 0) {
    return 60 * 60 * 1000;
  }
  return minutes * 60 * 1000;
}

function cancelSourceIngestion(sourceId) {
  const job = vulnerabilityIngestionJobs.get(sourceId);
  if (job?.timer) {
    clearTimeout(job.timer);
  }
  vulnerabilityIngestionJobs.delete(sourceId);
}

function scheduleNextRunForSource(sourceId, delayMs = 0) {
  const source = getVulnerabilitySource(sourceId);
  if (!source || !source.enabled) {
    cancelSourceIngestion(sourceId);
    return;
  }

  const job = vulnerabilityIngestionJobs.get(sourceId) ?? {};
  if (job.timer) {
    clearTimeout(job.timer);
  }

  job.timer = setTimeout(() => {
    runSourceIngestion(sourceId);
  }, Math.max(0, delayMs));
  vulnerabilityIngestionJobs.set(sourceId, job);
}

async function runSourceIngestion(sourceId) {
  const source = getVulnerabilitySource(sourceId);
  if (!source || !source.enabled) {
    return;
  }

  const implementation = VULNERABILITY_SOURCE_IMPLEMENTATIONS[sourceId];
  if (!implementation) {
    cancelSourceIngestion(sourceId);
    return;
  }

  try {
    await implementation();
  } catch (error) {
    console.error(`Vulnerability ingestion (${sourceId}) failed`, error);
  } finally {
    const intervalMs = getSourceIntervalMs(sourceId);
    scheduleNextRunForSource(sourceId, intervalMs);
  }
}

function rescheduleSourceIngestion(sourceId) {
  const source = getVulnerabilitySource(sourceId);
  if (!source || !source.enabled) {
    cancelSourceIngestion(sourceId);
    return;
  }

  scheduleNextRunForSource(sourceId, 0);
}

function markSourceIngested(sourceId) {
  const source = getVulnerabilitySource(sourceId);
  const timestamp = new Date().toISOString();
  if (source) {
    source.lastIngested = timestamp;
  }
  const legacyKey = `last${capitalize(sourceId)}Ingest`;
  vulnerabilityConfig[legacyKey] = timestamp;
  persistVulnerabilityConfig();
}

const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_ENDPOINT = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_ENDPOINT = 'https://api.first.org/data/v1/epss';

function startVulnerabilityIngestion() {
  const sources = Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [];
  for (const source of sources) {
    if (source.enabled) {
      scheduleNextRunForSource(source.id, 0);
    }
  }
}

const NVD_PAGE_SIZE = 2000;

async function ingestNvdFeed() {
  const limit = NVD_PAGE_SIZE;
  const headers = {};
  if (vulnerabilityConfig.nvdApiKey) {
    headers['API-Key'] = vulnerabilityConfig.nvdApiKey;
  }

  const metadata = await fetchNvdPage(1, 1, headers);
  const totalResults = Number(metadata?.totalResults ?? metadata?.totalResults ?? 0);
  const startIndex = totalResults > limit ? Math.max(1, totalResults - limit + 1) : 1;
  const data = await fetchNvdPage(limit, startIndex, headers);
  const items = data?.vulnerabilities ?? data?.result?.vulnerabilities ?? [];
  for (const item of items) {
    const entry = normalizeNvdItem(item);
    if (entry) {
      applyNormalizedVulnerability(entry, 'nvd');
    }
  }
  persistVulnerabilityStore();
  markSourceIngested('nvd');
}

async function ingestKevCatalog() {
  const data = await fetchJson(KEV_ENDPOINT, { cache: 'no-store' });
  const entries = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  for (const vuln of entries) {
    if (!vuln?.cveID) {
      continue;
    }
    applyNormalizedVulnerability({
      cveId: vuln.cveID.trim(),
      description: vuln?.vulnerabilityName ?? '',
      kev: true,
      sources: { kev: true },
      lastUpdated: vuln?.dateAdded ?? new Date().toISOString(),
    }, 'kev');
  }
  persistVulnerabilityStore();
  markSourceIngested('kev');
}

async function ingestEpssScores() {
  const data = await fetchJson(EPSS_ENDPOINT, { cache: 'no-store' });
  const entries = Array.isArray(data?.data) ? data.data : [];
  for (const item of entries) {
    const cveId = item?.cve;
    const probability = Number(item?.probability);
    if (!cveId) {
      continue;
    }
    applyNormalizedVulnerability({
      cveId: cveId.trim(),
      epss: Number.isFinite(probability) ? probability : 0,
      sources: { epss: true },
      lastUpdated: item?.timestamp ?? new Date().toISOString(),
    }, 'epss');
  }
  persistVulnerabilityStore();
  markSourceIngested('epss');
}

VULNERABILITY_SOURCE_IMPLEMENTATIONS.nvd = ingestNvdFeed;
VULNERABILITY_SOURCE_IMPLEMENTATIONS.kev = ingestKevCatalog;
VULNERABILITY_SOURCE_IMPLEMENTATIONS.epss = ingestEpssScores;

function applyNormalizedVulnerability(entry, source) {
  const existing = vulnerabilityStore.get(entry.cveId) ?? {
    cveId: entry.cveId,
    described: '',
    cvss: entry.cvss ?? 0,
    cpes: [],
    kev: false,
    epss: null,
    sources: {},
    lastUpdated: entry.lastUpdated ?? new Date().toISOString(),
  };
  const merged = {
    ...existing,
    ...entry,
    cvss: entry.cvss ?? existing.cvss,
    cpes: Array.from(new Set([...(entry.cpes ?? existing.cpes ?? [])])),
    kbArticleIDs: Array.from(
      new Set([
        ...((entry.kbArticleIDs ?? existing.kbArticleIDs ?? []) ?? []),
      ]),
    ),
    kev: existing.kev || Boolean(entry.kev),
    epss: entry.epss ?? existing.epss,
    lastUpdated: entry.lastUpdated ?? existing.lastUpdated,
    sources: { ...existing.sources, ...(entry.sources ?? {}), [source]: true },
  };
  vulnerabilityStore.set(entry.cveId, merged);
}

function normalizeNvdItem(item) {
  const cve = item?.cve ?? {};
  const cveId = cve?.id?.trim() || cve?.CVE_data_meta?.ID || cve?.cveDataMeta?.id?.trim();
  if (!cveId) {
    return null;
  }
  const descriptions = Array.isArray(cve?.descriptions) ? cve.descriptions : [];
  const english = descriptions.find((entry) => entry?.lang === 'en' || entry?.language === 'en');
  const description = english?.value ?? cve?.CVE_data_meta?.description ?? '';
  const metrics = cve?.metrics ?? item?.impact;
  const cvssV3Data = Array.isArray(metrics?.cvssMetricV3) ? metrics.cvssMetricV3[0]?.cvssData : null;
  const cvssV2Data = Array.isArray(metrics?.cvssMetricV2) ? metrics.cvssMetricV2[0]?.cvssData ?? metrics.cvssMetricV2[0] : null;
  const cvss = Number.isFinite(cvssV3Data?.baseScore ?? cvssV2Data?.baseScore ?? cvssV2Data?.score)
    ? Number(cvssV3Data?.baseScore ?? cvssV2Data?.baseScore ?? cvssV2Data?.score)
    : null;
  const vectors = cvssV3Data?.vectorString ?? cvssV2Data?.vectorString ?? null;
  const cpes = extractCpesFromItem(item);
  const kbArticleIDs = extractKbArticles(item);
  const lastModified = cve?.lastModified ?? cve?.lastModifiedDate ?? new Date().toISOString();
  return {
    cveId: cveId.trim(),
    description,
    cvss,
    vectors,
    cpes,
    kbArticleIDs,
    lastUpdated: lastModified,
    sources: { nvd: true },
  };
}

function extractCpesFromItem(item) {
  const nodes = item?.configurations?.nodes ?? [];
  const collected = new Set();
  for (const node of nodes) {
    const cpeMatches = node?.cpeMatch ?? [];
    for (const match of cpeMatches) {
      if (match?.cpe23Uri) {
        collected.add(match.cpe23Uri);
      }
    }
  }
  return Array.from(collected);
}

function extractKbArticles(item) {
  const references = item?.cve?.references?.reference_data ?? [];
  const collected = new Set();
  for (const entry of references) {
    const url = entry?.url ?? '';
    const match = url.match(/KB\d+/i);
    if (match) {
      collected.add(match[0].toUpperCase());
    }
  }
  return Array.from(collected);
}

function gatherAppliedPatches(info) {
  const applied = new Set();
  const summary = info.updatesSummary;
  if (!summary?.categories) {
    return applied;
  }

  for (const category of summary.categories) {
    const updates = Array.isArray(category.updates) ? category.updates : [];
    for (const update of updates) {
      const kbs = Array.isArray(update?.kbArticleIDs) ? update.kbArticleIDs : [];
      for (const kb of kbs) {
        if (typeof kb === 'string' && kb.trim()) {
          applied.add(kb.trim().toUpperCase());
        }
      }
    }
  }

  return applied;
}

async function fetchJson(url, options = {}) {
  const res = await globalThis.fetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  return res.json();
}

function getTenantTechDirectSettings(tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = sanitizeTenantId(tenantId);
  const tenantSettings = getGeneralSettingsForTenant(normalizedTenantId);
  return {
    ...DEFAULT_TECH_DIRECT_SETTINGS,
    ...(tenantSettings?.techDirect ?? {}),
  };
}

function clearTechDirectTokenCache(tenantId) {
  if (typeof tenantId === 'string' && tenantId.trim()) {
    techDirectTokenCache.delete(sanitizeTenantId(tenantId));
  } else {
    techDirectTokenCache.clear();
  }
}

async function getTechDirectAccessToken(tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = sanitizeTenantId(tenantId);
  const techDirectSettings = getTenantTechDirectSettings(normalizedTenantId);
  const apiKey = (techDirectSettings.apiKey ?? '').trim();
  const apiSecret = (techDirectSettings.apiSecret ?? '').trim();

  if (!apiKey || !apiSecret) {
    clearTechDirectTokenCache(normalizedTenantId);
    throw new Error('TechDirect credentials are missing');
  }

  const now = Date.now();
  const cached = techDirectTokenCache.get(normalizedTenantId);
  if (cached && cached.expiresAt > now) {
    return cached.token;
  }

  const params = new URLSearchParams();
  params.set('grant_type', 'client_credentials');
  params.set('client_id', apiKey);
  params.set('client_secret', apiSecret);
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')}`,
  };
  let payload;
  try {
    payload = await fetchJson(TECH_DIRECT_TOKEN_ENDPOINT, {
      method: 'POST',
      headers,
      body: params.toString(),
    });
  } catch (error) {
    console.error('TechDirect token fetch failed', {
      error: error?.message ?? error,
      apiKey: techDirectSettings.apiKey ? '<redacted>' : null,
    });
    throw error;
  }

  if (!payload || typeof payload !== 'object' || typeof payload.access_token !== 'string') {
    throw new Error('TechDirect access token missing from response');
  }

  const expiresIn = Number(payload.expires_in);
  const ttl = Number.isFinite(expiresIn) && expiresIn > 0
    ? expiresIn * 1000
    : TECH_DIRECT_TOKEN_MIN_TTL_MS;
  techDirectTokenCache.set(normalizedTenantId, {
    token: payload.access_token,
    expiresAt: now + Math.max(ttl, TECH_DIRECT_TOKEN_MIN_TTL_MS),
  });
  return payload.access_token;
}

function hasTechDirectCredentials(tenantId = DEFAULT_TENANT_ID) {
  const techDirect = getTenantTechDirectSettings(tenantId);
  const hasCredentials = Boolean(
    typeof techDirect.apiKey === 'string'
      && techDirect.apiKey.trim()
      && typeof techDirect.apiSecret === 'string'
      && techDirect.apiSecret.trim(),
  );
  if (!hasCredentials) {
    clearTechDirectTokenCache(tenantId);
  }
  return hasCredentials;
}

function shouldCheckDellWarranty(info) {
  const manufacturer = (info?.specs?.Manufacturer ?? '').toString();
  if (!manufacturer) {
    return false;
  }
  return manufacturer.toLowerCase().includes('dell');
}

function getServiceTagFromInfo(info) {
  const serial = info?.specs?.SerialNumber;
  if (!serial) {
    return '';
  }
  return `${serial}`.trim();
}

function normalizeWarrantyDate(value) {
  if (!value && value !== 0) {
    return null;
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return null;
  }
  return new Date(parsed).toISOString();
}

function collectWarrantyEntries(payload) {
  if (!payload) {
    return [];
  }

  const entries = [];
  if (Array.isArray(payload)) {
    entries.push(...payload);
  }

  if (typeof payload === 'object') {
    const candidateKeys = ['Asset', 'Assets', 'asset', 'assets'];
    for (const key of candidateKeys) {
      if (Array.isArray(payload[key])) {
        entries.push(...payload[key]);
      }
    }

    const nested = payload?.ResponseData ?? payload?.responseData ?? payload?.data;
    if (nested) {
      if (Array.isArray(nested)) {
        entries.push(...nested);
      }
      for (const key of candidateKeys) {
        if (Array.isArray(nested[key])) {
          entries.push(...nested[key]);
        }
      }
    }
  }

  return entries;
}

function parseDellWarrantyResponse(payload, serviceTag) {
  if (!payload) {
    throw new Error('Unexpected warranty response');
  }

  const errorMessage = [
    payload?.message,
    payload?.Message,
    payload?.errorMessage,
    payload?.error?.message,
  ].find(Boolean);

  const statusCode = Number(payload?.status ?? payload?.Status ?? payload?.StatusCode);
  const entries = collectWarrantyEntries(payload);

  if ((!entries.length && statusCode >= 400) || (!entries.length && errorMessage)) {
    throw new Error(errorMessage ?? 'Dell warranty data unavailable');
  }
  if (!entries.length) {
    console.error('Dell warranty response returned no entries', {
      serviceTag,
      statusCode,
      payloadType: Array.isArray(payload) ? 'array' : typeof payload,
    });
    throw new Error('Dell warranty data unavailable');
  }

  const normalizedTag = (serviceTag ?? '').toString().toLowerCase();
  const asset = entries.find((entry) => (entry?.ServiceTag ?? entry?.serviceTag ?? '')
    .toString()
    .toLowerCase() === normalizedTag) ?? entries[0];
  if (!asset) {
    throw new Error('Warranty entry not found');
  }

  const startDate = normalizeWarrantyDate(
    asset?.WarrantyStartDate
      ?? asset?.StartDate
      ?? asset?.ServiceLevelStartDate
      ?? asset?.WarrantyFromDate
      ?? asset?.ShipDate
      ?? asset?.shipDate,
  );
  const endDate = normalizeWarrantyDate(
    asset?.WarrantyEndDate
      ?? asset?.EndDate
      ?? asset?.ServiceLevelEndDate
      ?? asset?.WarrantyToDate
      ?? asset?.entitlementEndDate
      ?? asset?.endDate,
  );
  const serviceLevelFromAsset =
    asset?.ServiceLevelDescription
    ?? asset?.ServiceLevel
    ?? asset?.ServiceLevelCode
    ?? asset?.ServiceLevelName
    ?? asset?.serviceLevelDescription
    ?? null;
  const description =
    asset?.ProductDescription
    ?? asset?.ProductName
    ?? asset?.ProductType
    ?? asset?.productLineDescription
    ?? asset?.productLobDescription
    ?? null;

  const entitlements = (Array.isArray(asset?.Entitlements) ? asset.Entitlements : [])
    .concat(Array.isArray(asset?.entitlements) ? asset.entitlements : [])
    .map((entry) => ({
      name:
        entry?.ServiceLevelDescription
        ?? entry?.Description
        ?? entry?.ServiceLevel
        ?? entry?.ServiceLevelName
        ?? entry?.serviceLevelDescription
        ?? null,
      startDate: normalizeWarrantyDate(
        entry?.StartDate ?? entry?.ServiceLevelStartDate ?? entry?.WarrantyStartDate ?? entry?.startDate,
      ),
      endDate: normalizeWarrantyDate(
        entry?.EndDate ?? entry?.ServiceLevelEndDate ?? entry?.WarrantyEndDate ?? entry?.endDate,
      ),
    }))
    .filter((entry) => entry.name);

  const summaryEndDate = entitlements
    .map((entry) => entry.endDate)
    .filter(Boolean)
    .map((date) => Date.parse(date))
    .filter((ts) => !Number.isNaN(ts));
  const summaryEndDateValue = summaryEndDate.length
    ? Math.max(...summaryEndDate)
    : endDate
      ? Date.parse(endDate)
      : null;

  const summaryStartDate = entitlements
    .map((entry) => entry.startDate)
    .filter(Boolean)
    .map((date) => Date.parse(date))
    .filter((ts) => !Number.isNaN(ts));
  const summaryStartDateValue = summaryStartDate.length
    ? Math.min(...summaryStartDate)
    : startDate
      ? Date.parse(startDate)
      : null;

  const computedEndDate = summaryEndDateValue ? new Date(summaryEndDateValue).toISOString() : null;
  const computedStartDate = summaryStartDateValue ? new Date(summaryStartDateValue).toISOString() : null;
  const entitlementServiceLevel = entitlements[0]?.name ?? null;

  let status = 'unknown';
  if (computedEndDate || endDate) {
    const parsedEnd = Date.parse(computedEndDate ?? endDate);
    if (!Number.isNaN(parsedEnd)) {
      status = parsedEnd > Date.now() ? 'active' : 'expired';
    }
  }

  return {
    status,
    startDate: computedStartDate ?? startDate,
    endDate: computedEndDate ?? endDate,
    serviceLevel: serviceLevelFromAsset ?? entitlementServiceLevel,
    description,
    entitlements,
  };
}

async function fetchDellWarrantyForTag(serviceTag, tenantId = DEFAULT_TENANT_ID) {
  if (!hasTechDirectCredentials(tenantId)) {
    throw new Error('TechDirect credentials are missing');
  }

  const accessToken = await getTechDirectAccessToken(tenantId);
  const params = new URLSearchParams();
  const normalizedTag = (serviceTag ?? '').toString().trim().toLowerCase();
  params.set('servicetags', normalizedTag);
  params.set('format', 'json');

  const headers = {
    Accept: 'application/json',
    Authorization: `Bearer ${accessToken}`,
  };

  const url = `${TECH_DIRECT_WARRANTY_ENDPOINT}?${params.toString()}`;
  const payload = await fetchJson(url, { headers });
  return parseDellWarrantyResponse(payload, serviceTag);
}

async function maybeRefreshWarranty(info, { force = false } = {}) {
  if (!info) {
    return;
  }

  const tenantId = info?.tenantId ?? DEFAULT_TENANT_ID;
  if (!shouldCheckDellWarranty(info)) {
    if (info.warranty) {
      info.warranty = null;
    }
    return;
  }

  if (!hasTechDirectCredentials(tenantId)) {
    if (info.warranty) {
      info.warranty = null;
    }
    return;
  }

  const serviceTag = getServiceTagFromInfo(info);
  if (!serviceTag) {
    info.warranty = {
      serviceTag: null,
      status: 'unknown',
      lastRefreshed: new Date().toISOString(),
      error: 'Service tag missing',
    };
    return;
  }

  const lastRefreshed = info.warranty?.lastRefreshed
    ? Date.parse(info.warranty.lastRefreshed)
    : null;
  if (!force && Number.isFinite(lastRefreshed) && Date.now() - lastRefreshed < TECH_DIRECT_WARRANTY_TTL_MS) {
    return;
  }

  try {
    const summary = await fetchDellWarrantyForTag(serviceTag, tenantId);
    info.warranty = {
      ...summary,
      serviceTag,
      lastRefreshed: new Date().toISOString(),
    };
  } catch (error) {
    console.error('Dell warranty refresh failed', {
      agentId: info.id,
      serviceTag,
      error: error?.message ?? error,
    });
    info.warranty = {
      serviceTag,
      status: 'unknown',
      lastRefreshed: new Date().toISOString(),
      error: error?.message ?? 'Unable to fetch warranty',
    };
  }
}

async function refreshDellWarrantyForAllAgents({ force = false } = {}) {
  for (const info of agents.values()) {
    await maybeRefreshWarranty(info, { force });
  }
}

async function fetchNvdPage(limit, startIndex = 1, headers = {}) {
  const params = new URLSearchParams();
  params.set('resultsPerPage', String(limit));
  if (startIndex && startIndex > 1) {
    params.set('startIndex', String(startIndex));
  }
  const url = `${NVD_ENDPOINT}?${params.toString()}`;
  return fetchJson(url, { headers });
}

function computeAssetFingerprint(info) {
  const hash = crypto.createHash('sha256');
  hash.update(info.id ?? '');
  hash.update(info.os ?? '');
  hash.update(JSON.stringify(info.specs ?? {}));
  const software = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  const sortedSoftware = software
    .map((item) => `${normalizeToken(item.publisher ?? '')}:${normalizeToken(item.name ?? '')}:${item.version ?? ''}`)
    .sort()
    .join('|');
  hash.update(sortedSoftware);
  const updates = info.updatesSummary ?? {};
  hash.update(JSON.stringify(updates));
  return hash.digest('hex');
}

function normalizeToken(value) {
  return (value ?? '').toString().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function gatherSoftwareIdentifiers(info) {
  const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  return entries.map((item) => ({
    name: normalizeToken(item.name ?? ''),
    vendor: normalizeToken(item.publisher ?? ''),
    version: (item.version ?? '').toString(),
    original: item,
  }));
}

function evaluateAssetVulnerabilities(info) {
  if (!info?.id) {
    return [];
  }

  const fingerprint = computeAssetFingerprint(info);
  const cached = assetVulnerabilityCache.get(info.id);
  if (cached && cached.fingerprint === fingerprint) {
    return cached.results;
  }

  const softwareIdentifiers = gatherSoftwareIdentifiers(info);
  const osDescriptor = {
    raw: info.os ?? info.platform ?? '',
    normalized: normalizeToken(info.os ?? info.platform ?? ''),
  };
  const appliedPatches = gatherAppliedPatches(info);

  const matches = [];
  for (const entry of vulnerabilityStore.values()) {
    if (vulnerabilityConfig.ignoredCves?.includes(entry.cveId)) {
      continue;
    }

    const match = matchVulnerabilityToAsset(entry, osDescriptor, softwareIdentifiers, appliedPatches);
    if (!match) {
      continue;
    }

    const patchState = match.patchInfo?.patched ? 'vulnerable_but_patched' : 'vulnerable_unpatched';
    const priorityScore = computePriority(entry, patchState);
    matches.push({
      cveId: entry.cveId,
      description: entry.description,
      cvss: entry.cvss,
      severity: categorizeSeverity(entry.cvss),
      kev: Boolean(entry.kev),
      epss: entry.epss,
      component: match.component,
      componentType: match.type,
      matchedCpe: match.cpe,
      state: patchState,
      fixedBy: match.patchInfo?.fixedBy ?? [],
      explanation: match.explanation,
      updatedAt: new Date().toISOString(),
      priorityScore,
      priority:
        priorityScore >= 10
          ? 'urgent'
          : priorityScore >= 7
            ? 'high'
            : priorityScore >= 4
              ? 'medium'
              : match.patchInfo?.patched
                ? 'patched'
                : 'low',
    });
  }

  assetVulnerabilityCache.set(info.id, { fingerprint, results: matches });
  return matches;
}

function categorizeSeverity(cvss) {
  if (cvss >= 9) return 'Critical';
  if (cvss >= 7) return 'High';
  if (cvss >= 4) return 'Medium';
  if (cvss > 0) return 'Low';
  return 'Info';
}

function matchVulnerabilityToAsset(entry, osDescriptor, softwareIdentifiers, appliedPatches) {
  const cpes = Array.isArray(entry.cpes) ? entry.cpes : [];
  for (const raw of cpes) {
    const parsed = parseCpe(raw);
    if (!parsed) {
      continue;
    }

    const stateInfo = {
      fixedBy: Array.isArray(entry.kbArticleIDs) ? entry.kbArticleIDs : [],
      patched: false,
    };
    if (stateInfo.fixedBy.some((kb) => appliedPatches.has(kb))) {
      stateInfo.patched = true;
    }

    if (parsed.part === 'o' && matchesOsCpe(parsed, osDescriptor)) {
      return {
        component: osDescriptor.raw || 'Windows',
        type: 'os',
        cpe: raw,
        explanation: `OS matches ${parsed.vendor}:${parsed.product}`,
        patchInfo: stateInfo,
      };
    }

    if (parsed.part === 'a') {
      const matchedSoftware = matchesSoftwareCpe(parsed, softwareIdentifiers);
      if (matchedSoftware) {
        return {
          component: matchedSoftware.original.name || matchedSoftware.original.softwareId || 'Unknown software',
          type: 'software',
          cpe: raw,
          explanation: `Software ${matchedSoftware.original.name} matches ${parsed.vendor}:${parsed.product}`,
          patchInfo: stateInfo,
        };
      }
    }
  }

  return null;
}

function matchesOsCpe(parsed, osDescriptor) {
  const vendorMatch = normalizeToken(parsed.vendor).includes('microsoft');
  const productMatch = normalizeToken(parsed.product).includes('windows');
  return vendorMatch && productMatch && osDescriptor.normalized.includes('windows');
}

function matchesSoftwareCpe(parsed, softwareIdentifiers) {
  const vendor = normalizeToken(parsed.vendor);
  const product = normalizeToken(parsed.product);
  const version = (parsed.version ?? '').toString();

  for (const identifier of softwareIdentifiers) {
    if (vendor && identifier.vendor && !identifier.vendor.includes(vendor)) {
      continue;
    }
    if (product && identifier.name && !identifier.name.includes(product)) {
      continue;
    }

    if (version && identifier.version && identifier.version !== version) {
      continue;
    }

    return identifier;
  }

  return null;
}

function computePriority(entry, patchState) {
  let score = entry?.cvss ?? 0;
  if (entry?.kev) {
    score += 2;
  }
  if (entry?.epss >= (vulnerabilityConfig.epssThreshold ?? 0.4)) {
    score += 1;
  }
  if (patchState === 'vulnerable_but_patched') {
    score -= 4;
  }
  return Math.max(0, score);
}

function parseCpe(cpe) {
  if (typeof cpe !== 'string') {
    return null;
  }
  const parts = cpe.split(':');
  if (parts.length < 6) {
    return null;
  }
  return {
    part: parts[2],
    vendor: parts[3],
    product: parts[4],
    version: parts[5],
  };
}

function getVulnerabilityStatus() {
  const total = vulnerabilityStore.size;
  return {
    total,
    sources: (Array.isArray(vulnerabilityConfig.sources) ? vulnerabilityConfig.sources : [])
      .map((entry) => formatSourceForClient(entry)),
    lastNvdIngest: vulnerabilityConfig.lastNvdIngest ?? null,
    lastKevIngest: vulnerabilityConfig.lastKevIngest ?? null,
    lastEpssIngest: vulnerabilityConfig.lastEpssIngest ?? null,
    storedAt: new Date().toISOString(),
  };
}

function searchVulnerabilities(query, limit = 50) {
  const normalized = String(query ?? '').trim().toLowerCase();
  const matches = [];
  for (const entry of vulnerabilityStore.values()) {
    if (
      !normalized
      || entry.cveId.toLowerCase().includes(normalized)
      || entry.description?.toLowerCase().includes(normalized)
    ) {
      matches.push({
        cveId: entry.cveId,
        description: entry.description,
        cvss: entry.cvss,
        cpes: entry.cpes,
        kev: entry.kev,
        epss: entry.epss,
        sources: entry.sources,
      });
      if (matches.length >= limit) {
        break;
      }
    }
  }
  return { total: matches.length, items: matches };
}

function formatCveTargetLabel(entry) {
  const cpes = Array.isArray(entry?.cpes) ? entry.cpes : [];
  const targets = [];
  for (const cpe of cpes) {
    const label = describeCpe(cpe);
    if (label && label !== cpe && !targets.includes(label)) {
      targets.push(label);
    } else if (label && !targets.includes(label)) {
      targets.push(label);
    }
    if (targets.length >= 3) {
      break;
    }
  }

  if (targets.length) {
    return targets.join(', ');
  }

  const kbArticles = Array.isArray(entry?.kbArticleIDs) ? entry.kbArticleIDs : [];
  const normalized = [...new Set(kbArticles.filter(Boolean).map((kb) => `${kb}`.toUpperCase()))];
  if (normalized.length) {
    return normalized.slice(0, 3).map((kb) => `KB ${kb}`).join(', ');
  }

  return 'n/a';
}

function describeCpe(cpe) {
  if (typeof cpe !== 'string') {
    return null;
  }
  const parts = cpe.split(':');
  if (parts.length < 6) {
    return cpe;
  }
  const vendor = parts[3] ?? '';
  const product = parts[4] ?? '';
  const version = parts[5] ?? '';
  const build = parts[6] ?? '';
  const descriptor = [vendor, product, version, build].filter((value) => value).join(' ').trim();
  return descriptor || cpe;
}

function parseCveIdHunks(cveId) {
  if (typeof cveId !== 'string') {
    return { year: 0, number: 0 };
  }
  const match = cveId.toUpperCase().match(/^CVE-(\d{4})-(\d+)$/);
  if (!match) {
    return { year: 0, number: 0 };
  }
  return { year: Number(match[1]) || 0, number: Number(match[2]) || 0 };
}

function compareCveDesc(aId, bId) {
  const a = parseCveIdHunks(aId);
  const b = parseCveIdHunks(bId);
  if (a.year !== b.year) {
    return b.year - a.year;
  }
  return b.number - a.number;
}

function loadFirewallBaselines() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(FIREWALL_BASELINE_PATH)) {
      let raw = fs.readFileSync(FIREWALL_BASELINE_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load firewall baseline config', error);
  }

  const defaultProfiles = [];
  fs.writeFileSync(FIREWALL_BASELINE_PATH, JSON.stringify(defaultProfiles, null, 2));
  return defaultProfiles;
}

function persistFirewallBaselines() {
  try {
    ensureDataDirectory();
    fs.writeFileSync(FIREWALL_BASELINE_PATH, JSON.stringify(firewallBaselines, null, 2));
    return true;
  } catch (error) {
    console.error('Failed to persist firewall baseline config', error);
    return false;
  }
}

function getScriptByName(name) {
  if (!name) {
    return null;
  }

  return monitoringConfig.remediationScripts.find((entry) => entry.name === name) ?? null;
}

function sanitizeScriptFileName(value, language) {
  const extension = language === 'python' ? '.py' : '.ps1';
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `${normalized || 'script'}${extension}`;
}

function readScriptContent(entry) {
  try {
    const filePath = path.join(REMEDIATION_DIR, entry.file);
    return fs.readFileSync(filePath, 'utf-8');
  } catch (error) {
    return '';
  }
}

function saveMonitoringConfig() {
  ensureDataDirectory();
  fs.writeFileSync(MONITORING_CONFIG_PATH, JSON.stringify(monitoringConfig, null, 2));
}

function handleMonitoringMetrics(info, socket, payload) {
  if (!payload?.metrics || typeof payload.metrics !== 'object') {
    return;
  }

  const entry = {
    timestamp: Date.now(),
    cpuPercent: typeof payload.metrics.cpuPercent === 'number' ? payload.metrics.cpuPercent : null,
    ramPercent: typeof payload.metrics.ramPercent === 'number' ? payload.metrics.ramPercent : null,
    diskUsagePercent: typeof payload.metrics.diskUsagePercent === 'number' ? payload.metrics.diskUsagePercent : null,
    diskPerformancePercent: typeof payload.metrics.diskPerformancePercent === 'number' ? payload.metrics.diskPerformancePercent : null,
    networkKbSec: typeof payload.metrics.networkKbSec === 'number' ? payload.metrics.networkKbSec : null,
  };

  const history = agentMetrics.get(info.id) ?? [];
  history.push(entry);
  while (history.length > 120) {
    history.shift();
  }

  agentMetrics.set(info.id, history);
  evaluateMonitoringProfiles(info, history, socket);
}

function evaluateMonitoringProfiles(info, history, socket) {
  const now = Date.now();
  const profileTriggers = new Map();

  for (const profile of monitoringConfig.monitoringProfiles) {
    if (!canProfileMonitor(profile, info)) {
      continue;
    }

    let profileTriggered = false;
    for (const rule of profile.rules) {
      const metricKey = mapMetricToProperty(rule.metric);
      if (!metricKey) {
        continue;
      }

      const windowMs = Math.max((rule.windowSeconds ?? 30) * 1000, 1000);
      const threshold = typeof rule.threshold === 'number' ? rule.threshold : null;
      if (threshold === null) {
        continue;
      }

      const since = now - windowMs;
      const samples = history.filter((entry) => entry.timestamp >= since && typeof entry[metricKey] === 'number');
      if (samples.length === 0) {
        continue;
      }

      const average = samples.reduce((sum, entry) => sum + (entry[metricKey] ?? 0), 0) / samples.length;
      const comparison = (rule.comparison ?? 'gte').toLowerCase();
      const triggered = comparison === 'gt' ? average > threshold : average >= threshold;
      const key = `${info.id}:${profile.id}:${rule.id}`;
      const previouslyTriggered = alertStates.get(key) ?? false;

      if (triggered && !previouslyTriggered) {
        alertStates.set(key, true);
        triggerAlert(info, socket, profile, rule, average);
      } else if (!triggered && previouslyTriggered) {
        alertStates.set(key, false);
      }

      profileTriggered = profileTriggered || triggered;
    }

    profileTriggers.set(profile.id, profileTriggered);
  }

  for (const [profileId, triggered] of profileTriggers.entries()) {
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (profile) {
      updateAgentProfileStatus(info, profile, triggered);
    }
  }

  const overallTriggered = Array.from(agentProfileStatus.get(info.id) ?? new Map()).some((value) => value);
  updateAgentAlertStatus(info, overallTriggered);
}

function canProfileMonitor(profile, info) {
  if (profile.assignedAgents && profile.assignedAgents.includes(info.id)) {
    return true;
  }

  const group = info.group ?? DEFAULT_GROUP;
  if (profile.assignedGroups && profile.assignedGroups.includes(group)) {
    return true;
  }

  return false;
}

function mapMetricToProperty(metric) {
  switch ((metric ?? '').toLowerCase()) {
    case 'cpu':
      return 'cpuPercent';
    case 'ram':
    case 'memory':
      return 'ramPercent';
    case 'disk-usage':
      return 'diskUsagePercent';
    case 'disk-performance':
      return 'diskPerformancePercent';
    case 'network':
      return 'networkKbSec';
    default:
      return null;
  }
}

function getRequiredMetricsForProfiles(profiles) {
  if (!Array.isArray(profiles)) {
    return [];
  }

  const metrics = new Set();
  for (const profile of profiles) {
    if (!profile || !Array.isArray(profile.rules)) {
      continue;
    }

    for (const rule of profile.rules) {
      const property = mapMetricToProperty(rule.metric);
      if (property === 'cpuPercent') {
        metrics.add('cpu');
      } else if (property === 'ramPercent') {
        metrics.add('ram');
      } else if (property === 'diskUsagePercent') {
        metrics.add('disk-usage');
      } else if (property === 'diskPerformancePercent') {
        metrics.add('disk-performance');
      } else if (property === 'networkKbSec') {
        metrics.add('network');
      }
    }
  }

  return Array.from(metrics);
}

function triggerAlert(info, socket, profile, rule, value) {
  const alertProfile = monitoringConfig.alertProfiles.find((entry) => entry.id === profile.alertProfileId) ?? null;
  const eventPayload = {
    type: 'alert',
    agentId: info.id,
    agentName: info.name,
    profileId: profile.id,
    profileName: profile.name,
    ruleId: rule.id,
    metric: rule.metric,
    threshold: rule.threshold,
    value,
    timestamp: new Date().toISOString(),
    alertProfileId: alertProfile?.id ?? null,
    emails: alertProfile?.emails ?? [],
    dashboard: Boolean(alertProfile?.dashboard),
  };

  console.log(`Alert triggered for ${info.name}: ${rule.metric} = ${value.toFixed(1)} (${rule.threshold})`);
  sendMonitoringEvent('alert', eventPayload);
  if (alertProfile?.emails?.length > 0) {
    console.log(`Stub email: sending alert to ${alertProfile.emails.join(', ')}`);
  }

  if (alertProfile?.remediationScript) {
    runRemediation(info, socket, alertProfile.remediationScript, eventPayload);
  }
}

function runRemediation(info, socket, scriptName, eventPayload) {
  const script = monitoringConfig.remediationScripts.find((entry) => entry.name === scriptName);
  if (!script) {
    console.warn(`Remediation script ${scriptName} not found`);
    return;
  }

  const scriptPath = path.join(REMEDIATION_DIR, script.file);
  let content = '';
  try {
    content = fs.readFileSync(scriptPath, 'utf-8');
  } catch (error) {
    console.warn(`Unable to load remediation script ${script.file}: ${error.message}`);
    return;
  }

  const requestId = uuidv4();
  sendControl(socket, 'run-remediation', {
    requestId,
    scriptName: script.name,
    language: script.language,
    content,
  });
  sendMonitoringEvent('remediation-request', {
    type: 'remediation-request',
    agentId: info.id,
    agentName: info.name,
    scriptName: script.name,
    requestId,
    timestamp: new Date().toISOString(),
    originalEvent: eventPayload,
  });
}

function sendMonitoringEvent(eventName, payload) {
  monitoringHistory.push({
    eventName,
    payload: JSON.parse(JSON.stringify(payload)),
  });
  while (monitoringHistory.length > MONITORING_HISTORY_LIMIT) {
    monitoringHistory.shift();
  }

  const data = JSON.stringify(payload);
  for (const res of monitoringEvents) {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${data}\n\n`);
  }
}

function incrementChatNotification(agentId, messageTimestamp) {
  if (!agentId) {
    return;
  }

  const count = (chatNotificationCounts.get(agentId) ?? 0) + 1;
  chatNotificationCounts.set(agentId, count);
  sendMonitoringEvent('chat-notification', {
    agentId,
    count,
    timestamp: Date.now(),
    messageTimestamp: Number.isFinite(messageTimestamp) ? messageTimestamp : Date.now(),
  });
}

function clearChatNotification(agentId) {
  if (!agentId) {
    return;
  }

  chatNotificationCounts.delete(agentId);
  sendMonitoringEvent('chat-notification', { agentId, count: 0, timestamp: Date.now() });
}

function hasActiveAlertForAgent(agentId) {
  if (!agentId) {
    return false;
  }

  const prefix = `${agentId}:`;
  for (const [key, value] of alertStates) {
    if (value && key.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

function updateAgentProfileStatus(info, profile, triggered) {
  if (!info || !info.id || !profile) {
    return;
  }

  const agentId = info.id;
  let profileMap = agentProfileStatus.get(agentId);
  if (!profileMap) {
    profileMap = new Map();
    agentProfileStatus.set(agentId, profileMap);
  }

  const previous = profileMap.get(profile.id) ?? false;
  if (previous === triggered) {
    return;
  }

  profileMap.set(profile.id, Boolean(triggered));

  sendMonitoringEvent('monitoring-state', {
    agentId,
    agentName: info.name ?? 'Unknown agent',
    profileId: profile.id,
    profileName: profile.name,
    triggered: Boolean(triggered),
    status: triggered ? 'triggered' : 'resolved',
    monitoringEnabled: shouldMonitorAgent(info),
    metrics: getRequiredMetricsForProfiles([profile]),
    timestamp: new Date().toISOString(),
  });
}

function updateAgentAlertStatus(info, triggered) {
  if (!info || !info.id) {
    return;
  }

  const normalized = Boolean(triggered);
  const previous = agentAlertStatus.get(info.id) ?? false;
  if (previous === normalized) {
    return;
  }

  agentAlertStatus.set(info.id, normalized);
  sendMonitoringEvent('monitoring-state', {
    agentId: info.id,
    agentName: info.name ?? 'Unknown agent',
    triggered: normalized,
    monitoringEnabled: shouldMonitorAgent(info),
    status: normalized ? 'triggered' : 'resolved',
    metrics: getRequiredMetricsForProfiles(getAssignedProfiles(info)),
    timestamp: new Date().toISOString(),
  });
}

function getBaselineTargetAgentIds(profile) {
  if (!profile) {
    return [];
  }

  const ids = new Set(Array.isArray(profile.assignedAgents) ? profile.assignedAgents : []);
  const groups = Array.isArray(profile.assignedGroups) ? profile.assignedGroups : [];
  for (const entry of clientsById.values()) {
    const group = entry.info.group ?? DEFAULT_GROUP;
    if (groups.includes(group)) {
      ids.add(entry.info.id);
    }
  }

  return Array.from(ids).filter((value) => typeof value === 'string' && value);
}

function clearMonitoringProfileState(profileId) {
  if (!profileId) {
    return;
  }

  for (const profileMap of agentProfileStatus.values()) {
    profileMap.delete(profileId);
  }

  for (const key of Array.from(alertStates.keys())) {
    const [, id] = key.split(':');
    if (id === profileId) {
      alertStates.delete(key);
    }
  }

  for (const agentId of clientsById.keys()) {
    const entry = clientsById.get(agentId);
    if (entry) {
      updateAgentAlertStatus(entry.info, hasActiveAlertForAgent(agentId));
    }
  }
}
