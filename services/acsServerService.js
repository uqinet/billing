/**
 * ──────────────────────────────────────────────────────────────────────────────
 * Built-in ACS Server Service  (TR-069 / CWMP)
 * ──────────────────────────────────────────────────────────────────────────────
 *
 * Handles CWMP SOAP communication with CPE devices (ONUs / routers) directly
 * within the billing application – no external GenieACS required.
 *
 * Protocol flow:
 *   1. CPE  → POST Inform        → ACS responds InformResponse
 *   2. CPE  → POST Empty         → ACS sends queued task  (or 204)
 *   3. CPE  → POST TaskResponse  → ACS marks task, sends next or 204
 *
 * Exports:
 *   handleCwmpRequest        – Express handler for POST /acs
 *   triggerConnectionRequest – Kick a CPE to reconnect
 *   getBuiltinDevices        – Query acs_devices
 *   getBuiltinDevice         – Single device lookup
 *   createBuiltinTask        – Insert task + trigger CR
 */

'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const db = require('../config/database');
const { logger } = require('../config/logger');
const { getSetting, getNowLocal } = require('../config/settingsManager');

// Automatic ACS provisioning defaults. Environment variables may override them.
const AUTO_ACS_URL = process.env.ACS_BUILTIN_URL || 'http://192.168.8.2:3001/acs';
const AUTO_ACS_USERNAME = process.env.ACS_BUILTIN_USERNAME || 'acs';
const AUTO_ACS_PASSWORD = process.env.ACS_BUILTIN_PASSWORD || 'acsadmin12345';
const AUTO_CR_USERNAME = process.env.ACS_CR_USERNAME || AUTO_ACS_USERNAME;
const AUTO_CR_PASSWORD = process.env.ACS_CR_PASSWORD || AUTO_ACS_PASSWORD;

// Versioned bootstrap migration — only runs once per version change
try {
  const BOOTSTRAP_VERSION = 5; // v5: dynamic parameter discovery + automatic ACS credentials
  const migRow = db.prepare("SELECT value FROM app_settings WHERE key = 'acs_bootstrap_version'").get();
  const currentVersion = migRow ? parseInt(migRow.value, 10) : 0;
  if (currentVersion < BOOTSTRAP_VERSION) {
    const devices = db.prepare('SELECT id, tags FROM acs_devices').all();
    for (const dev of devices) {
      let tags = [];
      try { tags = JSON.parse(dev.tags || '[]'); } catch (_) {}
      if (tags.includes('bootstrapped')) {
        tags = tags.filter(t => !['bootstrapped', 'acs_discovered', 'acs_configured'].includes(t));
        db.prepare('UPDATE acs_devices SET tags = ? WHERE id = ?').run(JSON.stringify(tags), dev.id);
      }
    }
    // Drop only unfinished legacy monitoring/bootstrap tasks. Completed history is preserved.
    db.prepare("DELETE FROM acs_tasks WHERE status IN ('pending','in_progress') AND name IN ('getParameterValues','getParameterNames','refreshObject')").run();
    db.prepare("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('acs_bootstrap_version', ?)").run(String(BOOTSTRAP_VERSION));
    logger.info(`[ACS] Bootstrap migration v${BOOTSTRAP_VERSION} completed — cleared bootstrapped tags for re-bootstrap`);
  }
} catch (err) {
  logger.error(`[ACS] Failed bootstrap migration: ${err.message}`);
}

// Cleanup stale monitoring tasks from older ACS task formats so they don't keep faulting after restart.
try {
  db.prepare(
    `DELETE FROM acs_tasks
     WHERE status IN ('pending', 'in_progress')
       AND name IN ('getParameterValues', 'refreshObject')
       AND (
         payload LIKE '%WLANConfiguration.5.AssociatedDevice%' OR
         payload LIKE '%WLANConfiguration.5.TotalAssociations%' OR
         payload LIKE '%WLANConfiguration.5.AssociatedDeviceNumberOfEntries%' OR
         payload LIKE '%Hosts.HostNumberOfEntries%' OR
         payload LIKE '%AssociatedDeviceNumberOfEntries%'
       )`
  ).run();
} catch (err) {
  logger.error(`[ACS] Failed stale monitoring task cleanup: ${err.message}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOAP NAMESPACES & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
const CWMP_NS = 'urn:dslforum-org:cwmp-1-0';
const XSD_NS  = 'http://www.w3.org/2001/XMLSchema';
const XSI_NS  = 'http://www.w3.org/2001/XMLSchema-instance';
const SOAP_ENC_NS = 'http://schemas.xmlsoap.org/soap/encoding/';

const SESSION_TIMEOUT_MS = 120_000; // 120 seconds

// ═══════════════════════════════════════════════════════════════════════════════
//  IN-MEMORY SESSION STORE
// ═══════════════════════════════════════════════════════════════════════════════

/** @type {Map<string, {deviceId:string, step:string, currentTaskId:number|null, lastActivity:number}>} */
const sessions = new Map();
const lastDeviceByIp = new Map();
const recentFaultLogs = new Map();

/** Periodically clean expired sessions (every 60 s) */
setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of sessions) {
    if (now - sess.lastActivity > SESSION_TIMEOUT_MS) {
      sessions.delete(sid);
    }
  }
}, 60_000);

// Cleanup stale lastTriggerTimes entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [deviceId, ts] of lastTriggerTimes) {
    if (ts < cutoff) lastTriggerTimes.delete(deviceId);
  }
}, 5 * 60 * 1000);

setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [key, ts] of recentFaultLogs) {
    if (ts < cutoff) recentFaultLogs.delete(key);
  }
}, 5 * 60 * 1000);

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function getOrCreateSession(req, res) {
  // Try to read existing session from cookie
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)acs_session=([^;]+)/);
  let sid = match ? match[1] : null;

  if (sid && sessions.has(sid)) {
    const sess = sessions.get(sid);
    sess.lastActivity = Date.now();
    return { sid, session: sess, isNew: false };
  }

  // Create new session
  sid = generateSessionId();
  const session = { deviceId: null, step: null, currentTaskId: null, lastActivity: Date.now() };
  sessions.set(sid, session);
  res.setHeader('Set-Cookie', `acs_session=${sid}; Path=/acs; HttpOnly`);
  return { sid, session, isNew: true };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TIMESTAMP HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function nowLocal() {
  // Use ISO 8601 UTC format for ACS timestamps.
  // This ensures correct Date.now() comparison regardless of server timezone.
  // getNowLocal() returns local time WITHOUT timezone offset (e.g. "2026-06-08 11:49:50"),
  // which causes incorrect parsing on servers with UTC system timezone.
  return new Date().toISOString();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  REGEX-BASED SOAP / XML PARSING
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Extract the text content of a simple XML element.
 * Handles namespace-prefixed elements like <ns:Tag> and <Tag>.
 */
function xmlValue(xml, tag) {
  // Match both <tag>value</tag> and <ns:tag>value</ns:tag>
  const re = new RegExp(`<(?:[\\w-]+:)?${tag}[^>]*>([\\s\\S]*?)<\\/(?:[\\w-]+:)?${tag}>`, 'i');
  const m = xml.match(re);
  return m ? m[1].trim() : '';
}

/**
 * Detect whether the SOAP body contains a specific CWMP method.
 * E.g. hasCwmpMethod(xml, 'Inform') => true if <cwmp:Inform> or <Inform xmlns=...>
 */
function hasCwmpMethod(xml, method) {
  // <cwmp:Method> or <ns123:Method> or <Method xmlns="urn:dslforum-org:cwmp-1-0">
  const re = new RegExp(`<(?:[\\w-]+:)?${method}[\\s>]`, 'i');
  return re.test(xml);
}

/**
 * Extract CWMP ID from the SOAP header.
 */
function extractCwmpId(xml) {
  // <cwmp:ID ...>value</cwmp:ID> or <ID ...>value</ID>
  const m = xml.match(/<(?:[\w-]+:)?ID[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?ID>/i);
  return m ? m[1].trim() : '1';
}

/**
 * Parse <DeviceId> block from an Inform message.
 */
function parseDeviceId(xml) {
  const deviceIdBlock = xmlValue(xml, 'DeviceId');
  if (!deviceIdBlock) return null;
  return {
    Manufacturer: xmlValue(deviceIdBlock, 'Manufacturer'),
    OUI: xmlValue(deviceIdBlock, 'OUI'),
    SerialNumber: xmlValue(deviceIdBlock, 'SerialNumber'),
    ProductClass: xmlValue(deviceIdBlock, 'ProductClass'),
  };
}

/**
 * Parse all <ParameterValueStruct> entries.
 * Returns a flat object: { 'Device.Path.Name': 'value', ... }
 */
function parseParameterValues(xml) {
  const params = {};
  // Match each ParameterValueStruct block
  const structRe = /<(?:[\w-]+:)?ParameterValueStruct>([\s\S]*?)<\/(?:[\w-]+:)?ParameterValueStruct>/gi;
  let m;
  while ((m = structRe.exec(xml)) !== null) {
    const block = m[1];
    const name = xmlValue(block, 'Name');
    const value = xmlValue(block, 'Value');
    if (name) {
      params[name] = value;
    }
  }
  return params;
}

/**
 * Parse GetParameterValuesResponse – same structure as Inform parameter list.
 */
function parseGetParameterValuesResponse(xml) {
  return parseParameterValues(xml);
}

function parseGetParameterNamesResponse(xml) {
  const names = [];
  const structRe = /<(?:[\w-]+:)?ParameterInfoStruct>([\s\S]*?)<\/(?:[\w-]+:)?ParameterInfoStruct>/gi;
  let m;
  while ((m = structRe.exec(xml)) !== null) {
    const block = m[1];
    const name = xmlValue(block, 'Name');
    if (name) names.push(name);
  }
  return names;
}

/**
 * Parse AddObjectResponse – returns InstanceNumber and Status.
 */
function parseAddObjectResponse(xml) {
  return {
    instanceNumber: xmlValue(xml, 'InstanceNumber'),
    status: xmlValue(xml, 'Status'),
  };
}

/**
 * Parse SetParameterValuesResponse – returns Status (0 = success).
 */
function parseSetParameterValuesResponseStatus(xml) {
  return xmlValue(xml, 'Status') || '0';
}

/**
 * Parse FaultCode / FaultString from a SOAP Fault.
 */
function parseFault(xml) {
  if (!/<(?:[\w-]+:)?Fault/i.test(xml)) return null;
  return {
    faultCode: xmlValue(xml, 'FaultCode') || xmlValue(xml, 'faultcode'),
    faultString: xmlValue(xml, 'FaultString') || xmlValue(xml, 'faultstring'),
    detail: xmlValue(xml, 'detail') || xmlValue(xml, 'Detail'),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SOAP RESPONSE BUILDERS
// ═══════════════════════════════════════════════════════════════════════════════

function soapEnvelopeWrap(cwmpId, bodyContent) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
  xmlns:soap="${SOAP_NS}"
  xmlns:cwmp="${CWMP_NS}"
  xmlns:xsd="${XSD_NS}"
  xmlns:xsi="${XSI_NS}"
  xmlns:soap-enc="${SOAP_ENC_NS}">
  <soap:Header>
    <cwmp:ID soap:mustUnderstand="1">${cwmpId}</cwmp:ID>
  </soap:Header>
  <soap:Body>
    ${bodyContent}
  </soap:Body>
</soap:Envelope>`;
}

function buildInformResponse(cwmpId) {
  return soapEnvelopeWrap(cwmpId,
    `<cwmp:InformResponse>
      <MaxEnvelopes>1</MaxEnvelopes>
    </cwmp:InformResponse>`
  );
}

function buildReboot(cwmpId) {
  const cmdKey = `reboot-${Date.now()}`;
  return soapEnvelopeWrap(cwmpId,
    `<cwmp:Reboot>
      <CommandKey>${cmdKey}</CommandKey>
    </cwmp:Reboot>`
  );
}

function buildFactoryReset(cwmpId) {
  return soapEnvelopeWrap(cwmpId,
    `<cwmp:FactoryReset></cwmp:FactoryReset>`
  );
}

/**
 * Build SetParameterValues SOAP envelope.
 * @param {string} cwmpId
 * @param {Array} parameterValues – array of [path, value, type?] or [path, value]
 */
function buildSetParameterValues(cwmpId, parameterValues) {
  const pvList = (parameterValues || []).map(pv => {
    const name = pv[0];
    const value = pv[1];
    const xsdType = pv[2] || 'xsd:string';
    return `        <ParameterValueStruct>
          <Name>${escapeXml(name)}</Name>
          <Value xsi:type="${escapeXml(xsdType)}">${escapeXml(String(value))}</Value>
        </ParameterValueStruct>`;
  }).join('\n');

  const arrayType = `cwmp:ParameterValueStruct[${parameterValues.length}]`;

  return soapEnvelopeWrap(cwmpId,
    `<cwmp:SetParameterValues>
      <ParameterList soap-enc:arrayType="${arrayType}">
${pvList}
      </ParameterList>
      <ParameterKey>${Date.now()}</ParameterKey>
    </cwmp:SetParameterValues>`
  );
}

/**
 * Build GetParameterValues SOAP envelope.
 * @param {string} cwmpId
 * @param {string[]} parameterNames
 */
function buildGetParameterValues(cwmpId, parameterNames) {
  const names = (parameterNames || []).map(n =>
    `        <string>${escapeXml(n)}</string>`
  ).join('\n');

  return soapEnvelopeWrap(cwmpId,
    `<cwmp:GetParameterValues>
      <ParameterNames soap-enc:arrayType="xsd:string[${parameterNames.length}]">
${names}
      </ParameterNames>
    </cwmp:GetParameterValues>`
  );
}

function buildGetParameterNames(cwmpId, objectName, nextLevel = 0) {
  let path = objectName || '';
  if (path && !path.endsWith('.')) path += '.';
  const nl = nextLevel ? '1' : '0';
  return soapEnvelopeWrap(cwmpId,
    `<cwmp:GetParameterNames>
      <ParameterPath>${escapeXml(path)}</ParameterPath>
      <NextLevel>${nl}</NextLevel>
    </cwmp:GetParameterNames>`
  );
}

/**
 * Build GetParameterNames for subtree refresh (refreshObject).
 */
function buildRefreshObject(cwmpId, objectName) {
  return buildGetParameterNames(cwmpId, objectName, 0);
}

function normalizeObjectPath(objectName) {
  let path = String(objectName || '').trim();
  if (path && !path.endsWith('.')) path += '.';
  return path;
}

/**
 * Build AddObject SOAP envelope.
 * @param {string} cwmpId
 * @param {string} objectName – e.g. "InternetGatewayDevice.WANDevice.1.WANConnectionDevice."
 */
function buildAddObject(cwmpId, objectName) {
  const normalizedObjectName = normalizeObjectPath(objectName);
  return soapEnvelopeWrap(cwmpId,
    `<cwmp:AddObject>
      <ObjectName>${escapeXml(normalizedObjectName)}</ObjectName>
      <ParameterKey></ParameterKey>
    </cwmp:AddObject>`
  );
}

function escapeXml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DATABASE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Upsert device from Inform data.
 */
function upsertDevice(deviceId, deviceInfo, params, ipAddress) {
  const now = nowLocal();

  // Extract well-known parameters
  const swVer = params['InternetGatewayDevice.DeviceInfo.SoftwareVersion']
    || params['Device.DeviceInfo.SoftwareVersion']
    || '';
  const hwVer = params['InternetGatewayDevice.DeviceInfo.HardwareVersion']
    || params['Device.DeviceInfo.HardwareVersion']
    || '';

  // Connection request URL – look in multiple possible locations
  const connReqUrl = params['InternetGatewayDevice.ManagementServer.ConnectionRequestURL']
    || params['Device.ManagementServer.ConnectionRequestURL']
    || '';
  const connReqUser = params['InternetGatewayDevice.ManagementServer.ConnectionRequestUsername']
    || params['Device.ManagementServer.ConnectionRequestUsername']
    || '';
  const connReqPass = params['InternetGatewayDevice.ManagementServer.ConnectionRequestPassword']
    || params['Device.ManagementServer.ConnectionRequestPassword']
    || '';

  // Extract IP address from connection request URL if valid, to bypass NAT/masquerade
  let ipToSave = ipAddress;
  if (connReqUrl) {
    try {
      const cleanUrl = connReqUrl.trim();
      if (cleanUrl.startsWith('http')) {
        const urlObj = new URL(cleanUrl);
        if (urlObj.hostname && urlObj.hostname !== '0.0.0.0' && urlObj.hostname !== '127.0.0.1' && !urlObj.hostname.startsWith('169.254.')) {
          ipToSave = urlObj.hostname;
        }
      } else {
        const match = cleanUrl.match(/(?:https?:\/\/)?([^:/]+)/);
        if (match && match[1] && match[1] !== '0.0.0.0' && match[1] !== '127.0.0.1' && !match[1].startsWith('169.254.')) {
          ipToSave = match[1];
        }
      }
    } catch (_) {}
  }
  
  // Clean IPv6 mapped IPv4 prefix
  if (ipToSave && ipToSave.startsWith('::ffff:')) {
    ipToSave = ipToSave.slice(7);
  }

  // Check if device exists
  const existing = db.prepare('SELECT id, params, tags FROM acs_devices WHERE id = ?').get(deviceId);

  if (existing) {
    // Merge existing params with new params (new values overwrite)
    let mergedParams = {};
    try { mergedParams = JSON.parse(existing.params || '{}'); } catch (_) { /* empty */ }
    Object.assign(mergedParams, params);

    db.prepare(`
      UPDATE acs_devices SET
        serial_number = ?,
        manufacturer = ?,
        product_class = ?,
        oui = ?,
        software_version = ?,
        hardware_version = ?,
        ip_address = ?,
        connection_request_url = CASE WHEN ? != '' THEN ? ELSE connection_request_url END,
        connection_request_user = CASE WHEN ? != '' THEN ? ELSE connection_request_user END,
        connection_request_pass = CASE WHEN ? != '' THEN ? ELSE connection_request_pass END,
        params = ?,
        last_inform = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      deviceInfo.SerialNumber,
      deviceInfo.Manufacturer,
      deviceInfo.ProductClass,
      deviceInfo.OUI,
      swVer,
      hwVer,
      ipToSave,
      connReqUrl, connReqUrl,
      connReqUser, connReqUser,
      connReqPass, connReqPass,
      JSON.stringify(mergedParams),
      now,
      now,
      deviceId
    );
  } else {
    db.prepare(`
      INSERT INTO acs_devices
        (id, serial_number, manufacturer, product_class, oui,
         software_version, hardware_version, ip_address,
         connection_request_url, connection_request_user, connection_request_pass,
         tags, params, last_inform, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?)
    `).run(
      deviceId,
      deviceInfo.SerialNumber,
      deviceInfo.Manufacturer,
      deviceInfo.ProductClass,
      deviceInfo.OUI,
      swVer,
      hwVer,
      ipToSave,
      connReqUrl,
      connReqUser,
      connReqPass,
      JSON.stringify(params),
      now,
      now,
      now
    );
  }
}

/**
 * Merge GetParameterValuesResponse data into a device's params.
 */
function mergeDeviceParams(deviceId, newParams) {
  const now = nowLocal();
  const existing = db.prepare('SELECT params FROM acs_devices WHERE id = ?').get(deviceId);
  if (!existing) return;

  let merged = {};
  try { merged = JSON.parse(existing.params || '{}'); } catch (_) { /* empty */ }
  Object.assign(merged, newParams);

  db.prepare('UPDATE acs_devices SET params = ?, updated_at = ? WHERE id = ?')
    .run(JSON.stringify(merged), now, deviceId);
}

/**
 * Check if the device is missing WLAN, WAN, or RX optical power parameters,
 * and if so, queue a getParameterValues task to bootstrap them.
 */
function queueBootstrapTasksIfNeeded(deviceId, currentParams) {
  try {
    const device = db.prepare('SELECT tags FROM acs_devices WHERE id = ?').get(deviceId);
    if (!device) return;

    let tags = [];
    try { tags = JSON.parse(device.tags || '[]'); } catch (_) { tags = []; }

    // Discovery is the only source of truth. Never guess WAN/WLAN/vendor RX paths.
    const activeDiscovery = db.prepare(
      "SELECT COUNT(*) AS c FROM acs_tasks WHERE device_id = ? AND name = 'getParameterNames' AND status IN ('pending','in_progress')"
    ).get(deviceId);
    if (activeDiscovery && activeDiscovery.c > 0) return;

    if (tags.includes('acs_discovered')) return;

    const isTr181 = Object.keys(currentParams || {}).some(k => String(k).startsWith('Device.'));
    const root = isTr181 ? 'Device.' : 'InternetGatewayDevice.';
    const now = nowLocal();

    db.prepare(
      `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
       VALUES (?, 'getParameterNames', ?, 'pending', ?, ?)`
    ).run(deviceId, JSON.stringify({
      objectName: root,
      nextLevel: 0,
      bootstrapDiscovery: true
    }), now, now);

    logger.info(`[ACS] Device ${deviceId}: starting dynamic parameter discovery at ${root}`);
  } catch (err) {
    logger.error(`[ACS] Error in dynamic bootstrap discovery for ${deviceId}: ${err.message}`);
  }
}
function queueRealtimeMonitoringTasks(deviceId, currentParams) {
  try {
    const device = db.prepare('SELECT tags FROM acs_devices WHERE id = ?').get(deviceId);
    if (!device) return;
    let tags = [];
    try { tags = JSON.parse(device.tags || '[]'); } catch (_) { tags = []; }

    // Do not start monitoring until the parameter tree has been discovered.
    if (!tags.includes('acs_discovered')) return;

    const pending = db.prepare(
      "SELECT COUNT(*) as c FROM acs_tasks WHERE device_id = ? AND name IN ('getParameterValues','getParameterNames','refreshObject') AND status IN ('pending','in_progress')"
    ).get(deviceId);
    if (pending && pending.c > 0) return;

    const lastDone = db.prepare(
      "SELECT updated_at FROM acs_tasks WHERE device_id = ? AND name IN ('getParameterValues','getParameterNames','refreshObject') AND status = 'completed' ORDER BY updated_at DESC LIMIT 1"
    ).get(deviceId);
    if (lastDone && lastDone.updated_at) {
      const diffMs = Date.now() - new Date(lastDone.updated_at).getTime();
      if (diffMs < 60_000) return;
    }

    // Only refresh objects that were actually advertised by the CPE.
    const keys = Object.keys(currentParams || {});
    const objectNames = new Set();
    for (const k of keys) {
      const name = String(k);
      if (name.endsWith('.AssociatedDevice.')) {
        objectNames.add(name.slice(0, -1));
      }
      if (name.endsWith('.Hosts.Host.')) {
        objectNames.add(name.slice(0, -1));
      }
    }

    const now = nowLocal();
    for (const objectName of objectNames) {
      db.prepare(
        `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
         VALUES (?, 'refreshObject', ?, 'pending', ?, ?)`
      ).run(deviceId, JSON.stringify({ objectName }), now, now);
    }
  } catch (err) {
    logger.error(`[ACS] Error in dynamic realtime monitoring for ${deviceId}: ${err.message}`);
  }
}
/**
 * Get the next pending task for a device.
 */
function getNextPendingTask(deviceId) {
  return db.prepare(
    `SELECT * FROM acs_tasks
     WHERE device_id = ? AND status = 'pending'
     ORDER BY id ASC LIMIT 1`
  ).get(deviceId) || null;
}

function getTaskById(taskId) {
  return db.prepare(
    `SELECT * FROM acs_tasks WHERE id = ? LIMIT 1`
  ).get(taskId) || null;
}

function applyTemplateVariables(value, templateVars) {
  const vars = templateVars && typeof templateVars === 'object' ? templateVars : {};
  if (Array.isArray(value)) {
    return value.map(item => applyTemplateVariables(item, vars));
  }
  if (value && typeof value === 'object') {
    const next = {};
    for (const [k, v] of Object.entries(value)) {
      next[k] = applyTemplateVariables(v, vars);
    }
    return next;
  }
  if (typeof value !== 'string' || !value.includes('{{')) return value;
  return value.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (match, key) => {
    if (!(key in vars)) return match;
    const resolved = vars[key];
    return resolved == null ? '' : String(resolved);
  });
}

function enqueueFollowupTasks(deviceId, followupTasks, templateVars) {
  if (!deviceId || !Array.isArray(followupTasks) || followupTasks.length === 0) return 0;
  const now = nowLocal();
  const insertTask = db.prepare(
    `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
     VALUES (?, ?, ?, 'pending', ?, ?)`
  );
  let created = 0;

  for (const spec of followupTasks) {
    if (!spec || typeof spec !== 'object') continue;
    const taskName = String(spec.name || '').trim();
    if (!taskName) continue;

    const rawPayload = (spec.payload && typeof spec.payload === 'object' && !Array.isArray(spec.payload))
      ? spec.payload
      : Object.fromEntries(Object.entries(spec).filter(([key]) => key !== 'name'));
    const hydratedPayload = applyTemplateVariables(rawPayload, templateVars);

    if (spec.instanceVariable && !hydratedPayload.instanceVariable) {
      hydratedPayload.instanceVariable = spec.instanceVariable;
    }
    if (templateVars && typeof templateVars === 'object' && Object.keys(templateVars).length > 0) {
      hydratedPayload.templateVars = {
        ...(hydratedPayload.templateVars && typeof hydratedPayload.templateVars === 'object' ? hydratedPayload.templateVars : {}),
        ...templateVars
      };
    }

    insertTask.run(deviceId, taskName, JSON.stringify(hydratedPayload), now, now);
    created += 1;
  }

  return created;
}

/**
 * Mark a task as completed.
 */
function completeTask(taskId, result) {
  const now = nowLocal();
  db.prepare(
    `UPDATE acs_tasks SET status = 'completed', result = ?, updated_at = ? WHERE id = ?`
  ).run(result ? JSON.stringify(result) : null, now, taskId);
}

/**
 * Mark a task as failed.
 */
function failTask(taskId, error) {
  const now = nowLocal();
  db.prepare(
    `UPDATE acs_tasks SET status = 'failed', result = ?, retry_count = retry_count + 1, updated_at = ? WHERE id = ?`
  ).run(error ? JSON.stringify(error) : null, now, taskId);
}

function shouldThrottleFaultLog(deviceId, fault, taskName, payload) {
  const normalizedPayload = String(payload || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240);
  const key = [
    String(deviceId || '-'),
    String(fault?.faultCode || '-'),
    String(taskName || '-'),
    normalizedPayload
  ].join('|');
  const now = Date.now();
  const lastSeen = recentFaultLogs.get(key) || 0;
  recentFaultLogs.set(key, now);
  return !!lastSeen && (now - lastSeen) < 10 * 60 * 1000;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TASK → SOAP BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build the SOAP request for a given task.
 * Returns the SOAP XML string or null if the task type is unknown.
 */
function buildTaskSoap(cwmpId, task) {
  let payload = {};
  try { payload = JSON.parse(task.payload || '{}'); } catch (_) { /* empty */ }

  switch (task.name) {
    case 'reboot':
      return buildReboot(cwmpId);

    case 'factoryReset':
      return buildFactoryReset(cwmpId);

    case 'setParameterValues': {
      const pvs = payload.parameterValues || payload.values || [];
      if (!Array.isArray(pvs) || pvs.length === 0) return null;
      return buildSetParameterValues(cwmpId, pvs);
    }

    case 'getParameterValues': {
      const names = payload.parameterNames || payload.names || [];
      if (!Array.isArray(names) || names.length === 0) return null;
      return buildGetParameterValues(cwmpId, names);
    }

    case 'getParameterNames': {
      const objName = payload.objectName || payload.object || payload.parameterPath || '';
      const nextLevel = payload.nextLevel ? 1 : 0;
      if (!objName) return null;
      return buildGetParameterNames(cwmpId, objName, nextLevel);
    }

    case 'refreshObject': {
      const objName = payload.objectName || payload.object || '';
      return buildRefreshObject(cwmpId, objName);
    }

    case 'addObject': {
      const objName = payload.objectName || payload.object || '';
      if (!objName) return null;
      return buildAddObject(cwmpId, objName);
    }

    default:
      logger.warn(`[ACS] Unknown task type: ${task.name}`);
      return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DETERMINE DEVICE ID
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build the canonical device ID from DeviceId fields.
 * Format: {OUI}-{ProductClass}-{SerialNumber}
 */
function buildDeviceId(deviceInfo) {
  const oui = (deviceInfo.OUI || '000000').trim();
  const pc = (deviceInfo.ProductClass || '').trim();
  const sn = (deviceInfo.SerialNumber || '').trim();
  if (pc) {
    return `${oui}-${pc}-${sn}`;
  }
  return `${oui}-${sn}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN CWMP REQUEST HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Express handler for POST /acs
 *
 * Must be mounted with:
 *   app.post('/acs', express.raw({ type: ['text/xml', 'application/soap+xml', 'application/xml'] }), handleCwmpRequest);
 */
const handleCwmpRequest = async (req, res) => {
  try {
    // Get body as string
    let body = '';
    if (Buffer.isBuffer(req.body)) {
      body = req.body.toString('utf-8');
    } else if (typeof req.body === 'string') {
      body = req.body;
    } else if (req.body) {
      body = String(req.body);
    }

    // Determine CPE IP address
    const cpeIp = req.headers['x-forwarded-for']
      ? String(req.headers['x-forwarded-for']).split(',')[0].trim()
      : req.socket?.remoteAddress || req.ip || '';

    // Get or create session
    const { sid, session } = getOrCreateSession(req, res);

    // ── EMPTY POST (step 2 or 3) ───────────────────────────────────────────
    if (!body || body.trim().length === 0) {
      return handleEmptyPost(session, sid, res, cpeIp);
    }

    // ── INFORM ─────────────────────────────────────────────────────────────
    if (hasCwmpMethod(body, 'Inform')) {
      return handleInform(body, session, sid, cpeIp, res);
    }

    // ── RESPONSE TO A TASK ─────────────────────────────────────────────────
    // Check for known response types
    if (hasCwmpMethod(body, 'SetParameterValuesResponse')) {
      return handleTaskResponse(body, session, sid, 'setParameterValues', res);
    }
    if (hasCwmpMethod(body, 'RebootResponse')) {
      return handleTaskResponse(body, session, sid, 'reboot', res);
    }
    if (hasCwmpMethod(body, 'FactoryResetResponse')) {
      return handleTaskResponse(body, session, sid, 'factoryReset', res);
    }
    if (hasCwmpMethod(body, 'GetParameterValuesResponse')) {
      return handleGetParameterValuesResponse(body, session, sid, res);
    }
    if (hasCwmpMethod(body, 'GetParameterNamesResponse')) {
      return handleGetParameterNamesResponse(body, session, sid, res);
    }
    if (hasCwmpMethod(body, 'AddObjectResponse')) {
      return handleAddObjectResponse(body, session, sid, res);
    }

    // ── FAULT ──────────────────────────────────────────────────────────────
    const fault = parseFault(body);
    if (fault) {
      return handleFault(fault, session, sid, res);
    }

    // ── UNKNOWN / UNRECOGNIZED ─────────────────────────────────────────────
    // Treat as empty post (next task or 204)
    logger.debug(`[ACS] Unrecognized SOAP body from session ${sid.substring(0, 8)}, treating as empty`);
    return handleEmptyPost(session, sid, res, cpeIp);

  } catch (err) {
    logger.error(`[ACS] Error handling CWMP request: ${err.message}`);
    res.status(500).set('Content-Type', 'text/xml; charset=utf-8').send('');
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  HANDLER: Inform
// ═══════════════════════════════════════════════════════════════════════════════

function handleInform(body, session, sid, cpeIp, res) {
  const cwmpId = extractCwmpId(body);
  const deviceInfo = parseDeviceId(body);

  if (!deviceInfo || !deviceInfo.SerialNumber) {
    logger.warn(`[ACS] Inform received but could not parse DeviceId`);
    return sendSoapResponse(res, buildInformResponse(cwmpId));
  }

  const deviceId = buildDeviceId(deviceInfo);
  const params = parseParameterValues(body);

  logger.info(`[ACS] Inform from ${deviceId} (${deviceInfo.Manufacturer} ${deviceInfo.ProductClass}) IP=${cpeIp}`);

  // Upsert device in database
  let mergedParams = params;
  try {
    upsertDevice(deviceId, deviceInfo, params, cpeIp);
    const existing = db.prepare('SELECT params FROM acs_devices WHERE id = ?').get(deviceId);
    if (existing) {
      mergedParams = JSON.parse(existing.params || '{}');
    }
  } catch (err) {
    logger.error(`[ACS] Failed to upsert device ${deviceId}: ${err.message}`);
  }

  // Queue bootstrap parameter fetch if needed
  queueBootstrapTasksIfNeeded(deviceId, mergedParams);
  queueRealtimeMonitoringTasks(deviceId, mergedParams);

  if (cpeIp) {
    lastDeviceByIp.set(String(cpeIp), { deviceId, ts: Date.now() });
    if (lastDeviceByIp.size > 5000) {
      const now = Date.now();
      for (const [k, v] of lastDeviceByIp.entries()) {
        if (!v || (now - (v.ts || 0)) > 10 * 60 * 1000) lastDeviceByIp.delete(k);
      }
    }
  }

  // Update session
  session.deviceId = deviceId;
  session.step = 'informed';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  return sendSoapResponse(res, buildInformResponse(cwmpId));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HANDLER: Empty POST (check task queue)
// ═══════════════════════════════════════════════════════════════════════════════

function handleEmptyPost(session, sid, res, cpeIp = '') {
  if (!session.deviceId) {
    const ipKey = String(cpeIp || '').trim();
    if (ipKey) {
      const rec = lastDeviceByIp.get(ipKey);
      if (rec && rec.deviceId && (Date.now() - (rec.ts || 0)) < SESSION_TIMEOUT_MS) {
        session.deviceId = rec.deviceId;
        session.step = 'inferred';
        logger.info(`[ACS] Inferred session deviceId=${rec.deviceId} from IP=${ipKey}`);
      }
    }
    if (!session.deviceId) return res.status(204).set('Content-Type', 'text/xml; charset=utf-8').send('');
  }

  // Look for a pending task for this device
  const task = getNextPendingTask(session.deviceId);
  if (!task) {
    // No more tasks – signal end of session
    logger.debug(`[ACS] No pending tasks for ${session.deviceId}, sending 204`);
    return res.status(204).set('Content-Type', 'text/xml; charset=utf-8').send('');
  }

  // Build SOAP request for this task
  const cwmpId = String(task.id);
  const soapXml = buildTaskSoap(cwmpId, task);

  if (!soapXml) {
    // Invalid task – mark as failed and try next
    logger.warn(`[ACS] Could not build SOAP for task ${task.id} (${task.name}), marking failed`);
    failTask(task.id, { error: 'Could not build SOAP request for task' });
    return handleEmptyPost(session, sid, res, cpeIp);
  }

  // Update session – we are now waiting for the response to this task
  session.currentTaskId = task.id;
  session.step = 'task_sent';
  session.lastActivity = Date.now();

  // Mark task as in-progress (optional, keeps it 'pending' until response)
  const now = nowLocal();
  db.prepare("UPDATE acs_tasks SET status = 'in_progress', updated_at = ? WHERE id = ?")
    .run(now, task.id);

  logger.info(`[ACS] Sending task ${task.id} (${task.name}) to device ${session.deviceId}`);
  return sendSoapResponse(res, soapXml);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HANDLER: Task Responses
// ═══════════════════════════════════════════════════════════════════════════════

function handleTaskResponse(body, session, sid, taskType, res) {
  const taskId = session.currentTaskId;

  if (taskId) {
    let result = {};
    if (taskType === 'setParameterValues') {
      const status = parseSetParameterValuesResponseStatus(body);
      result = { status };
      
      // If setting parameter values succeeded, merge those values into the device's local record immediately
      if (status === '0' || status === 0 || status === '') {
        try {
          const task = db.prepare('SELECT payload FROM acs_tasks WHERE id = ?').get(taskId);
          if (task) {
            const payload = JSON.parse(task.payload || '{}');
            const pvs = payload.parameterValues || payload.values || [];
            if (Array.isArray(pvs) && pvs.length > 0) {
              const newParams = {};
              for (const pv of pvs) {
                if (pv && pv[0]) {
                  newParams[pv[0]] = pv[1];
                }
              }
              mergeDeviceParams(session.deviceId, newParams);

              if (payload.automaticAcsProvisioning === true) {
                const dev = db.prepare('SELECT tags FROM acs_devices WHERE id = ?').get(session.deviceId);
                let tags = [];
                try { tags = JSON.parse(dev?.tags || '[]'); } catch (_) { tags = []; }
                if (!tags.includes('acs_configured')) tags.push('acs_configured');
                db.prepare('UPDATE acs_devices SET tags = ?, updated_at = ? WHERE id = ?')
                  .run(JSON.stringify(tags), nowLocal(), session.deviceId);
                logger.info(`[ACS] ${session.deviceId}: automatic ACS provisioning completed`);
              }

              logger.debug(`[ACS] Merged ${Object.keys(newParams).length} set parameters into local device record for ${session.deviceId}`);
            }
          }
        } catch (err) {
          logger.error(`[ACS] Failed to merge set parameters after task completion: ${err.message}`);
        }
      }
    } else {
      result = { status: 'ok' };
    }

    logger.info(`[ACS] Task ${taskId} (${taskType}) completed for device ${session.deviceId}`);
    completeTask(taskId, result);
  }

  session.step = 'response_received';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  // Check for next task
  return handleEmptyPost(session, sid, res);
}

function queueAutomaticAcsConfiguration(deviceId, discoveredNames) {
  try {
    const device = db.prepare('SELECT tags, params FROM acs_devices WHERE id = ?').get(deviceId);
    if (!device) return;
    let tags = [];
    try { tags = JSON.parse(device.tags || '[]'); } catch (_) { tags = []; }
    if (tags.includes('acs_configured')) return;

    let names = Array.isArray(discoveredNames) ? discoveredNames.map(String) : [];
    let params = {};
    try { params = JSON.parse(device.params || '{}'); } catch (_) { params = {}; }
    names = [...new Set([...names, ...Object.keys(params)])];

    const findExact = (suffixes) => {
      for (const suffix of suffixes) {
        const found = names.find(n => String(n).toLowerCase().endsWith(suffix.toLowerCase()));
        if (found) return found;
      }
      return null;
    };

    const urlName = findExact(['.ManagementServer.URL']);
    const userName = findExact(['.ManagementServer.Username']);
    const passName = findExact(['.ManagementServer.Password']);
    const periodicEnable = findExact(['.ManagementServer.PeriodicInformEnable']);
    const periodicInterval = findExact(['.ManagementServer.PeriodicInformInterval']);

    const pvs = [];
    if (urlName) pvs.push([urlName, AUTO_ACS_URL, 'xsd:string']);
    if (userName) pvs.push([userName, AUTO_ACS_USERNAME, 'xsd:string']);
    if (passName) pvs.push([passName, AUTO_ACS_PASSWORD, 'xsd:string']);
    if (periodicEnable) pvs.push([periodicEnable, 'true', 'xsd:boolean']);
    if (periodicInterval) pvs.push([periodicInterval, '300', 'xsd:unsignedInt']);

    if (pvs.length === 0) {
      logger.warn(`[ACS] ${deviceId}: ManagementServer parameters were not advertised; skipping automatic ACS provisioning`);
      return;
    }

    const pending = db.prepare(
      "SELECT COUNT(*) AS c FROM acs_tasks WHERE device_id = ? AND name = 'setParameterValues' AND status IN ('pending','in_progress')"
    ).get(deviceId);
    if (pending && pending.c > 0) return;

    const now = nowLocal();
    db.prepare(
      `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)\n       VALUES (?, 'setParameterValues', ?, 'pending', ?, ?)`
    ).run(deviceId, JSON.stringify({ parameterValues: pvs, automaticAcsProvisioning: true }), now, now);

    logger.info(`[ACS] ${deviceId}: queued automatic ACS provisioning for ${pvs.length} discovered ManagementServer parameters`);
  } catch (err) {
    logger.error(`[ACS] Failed to queue automatic ACS provisioning for ${deviceId}: ${err.message}`);
  }
}

function handleGetParameterValuesResponse(body, session, sid, res) {
  const taskId = session.currentTaskId;
  const params = parseGetParameterValuesResponse(body);

  if (taskId) {
    logger.info(`[ACS] Task ${taskId} (getParameterValues/refreshObject) completed for device ${session.deviceId} – ${Object.keys(params).length} params`);
    completeTask(taskId, params);
  }

  // Merge returned params into device record
  if (session.deviceId && Object.keys(params).length > 0) {
    try {
      mergeDeviceParams(session.deviceId, params);

      let taskPayload = {};
      try {
        const row = taskId ? db.prepare('SELECT payload FROM acs_tasks WHERE id = ?').get(taskId) : null;
        taskPayload = JSON.parse(row?.payload || '{}');
      } catch (_) {}

      if (taskPayload.bootstrapValues === true) {
        queueAutomaticAcsConfiguration(session.deviceId, taskPayload.discoveredNames || Object.keys(params));
      }
    } catch (err) {
      logger.error(`[ACS] Failed to merge params for device ${session.deviceId}: ${err.message}`);
    }
  }

  session.step = 'response_received';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  return handleEmptyPost(session, sid, res);
}

function handleGetParameterNamesResponse(body, session, sid, res) {
  const taskId = session.currentTaskId;
  const names = [...new Set(parseGetParameterNamesResponse(body).map(String))];
  let taskPayload = {};

  if (taskId) {
    try {
      const row = db.prepare('SELECT payload FROM acs_tasks WHERE id = ?').get(taskId);
      taskPayload = JSON.parse(row?.payload || '{}');
    } catch (_) { taskPayload = {}; }

    logger.info(`[ACS] Task ${taskId} (getParameterNames/refreshObject) completed for device ${session.deviceId} – ${names.length} names`);
    completeTask(taskId, { names });
  }

  if (session.deviceId && names.length > 0) {
    try {
      const now = nowLocal();
      const isBootstrap = taskPayload.bootstrapDiscovery === true;

      if (isBootstrap) {
        // Keep only exact leaf names for GetParameterValues. Object names end in '.'.
        const leaves = names.filter(n => !n.endsWith('.'));
        const lower = leaves.map(n => [n, n.toLowerCase()]);

        // Pull ManagementServer parameters plus useful monitoring values, but only when
        // the CPE explicitly advertised the exact parameter name.
        const selected = [];
        for (const [name, low] of lower) {
          const interesting =
            low.includes('.managementserver.') ||
            low.endsWith('.ssid') ||
            low.endsWith('.username') ||
            low.endsWith('.externalipaddress') ||
            low.endsWith('.rxpower') ||
            low.endsWith('.opticalsignallevel') ||
            low.endsWith('.hostname') ||
            low.endsWith('.ipaddress') ||
            low.endsWith('.macaddress');
          if (interesting) selected.push(name);
        }

        // Always include basic device information if advertised.
        for (const name of leaves) {
          const low = name.toLowerCase();
          if (low.includes('.deviceinfo.modelname') ||
              low.includes('.deviceinfo.softwareversion') ||
              low.includes('.deviceinfo.hardwareversion') ||
              low.includes('.deviceinfo.uptime')) {
            selected.push(name);
          }
        }

        const unique = [...new Set(selected)].slice(0, 500);
        if (unique.length > 0) {
          db.prepare(
            `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
             VALUES (?, 'getParameterValues', ?, 'pending', ?, ?)`
          ).run(session.deviceId, JSON.stringify({
            parameterNames: unique,
            bootstrapValues: true,
            discoveredNames: names
          }), now, now);
        }

        // Cache every advertised name in params as a marker. Values are populated by GPV.
        const markerParams = {};
        for (const name of names) {
          if (name.endsWith('.')) markerParams[name] = markerParams[name] || '';
        }
        if (Object.keys(markerParams).length) mergeDeviceParams(session.deviceId, markerParams);

        const device = db.prepare('SELECT tags FROM acs_devices WHERE id = ?').get(session.deviceId);
        let tags = [];
        try { tags = JSON.parse(device?.tags || '[]'); } catch (_) { tags = []; }
        if (!tags.includes('acs_discovered')) tags.push('acs_discovered');
        db.prepare('UPDATE acs_devices SET tags = ?, updated_at = ? WHERE id = ?')
          .run(JSON.stringify(tags), now, session.deviceId);
      } else if (names.length > 0) {
        // refreshObject: query only the exact leaf names relevant to client/host reporting.
        const objectName = String(taskPayload.objectName || taskPayload.object || '');
        let filtered = names.filter(n => !n.endsWith('.'));
        if (objectName.includes('Hosts.Host')) {
          filtered = filtered.filter(n => /\.(HostName|IPAddress|MACAddress|InterfaceType|Active|LeaseTimeRemaining|RemainingLeaseTime)$/i.test(n));
        } else if (objectName.includes('AssociatedDevice')) {
          filtered = filtered.filter(n => /\.(AssociatedDeviceMACAddress|MACAddress|IPAddress|HostName|DeviceName)$/i.test(n));
        }
        if (filtered.length > 0) {
          db.prepare(
            `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
             VALUES (?, 'getParameterValues', ?, 'pending', ?, ?)`
          ).run(session.deviceId, JSON.stringify({ parameterNames: filtered.slice(0, 500) }), now, now);
        }
      }
    } catch (err) {
      logger.error(`[ACS] Failed to process GetParameterNames for ${session.deviceId}: ${err.message}`);
    }
  }

  session.step = 'response_received';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  return handleEmptyPost(session, sid, res);
}
function handleAddObjectResponse(body, session, sid, res) {
  const taskId = session.currentTaskId;
  const result = parseAddObjectResponse(body);
  const taskRow = taskId ? getTaskById(taskId) : null;
  let taskPayload = {};
  try { taskPayload = JSON.parse(taskRow?.payload || '{}'); } catch (_) { taskPayload = {}; }

  if (taskId) {
    logger.info(`[ACS] Task ${taskId} (addObject) completed – instance=${result.instanceNumber}`);
    completeTask(taskId, result);
  }

  if (session.deviceId && Array.isArray(taskPayload.followup) && taskPayload.followup.length > 0) {
    const inheritedVars = taskPayload.templateVars && typeof taskPayload.templateVars === 'object'
      ? taskPayload.templateVars
      : {};
    const instanceVarName = String(taskPayload.instanceVariable || taskPayload.instanceVar || 'instanceNumber').trim();
    const nextVars = { ...inheritedVars };
    if (instanceVarName && result.instanceNumber != null && result.instanceNumber !== '') {
      nextVars[instanceVarName] = String(result.instanceNumber);
    }

    const created = enqueueFollowupTasks(session.deviceId, taskPayload.followup, nextVars);
    if (created > 0) {
      logger.info(`[ACS] Enqueued ${created} follow-up task(s) after addObject for ${session.deviceId}`);
    }
  }

  session.step = 'response_received';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  return handleEmptyPost(session, sid, res);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HANDLER: SOAP Fault
// ═══════════════════════════════════════════════════════════════════════════════

function handleFault(fault, session, sid, res) {
  const taskId = session.currentTaskId;

  try {
    let taskInfo = '';
    let taskName = '';
    let taskPayload = '';
    if (taskId) {
      const row = db.prepare('SELECT name, payload FROM acs_tasks WHERE id = ?').get(taskId);
      if (row) {
        taskName = String(row.name || '');
        taskPayload = String(row.payload || '');
        taskInfo = ` task=${taskName} payload=${taskPayload.substring(0, 500)}`;
      }
    }
    const det = fault.detail ? String(fault.detail).replace(/\s+/g, ' ').trim().slice(0, 500) : '';
    const repeated = shouldThrottleFaultLog(session.deviceId, fault, taskName, taskPayload);
    const message = `[ACS] SOAP Fault from device ${session.deviceId}: code=${fault.faultCode} string=${fault.faultString}${det ? ' detail=' + det : ''}${taskInfo}`;
    if (repeated) logger.debug(`${message} (repeat suppressed)`);
    else logger.warn(message);
  } catch (e) {
    logger.warn(`[ACS] SOAP Fault from device ${session.deviceId}: code=${fault.faultCode} string=${fault.faultString}`);
  }

  if (taskId) {
    failTask(taskId, fault);
  }

  session.step = 'response_received';
  session.currentTaskId = null;
  session.lastActivity = Date.now();

  // Try next task
  return handleEmptyPost(session, sid, res);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function sendSoapResponse(res, soapXml) {
  res.status(200)
    .set('Content-Type', 'text/xml; charset=utf-8')
    .set('SOAPAction', '')
    .send(soapXml);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONNECTION REQUEST TRIGGER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Send an HTTP GET to the CPE's ConnectionRequestURL to trigger a new session.
 * Fire-and-forget. Supports Basic Auth.
 *
 * @param {string} deviceId
 * @returns {Promise<{success:boolean, message:string}>}
 */
const activeTriggers = new Map();
const lastTriggerTimes = new Map();

async function triggerConnectionRequest(deviceId) {
  if (activeTriggers.has(deviceId)) {
    clearTimeout(activeTriggers.get(deviceId));
  }

  return new Promise((resolve) => {
    const timeoutObj = setTimeout(async () => {
      activeTriggers.delete(deviceId);

      const lastTime = lastTriggerTimes.get(deviceId) || 0;
      if (Date.now() - lastTime < 3000) {
        logger.debug(`[ACS] Connection request to ${deviceId} throttled (already sent within 3s)`);
        resolve({ success: true, message: 'Throttled' });
        return;
      }

      lastTriggerTimes.set(deviceId, Date.now());

      try {
        const res = await performConnectionRequest(deviceId);
        resolve(res);
      } catch (err) {
        resolve({ success: false, message: err.message });
      }
    }, 1000); // 1-second debounce window

    activeTriggers.set(deviceId, timeoutObj);
  });
}

function parseWwwAuthenticate(header) {
  const params = {};
  const cleanHeader = header.replace(/^Digest\s+/i, '');
  const parts = cleanHeader.split(/,\s*/);
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx > 0) {
      const key = part.substring(0, eqIdx).trim();
      let val = part.substring(eqIdx + 1).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.substring(1, val.length - 1);
      }
      params[key] = val;
    }
  }
  return params;
}

function buildDigestAuthorization(method, uri, authParams, username, password) {
  const realm = authParams.realm;
  const nonce = authParams.nonce;
  const opaque = authParams.opaque;
  const qop = authParams.qop;
  
  const ha1 = crypto.createHash('md5').update(`${username}:${realm}:${password}`).digest('hex');
  const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');
  
  let authHeader = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}"`;
  
  if (qop) {
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');
    const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`).digest('hex');
    authHeader += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}", response="${response}"`;
  } else {
    const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${ha2}`).digest('hex');
    authHeader += `, response="${response}"`;
  }
  
  if (opaque) {
    authHeader += `, opaque="${opaque}"`;
  }
  
  return authHeader;
}

async function performConnectionRequest(deviceId) {
  try {
    const device = db.prepare('SELECT * FROM acs_devices WHERE id = ?').get(deviceId);
    if (!device) {
      return { success: false, message: `Device ${deviceId} not found` };
    }

    const crUrl = device.connection_request_url;
    if (!crUrl) {
      return { success: false, message: `No ConnectionRequestURL for device ${deviceId}` };
    }

    logger.info(`[ACS] Triggering connection request to ${deviceId} → ${crUrl}`);

    const url = new URL(crUrl);
    const isHttps = url.protocol === 'https:';
    const transport = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      timeout: 10000,
      rejectUnauthorized: false, // Self-signed certs on CPE devices
    };

    // Connection Request authentication is adaptive: first try without credentials.
    // Only retry after a 401 challenge. Existing per-device credentials are preferred;
    // otherwise the configured fallback is used.
    const crUser = device.connection_request_user || AUTO_CR_USERNAME;
    const crPass = device.connection_request_pass || AUTO_CR_PASSWORD;

    return new Promise((resolve) => {
      const executeRequest = (authHeader = null) => {
        const reqOptions = { ...options };
        if (authHeader) {
          delete reqOptions.auth;
          reqOptions.headers = reqOptions.headers || {};
          reqOptions.headers['Authorization'] = authHeader;
        }

        const req = transport.request(reqOptions, (resp) => {
          resp.resume();
          logger.info(`[ACS] Connection request to ${deviceId} returned HTTP ${resp.statusCode}`);

          if (resp.statusCode === 401 && resp.headers['www-authenticate'] && !authHeader && crUser) {
            const wwwAuth = resp.headers['www-authenticate'];
            logger.info(`[ACS] Got 401 challenge from ${deviceId}, retrying with configured Connection Request credentials`);
            try {
              if (/^Digest\s/i.test(wwwAuth)) {
                const authParams = parseWwwAuthenticate(wwwAuth);
                const digestHeader = buildDigestAuthorization('GET', options.path, authParams, crUser, crPass);
                executeRequest(digestHeader);
              } else if (/^Basic\s/i.test(wwwAuth)) {
                const basic = Buffer.from(`${crUser}:${crPass}`).toString('base64');
                executeRequest(`Basic ${basic}`);
              } else {
                resolve({ success: false, message: `Unsupported Connection Request auth challenge: ${wwwAuth}` });
              }
            } catch (err) {
              logger.error(`[ACS] Failed to construct Connection Request Auth: ${err.message}`);
              resolve({ success: false, message: `Connection Request Auth failure: ${err.message}` });
            }
            return;
          }

          resolve({ success: resp.statusCode < 400, message: `Connection request completed with HTTP ${resp.statusCode}` });
        });

        req.on('error', (err) => {
          logger.warn(`[ACS] Connection request to ${deviceId} failed: ${err.message}`);
          resolve({ success: false, message: `Connection request failed: ${err.message}` });
        });

        req.on('timeout', () => {
          req.destroy();
          logger.warn(`[ACS] Connection request to ${deviceId} timed out`);
          resolve({ success: false, message: 'Connection request timed out' });
        });

        req.end();
      };

      // Start first connection request attempt
      executeRequest();
    });
  } catch (err) {
    logger.error(`[ACS] Connection request error for ${deviceId}: ${err.message}`);
    return { success: false, message: err.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API: Query Devices & Create Tasks
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Query acs_devices with optional filtering.
 *
 * @param {Object} [query]  – Flat object of column → value filters (AND logic).
 *                            Special keys: 'search' (fuzzy across SN/manufacturer/product_class)
 * @param {string} [projection] – Comma-separated column names to select (default: '*')
 * @returns {Array}
 */
function getBuiltinDevices(query, projection) {
  try {
    let cols = '*';
    if (projection) {
      const allowed = new Set([
        'id', 'serial_number', 'manufacturer', 'product_class', 'oui',
        'software_version', 'hardware_version', 'ip_address',
        'connection_request_url', 'connection_request_user', 'connection_request_pass',
        'tags', 'params', 'last_inform', 'created_at', 'updated_at'
      ]);
      const requested = projection.split(',').map(c => c.trim()).filter(c => allowed.has(c));
      if (requested.length > 0) cols = requested.join(', ');
    }

    let sql = `SELECT ${cols} FROM acs_devices`;
    const conditions = [];
    const values = [];

    if (query && typeof query === 'object') {
      for (const [key, val] of Object.entries(query)) {
        if (key === 'search' && val) {
          conditions.push(
            `(serial_number LIKE ? OR manufacturer LIKE ? OR product_class LIKE ? OR id LIKE ?)`
          );
          const like = `%${val}%`;
          values.push(like, like, like, like);
        } else if (key === 'tags' && val) {
          conditions.push(`tags LIKE ?`);
          values.push(`%${val}%`);
        } else if (['id', 'serial_number', 'manufacturer', 'product_class', 'oui', 'ip_address'].includes(key)) {
          conditions.push(`${key} = ?`);
          values.push(val);
        }
      }
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY last_inform DESC';

    const rows = db.prepare(sql).all(...values);

    // Parse JSON fields
    return rows.map(row => {
      try { row.tags = JSON.parse(row.tags || '[]'); } catch (_) { row.tags = []; }
      try { row.params = JSON.parse(row.params || '{}'); } catch (_) { row.params = {}; }
      return row;
    });
  } catch (err) {
    logger.error(`[ACS] getBuiltinDevices error: ${err.message}`);
    return [];
  }
}

/**
 * Get a single device by its canonical ID.
 *
 * @param {string} deviceId
 * @returns {Object|null}
 */
function getBuiltinDevice(deviceId) {
  try {
    const row = db.prepare('SELECT * FROM acs_devices WHERE id = ?').get(deviceId);
    if (!row) return null;
    try { row.tags = JSON.parse(row.tags || '[]'); } catch (_) { row.tags = []; }
    try { row.params = JSON.parse(row.params || '{}'); } catch (_) { row.params = {}; }
    return row;
  } catch (err) {
    logger.error(`[ACS] getBuiltinDevice error: ${err.message}`);
    return null;
  }
}

/**
 * Create a new task for a device and trigger a connection request.
 *
 * @param {string}  deviceId  – acs_devices.id
 * @param {string}  taskName  – reboot | setParameterValues | getParameterValues | refreshObject | factoryReset | addObject
 * @param {Object}  payload   – Task-specific data
 * @returns {{ success: boolean, taskId?: number, message?: string }}
 */
function createBuiltinTask(deviceId, taskName, payload) {
  try {
    const now = nowLocal();
    const payloadStr = JSON.stringify(payload || {});

    const info = db.prepare(
      `INSERT INTO acs_tasks (device_id, name, payload, status, created_at, updated_at)
       VALUES (?, ?, ?, 'pending', ?, ?)`
    ).run(deviceId, taskName, payloadStr, now, now);

    const taskId = Number(info.lastInsertRowid);

    logger.info(`[ACS] Task ${taskId} (${taskName}) created for device ${deviceId}`);

    // Fire-and-forget connection request to wake up the CPE
    triggerConnectionRequest(deviceId).catch(err => {
      logger.warn(`[ACS] Failed to trigger connection request for ${deviceId}: ${err.message}`);
    });

    return { success: true, taskId, message: `Task ${taskName} created` };
  } catch (err) {
    logger.error(`[ACS] createBuiltinTask error: ${err.message}`);
    return { success: false, message: err.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  handleCwmpRequest,
  triggerConnectionRequest,
  getBuiltinDevices,
  getBuiltinDevice,
  createBuiltinTask,
};