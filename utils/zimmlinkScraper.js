const { Telnet } = require('telnet-client');
const winston = require('winston');

// Gunakan logger bawaan app jika ada, atau fallback ke console
const logger = winston.loggers.get('default') || console;

/**
 * Membuka koneksi Telnet ke OLT Zimmlink, mengeksekusi perintah CLI, dan mengambil raw text.
 */
async function fetchRawZimmlinkData(olt) {
  const connection = new Telnet();

  // Penyesuaian properti login sesuai kolom DB: web_user dan web_password
  const params = {
    host: olt.host,
    port: olt.telnet_port || 23,
    shellPrompt: /.*[>#]\s*\$/, // Prompt CLI Zimmlink ('OLT>' atau 'OLT#')
    loginPrompt: /Username:|login:/i,
    passwordPrompt: /Password:/i,
    username: olt.web_user || 'admin', 
    password: olt.web_password || 'admin',
    timeout: 10000,
  };

  try {
    await connection.connect(params);

    // Kirim perintah CLI Zimmlink untuk melihat daftar ONU & Redaman (Optic Power)
    const onuListRaw = await connection.exec('show onu active');
    const onuPowerRaw = await connection.exec('show onu power');
    const sysInfoRaw = await connection.exec('show system info');

    await connection.end();

    return {
      onuListRaw,
      onuPowerRaw,
      sysInfoRaw
    };
  } catch (error) {
    console.error(`[Zimmlink Scraper Error] Host ${olt.host}:`, error.message);
    throw new Error(`Gagal terhubung ke OLT Zimmlink via CLI/Telnet: ${error.message}`);
  }
}

/**
 * Mengolah (parse) output teks CLI Zimmlink menjadi format data standar aplikasi.
 */
function parseZimmlinkOutput(rawOutputs) {
  const { onuListRaw, onuPowerRaw, sysInfoRaw } = rawOutputs;

  const onus = [];
  let onlineCount = 0;
  let offlineCount = 0;

  // 1. Parsing data Sistem (Suhu, CPU, RAM, Uptime)
  let cpu = 'N/A';
  let ram = 'N/A';
  let temp = 'N/A';

  if (sysInfoRaw) {
    const cpuMatch = sysInfoRaw.match(/CPU\s*(?:Usage)?:?\s*(\d+%)/i);
    const ramMatch = sysInfoRaw.match(/(?:Memory|RAM)\s*(?:Usage)?:?\s*(\d+%)/i);
    const tempMatch = sysInfoRaw.match(/(?:Temperature|Suhu):?\s*(\d+°C|\d+\s*C)/i);

    if (cpuMatch) cpu = cpuMatch[1];
    if (ramMatch) ram = ramMatch[1];
    if (tempMatch) temp = tempMatch[1];
  }

  // 2. Parsing Tabel ONU & Redaman (RX Power)
  const lines = (onuListRaw || '').split(/\r?\n/);

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.toLowerCase().startsWith('port') || trimmed.startsWith('---')) return;

    const parts = trimmed.split(/\s+/);
    if (parts.length >= 3) {
      const portName = parts[0];             // e.g., EPON0/1:1
      const statusStr = parts[1].toUpperCase(); // ONLINE / OFFLINE
      const macOrSn = parts[2].toUpperCase().replace(/[^a-zA-Z0-9]/g, ''); // Bersihkan karakter non-alfa numerik

      const isOnline = statusStr.includes('ONLINE') || statusStr.includes('UP') || statusStr.includes('AUTH');
      if (isOnline) {
        onlineCount++;
      } else {
        offlineCount++;
      }

      // Cari redaman/power jika ada di output 'show onu power'
      let rxPower = 'N/A';
      if (onuPowerRaw) {
        // Cari baris yang mengandung portName diikuti oleh nilai minus redaman
        const powerMatch = new RegExp(`${portName.replace('/', '\\/')}\\s+([-\\d\\.]+)\\s*(?:dBm)?`, 'i').exec(onuPowerRaw);
        if (powerMatch) {
          rxPower = `${powerMatch[1]} dBm`;
        }
      }

      // PETAKAN PROPERTI SESUAI STANDAR CORE APLIKASI BILLING ANDA
      onus.push({
        index: String(idx + 1),
        id: portName,
        name: portName, 
        sn: macOrSn || '-',
        status: isOnline ? 'Online' : 'Offline',
        offline_reason: isOnline ? null : 'Terputus (ZimmLink CLI)',
        tx: 'N/A', // OLT tipe tertentu tidak memunculkan TX power ONU secara kolektif
        rx: rxPower !== 'N/A' && !rxPower.includes('dBm') ? rxPower + ' dBm' : rxPower,
        distance: '-',
        firmware: '-',
        uptime: '-'
      });
    }
  });

  const totalOnu = onlineCount + offlineCount;

  return {
    status: 'Online',
    temp,
    cpu,
    ram,
    uptime: 'Ditarik via Telnet Scraper',
    onus_total: totalOnu,
    onus_online: onlineCount,
    onus_offline: offlineCount,
    onus // Array data ONU yang sudah terstandarisasi
  };
}

/**
 * Entry point utama scraper Zimmlink untuk dipanggil oleh service OLT.
 */
async function scrapeZimmlinkOlt(olt) {
  const rawData = await fetchRawZimmlinkData(olt);
  return parseZimmlinkOutput(rawData);
}

module.exports = {
  scrapeZimmlinkOlt
};