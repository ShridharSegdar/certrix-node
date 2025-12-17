// netlify/functions/certrix-core.js
const forge = require('node-forge');
const JSZip = require('jszip');
const crypto = require('crypto');

const pki = forge.pki;

// ---- Config ----
const CA_COMMON_NAME = 'ICICI Bank Certifying Authority for S2S';
const CA_ORG = 'ICICI Bank';
const CA_COUNTRY = 'IN';

// Optional: provide a persistent CA via env vars
// CERTRIX_CA_KEY_PEM, CERTRIX_CA_CERT_PEM
let cachedCa = null;

// ---------- Helpers ----------
function pemCertToDerBuffer(pem) {
  const cert = pki.certificateFromPem(pem);
  const derBytes = forge.asn1
    .toDer(pki.certificateToAsn1(cert))
    .getBytes();
  return Buffer.from(derBytes, 'binary');
}

function sanitizeField(s, maxLen) {
  if (!s) return '';
  s = String(s);
  let out = '';
  for (const ch of s) {
    if (/[0-9A-Za-z]/.test(ch) || ' -_.@()&,/'.includes(ch)) {
      out += ch;
    }
    if (out.length >= maxLen) break;
  }
  return out.trim();
}

function safeCertName(raw, def = 'certificate') {
  if (!raw) return def;
  let s = '';
  for (const ch of String(raw)) {
    if (/[0-9A-Za-z]/.test(ch) || '-_.@()'.includes(ch)) {
      s += ch;
    }
  }
  s = s.trim();
  return s || def;
}

function addYearsExact(date, years) {
  const d = new Date(date.getTime());
  const targetYear = d.getUTCFullYear() + years;
  d.setUTCFullYear(targetYear);
  return d;
}

// Persistent-ish CA
function getOrCreateCA() {
  if (cachedCa) return cachedCa;

  if (process.env.CERTRIX_CA_KEY_PEM && process.env.CERTRIX_CA_CERT_PEM) {
    const caKey = pki.privateKeyFromPem(process.env.CERTRIX_CA_KEY_PEM);
    const caCert = pki.certificateFromPem(process.env.CERTRIX_CA_CERT_PEM);
    cachedCa = { caKey, caCert };
    return cachedCa;
  }

  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString('hex');

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60 * 1000);
  const notAfter = addYearsExact(notBefore, 20);

  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  const attrs = [
    { name: 'commonName', value: CA_COMMON_NAME },
    { name: 'organizationName', value: CA_ORG },
    { name: 'countryName', value: CA_COUNTRY }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  cachedCa = { caKey: keys.privateKey, caCert: cert };
  console.warn(
    '[Certrix] Generated ephemeral CA. Configure CERTRIX_CA_KEY_PEM / CERTRIX_CA_CERT_PEM env vars for persistence.'
  );
  return cachedCa;
}

// Auto-detect CSR PEM vs DER
function loadCsrAuto(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }

  // Try to interpret as UTF-8 text
  const text = buffer.toString('utf8').trim();

  const hasPemHeader =
    /-----BEGIN\s+CERTIFICATE REQUEST-----/i.test(text) ||
    /-----BEGIN\s+NEW CERTIFICATE REQUEST-----/i.test(text) ||
    /-----BEGIN\s+CSR-----/i.test(text);

  // 1) If it *looks* like PEM, parse as PEM ONLY
  if (hasPemHeader) {
    const normalized = text.replace(/\r\n/g, '\n');
    return pki.certificationRequestFromPem(normalized);
  }

  // 2) Otherwise, assume it's raw DER (binary)
  try {
    const derBytes = buffer.toString('binary');
    const asn1 = forge.asn1.fromDer(derBytes);
    return pki.certificationRequestFromAsn1(asn1);
  } catch (e) {
    throw new Error('Invalid CSR (DER decode failed)');
  }
}

// CSR → subject dict (CN, O, OU, C, ST, L)
function csrSubjectDict(csr) {
  const subject = { CN: '', O: '', OU: '', C: '', ST: '', L: '' };
  for (const attr of csr.subject.attributes || []) {
    switch (attr.name) {
      case 'commonName':
        subject.CN = attr.value;
        break;
      case 'organizationName':
        subject.O = attr.value;
        break;
      case 'organizationalUnitName':
        subject.OU = attr.value;
        break;
      case 'countryName':
        subject.C = attr.value;
        break;
      case 'stateOrProvinceName':
        subject.ST = attr.value;
        break;
      case 'localityName':
        subject.L = attr.value;
        break;
      default:
        break;
    }
  }
  return subject;
}

// Sign CSR with CA & apply default KU/EKU/SKI
function signCsrWithDefaults(csr, years) {
  const { caKey, caCert } = getOrCreateCA();
  const cert = pki.createCertificate();

  cert.publicKey = csr.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString('hex');

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60 * 1000);
  const notAfter = addYearsExact(notBefore, years);

  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  cert.setSubject(csr.subject.attributes);
  cert.setIssuer(caCert.subject.attributes);

  const extensions = [];

  const extReq = csr.getAttribute({ name: 'extensionRequest' });
  if (extReq && Array.isArray(extReq.extensions)) {
    extensions.push(...extReq.extensions);
  }

  extensions.push(
    { name: 'subjectKeyIdentifier' },
    {
      name: 'keyUsage',
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: false,
      keyCertSign: false,
      cRLSign: false
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true
    }
  );

  cert.setExtensions(extensions);
  cert.sign(caKey, forge.md.sha256.create());
  return cert;
}

// ---------- High-level ops ----------

// 1. New certificate ZIP
async function generateNewCertificateZip(data) {
  const cn = sanitizeField(data.cn || '', 128);
  if (!cn) {
    return { error: 'CN required' };
  }

  const country = sanitizeField(data.country || '', 2);
  const state = sanitizeField(data.state || '', 64);
  const locality = sanitizeField(data.locality || '', 64);
  const org = sanitizeField(data.org || '', 128);
  const ou = sanitizeField(data.ou || '', 128);

  let years = parseInt(data.years || '1', 10);
  if (isNaN(years)) years = 1;
  years = Math.max(1, Math.min(years, 50));

  let keySize = parseInt(data.key_size || '2048', 10);
  if (![2048, 3072, 4096].includes(keySize)) {
    keySize = 2048;
  }

  const keyPass = data.key_pass || '';
  const pfxPass = data.pfx_pass || '';

  const subjectAttrs = [{ name: 'commonName', value: cn }];
  if (country) subjectAttrs.push({ name: 'countryName', value: country });
  if (state) subjectAttrs.push({ name: 'stateOrProvinceName', value: state });
  if (locality) subjectAttrs.push({ name: 'localityName', value: locality });
  if (org) subjectAttrs.push({ name: 'organizationName', value: org });
  if (ou) subjectAttrs.push({ name: 'organizationalUnitName', value: ou });

  const { caKey, caCert } = getOrCreateCA();

  const eeKeys = pki.rsa.generateKeyPair(keySize);

  const csr = pki.createCertificationRequest();
  csr.publicKey = eeKeys.publicKey;
  csr.setSubject(subjectAttrs);
  csr.sign(eeKeys.privateKey, forge.md.sha256.create());

  const eeCert = signCsrWithDefaults(csr, years);

  let privateKeyPem;
  if (keyPass) {
    privateKeyPem = pki.encryptRsaPrivateKey(eeKeys.privateKey, keyPass, {
      algorithm: 'aes256'
    });
  } else {
    privateKeyPem = pki.privateKeyToPem(eeKeys.privateKey);
  }

  const csrPem = pki.certificationRequestToPem(csr);
  const certPem = pki.certificateToPem(eeCert);
  const caPem = pki.certificateToPem(caCert);

  const certChain = [eeCert, caCert];
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    eeKeys.privateKey,
    certChain,
    pfxPass || '',
    { algorithm: '3des' }
  );
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const p12Buffer = Buffer.from(p12Der, 'binary');

  const zip = new JSZip();
  zip.file(`${cn}.prv`, privateKeyPem);
  zip.file(`${cn}.csr`, csrPem);
  zip.file(`${cn}.cer`, certPem);
  zip.file(`${cn}.pfx`, p12Buffer);
  zip.file('ca_certificate.cer', caPem);

  const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
  const zipFilename = `${cn}_certs.zip`;

  return { buffer: zipBuffer, zipFilename };
}

// 2. Single CSR renew
async function renewFromCsrBytes(csrBytes, years, uploadedName) {
  let csr;
  try {
    csr = loadCsrAuto(csrBytes);
  } catch (e) {
    throw new Error('Invalid CSR: ' + e.message);
  }

  let cnFromCsr = '';
  for (const attr of csr.subject.attributes || []) {
    if (attr.name === 'commonName') {
      cnFromCsr = attr.value;
      break;
    }
  }

  const rawName = cnFromCsr || (uploadedName || 'certificate');
  const clientId = rawName.split('_', 1)[0];
  const fileCn = safeCertName(clientId);

  let y = parseInt(years || '1', 10);
  if (isNaN(y)) y = 1;
  y = Math.max(1, Math.min(y, 50));

  const cert = signCsrWithDefaults(csr, y);
  const pem = pki.certificateToPem(cert);
  const derBuffer = pemCertToDerBuffer(pem);
  
  return {
    filename: `${fileCn}.cer`,
    buffer: derBuffer
  };
}

// 3. CSR preview
function previewCsr(csrBytes, sourceLabel) {
  let csr;
  try {
    csr = loadCsrAuto(csrBytes);
  } catch (e) {
    throw new Error('Invalid CSR: ' + e.message);
  }
  const subject = csrSubjectDict(csr);
  return {
    source: sourceLabel || 'unknown',
    subject
  };
}

// 4. Bulk renew from ZIP
async function renewBulkZip(zipBuffer, years) {
  getOrCreateCA();
  let y = parseInt(years || '1', 10);
  if (isNaN(y)) y = 1;
  y = Math.max(1, Math.min(y, 50));

  const inZip = await JSZip.loadAsync(zipBuffer);
  const outZip = new JSZip();
  let count = 0;

  const entries = Object.values(inZip.files);

  for (const entry of entries) {
    if (entry.dir) continue;
    const name = entry.name;
    const lower = name.toLowerCase();
    if (
      !(
        lower.endsWith('.csr') ||
        lower.endsWith('.pem') ||
        lower.endsWith('.der')
      )
    ) {
      continue;
    }

    const csrBytes = await entry.async('nodebuffer');
    let csr;
    try {
      csr = loadCsrAuto(csrBytes);
    } catch {
      continue;
    }

    let cnFromCsr = '';
    for (const attr of csr.subject.attributes || []) {
      if (attr.name === 'commonName') {
        cnFromCsr = attr.value;
        break;
      }
    }
    const fallback = name.replace(/^.*[\\/]/, '').replace(/\.[^.]+$/, '');
    const rawName = cnFromCsr || fallback;
    const clientId = rawName.split('_', 1)[0];
    const fileCn = safeCertName(clientId);

    const cert = signCsrWithDefaults(csr, y);
    const pem = pki.certificateToPem(cert);
    const derBuffer = pemCertToDerBuffer(pem);
    
    outZip.file(`${fileCn}.cer`, derBuffer);
    count += 1;
  }

  if (count === 0) {
    return { error: 'No valid CSRs found in ZIP' };
  }

  const outBuffer = await outZip.generateAsync({ type: 'nodebuffer' });
  const outName = `renewed_${count}_certs.zip`;
  return { buffer: outBuffer, filename: outName, count };
}

module.exports = {
  generateNewCertificateZip,
  renewFromCsrBytes,
  previewCsr,
  renewBulkZip
};
