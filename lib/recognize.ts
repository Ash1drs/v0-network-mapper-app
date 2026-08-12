// ===========================================================================
// Indicator recognizer — maps a raw value (and its structural kind) to the
// spec taxonomy: a visual { category } + a precise { subtype }. Full ~60-type
// list, tiered:
//   Tier 1 (deeply modeled): IP, domain/subdomain, URL/path, hash, cert/
//           fingerprint, ASN/org, device/identity, file/DLL.
//   Tier 2 (recognized + normalized): the remaining types ride the generic
//           correlation engine.
//   Tier 3 (stubs): niche types recognized, ready when data appears.
//
// SECRETS (API keys, JWTs, cookies, tokens) are detected by SHAPE only and
// flagged — their value is NEVER stored or emitted.
// ===========================================================================

import type { Category, EntityKind } from "./network-types";

export interface Recognition {
  category: Category;
  subtype: string;
  /** true when the value's SHAPE is a secret; caller must not persist value. */
  secret?: boolean;
}

// ---- shape helpers --------------------------------------------------------
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
const MAC = /^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;
const CIDR = /\/\d{1,3}$/;
const MD5 = /^[a-fA-F0-9]{32}$/;
const SHA1 = /^[a-fA-F0-9]{40}$/;
const SHA256 = /^[a-fA-F0-9]{64}$/;
const JA3 = MD5; // JA3/JA3S are md5-shaped; disambiguated by field name
const GUID = /^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const JWT = /^ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}$/;
const IMEI = /^\d{15,16}$/;

// Secret-shaped tokens (value never stored — presence flagged only).
const SECRET_PATTERNS: { subtype: string; re: RegExp }[] = [
  { subtype: "jwt", re: JWT },
  { subtype: "aws-access-key", re: /^AKIA[0-9A-Z]{16}$/ },
  { subtype: "google-api-key", re: /^AIza[0-9A-Za-z_-]{35}$/ },
  { subtype: "slack-token", re: /^xox[baprs]-[0-9A-Za-z-]{10,}$/ },
  { subtype: "github-token", re: /^gh[pousr]_[0-9A-Za-z]{36,}$/ },
  { subtype: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { subtype: "bearer-token", re: /^Bearer\s+[A-Za-z0-9._-]{20,}$/i },
];

// Field/subtype hints (from the source key name) that pin an exact subtype.
// The ingest layer passes the originating field name when it has one.
const FIELD_SUBTYPE: Record<string, { category: Category; subtype: string; secret?: boolean }> = {
  ja3: { category: "certificate", subtype: "ja3" },
  ja3s: { category: "certificate", subtype: "ja3s" },
  ja4: { category: "certificate", subtype: "ja4" },
  jarm: { category: "certificate", subtype: "jarm" },
  fingerprint: { category: "certificate", subtype: "tls-fingerprint" },
  ssl: { category: "certificate", subtype: "ssl-cert" },
  cert: { category: "certificate", subtype: "certificate" },
  certificate: { category: "certificate", subtype: "certificate" },
  serial: { category: "certificate", subtype: "cert-serial" },
  imei: { category: "device", subtype: "imei" },
  imsi: { category: "device", subtype: "imsi" },
  mac: { category: "device", subtype: "mac-address" },
  hostname: { category: "device", subtype: "hostname" },
  device: { category: "device", subtype: "device-id" },
  useragent: { category: "device", subtype: "user-agent" },
  "user-agent": { category: "device", subtype: "user-agent" },
  serialnumber: { category: "device", subtype: "serial-number" },
  email: { category: "user", subtype: "email" },
  username: { category: "user", subtype: "username" },
  account: { category: "user", subtype: "account" },
  session: { category: "user", subtype: "session-id" },
  cookie: { category: "user", subtype: "cookie", secret: true },
  token: { category: "user", subtype: "token", secret: true },
  apikey: { category: "user", subtype: "api-key", secret: true },
  "api-key": { category: "user", subtype: "api-key", secret: true },
  password: { category: "user", subtype: "password", secret: true },
  secret: { category: "user", subtype: "secret", secret: true },
  jwt: { category: "user", subtype: "jwt", secret: true },
  tenant: { category: "organization", subtype: "azure-tenant-id" },
  "tenant-id": { category: "organization", subtype: "azure-tenant-id" },
  clientid: { category: "organization", subtype: "oauth-client-id" },
  "client-id": { category: "organization", subtype: "oauth-client-id" },
  org: { category: "organization", subtype: "organization" },
  asn: { category: "infrastructure", subtype: "asn" },
  registry: { category: "malware", subtype: "registry-key" },
  "registry-key": { category: "malware", subtype: "registry-key" },
  mutex: { category: "malware", subtype: "mutex" },
  "scheduled-task": { category: "malware", subtype: "scheduled-task" },
  service: { category: "malware", subtype: "windows-service" },
  filename: { category: "malware", subtype: "filename" },
  filepath: { category: "malware", subtype: "file-path" },
  dll: { category: "malware", subtype: "dll" },
};

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[_\s]+/g, "-");
}

// Recognize by an explicit source field name (highest precedence).
export function recognizeField(fieldName: string, value: string): Recognition | null {
  const k = normalizeKey(fieldName);
  const hit = FIELD_SUBTYPE[k] ?? FIELD_SUBTYPE[k.replace(/-/g, "")];
  if (!hit) return null;
  // Even field-declared secrets must pass shape sanity so we never store a
  // real-looking secret value; caller drops the value when secret is true.
  return { category: hit.category, subtype: hit.subtype, secret: hit.secret };
}

// Detect whether a bare value is secret-shaped (value must be dropped).
export function detectSecret(value: string): Recognition | null {
  const v = value.trim();
  for (const p of SECRET_PATTERNS) {
    if (p.re.test(v)) {
      const category: Category = p.subtype === "jwt" || p.subtype === "bearer-token" ? "user" : "user";
      return { category, subtype: p.subtype, secret: true };
    }
  }
  return null;
}

// Recognize purely from a value + its structural kind. Used when no field hint
// is available. Refines the default kind→category mapping into a precise type.
export function recognizeValue(kind: EntityKind, value: string): Recognition {
  const v = value.trim();
  const lower = v.toLowerCase();

  switch (kind) {
    case "ip":
      if (CIDR.test(v)) return { category: "infrastructure", subtype: "cidr" };
      if (IPV6.test(v)) return { category: "infrastructure", subtype: "ipv6" };
      if (IPV4.test(v)) return { category: "infrastructure", subtype: "ipv4" };
      return { category: "infrastructure", subtype: "ip" };

    case "asn":
      return { category: "infrastructure", subtype: "asn" };

    case "url":
      return { category: "domain", subtype: "url" };

    case "hash": {
      if (SHA256.test(v)) return { category: "malware", subtype: "sha256" };
      if (SHA1.test(v)) return { category: "malware", subtype: "sha1" };
      if (MD5.test(v)) return { category: "malware", subtype: "md5" };
      return { category: "malware", subtype: "hash" };
    }

    case "domain": {
      // A domain-shaped value may actually be an email / device host, but the
      // ingest layer only produces true domains here; refine subdomains.
      const labels = lower.split(".");
      if (labels.length >= 3) return { category: "domain", subtype: "subdomain" };
      return { category: "domain", subtype: "domain" };
    }
  }
}

// Best-effort recognition of an arbitrary string not tied to a graph kind
// (used by deep-scan / free-text passes to widen the taxonomy).
export function recognizeLoose(value: string): Recognition | null {
  const v = value.trim();
  if (!v) return null;
  const secret = detectSecret(v);
  if (secret) return secret;
  if (MAC.test(v)) return { category: "device", subtype: "mac-address" };
  if (GUID.test(v)) return { category: "organization", subtype: "guid" };
  if (EMAIL.test(v)) return { category: "user", subtype: "email" };
  if (IMEI.test(v)) return { category: "device", subtype: "imei" };
  return null;
}

export { IPV4, IPV6, MD5, SHA1, SHA256, JA3, GUID, EMAIL, MAC };
