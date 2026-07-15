import {
  entityId,
  type EdgeKind,
  type Entity,
  type EntityKind,
  type Relationship,
  type ThreatGraph,
} from "@/lib/network-types";
import { recognizeValue } from "@/lib/recognize";
import { scoreEdge, scoreObservedEdges } from "@/lib/scoring";

export interface IngestResult {
  graph: ThreatGraph;
  format: string;
  feed: string;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function normalizeAsn(raw: unknown): string {
  if (raw === null || raw === undefined || raw === "") return "";
  const s = String(raw).trim();
  if (!s) return "";
  const num = s.replace(/^AS/i, "").trim();
  if (/^\d+$/.test(num)) return `AS${num}`;
  return s;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;

function isIp(value: string): boolean {
  return IPV4.test(value.trim()) || IPV6.test(value.trim());
}

function isHash(value: string): boolean {
  return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value.trim());
}

function hostFromUrl(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    const m = value.match(/^[a-z]+:\/\/([^/:?#]+)/i);
    return m ? m[1] : value;
  }
}

// "6/91" -> 0-100 risk
function detectionRatioToRisk(ratio: string): number {
  const m = String(ratio).match(/(\d+)\s*\/\s*(\d+)/);
  if (!m) return 0;
  const malicious = Number(m[1]);
  const total = Number(m[2]);
  if (!total) return 0;
  return Math.round((malicious / total) * 100);
}

function clampRisk(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

// ---------------------------------------------------------------------------
// Graph builder — accumulates entities + relationships for a single feed
// ---------------------------------------------------------------------------

class GraphBuilder {
  private entities = new Map<string, Entity>();
  private rels = new Map<string, Relationship>();
  constructor(private feed: string) {}

  addEntity(
    kind: EntityKind,
    rawValue: string,
    extra: Partial<Pick<Entity, "riskScore" | "asn" | "asName" | "firstSeen" | "lastSeen">> = {},
  ): string | null {
    const value = (rawValue ?? "").trim();
    if (!value) return null;
    const id = entityId(kind, value);
    const existing = this.entities.get(id);
    if (existing) {
      if (extra.riskScore) existing.riskScore = Math.max(existing.riskScore, clampRisk(extra.riskScore));
      if (extra.asn && !existing.asn) existing.asn = extra.asn;
      if (extra.asName && !existing.asName) existing.asName = extra.asName;
      if (extra.firstSeen && !existing.firstSeen) existing.firstSeen = extra.firstSeen;
      if (extra.lastSeen && !existing.lastSeen) existing.lastSeen = extra.lastSeen;
      return id;
    }
    const rec = recognizeValue(kind, value);
    this.entities.set(id, {
      id,
      kind,
      value,
      feeds: [this.feed],
      riskScore: clampRisk(extra.riskScore ?? 0),
      asn: extra.asn,
      asName: extra.asName,
      firstSeen: extra.firstSeen,
      lastSeen: extra.lastSeen,
      category: rec.category,
      subtype: rec.subtype,
    });
    return id;
  }

  addRel(sourceId: string | null, kind: EdgeKind, targetId: string | null) {
    if (!sourceId || !targetId || sourceId === targetId) return;
    const id = `${sourceId}|${kind}|${targetId}`;
    if (this.rels.has(id)) return;
    this.rels.set(id, { id, source: sourceId, target: targetId, kind, feeds: [this.feed] });
  }

  // Convenience: a domain that resolves to an IP, optionally within an ASN.
  addResolution(domain: string, ip: string, opts: { risk?: number; asn?: string; asName?: string; firstSeen?: string; lastSeen?: string } = {}) {
    const d = domain ? this.addEntity("domain", domain, { riskScore: opts.risk, firstSeen: opts.firstSeen, lastSeen: opts.lastSeen }) : null;
    const i = ip ? this.addEntity("ip", ip, { asn: opts.asn, asName: opts.asName, firstSeen: opts.firstSeen, lastSeen: opts.lastSeen }) : null;
    if (d && i) this.addRel(d, "resolves-to", i);
    if (i && opts.asn) {
      const a = this.addEntity("asn", opts.asn, { asName: opts.asName });
      this.addRel(i, "belongs-to", a);
    }
    return { d, i };
  }

  build(): ThreatGraph {
    return {
      entities: Array.from(this.entities.values()),
      relationships: Array.from(this.rels.values()),
    };
  }

  get size() {
    return this.entities.size;
  }
}

// Map a source feed's relationship label onto our edge vocabulary.
function mapEdgeKind(raw: string): EdgeKind {
  const r = raw.toLowerCase().replace(/_/g, "-");
  if (r.includes("resolve")) return "resolves-to";
  if (r.includes("subdomain") || r.includes("sub-domain")) return "sub-domain-of";
  if (r.includes("sibling")) return "sibling-of";
  if (r.includes("communicat") || r.includes("contact") || r.includes("connect")) return "communicates-with";
  if (r.includes("belong")) return "belongs-to";
  if (r.includes("download") || r.includes("drop")) return "downloaded-from";
  return "related-to";
}

// ---------------------------------------------------------------------------
// Format: STIX 2.x bundle
// ---------------------------------------------------------------------------

function scoKind(type: string): EntityKind | null {
  if (type === "domain-name") return "domain";
  if (type === "ipv4-addr" || type === "ipv6-addr") return "ip";
  if (type === "url") return "url";
  if (type === "file") return "hash";
  if (type === "autonomous-system") return "asn";
  return null;
}

function scoValue(o: any): string {
  if (o.type === "file") {
    const h = o.hashes || {};
    return h["SHA-256"] || h["SHA-1"] || h["MD5"] || h.sha256 || h.sha1 || h.md5 || "";
  }
  if (o.type === "autonomous-system") return normalizeAsn(o.number);
  return o.value || "";
}

function parseStixGraph(bundle: any, feed: string): ThreatGraph {
  const gb = new GraphBuilder(feed);
  const objects: any[] = bundle.objects || [];
  const byId = new Map<string, any>();
  for (const o of objects) if (o?.id) byId.set(o.id, o);

  // Register SCO entities and remember their entity id by SCO id.
  const entIdBySco = new Map<string, string>();
  for (const o of objects) {
    const kind = scoKind(o.type);
    if (!kind) continue;
    const value = scoValue(o);
    if (!value) continue;
    const id = gb.addEntity(kind, value, {
      asName: o.type === "autonomous-system" ? o.name : undefined,
    });
    if (id) entIdBySco.set(o.id, id);
  }

  // Relationships between SCOs.
  for (const o of objects) {
    if (o.type !== "relationship") continue;
    const src = entIdBySco.get(o.source_ref);
    const tgt = entIdBySco.get(o.target_ref);
    if (!src || !tgt) continue;
    gb.addRel(src, mapEdgeKind(o.relationship_type || "related-to"), tgt);
  }

  // Indicator patterns: extract indicators and relate co-occurring ones.
  for (const o of objects) {
    if (o.type !== "indicator" || typeof o.pattern !== "string") continue;
    const score = typeof o.confidence === "number" ? o.confidence : 0;
    const found: string[] = [];
    for (const m of o.pattern.matchAll(/(?:domain-name|hostname)[^']*'([^']+)'/g))
      found.push(gb.addEntity("domain", m[1], { riskScore: score }) || "");
    for (const m of o.pattern.matchAll(/ipv[46]-addr:value\s*=\s*'([^']+)'/g))
      found.push(gb.addEntity("ip", m[1], { riskScore: score }) || "");
    for (const m of o.pattern.matchAll(/url:value\s*=\s*'([^']+)'/g))
      found.push(gb.addEntity("url", m[1], { riskScore: score }) || "");
    for (const m of o.pattern.matchAll(/file:hashes\.[^=]*=\s*'([^']+)'/g))
      found.push(gb.addEntity("hash", m[1], { riskScore: score }) || "");
    const real = found.filter(Boolean);
    // Co-occurring indicators in one pattern are related.
    for (let a = 0; a < real.length; a++)
      for (let b = a + 1; b < real.length; b++) gb.addRel(real[a], "related-to", real[b]);
  }

  return gb.build();
}

// ---------------------------------------------------------------------------
// Format: MISP Event (also produced by VirusTotal Graph "export")
// ---------------------------------------------------------------------------

interface MispObject {
  uuid: string;
  name: string;
  Attribute?: any[];
  ObjectReference?: any[];
}

function parseMispGraph(event: any, feed: string): ThreatGraph {
  const gb = new GraphBuilder(feed);
  const attributes: any[] = event.Attribute || [];
  const objects: MispObject[] = event.Object || [];
  const objById = new Map<string, MispObject>();
  for (const o of objects) if (o.uuid) objById.set(o.uuid, o);

  const attrVal = (o: MispObject | undefined, ...keys: string[]) => {
    if (!o?.Attribute) return "";
    for (const a of o.Attribute) {
      const rel = (a.object_relation || a.type || "").toLowerCase();
      if (keys.includes(rel)) return String(a.value ?? "");
    }
    return "";
  };

  // Detection ratio -> risk, resolved via analysed-with -> report object.
  const riskByObject = new Map<string, number>();
  for (const o of objects) {
    for (const ref of o.ObjectReference || []) {
      if (mapEdgeKind(ref.relationship_type || "") === "related-to" && /analys|report/i.test(ref.relationship_type || "")) {
        const report = objById.get(ref.referenced_uuid);
        const ratio = attrVal(report, "detection-ratio");
        if (ratio) riskByObject.set(o.uuid, detectionRatioToRisk(ratio));
      }
    }
    // Some exports inline the ratio on the object itself.
    const inlineRatio = attrVal(o, "detection-ratio");
    if (inlineRatio) riskByObject.set(o.uuid, detectionRatioToRisk(inlineRatio));
  }

  // Primary entity per object (domain preferred, then ip, url, hash).
  const primaryByObject = new Map<string, string>();
  for (const o of objects) {
    if (o.name === "virustotal-report" || o.name === "virustotal-graph") continue;
    const risk = riskByObject.get(o.uuid) || 0;
    const domain = attrVal(o, "domain", "hostname");
    const ip = attrVal(o, "ip", "ip-dst", "ip-src", "ip-addr");
    const url = attrVal(o, "url");
    const hash = attrVal(o, "sha256", "sha1", "md5", "hash");

    let primary: string | null = null;
    let ipId: string | null = null;
    let hashId: string | null = null;
    if (ip) ipId = gb.addEntity("ip", ip, { riskScore: risk });
    // Always register the file hash WITH the object's detection-ratio risk, even
    // when a domain/ip is the primary node — otherwise a malicious file's score
    // is dropped and its risk renders as "—" in the report.
    if (hash) hashId = gb.addEntity("hash", hash, { riskScore: risk });
    if (domain) primary = gb.addEntity("domain", domain, { riskScore: risk });
    if (!primary && url) primary = gb.addEntity("url", url, { riskScore: risk });
    if (!primary && hashId) primary = hashId;
    if (!primary && ipId) primary = ipId;

    // domain-ip object encodes a resolution.
    if (primary && ipId && primary !== ipId) gb.addRel(primary, "resolves-to", ipId);
    // A file seen alongside infrastructure was delivered from / talks to it.
    if (hashId && primary && hashId !== primary) gb.addRel(hashId, "downloaded-from", primary);
    if (hashId && ipId && hashId !== ipId) gb.addRel(hashId, "communicates-with", ipId);
    if (primary) primaryByObject.set(o.uuid, primary);
  }

  // Typed relationships between objects.
  for (const o of objects) {
    const src = primaryByObject.get(o.uuid);
    if (!src) continue;
    for (const ref of o.ObjectReference || []) {
      const tgt = primaryByObject.get(ref.referenced_uuid);
      if (!tgt) continue;
      gb.addRel(src, mapEdgeKind(ref.relationship_type || "related-to"), tgt);
    }
  }

  // Flat event-level attributes (standalone indicators).
  for (const a of attributes) {
    const type = String(a.type || "").toLowerCase();
    const value = String(a.value ?? "");
    if (!value) continue;
    if (type.includes("ip") || isIp(value)) gb.addEntity("ip", value);
    else if (type.includes("md5") || type.includes("sha") || isHash(value)) gb.addEntity("hash", value);
    else if (type === "url" || type.includes("uri")) gb.addEntity("url", value);
    else if (type === "domain" || type === "hostname") gb.addEntity("domain", value);
  }

  return gb.build();
}

// ---------------------------------------------------------------------------
// Format: OpenIOC 1.1 XML (AlienVault OTX export)
// ---------------------------------------------------------------------------

function openIocKind(search: string): EntityKind | null {
  const s = search.toLowerCase();
  if (s.includes("md5") || s.includes("sha1") || s.includes("sha256") || s.includes("sha-")) return "hash";
  if (s.includes("uri") || s.includes("url")) return "url";
  if (s.includes("ip")) return "ip";
  if (s.includes("dns") || s.includes("host") || s.includes("domain")) return "domain";
  return null;
}

function parseOpenIoc(text: string, feed: string): ThreatGraph {
  const gb = new GraphBuilder(feed);
  // Each IndicatorItem carries a <Context search="..."/> and a <Content>value</Content>.
  const itemRe = /<IndicatorItem\b[\s\S]*?<\/IndicatorItem>/g;
  const searchRe = /<Context\b[^>]*\bsearch="([^"]+)"/i;
  const contentRe = /<Content\b[^>]*>([\s\S]*?)<\/Content>/i;
  for (const block of text.match(itemRe) || []) {
    const search = block.match(searchRe)?.[1];
    const rawContent = block.match(contentRe)?.[1];
    if (!search || rawContent == null) continue;
    const value = rawContent.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
    if (!value) continue;
    let kind = openIocKind(search);
    // Fall back to shape detection when the search field is ambiguous.
    if (!kind) {
      if (isIp(value)) kind = "ip";
      else if (isHash(value)) kind = "hash";
      else if (/^[a-z]+:\/\//i.test(value)) kind = "url";
      else if (/\./.test(value)) kind = "domain";
    }
    if (kind) gb.addEntity(kind, kind === "url" ? value : value.toLowerCase());
  }
  return gb.build();
}

// ---------------------------------------------------------------------------
// Simpler feeds: OTX JSON, VirusTotal v3, passive DNS, generic JSON, CSV
// (These produce flat rows that we convert into resolution edges.)
// ---------------------------------------------------------------------------

function parseOtxPassiveDns(rows: any[], gb: GraphBuilder) {
  for (const r of rows) {
    gb.addResolution(r.hostname || r.domain || "", r.address || r.ip || "", {
      asn: normalizeAsn(r.asn),
      asName: r.asn_name || r.as_name || r.name || "",
      firstSeen: r.first || r.first_seen || "",
      lastSeen: r.last || r.last_seen || "",
    });
  }
}

function parseOtxPulse(indicators: any[], gb: GraphBuilder) {
  for (const ind of indicators) {
    const value = ind.indicator || ind.value;
    if (!value) continue;
    const type = String(ind.type || "").toLowerCase();
    if (type.includes("ip") || isIp(value)) gb.addEntity("ip", value, { asn: normalizeAsn(ind.asn) });
    else if (type.includes("hash") || type.includes("md5") || type.includes("sha") || isHash(value)) gb.addEntity("hash", value);
    else if (type.includes("url")) gb.addEntity("url", value);
    else if (type.includes("domain") || type.includes("hostname")) gb.addEntity("domain", value);
  }
}

// Map a VirusTotal v3 object ({ type, id, attributes }) to a graph entity.
// Returns the entity id (already added to the builder) or null.
function vtAddEntity(item: any, gb: GraphBuilder): string | null {
  if (!item) return null;
  const attrs = item.attributes || {};
  const risk = clampRisk(attrs.last_analysis_stats?.malicious ?? 0);

  switch (item.type) {
    case "ip_address":
      return gb.addEntity("ip", item.id || attrs.ip_address || "", {
        riskScore: risk,
        asn: normalizeAsn(attrs.asn),
        asName: attrs.as_owner || "",
      });
    case "domain":
      return gb.addEntity("domain", item.id || "", { riskScore: risk });
    case "file":
      return gb.addEntity("hash", attrs.sha256 || attrs.sha1 || attrs.md5 || item.id || "", { riskScore: risk });
    case "url":
      return gb.addEntity("url", attrs.url || item.id || "", { riskScore: risk });
    default:
      // Fall back to inferring the kind from the id value.
      if (item.id && isIp(item.id)) return gb.addEntity("ip", item.id, { riskScore: risk });
      if (item.id && isHash(item.id)) return gb.addEntity("hash", item.id, { riskScore: risk });
      if (item.id) return gb.addEntity("domain", item.id, { riskScore: risk });
      return null;
  }
}

// VT v3 relationship name -> how to connect the related item to the parent.
// dir "from-parent": parent -> related; "to-parent": related -> parent.
const VT_REL_MAP: Record<string, { kind: EdgeKind; dir: "from-parent" | "to-parent" }> = {
  resolutions: { kind: "resolves-to", dir: "from-parent" },
  subdomains: { kind: "sub-domain-of", dir: "to-parent" },
  siblings: { kind: "sibling-of", dir: "from-parent" },
  communicating_files: { kind: "communicates-with", dir: "to-parent" },
  downloaded_files: { kind: "downloaded-from", dir: "to-parent" },
  referrer_files: { kind: "related-to", dir: "to-parent" },
  contacted_domains: { kind: "communicates-with", dir: "from-parent" },
  contacted_ips: { kind: "communicates-with", dir: "from-parent" },
  contacted_urls: { kind: "related-to", dir: "from-parent" },
  urls: { kind: "related-to", dir: "from-parent" },
};

function parseVirusTotalV3(body: any, gb: GraphBuilder) {
  const items = Array.isArray(body.data) ? body.data : [body.data];
  for (const item of items) {
    if (!item) continue;
    const attrs = item.attributes || {};
    const risk = clampRisk(attrs.last_analysis_stats?.malicious ?? 0);

    // Legacy resolution object (host_name + ip_address on the same record).
    if (attrs.host_name || attrs.ip_address) {
      gb.addResolution(attrs.host_name || "", attrs.ip_address || "", {
        risk,
        asn: normalizeAsn(attrs.asn),
        asName: attrs.as_owner || "",
        firstSeen: attrs.date ? String(attrs.date) : "",
      });
      continue;
    }

    // The primary object (domain / ip / file / url).
    const parentId = vtAddEntity(item, gb);
    const parentKind = item.type === "ip_address" ? "ip" : item.type;

    // DNS records embedded on a domain object (A/AAAA/CNAME/MX/NS).
    if (parentKind === "domain" && Array.isArray(attrs.last_dns_records)) {
      for (const rec of attrs.last_dns_records) {
        const val = String(rec?.value || "");
        if (!val) continue;
        const t = String(rec?.type || "").toUpperCase();
        if (t === "A" || t === "AAAA") {
          gb.addRel(parentId, "resolves-to", gb.addEntity("ip", val));
        } else if (t === "CNAME" || t === "MX" || t === "NS") {
          gb.addRel(parentId, "related-to", gb.addEntity("domain", val.replace(/\.$/, "")));
        }
      }
    }

    // The relationships block — the core of a VT v3 export.
    const rels = item.relationships || {};
    for (const [name, block] of Object.entries<any>(rels)) {
      const spec = VT_REL_MAP[name];
      const data = (block as any)?.data;
      if (!spec || !data) continue;
      const relItems = Array.isArray(data) ? data : [data];
      for (const rel of relItems) {
        // "resolution" pseudo-objects carry both endpoints in attributes.
        if (rel?.type === "resolution") {
          const ra = rel.attributes || {};
          gb.addResolution(ra.host_name || "", ra.ip_address || "", {
            asn: normalizeAsn(ra.asn),
            asName: ra.as_owner || "",
          });
          continue;
        }
        const relId = vtAddEntity(rel, gb);
        if (!relId || !parentId) continue;
        // Orient resolves-to consistently as domain -> ip when applicable.
        if (name === "resolutions") {
          const dom = parentKind === "domain" ? parentId : relId;
          const ip = parentKind === "domain" ? relId : parentId;
          gb.addRel(dom, "resolves-to", ip);
        } else if (spec.dir === "from-parent") {
          gb.addRel(parentId, spec.kind, relId);
        } else {
          gb.addRel(relId, spec.kind, parentId);
        }
      }
    }
  }
}

const DOMAIN_KEYS = ["query", "domain", "hostname", "host", "fqdn", "name"];
const IP_KEYS = ["answer", "ip", "ip_address", "address", "resolved_ip", "a"];
const ASN_KEYS = ["answer_asn", "asn", "as", "as_number", "query_asn"];
const ASNAME_KEYS = ["answer_as_name", "as_name", "as_owner", "asn_name", "org", "organization"];
const HASH_KEYS = ["hash", "md5", "sha1", "sha256", "sha-256"];
const URL_KEYS = ["url", "uri"];

function pick(row: any, keys: string[]): any {
  for (const k of Object.keys(row)) if (keys.includes(k.toLowerCase())) return row[k];
  return undefined;
}

function looksNative(row: any): boolean {
  return (
    row &&
    typeof row === "object" &&
    ("query" in row || "answer" in row) &&
    ("answer_asn" in row || "answer_as_name" in row || "query_asn" in row)
  );
}

function parseGenericRows(rows: any[], gb: GraphBuilder) {
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const domain = pick(row, DOMAIN_KEYS);
    const ip = pick(row, IP_KEYS);
    const hash = pick(row, HASH_KEYS);
    const url = pick(row, URL_KEYS);
    const asn = normalizeAsn(pick(row, ASN_KEYS));
    const asName = pick(row, ASNAME_KEYS) ? String(pick(row, ASNAME_KEYS)) : "";
    const risk = clampRisk(Number(pick(row, ["answer_risk_score", "query_risk_score", "risk", "score"])) || 0);
    if (domain || ip) {
      gb.addResolution(domain ? String(domain) : "", ip ? String(ip) : "", { asn, asName, risk });
    }
    if (hash) gb.addEntity("hash", String(hash));
    if (url) gb.addEntity("url", String(url));
  }
}

function parseCsv(text: string, gb: GraphBuilder) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return;
  const delimiter = lines[0].includes("\t") ? "\t" : ",";
  const split = (line: string) => line.split(delimiter).map((c) => c.trim().replace(/^"|"$/g, ""));
  const headers = split(lines[0]).map((h) => h.toLowerCase());
  const rows: any[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = split(lines[i]);
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => (row[h] = cells[idx] ?? ""));
    rows.push(row);
  }
  parseGenericRows(rows, gb);
}

// ---------------------------------------------------------------------------
// Master entry point
// ---------------------------------------------------------------------------

export function ingest(text: string, filename = ""): IngestResult {
  // Always derive a real, non-empty feed label. A missing/blank name used to
  // fall through to `undefined`, which surfaced as the "undefined (66)" feed
  // in reports; guard it here so the label is always the filename or a stable
  // fallback.
  const feed = (typeof filename === "string" && filename.trim()) || "upload";
  const trimmed = text.trim();

  // XML? -> OpenIOC (AlienVault OTX)
  if (/^<\?xml|<(?:ioc|OpenIOC)\b/i.test(trimmed) || (trimmed.startsWith("<") && /<IndicatorItem\b/.test(trimmed))) {
    const graph = parseOpenIoc(trimmed, feed);
    return { graph, format: "OpenIOC (AlienVault OTX)", feed };
  }

  // JSON (or JSON embedded in extracted text)
  let json: any = null;
  try {
    json = JSON.parse(trimmed);
  } catch {
    const arrayMatch = trimmed.match(/\[[\s\S]*\]/);
    if (arrayMatch) {
      try {
        json = JSON.parse(arrayMatch[0].replace(/-\n/g, "").replace(/\n/g, " "));
      } catch {
        /* fall through */
      }
    }
  }

  if (json !== null && typeof json === "object") {
    // MISP Event / VirusTotal Graph export
    const mispEvent =
      json.Event && typeof json.Event === "object"
        ? json.Event
        : Array.isArray(json.Attribute) || Array.isArray(json.Object)
        ? json
        : null;
    if (mispEvent && (Array.isArray(mispEvent.Attribute) || Array.isArray(mispEvent.Object))) {
      const isVt = (mispEvent.Object || []).some(
        (o: any) => o?.name === "virustotal-graph" || o?.name === "virustotal-report",
      );
      return {
        graph: parseMispGraph(mispEvent, feed),
        format: isVt ? "VirusTotal Graph (MISP)" : "MISP Event",
        feed,
      };
    }

    // STIX 2.x bundle
    if (json.type === "bundle" && Array.isArray(json.objects)) {
      return { graph: parseStixGraph(json, feed), format: "STIX 2.x", feed };
    }

    const gb = new GraphBuilder(feed);

    // OTX passive DNS
    if (Array.isArray(json.passive_dns)) {
      parseOtxPassiveDns(json.passive_dns, gb);
      return { graph: gb.build(), format: "AlienVault OTX (passive DNS)", feed };
    }
    // OTX pulse
    const pulseIndicators =
      (json.pulse_info?.pulses?.[0]?.indicators as any[]) ||
      (Array.isArray(json.indicators) && json.indicators.some((i: any) => i && (i.indicator || i.type))
        ? json.indicators
        : null);
    if (pulseIndicators) {
      parseOtxPulse(pulseIndicators, gb);
      return { graph: gb.build(), format: "AlienVault OTX (pulse)", feed };
    }
    // VirusTotal v3
    if (json.data && (json.meta || (Array.isArray(json.data) ? json.data[0]?.attributes : json.data.attributes))) {
      parseVirusTotalV3(json, gb);
      return { graph: gb.build(), format: "VirusTotal", feed };
    }

    // Array-ish payloads
    let rows: any[] | null = null;
    if (Array.isArray(json)) rows = json;
    else if (Array.isArray(json.records)) rows = json.records;
    else if (Array.isArray(json.data)) rows = json.data;
    else if (Array.isArray(json.results)) rows = json.results;
    if (rows) {
      parseGenericRows(rows, gb);
      const native = gb.size > 0 && rows.some(looksNative);
      // Supplement with a deep scan so indicators in unrecognized fields
      // (hashes, URLs, nested objects) are still captured. GraphBuilder
      // de-dupes, so this only adds what parseGenericRows missed.
      deepScanJson(json, gb);
      if (gb.size) {
        return { graph: gb.build(), format: native ? "Passive DNS" : "Generic JSON", feed };
      }
    }

    // Unrecognized JSON shape (e.g. an unusual VirusTotal export): recursively
    // scan every field for indicators and infer edges from co-occurrence.
    deepScanJson(json, gb);
    if (gb.size) {
      return { graph: gb.build(), format: "JSON (deep-scanned)", feed };
    }
  }

  // JSONL
  const jsonlLines = trimmed.split("\n").filter((l) => l.trim().startsWith("{"));
  if (jsonlLines.length) {
    const rows: any[] = [];
    for (const line of jsonlLines) {
      try {
        rows.push(JSON.parse(line.replace(/,\s*$/, "")));
      } catch {
        /* skip */
      }
    }
    if (rows.length) {
      const gb = new GraphBuilder(feed);
      parseGenericRows(rows, gb);
      if (!gb.size) deepScanJson(rows, gb);
      if (gb.size) return { graph: gb.build(), format: "Generic JSONL", feed };
    }
  }

  // CSV / TSV
  if (/,|\t/.test(trimmed) && trimmed.includes("\n")) {
    const gb = new GraphBuilder(feed);
    parseCsv(trimmed, gb);
    if (gb.size) return { graph: gb.build(), format: "CSV", feed };
  }

  // Last resort: scan unstructured text (e.g. extracted PDF reports) for IOCs.
  const freeText = parseFreeText(trimmed, feed);
  if (freeText.entities.length) {
    return { graph: freeText, format: "Text report (extracted IOCs)", feed };
  }

  return { graph: { entities: [], relationships: [] }, format: "unknown", feed };
}

// ---------------------------------------------------------------------------
// Free-text IOC extractor — for PDF reports and other unstructured text.
// Handles defanged indicators (hxxp, evil[.]com, 1[.]2[.]3[.]4, foo(dot)bar).
// ---------------------------------------------------------------------------

// A conservative TLD allow-list keeps prose words from being read as domains.
const COMMON_TLDS = new Set([
  "com", "net", "org", "info", "biz", "io", "co", "gov", "edu", "mil", "int",
  "ru", "cn", "us", "uk", "de", "fr", "nl", "jp", "kr", "br", "in", "it", "es",
  "pl", "ca", "au", "se", "no", "fi", "dk", "ch", "at", "be", "cz", "ua", "tr",
  "ir", "tw", "hk", "sg", "za", "mx", "eu", "top", "xyz", "online", "site",
  "club", "shop", "app", "dev", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "su",
  "me", "tv", "cloud", "live", "icu", "vip", "work", "link", "buzz", "monster",
]);

function refang(text: string): string {
  return text
    .replace(/h(?:xx|tt)p(s?)(?::|\[:\]|\[colon\])?\/\//gi, "http$1://")
    .replace(/\[\s*(?:\.|dot)\s*\]/gi, ".")
    .replace(/\(\s*(?:\.|dot)\s*\)/gi, ".")
    .replace(/\s(?:\.|dot)\s/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*@\s*\]|\(\s*at\s*\)|\[\s*at\s*\]/gi, "@")
    .replace(/[（）]/g, "");
}

const RE_URL = /\bhttps?:\/\/[^\s"'<>()]+/gi;
const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const RE_HASH = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const RE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

function parseFreeText(text: string, feed: string): ThreatGraph {
  const clean = refang(text);
  const gb = new GraphBuilder(feed);
  const seen = new Set<string>();

  const add = (kind: EntityKind, value: string) => {
    const key = `${kind}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    gb.addEntity(kind, value);
  };

  // URLs first, and register their host as a domain/ip too.
  for (const m of clean.match(RE_URL) || []) {
    const url = m.replace(/[.,;:)\]]+$/, "");
    add("url", url);
    const host = hostFromUrl(url);
    if (host) add(isIp(host) ? "ip" : "domain", host);
  }
  // File hashes (before IPs so hex strings aren't mis-scanned).
  for (const m of clean.match(RE_HASH) || []) add("hash", m.toLowerCase());
  // IPv4 addresses.
  for (const m of clean.match(RE_IPV4) || []) add("ip", m);
  // Bare domains, filtered by a known TLD to avoid false positives.
  for (const m of clean.match(RE_DOMAIN) || []) {
    const domain = m.toLowerCase().replace(/\.$/, "");
    const tld = domain.split(".").pop() || "";
    if (!COMMON_TLDS.has(tld)) continue;
    if (isIp(domain)) continue;
    add("domain", domain);
  }

  return gb.build();
}

// ---------------------------------------------------------------------------
// Deep JSON scan — fallback for arbitrary / unrecognized JSON structures
// (e.g. an unusual VirusTotal export). Walks the whole tree, extracts
// indicators from every string field, and links indicators that co-occur
// inside the same object as relationships so edges are still mapped.
// ---------------------------------------------------------------------------

interface ScanHit {
  kind: EntityKind;
  value: string;
}

// Pull indicators out of a single string value.
function iocsFromString(raw: string): ScanHit[] {
  const hits: ScanHit[] = [];
  const s = refang(String(raw)).trim();
  if (!s || s.length > 2048) return hits;

  // Whole-string exact matches — the common case for structured fields.
  if (isIp(s)) return [{ kind: "ip", value: s }];
  if (isHash(s)) return [{ kind: "hash", value: s.toLowerCase() }];
  if (/^https?:\/\//i.test(s)) {
    hits.push({ kind: "url", value: s });
    const host = hostFromUrl(s);
    if (host) hits.push({ kind: isIp(host) ? "ip" : "domain", value: host });
    return hits;
  }
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(s)) {
    const tld = s.toLowerCase().split(".").pop() || "";
    if (COMMON_TLDS.has(tld)) return [{ kind: "domain", value: s.toLowerCase() }];
  }

  // Otherwise scan for indicators embedded in free-text fields.
  for (const m of s.match(RE_URL) || []) {
    const url = m.replace(/[.,;:)\]]+$/, "");
    hits.push({ kind: "url", value: url });
    const host = hostFromUrl(url);
    if (host) hits.push({ kind: isIp(host) ? "ip" : "domain", value: host });
  }
  for (const m of s.match(RE_HASH) || []) hits.push({ kind: "hash", value: m.toLowerCase() });
  for (const m of s.match(RE_IPV4) || []) hits.push({ kind: "ip", value: m });
  for (const m of s.match(RE_DOMAIN) || []) {
    const d = m.toLowerCase().replace(/\.$/, "");
    if (isIp(d)) continue;
    const tld = d.split(".").pop() || "";
    if (COMMON_TLDS.has(tld)) hits.push({ kind: "domain", value: d });
  }
  return hits;
}

// Register a set of co-occurring indicators and link them with inferred edges.
function linkCoOccurring(hits: ScanHit[], gb: GraphBuilder) {
  if (hits.length < 1) return;
  const uniq = new Map<string, ScanHit>();
  for (const h of hits) uniq.set(`${h.kind}:${h.value.toLowerCase()}`, h);
  const list = [...uniq.values()];
  for (const h of list) gb.addEntity(h.kind, h.value);

  const domains = list.filter((h) => h.kind === "domain");
  const ips = list.filter((h) => h.kind === "ip");
  const urls = list.filter((h) => h.kind === "url");
  const hashes = list.filter((h) => h.kind === "hash");

  // domain + ip in the same record => resolves-to (guard against blow-up).
  if (domains.length && ips.length && domains.length * ips.length <= 16) {
    for (const d of domains)
      for (const i of ips)
        gb.addRel(entityId("domain", d.value), "resolves-to", entityId("ip", i.value));
  }
  // url => its host.
  for (const u of urls) {
    const host = hostFromUrl(u.value);
    if (!host) continue;
    gb.addRel(entityId("url", u.value), "related-to", entityId(isIp(host) ? "ip" : "domain", host));
  }
  // hash co-occurring with infra => downloaded-from.
  if (hashes.length && domains.length + ips.length <= 8) {
    for (const h of hashes) {
      for (const d of domains) gb.addRel(entityId("hash", h.value), "downloaded-from", entityId("domain", d.value));
      for (const i of ips) gb.addRel(entityId("hash", h.value), "downloaded-from", entityId("ip", i.value));
    }
  }
}

function deepScanJson(root: any, gb: GraphBuilder, depth = 0) {
  if (root === null || root === undefined || depth > 8) return;

  if (Array.isArray(root)) {
    for (const item of root) deepScanJson(item, gb, depth + 1);
    return;
  }
  if (typeof root === "object") {
    // Indicators found directly on this object's own primitive fields co-occur.
    const local: ScanHit[] = [];
    for (const key of Object.keys(root)) {
      const v = (root as any)[key];
      if (typeof v === "string") local.push(...iocsFromString(v));
    }
    linkCoOccurring(local, gb);
    for (const key of Object.keys(root)) {
      const v = (root as any)[key];
      if (v && typeof v === "object") deepScanJson(v, gb, depth + 1);
    }
    return;
  }
  if (typeof root === "string") linkCoOccurring(iocsFromString(root), gb);
}

// ---------------------------------------------------------------------------
// Merge multiple feed graphs into one, computing cross-feed matches.
// ---------------------------------------------------------------------------

export function mergeGraphs(graphs: ThreatGraph[]): ThreatGraph {
  const entities = new Map<string, Entity>();
  const rels = new Map<string, Relationship>();

  for (const g of graphs) {
    for (const e of g.entities) {
      const existing = entities.get(e.id);
      if (!existing) {
        entities.set(e.id, { ...e, feeds: [...e.feeds] });
        continue;
      }
      existing.riskScore = Math.max(existing.riskScore, e.riskScore);
      existing.asn = existing.asn || e.asn;
      existing.asName = existing.asName || e.asName;
      existing.firstSeen = existing.firstSeen || e.firstSeen;
      existing.lastSeen = existing.lastSeen || e.lastSeen;
      for (const f of e.feeds) if (!existing.feeds.includes(f)) existing.feeds.push(f);
    }
    for (const r of g.relationships) {
      const existing = rels.get(r.id);
      if (!existing) {
        rels.set(r.id, { ...r, feeds: [...r.feeds] });
        continue;
      }
      for (const f of r.feeds) if (!existing.feeds.includes(f)) existing.feeds.push(f);
    }
  }

  for (const e of entities.values()) e.matched = e.feeds.length > 1;
  for (const r of rels.values()) r.matched = r.feeds.length > 1;

  return { entities: Array.from(entities.values()), relationships: Array.from(rels.values()) };
}

// ---------------------------------------------------------------------------
// Case seed-anchors — indicators the investigation is anchored to. Nodes that
// match are flagged so the graph, clusters, and scoring can surface them.
// (User-asserted evidence, not adjudicated fact — see plan/case context.)
// ---------------------------------------------------------------------------
const ANCHOR_IPS = new Set(["35.199.191.174", "98.64.189.28", "103.224.212.217"]);
const ANCHOR_DOMAINS = ["agp.com", "elo.agp.com", "corp.agp.com", "catchintelligence.com"];

export function markAnchors(entities: Entity[]): void {
  for (const e of entities) {
    const v = e.value.toLowerCase();
    if (e.kind === "ip" && ANCHOR_IPS.has(v)) e.isAnchor = true;
    else if (
      (e.kind === "domain" || e.kind === "url") &&
      ANCHOR_DOMAINS.some((d) => v === d || v.endsWith(`.${d}`) || v.includes(`//${d}`) || v.includes(`.${d}/`))
    )
      e.isAnchor = true;
  }
}

// ---------------------------------------------------------------------------
// Cross-dataset correlation — EARN `SHARES_*` edges. Two distinct nodes that
// both connect to the same hub artifact (IP, cert, hash, device, user, ASN)
// share that infrastructure. Each new edge is scored + explained.
// ---------------------------------------------------------------------------

// Hub categories worth correlating over. A domain hub is intentionally excluded
// (many things resolve through one domain without being related).
function shareKindForHub(hub: Entity): EdgeKind | null {
  if (hub.subtype === "asn") return "shares-asn";
  if (hub.subtype === "cidr") return "shares-infrastructure";
  switch (hub.category) {
    case "infrastructure":
      return "shares-ip";
    case "certificate":
      return "shares-cert";
    case "malware":
      return "shares-hash";
    case "device":
      return "shares-device";
    case "user":
      return "shares-user";
    default:
      return null;
  }
}

const MAX_HUB_FANOUT = 24; // skip pairwise expansion on very dense hubs
const MAX_CORRELATION_EDGES = 4000;

function buildCorrelationEdges(graph: ThreatGraph, byId: Map<string, Entity>): Relationship[] {
  // Adjacency: hub id -> set of endpoint ids directly linked to it.
  const adj = new Map<string, Set<string>>();
  const link = (a: string, b: string) => {
    let s = adj.get(a);
    if (!s) adj.set(a, (s = new Set()));
    s.add(b);
  };
  for (const r of graph.relationships) {
    link(r.source, r.target);
    link(r.target, r.source);
  }

  const out = new Map<string, Relationship>();
  for (const hub of graph.entities) {
    if (out.size >= MAX_CORRELATION_EDGES) break;
    const kind = shareKindForHub(hub);
    if (!kind) continue;
    const neighbors = [...(adj.get(hub.id) ?? [])]
      .map((id) => byId.get(id))
      .filter((e): e is Entity => !!e);
    if (neighbors.length < 2 || neighbors.length > MAX_HUB_FANOUT) continue;

    for (let i = 0; i < neighbors.length; i++) {
      for (let j = i + 1; j < neighbors.length; j++) {
        const a = neighbors[i];
        const b = neighbors[j];
        // order endpoints for a stable, symmetric edge id
        const [s, t] = a.id < b.id ? [a, b] : [b, a];
        const id = `${s.id}|${kind}|${t.id}`;
        if (out.has(id)) continue;
        const feeds = [...new Set([...s.feeds, ...t.feeds, ...hub.feeds])];
        const anchor = !!(s.isAnchor || t.isAnchor || hub.isAnchor);
        const { confidence, explanation } = scoreEdge({
          kind,
          feeds,
          source: s,
          target: t,
          sharedValue: hub.value,
          anchor,
        });
        out.set(id, {
          id,
          source: s.id,
          target: t.id,
          kind,
          feeds,
          matched: feeds.length > 1,
          confidence,
          explanation,
        });
        if (out.size >= MAX_CORRELATION_EDGES) break;
      }
      if (out.size >= MAX_CORRELATION_EDGES) break;
    }
  }
  return [...out.values()];
}

// Final enrichment pass over the merged graph: mark anchors, correlate shared
// infrastructure into scored edges, then score every remaining observed edge.
export function enrichGraph(graph: ThreatGraph): ThreatGraph {
  markAnchors(graph.entities);
  const byId = new Map(graph.entities.map((e) => [e.id, e]));

  const relMap = new Map(graph.relationships.map((r) => [r.id, r]));
  for (const r of buildCorrelationEdges(graph, byId)) {
    if (!relMap.has(r.id)) relMap.set(r.id, r);
  }
  const relationships = [...relMap.values()];

  scoreObservedEdges(relationships, byId);
  return { entities: graph.entities, relationships };
}
