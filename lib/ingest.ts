import type { DnsRecord } from "@/lib/network-types";

export interface IngestResult {
  records: DnsRecord[];
  format: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeAsn(raw: unknown): string {
  if (raw === null || raw === undefined || raw === "") return "";
  const s = String(raw).trim();
  if (!s) return "";
  // Already prefixed (AS15169) or bare number (15169) -> normalize to AS#####
  const num = s.replace(/^AS/i, "").trim();
  if (/^\d+$/.test(num)) return `AS${num}`;
  return s;
}

function makeRecord(partial: Partial<DnsRecord>): DnsRecord {
  return {
    query: partial.query ?? "",
    query_risk_score: partial.query_risk_score ?? 0,
    query_risk_score_decider: partial.query_risk_score_decider ?? "",
    query_asn: partial.query_asn ?? "",
    query_as_name: partial.query_as_name ?? "",
    answer: partial.answer ?? "",
    answer_risk_score: partial.answer_risk_score ?? 0,
    answer_risk_score_decider: partial.answer_risk_score_decider ?? "",
    answer_asn: partial.answer_asn ?? "",
    answer_as_name: partial.answer_as_name ?? "",
    count: partial.count ?? 1,
    first_seen: partial.first_seen ?? "",
    last_seen: partial.last_seen ?? "",
    type: partial.type ?? "A",
  };
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;

function isIp(value: string): boolean {
  return IPV4.test(value) || IPV6.test(value);
}

// ---------------------------------------------------------------------------
// Format: INFRARUN / native passive DNS (already the right shape)
// ---------------------------------------------------------------------------

function looksNative(row: any): boolean {
  return (
    row &&
    typeof row === "object" &&
    ("query" in row || "answer" in row) &&
    ("answer_asn" in row || "answer_as_name" in row || "query_asn" in row)
  );
}

// ---------------------------------------------------------------------------
// Format: STIX 2.x bundle
// ---------------------------------------------------------------------------

function parseStix(bundle: any): DnsRecord[] {
  const objects: any[] = bundle.objects || [];
  const byId = new Map<string, any>();
  for (const o of objects) if (o?.id) byId.set(o.id, o);

  // Build AS lookup: SCO id -> { asn, name }
  const asById = new Map<string, { asn: string; name: string }>();
  for (const o of objects) {
    if (o.type === "autonomous-system") {
      asById.set(o.id, {
        asn: normalizeAsn(o.number),
        name: o.name || "",
      });
    }
  }

  // belongs-to relationships link an addr SCO to an autonomous-system SCO
  const addrToAs = new Map<string, { asn: string; name: string }>();
  for (const o of objects) {
    if (o.type === "relationship" && o.relationship_type === "belongs-to") {
      const as = asById.get(o.target_ref);
      if (as) addrToAs.set(o.source_ref, as);
    }
  }

  const records: DnsRecord[] = [];

  // resolves-to relationships: domain-name -> ipv4-addr/ipv6-addr
  let hadRelationship = false;
  for (const o of objects) {
    if (o.type === "relationship" && o.relationship_type === "resolves-to") {
      const src = byId.get(o.source_ref);
      const tgt = byId.get(o.target_ref);
      const domain = src?.value;
      const ip = tgt?.value;
      if (domain || ip) {
        hadRelationship = true;
        const as = tgt ? addrToAs.get(tgt.id) : undefined;
        records.push(
          makeRecord({
            query: domain || "",
            answer: ip || "",
            answer_asn: as?.asn || "",
            answer_as_name: as?.name || "",
            first_seen: o.created || "",
            last_seen: o.modified || "",
          }),
        );
      }
    }
  }

  // Extract from indicator patterns: [domain-name:value = 'x'] / [ipv4-addr:value = 'y']
  for (const o of objects) {
    if (o.type === "indicator" && typeof o.pattern === "string") {
      const domains = [...o.pattern.matchAll(/(?:domain-name|hostname)[^']*'([^']+)'/g)].map(
        (m) => m[1],
      );
      const ips = [
        ...o.pattern.matchAll(/ipv[46]-addr:value\s*=\s*'([^']+)'/g),
      ].map((m) => m[1]);
      const score = typeof o.confidence === "number" ? o.confidence : 0;
      if (domains.length && ips.length) {
        for (const d of domains)
          for (const ip of ips)
            records.push(
              makeRecord({
                query: d,
                answer: ip,
                answer_risk_score: score,
                first_seen: o.valid_from || o.created || "",
                last_seen: o.modified || "",
              }),
            );
      } else if (!hadRelationship) {
        for (const d of domains)
          records.push(makeRecord({ query: d, answer_risk_score: score }));
        for (const ip of ips)
          records.push(makeRecord({ answer: ip, answer_risk_score: score }));
      }
    }
  }

  // Standalone observable SCOs (observed-data / plain SCOs) with no relationship
  if (!hadRelationship && records.length === 0) {
    for (const o of objects) {
      if (o.type === "domain-name" && o.value) {
        records.push(makeRecord({ query: o.value }));
      } else if ((o.type === "ipv4-addr" || o.type === "ipv6-addr") && o.value) {
        const as = addrToAs.get(o.id);
        records.push(
          makeRecord({
            answer: o.value,
            answer_asn: as?.asn || "",
            answer_as_name: as?.name || "",
          }),
        );
      }
    }
  }

  return records;
}

// ---------------------------------------------------------------------------
// Format: AlienVault OTX
// ---------------------------------------------------------------------------

function parseOtxPassiveDns(rows: any[]): DnsRecord[] {
  return rows.map((r) =>
    makeRecord({
      query: r.hostname || r.domain || "",
      answer: r.address || r.ip || "",
      answer_asn: normalizeAsn(r.asn),
      answer_as_name: r.asn_name || r.as_name || r.name || "",
      first_seen: r.first || r.first_seen || "",
      last_seen: r.last || r.last_seen || "",
      type: r.record_type || r.type || "A",
    }),
  );
}

function parseOtxPulse(indicators: any[]): DnsRecord[] {
  const records: DnsRecord[] = [];
  for (const ind of indicators) {
    const value = ind.indicator || ind.value;
    if (!value) continue;
    const type = String(ind.type || "").toLowerCase();
    if (type.includes("ip") || isIp(value)) {
      records.push(
        makeRecord({
          answer: value,
          answer_asn: normalizeAsn(ind.asn),
          first_seen: ind.created || "",
        }),
      );
    } else if (type.includes("domain") || type.includes("hostname") || type.includes("url")) {
      let host = value;
      try {
        if (type.includes("url")) host = new URL(value).hostname;
      } catch {
        /* keep raw */
      }
      records.push(makeRecord({ query: host, first_seen: ind.created || "" }));
    }
  }
  return records;
}

// ---------------------------------------------------------------------------
// Format: VirusTotal v3
// ---------------------------------------------------------------------------

function parseVirusTotal(body: any): DnsRecord[] {
  const records: DnsRecord[] = [];
  const items = Array.isArray(body.data) ? body.data : [body.data];

  for (const item of items) {
    if (!item) continue;
    const attrs = item.attributes || {};

    // Resolution objects: host_name + ip_address
    if (attrs.host_name || attrs.ip_address) {
      records.push(
        makeRecord({
          query: attrs.host_name || "",
          answer: attrs.ip_address || "",
          answer_asn: normalizeAsn(attrs.asn),
          answer_as_name: attrs.as_owner || "",
          answer_risk_score: attrs.last_analysis_stats?.malicious ?? 0,
          first_seen: attrs.date ? String(attrs.date) : "",
        }),
      );
      continue;
    }

    // IP address object
    if (item.type === "ip_address" || (item.id && isIp(item.id))) {
      records.push(
        makeRecord({
          answer: item.id || "",
          answer_asn: normalizeAsn(attrs.asn),
          answer_as_name: attrs.as_owner || "",
          answer_risk_score: attrs.last_analysis_stats?.malicious ?? 0,
        }),
      );
      continue;
    }

    // Domain object
    if (item.type === "domain" || item.id) {
      records.push(
        makeRecord({
          query: item.id || "",
          answer_risk_score: attrs.last_analysis_stats?.malicious ?? 0,
        }),
      );
    }
  }
  return records;
}

// ---------------------------------------------------------------------------
// Format: generic JSON array of objects (fuzzy field mapping)
// ---------------------------------------------------------------------------

const DOMAIN_KEYS = ["query", "domain", "hostname", "host", "fqdn", "name"];
const IP_KEYS = ["answer", "ip", "ip_address", "address", "resolved_ip", "a"];
const ASN_KEYS = ["answer_asn", "asn", "as", "as_number"];
const ASNAME_KEYS = ["answer_as_name", "as_name", "as_owner", "asn_name", "org", "organization"];

function pick(row: any, keys: string[]): any {
  for (const k of Object.keys(row)) {
    if (keys.includes(k.toLowerCase())) return row[k];
  }
  return undefined;
}

function parseGeneric(rows: any[]): DnsRecord[] {
  const records: DnsRecord[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const domain = pick(row, DOMAIN_KEYS);
    const ip = pick(row, IP_KEYS);
    if (!domain && !ip) continue;
    records.push(
      makeRecord({
        query: domain ? String(domain) : "",
        answer: ip ? String(ip) : "",
        answer_asn: normalizeAsn(pick(row, ASN_KEYS)),
        answer_as_name: pick(row, ASNAME_KEYS) ? String(pick(row, ASNAME_KEYS)) : "",
      }),
    );
  }
  return records;
}

// ---------------------------------------------------------------------------
// Format: CSV
// ---------------------------------------------------------------------------

function parseCsv(text: string): DnsRecord[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const delimiter = lines[0].includes("\t") ? "\t" : ",";
  const split = (line: string) =>
    line.split(delimiter).map((c) => c.trim().replace(/^"|"$/g, ""));
  const headers = split(lines[0]).map((h) => h.toLowerCase());
  const rows: any[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = split(lines[i]);
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => (row[h] = cells[idx] ?? ""));
    rows.push(row);
  }
  return parseGeneric(rows);
}

// ---------------------------------------------------------------------------
// Master entry point
// ---------------------------------------------------------------------------

export function ingest(text: string, filename = ""): IngestResult {
  const trimmed = text.trim();

  // Attempt JSON first
  let json: any = null;
  try {
    json = JSON.parse(trimmed);
  } catch {
    // Try to recover a JSON array embedded in text (e.g. PDF extraction)
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
    // STIX bundle
    if (json.type === "bundle" && Array.isArray(json.objects)) {
      return { records: parseStix(json), format: "STIX 2.x" };
    }
    // OTX passive DNS
    if (Array.isArray(json.passive_dns)) {
      return { records: parseOtxPassiveDns(json.passive_dns), format: "AlienVault OTX (passive DNS)" };
    }
    // OTX pulse
    const pulseIndicators =
      (json.pulse_info?.pulses?.[0]?.indicators as any[]) ||
      (Array.isArray(json.indicators) &&
      json.indicators.some((i: any) => i && (i.indicator || i.type))
        ? json.indicators
        : null);
    if (pulseIndicators) {
      return { records: parseOtxPulse(pulseIndicators), format: "AlienVault OTX (pulse)" };
    }
    // VirusTotal v3 (has data with attributes / meta)
    if (json.data && (json.meta || (Array.isArray(json.data) ? json.data[0]?.attributes : json.data.attributes))) {
      return { records: parseVirusTotal(json), format: "VirusTotal" };
    }

    // Array-ish payloads
    let rows: any[] | null = null;
    if (Array.isArray(json)) rows = json;
    else if (Array.isArray(json.records)) rows = json.records;
    else if (Array.isArray(json.data)) rows = json.data;
    else if (Array.isArray(json.results)) rows = json.results;

    if (rows) {
      if (rows.some(looksNative)) {
        return { records: rows.filter(looksNative).map(makeRecord), format: "Passive DNS (native)" };
      }
      return { records: parseGeneric(rows), format: "Generic JSON" };
    }
  }

  // JSONL (one JSON object per line)
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
      if (rows.some(looksNative)) {
        return { records: rows.filter(looksNative).map(makeRecord), format: "Passive DNS (JSONL)" };
      }
      return { records: parseGeneric(rows), format: "Generic JSONL" };
    }
  }

  // CSV / TSV fallback
  if (/,|\t/.test(trimmed) && trimmed.includes("\n")) {
    const records = parseCsv(trimmed);
    if (records.length) return { records, format: "CSV" };
  }

  return { records: [], format: "unknown" };
}
