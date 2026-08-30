import type { AsnGroup, DnsRecord } from "./network-types";

// A single hop in the lineage chain, from the observed artifact up to the
// ultimate parent organization.
export interface LineageHop {
  level: "domain" | "ip" | "asn" | "org" | "parent";
  label: string;
  sublabel?: string;
  detail?: string;
  // Where this hop's data came from
  source: "uploaded" | "derived" | "rdap";
  confidence: "high" | "medium" | "low";
}

export interface Lineage {
  // The node the user clicked / is tracing from
  root: {
    kind: "domain" | "ip" | "asn";
    value: string;
  };
  hops: LineageHop[];
  // The resolved ultimate parent org name (top of the chain)
  origin: string;
  originConfidence: "high" | "medium" | "low";
}

// Known ASN / org-name -> ultimate parent rollups. Many large providers
// operate dozens of ASNs and org-name variants; this table folds the common
// ones back to a single canonical parent so the lineage terminates at the
// real owner.
const PARENT_RULES: { match: RegExp; parent: string }[] = [
  { match: /google|goog|youtube|15169|19527|36040|36384|43515|139070/i, parent: "Google LLC" },
  { match: /amazon|aws|14618|16509|8987|38895|amazon-02|amazon-aes/i, parent: "Amazon.com, Inc." },
  { match: /microsoft|msft|azure|8075|8068|8069|3598/i, parent: "Microsoft Corporation" },
  { match: /cloudflare|13335|132892|209242/i, parent: "Cloudflare, Inc." },
  { match: /meta|facebook|instagram|whatsapp|32934|63293/i, parent: "Meta Platforms, Inc." },
  { match: /apple|714|6185/i, parent: "Apple Inc." },
  { match: /akamai|16625|20940|12222|21342/i, parent: "Akamai Technologies" },
  { match: /digitalocean|14061|digital ocean/i, parent: "DigitalOcean, LLC" },
  { match: /hetzner|24940|213230/i, parent: "Hetzner Online GmbH" },
  { match: /\bovh\b|16276|ovh sas/i, parent: "OVH SAS" },
  { match: /tencent|45090|132203|132591/i, parent: "Tencent Holdings Ltd." },
  { match: /alibaba|37963|45102|alicloud|aliyun/i, parent: "Alibaba Group" },
  { match: /oracle|31898|oracle-bmc/i, parent: "Oracle Corporation" },
  { match: /linode|63949|akamai-linode/i, parent: "Akamai Technologies" },
  { match: /leaseweb|60781|28753|hostingprovider/i, parent: "LeaseWeb Global" },
  { match: /contabo|51167/i, parent: "Contabo GmbH" },
  { match: /godaddy|go-daddy|26496|398101/i, parent: "GoDaddy.com, LLC" },
  { match: /namecheap|22612/i, parent: "Namecheap, Inc." },
];

// Strip common corporate suffixes and noise so two spellings of the same org
// collapse together when we don't have an explicit rule.
function canonicalizeOrg(name: string): string {
  return name
    .replace(/[,.]/g, " ")
    .replace(/\b(inc|llc|ltd|limited|gmbh|corp|corporation|co|sas|sa|bv|as|plc|holdings|group|technologies|networks|network|hosting|communications|telecom|the)\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

export function deriveParent(asName: string, asn: string): { parent: string; confidence: "high" | "medium" | "low" } {
  const haystack = `${asName} ${asn}`;
  for (const rule of PARENT_RULES) {
    if (rule.match.test(haystack)) {
      return { parent: rule.parent, confidence: "high" };
    }
  }
  // No explicit rule -- fall back to a cleaned version of the org name itself
  const canon = canonicalizeOrg(asName);
  if (canon.length > 0) {
    // Title-case the canonical form for display
    const display = asName.trim() || "Unknown Origin";
    return { parent: display, confidence: "medium" };
  }
  return { parent: "Unknown Origin", confidence: "low" };
}

// Build the lineage chain for an IP within a given ASN group, using only the
// data we already have (offline / derived). RDAP enrichment layers on top of
// this later.
export function buildLineageForIp(ip: string, group: AsnGroup): Lineage {
  const ipRecords = group.records.filter((r) => r.answer === ip);
  const domains = [...new Set(ipRecords.map((r) => r.query).filter(Boolean))];
  const { parent, confidence } = deriveParent(group.asName, group.asn);

  const hops: LineageHop[] = [];

  if (domains.length > 0) {
    hops.push({
      level: "domain",
      label: domains[0],
      sublabel: domains.length > 1 ? `+${domains.length - 1} more domain${domains.length > 2 ? "s" : ""}` : undefined,
      detail: "Observed query resolving to this address",
      source: "uploaded",
      confidence: "high",
    });
  }

  hops.push({
    level: "ip",
    label: ip,
    detail: "Resolved answer address",
    source: "uploaded",
    confidence: "high",
  });

  hops.push({
    level: "asn",
    label: group.asn,
    sublabel: group.asName,
    detail: "Announcing autonomous system",
    source: "uploaded",
    confidence: "high",
  });

  hops.push({
    level: "org",
    label: group.asName,
    detail: "Registered network operator",
    source: "uploaded",
    confidence: "high",
  });

  hops.push({
    level: "parent",
    label: parent,
    detail: "Ultimate parent organization",
    source: "derived",
    confidence,
  });

  return {
    root: { kind: "ip", value: ip },
    hops,
    origin: parent,
    originConfidence: confidence,
  };
}

// Build lineage from an ASN group directly (no specific IP selected).
export function buildLineageForAsn(group: AsnGroup): Lineage {
  const { parent, confidence } = deriveParent(group.asName, group.asn);
  const hops: LineageHop[] = [
    {
      level: "asn",
      label: group.asn,
      sublabel: group.asName,
      detail: `${group.ips.length} IP${group.ips.length !== 1 ? "s" : ""}, ${group.domains.length} domain${group.domains.length !== 1 ? "s" : ""}`,
      source: "uploaded",
      confidence: "high",
    },
    {
      level: "org",
      label: group.asName,
      detail: "Registered network operator",
      source: "uploaded",
      confidence: "high",
    },
    {
      level: "parent",
      label: parent,
      detail: "Ultimate parent organization",
      source: "derived",
      confidence,
    },
  ];

  return {
    root: { kind: "asn", value: group.asn },
    hops,
    origin: parent,
    originConfidence: confidence,
  };
}

// Roll every group up to its parent so we can show an origin summary:
// which ultimate parents own the observed infrastructure.
export interface OriginRollup {
  parent: string;
  confidence: "high" | "medium" | "low";
  asns: string[];
  ipCount: number;
  domainCount: number;
  maxRisk: number;
}

export function rollupOrigins(groups: AsnGroup[]): OriginRollup[] {
  const map = new Map<string, OriginRollup>();
  for (const g of groups) {
    const { parent, confidence } = deriveParent(g.asName, g.asn);
    if (!map.has(parent)) {
      map.set(parent, {
        parent,
        confidence,
        asns: [],
        ipCount: 0,
        domainCount: 0,
        maxRisk: 0,
      });
    }
    const entry = map.get(parent)!;
    if (!entry.asns.includes(g.asn)) entry.asns.push(g.asn);
    entry.ipCount += g.ips.length;
    entry.domainCount += g.domains.length;
    entry.maxRisk = Math.max(entry.maxRisk, g.maxRiskScore);
  }
  return Array.from(map.values()).sort((a, b) => b.ipCount - a.ipCount);
}

// Merge live RDAP data into an existing lineage, inserting/annotating hops
// with authoritative registrant + parent info where available.
export interface RdapResult {
  ip: string;
  handle?: string;
  name?: string;
  parentHandle?: string;
  parentName?: string;
  country?: string;
  registrant?: string;
  cidr?: string;
}

export function applyRdapToLineage(lineage: Lineage, rdap: RdapResult): Lineage {
  const hops = [...lineage.hops];

  // Annotate the IP hop with CIDR / country if we learned them
  const ipHop = hops.find((h) => h.level === "ip");
  if (ipHop && (rdap.cidr || rdap.country)) {
    ipHop.sublabel = [rdap.cidr, rdap.country].filter(Boolean).join(" \u00b7 ");
    ipHop.source = "rdap";
  }

  // If RDAP gives us an authoritative registrant/parent, upgrade the parent hop
  const authoritativeParent = rdap.parentName || rdap.registrant || rdap.name;
  if (authoritativeParent) {
    const parentHop = hops.find((h) => h.level === "parent");
    if (parentHop) {
      // Only override if we were previously guessing (medium/low confidence)
      if (lineage.originConfidence !== "high") {
        parentHop.label = authoritativeParent;
        parentHop.detail = "Authoritative RDAP registrant";
      } else {
        parentHop.sublabel = `RDAP: ${authoritativeParent}`;
      }
      parentHop.source = "rdap";
      parentHop.confidence = "high";
    }
    return {
      ...lineage,
      hops,
      origin: lineage.originConfidence === "high" ? lineage.origin : authoritativeParent,
      originConfidence: "high",
    };
  }

  return { ...lineage, hops };
}
