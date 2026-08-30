import { NextRequest, NextResponse } from "next/server";
import type { RdapResult } from "@/lib/origin-trace";

// RDAP (Registration Data Access Protocol) is the structured JSON successor to
// WHOIS. rdap.org is a bootstrap redirector that forwards each query to the
// authoritative RIR (ARIN, RIPE, APNIC, etc.), so a single endpoint works
// worldwide.
const RDAP_BOOTSTRAP = "https://rdap.org/ip/";

interface RdapEntity {
  handle?: string;
  roles?: string[];
  vcardArray?: unknown[];
  entities?: RdapEntity[];
}

interface RdapResponse {
  handle?: string;
  name?: string;
  country?: string;
  startAddress?: string;
  endAddress?: string;
  cidr0_cidrs?: { v4prefix?: string; v6prefix?: string; length?: number }[];
  entities?: RdapEntity[];
  // Some RIRs nest the parent network here
  network?: { name?: string; handle?: string };
}

// Pull the org / registrant name out of a vCard array, which looks like:
// ["vcard", [["fn", {}, "text", "Google LLC"], ...]]
function nameFromVcard(vcardArray: unknown[] | undefined): string | undefined {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return undefined;
  const fields = vcardArray[1];
  if (!Array.isArray(fields)) return undefined;
  for (const field of fields) {
    if (Array.isArray(field) && field[0] === "fn" && typeof field[3] === "string") {
      return field[3];
    }
  }
  return undefined;
}

// Walk entities to find the best registrant/org name, preferring the
// "registrant" then "administrative" then any org role.
function extractRegistrant(entities: RdapEntity[] | undefined): string | undefined {
  if (!entities) return undefined;
  const byRole = (role: string) =>
    entities.find((e) => e.roles?.includes(role));

  const candidate =
    byRole("registrant") ||
    byRole("administrative") ||
    byRole("owner") ||
    entities[0];

  if (candidate) {
    const name = nameFromVcard(candidate.vcardArray);
    if (name) return name;
    // Recurse into nested entities
    const nested = extractRegistrant(candidate.entities);
    if (nested) return nested;
  }
  return undefined;
}

async function lookupIp(ip: string): Promise<RdapResult> {
  try {
    const res = await fetch(`${RDAP_BOOTSTRAP}${ip}`, {
      headers: { Accept: "application/rdap+json" },
      // RDAP responses are cacheable and stable; cache for a day
      next: { revalidate: 86400 },
    });

    if (!res.ok) {
      return { ip };
    }

    const data: RdapResponse = await res.json();
    const registrant = extractRegistrant(data.entities);

    let cidr: string | undefined;
    if (data.cidr0_cidrs && data.cidr0_cidrs.length > 0) {
      const c = data.cidr0_cidrs[0];
      const prefix = c.v4prefix || c.v6prefix;
      if (prefix && c.length !== undefined) cidr = `${prefix}/${c.length}`;
    }

    return {
      ip,
      handle: data.handle,
      name: data.name,
      parentName: data.network?.name,
      parentHandle: data.network?.handle,
      country: data.country,
      registrant,
      cidr,
    };
  } catch {
    return { ip };
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const ips: string[] = Array.isArray(body.ips) ? body.ips : [];

    if (ips.length === 0) {
      return NextResponse.json({ error: "No IPs provided" }, { status: 400 });
    }

    // Cap to protect the public RDAP endpoints from abuse
    const capped = [...new Set(ips)].slice(0, 25);

    // Run lookups with limited concurrency so we don't hammer the RIRs
    const results: RdapResult[] = [];
    const CONCURRENCY = 5;
    for (let i = 0; i < capped.length; i += CONCURRENCY) {
      const batch = capped.slice(i, i + CONCURRENCY);
      const settled = await Promise.all(batch.map(lookupIp));
      results.push(...settled);
    }

    return NextResponse.json({ results });
  } catch (error) {
    console.error("RDAP lookup error:", error);
    return NextResponse.json(
      { error: "RDAP lookup failed" },
      { status: 500 }
    );
  }
}
