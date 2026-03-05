import { NextRequest, NextResponse } from "next/server";

interface IpApiResponse {
  status: string;
  message?: string;
  query: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
}

export interface LookupResult {
  ip: string;
  org: string;
  isp: string;
  asn: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  cidr: string;
  error?: string;
}

function inferCidr(ip: string, asn: string): string {
  const parts = ip.split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return `${ip}/32`;
}

export async function POST(request: NextRequest) {
  try {
    const { ips } = (await request.json()) as { ips: string[] };

    if (!ips || !Array.isArray(ips) || ips.length === 0) {
      return NextResponse.json(
        { error: "Please provide an array of IP addresses" },
        { status: 400 }
      );
    }

    if (ips.length > 500) {
      return NextResponse.json(
        { error: "Maximum 500 IPs per request" },
        { status: 400 }
      );
    }

    const ipRegex =
      /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    const validIps = [...new Set(ips.map((ip) => ip.trim()).filter((ip) => ipRegex.test(ip)))];

    if (validIps.length === 0) {
      return NextResponse.json(
        { error: "No valid IPv4 addresses found in the provided data" },
        { status: 400 }
      );
    }

    // ip-api.com supports batch queries up to 100 per call, so we chunk
    const CHUNK_SIZE = 100;
    const chunks: string[][] = [];
    for (let i = 0; i < validIps.length; i += CHUNK_SIZE) {
      chunks.push(validIps.slice(i, i + CHUNK_SIZE));
    }

    const batchData: IpApiResponse[] = [];
    for (const chunk of chunks) {
      const batchResponse = await fetch("http://ip-api.com/batch?fields=66846719", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(chunk.map((ip) => ({ query: ip }))),
      });

      if (!batchResponse.ok) {
        throw new Error(`ip-api returned ${batchResponse.status}`);
      }

      const chunkData: IpApiResponse[] = await batchResponse.json();
      batchData.push(...chunkData);

      // ip-api free tier rate limit: 15 requests/minute, add a small delay between chunks
      if (chunks.length > 1) {
        await new Promise((r) => setTimeout(r, 1500));
      }
    }

    const results: LookupResult[] = batchData.map((item) => {
      if (item.status === "fail") {
        return {
          ip: item.query,
          org: "",
          isp: "",
          asn: "",
          country: "",
          countryCode: "",
          region: "",
          city: "",
          lat: 0,
          lon: 0,
          cidr: "",
          error: item.message || "Lookup failed",
        };
      }

      return {
        ip: item.query,
        org: item.org || item.isp || "Unknown",
        isp: item.isp || "Unknown",
        asn: item.as || "",
        country: item.country || "",
        countryCode: item.countryCode || "",
        region: item.regionName || "",
        city: item.city || "",
        lat: item.lat || 0,
        lon: item.lon || 0,
        cidr: inferCidr(item.query, item.as || ""),
      };
    });

    return NextResponse.json({ results });
  } catch (error) {
    console.error("IP lookup error:", error);
    return NextResponse.json(
      { error: "Failed to perform IP lookup" },
      { status: 500 }
    );
  }
}
