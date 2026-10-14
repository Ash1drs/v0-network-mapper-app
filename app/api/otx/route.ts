import { NextResponse } from "next/server";

const OTX_BASE = "https://otx.alienvault.com/api/v1/indicators";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function otxSection(indicator: string): string | null {
  if (IPV4.test(indicator)) return "IPv4";
  if (indicator.includes(":") && IPV6.test(indicator)) return "IPv6";
  if (HOST.test(indicator)) {
    return indicator.split(".").length > 2 ? "hostname" : "domain";
  }
  return null;
}

export async function GET(req: Request) {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "OTX_API_KEY is not configured. Add it in the Vars section of project settings." },
      { status: 500 },
    );
  }

  const indicator = new URL(req.url).searchParams.get("indicator")?.trim().toLowerCase() ?? "";
  const section = otxSection(indicator);
  if (!section) {
    return NextResponse.json(
      { error: "Enter a valid IP address, domain, or hostname." },
      { status: 400 },
    );
  }

  const res = await fetch(
    `${OTX_BASE}/${section}/${encodeURIComponent(indicator)}/passive_dns`,
    {
      headers: { "X-OTX-API-KEY": apiKey, Accept: "application/json" },
      next: { revalidate: 3600 },
    },
  );

  if (res.status === 403 || res.status === 401) {
    return NextResponse.json({ error: "AlienVault rejected the API key." }, { status: 502 });
  }
  if (!res.ok) {
    return NextResponse.json(
      { error: `AlienVault OTX returned ${res.status}.` },
      { status: 502 },
    );
  }

  const data = await res.json();
  const passive_dns = Array.isArray(data?.passive_dns) ? data.passive_dns : [];
  return NextResponse.json({ indicator, section, passive_dns });
}
