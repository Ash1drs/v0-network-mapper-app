// ===========================================================================
// Safety layer — the guardrail behind the Golden Rule.
//
// Large cloud/CDN/identity providers host BOTH benign and malicious traffic.
// Their presence is INFRASTRUCTURE, never evidence of compromise or shared
// intent. This module lets scoring + narratives recognize provider-owned
// artifacts so provider co-tenancy can NEVER inflate confidence or attribution.
// ===========================================================================

// Provider signatures matched against a value, ASN name, or org string.
const PROVIDER_SIGNATURES: { name: string; patterns: RegExp }[] = [
  { name: "Microsoft / Azure / Entra", patterns: /microsoft|azure|entra|office365|outlook\.office|onmicrosoft|windows\.net|msft|graph\.microsoft|azurestaticapps|azurewebsites|as8075/i },
  { name: "Amazon AWS", patterns: /amazon|aws|amazonaws|ec2|cloudfront|as16509|as14618/i },
  { name: "Google / GCP", patterns: /google|gcp|googleusercontent|googleapis|1e100|as15169|as396982/i },
  { name: "Cloudflare", patterns: /cloudflare|as13335/i },
  { name: "Akamai", patterns: /akamai|as20940|as16625/i },
  { name: "Fastly", patterns: /fastly|as54113/i },
  { name: "Okta", patterns: /okta(?!.*(cdn|-))|oktapreview/i },
  { name: "CrowdStrike", patterns: /crowdstrike|crowdstr/i },
  { name: "Digital Ocean", patterns: /digitalocean|as14061/i },
  { name: "Oracle Cloud", patterns: /oraclecloud|as31898/i },
  { name: "GitHub", patterns: /github|githubusercontent/i },
];

export interface ProviderMatch {
  isProvider: boolean;
  provider?: string;
}

// Check a set of strings (value, asName, org) for a known provider signature.
export function detectProvider(...fields: (string | undefined)[]): ProviderMatch {
  const hay = fields.filter(Boolean).join(" ");
  if (!hay) return { isProvider: false };
  for (const p of PROVIDER_SIGNATURES) {
    if (p.patterns.test(hay)) return { isProvider: true, provider: p.name };
  }
  return { isProvider: false };
}

export function isProviderInfra(...fields: (string | undefined)[]): boolean {
  return detectProvider(...fields).isProvider;
}

// The standard disclaimer appended to cluster narratives + report conclusions.
export const SAFETY_DISCLAIMER =
  "Correlation reflects shared or overlapping infrastructure only. Shared hosting on " +
  "a large provider (Azure, AWS, GCP, Cloudflare, etc.) is not, by itself, evidence of " +
  "coordination, common ownership, or malicious intent. All conclusions are traceable " +
  "to the cited observations and should be corroborated before attribution.";

// A one-line note when a provider is involved in an otherwise-shared artifact.
export function providerCaveat(provider: string): string {
  return `Shared artifact sits on ${provider} infrastructure — treat co-tenancy as weak/neutral evidence, not attribution.`;
}
