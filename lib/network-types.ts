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

export interface GraphNode {
  id: string;
  label: string;
  type: "ip" | "org" | "cidr";
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  data?: LookupResult;
}

export interface GraphEdge {
  source: string;
  target: string;
  color: string;
}

export interface NetworkGroup {
  org: string;
  asn: string;
  cidr: string;
  ips: LookupResult[];
  color: string;
}
