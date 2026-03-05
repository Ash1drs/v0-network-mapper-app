"use client";

import type { LookupResult, NetworkGroup } from "@/lib/network-types";
import { Globe, Server, Building2, MapPin, Network, X } from "lucide-react";
import { Button } from "@/components/ui/button";

interface DetailPanelProps {
  selectedIp: LookupResult | null;
  groups: NetworkGroup[];
  onClearSelection: () => void;
}

function InfoRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-2.5 py-1.5">
      <span className="mt-0.5 text-muted-foreground">{icon}</span>
      <div className="flex flex-col">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="text-sm font-mono text-foreground break-all">{value}</span>
      </div>
    </div>
  );
}

export function DetailPanel({ selectedIp, groups, onClearSelection }: DetailPanelProps) {
  if (selectedIp) {
    return (
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">IP Details</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClearSelection}
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
        <div className="rounded-lg border border-border bg-secondary/30 p-3">
          <div className="mb-2 font-mono text-base font-bold text-primary">{selectedIp.ip}</div>
          <div className="flex flex-col gap-0.5">
            <InfoRow icon={<Building2 className="h-3.5 w-3.5" />} label="Organization" value={selectedIp.org} />
            <InfoRow icon={<Server className="h-3.5 w-3.5" />} label="ISP" value={selectedIp.isp} />
            <InfoRow icon={<Network className="h-3.5 w-3.5" />} label="ASN" value={selectedIp.asn} />
            <InfoRow icon={<Network className="h-3.5 w-3.5" />} label="CIDR Block" value={selectedIp.cidr} />
            <InfoRow
              icon={<MapPin className="h-3.5 w-3.5" />}
              label="Location"
              value={[selectedIp.city, selectedIp.region, selectedIp.country].filter(Boolean).join(", ")}
            />
            <InfoRow icon={<Globe className="h-3.5 w-3.5" />} label="Country Code" value={selectedIp.countryCode} />
          </div>
        </div>
      </div>
    );
  }

  if (groups.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">Network Groups</h2>
        <p className="text-xs text-muted-foreground">
          Groups will appear here after scanning. Click a node to see details.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-foreground">
        Network Groups
        <span className="ml-2 text-xs font-normal text-muted-foreground">
          ({groups.length} {groups.length === 1 ? "org" : "orgs"})
        </span>
      </h2>
      <div className="flex flex-col gap-2 max-h-[50vh] overflow-y-auto">
        {groups.map((group) => (
          <div
            key={group.org}
            className="rounded-lg border border-border bg-secondary/30 p-3"
          >
            <div className="flex items-center gap-2 mb-1.5">
              <span
                className="inline-block h-3 w-3 rounded-full"
                style={{ backgroundColor: group.color }}
              />
              <span className="text-sm font-semibold text-foreground truncate">
                {group.org}
              </span>
            </div>
            {group.asn && (
              <p className="text-xs font-mono text-muted-foreground mb-1">{group.asn}</p>
            )}
            <div className="flex flex-wrap gap-1 mt-1.5">
              {group.ips.map((ip) => (
                <span
                  key={ip.ip}
                  className="inline-block rounded-md border px-1.5 py-0.5 font-mono text-xs"
                  style={{
                    borderColor: group.color + "50",
                    color: group.color,
                    backgroundColor: group.color + "10",
                  }}
                >
                  {ip.ip}
                </span>
              ))}
            </div>
            {group.cidr && (
              <p
                className="mt-1.5 text-xs font-mono"
                style={{ color: group.color + "99" }}
              >
                {group.cidr}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
