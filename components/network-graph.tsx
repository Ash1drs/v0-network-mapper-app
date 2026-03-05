"use client";

import { useRef, useEffect, useCallback, useState } from "react";
import type { GraphNode, GraphEdge, AsnGroup } from "@/lib/network-types";

function riskColor(score: number): string {
  if (score >= 70) return "#f87171";
  if (score >= 40) return "#fbbf24";
  if (score >= 20) return "#38bdf8";
  return "#4ade80";
}

function buildGraph(groups: AsnGroup[], width: number, height: number): {
  nodes: GraphNode[];
  edges: GraphEdge[];
} {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const cx = width / 2;
  const cy = height / 2;

  for (const group of groups) {
    // ASN hub node
    const asnId = `asn-${group.asn}`;
    const angle = Math.random() * Math.PI * 2;
    const dist = 100 + Math.random() * Math.min(width, height) * 0.25;
    nodes.push({
      id: asnId,
      label: group.asName.length > 24 ? group.asName.slice(0, 22) + "..." : group.asName,
      type: "asn",
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      vx: 0,
      vy: 0,
      radius: Math.min(14 + group.ips.length * 2, 36),
      color: group.color,
      riskScore: group.maxRiskScore,
      asnGroup: group,
    });

    // IP nodes radiating from ASN
    for (let i = 0; i < group.ips.length; i++) {
      const ip = group.ips[i];
      const ipId = `ip-${ip}`;
      const ipAngle = angle + ((i / group.ips.length) * Math.PI * 2) / groups.length - Math.PI / groups.length;
      const ipDist = 40 + Math.random() * 60;
      const parentNode = nodes.find((n) => n.id === asnId)!;

      // Find the records for this IP to get its risk
      const ipRecords = group.records.filter((r) => r.answer === ip);
      const ipRisk = ipRecords.length > 0 ? Math.max(...ipRecords.map((r) => r.answer_risk_score)) : 0;

      nodes.push({
        id: ipId,
        label: ip,
        type: "ip",
        x: parentNode.x + Math.cos(ipAngle) * ipDist,
        y: parentNode.y + Math.sin(ipAngle) * ipDist,
        vx: 0,
        vy: 0,
        radius: 8,
        color: group.color,
        riskScore: ipRisk,
      });

      edges.push({ source: asnId, target: ipId, color: group.color });

      // Domain nodes branching from IPs (limit to avoid overload)
      const domainsForIp = ipRecords.map((r) => r.query);
      const uniqueDomains = [...new Set(domainsForIp)].slice(0, 3);

      for (let d = 0; d < uniqueDomains.length; d++) {
        const domain = uniqueDomains[d];
        const domainId = `dom-${domain}-${ip}`;
        const domAngle = ipAngle + ((d - uniqueDomains.length / 2) * 0.4);
        const domDist = 25 + Math.random() * 20;
        const ipNode = nodes.find((n) => n.id === ipId)!;

        const domRecord = ipRecords.find((r) => r.query === domain);
        const domRisk = domRecord?.query_risk_score ?? 0;

        nodes.push({
          id: domainId,
          label: domain.length > 20 ? domain.slice(0, 18) + "..." : domain,
          type: "domain",
          x: ipNode.x + Math.cos(domAngle) * domDist,
          y: ipNode.y + Math.sin(domAngle) * domDist,
          vx: 0,
          vy: 0,
          radius: 5,
          color: riskColor(domRisk),
          riskScore: domRisk,
          data: domRecord,
        });

        edges.push({ source: ipId, target: domainId, color: group.color + "60" });
      }
    }
  }

  return { nodes, edges };
}

function simulateForces(
  nodes: GraphNode[],
  edges: GraphEdge[],
  width: number,
  height: number
) {
  const REPULSION = 2500;
  const ATTRACTION = 0.008;
  const DAMPING = 0.82;
  const CENTER_GRAVITY = 0.005;

  const cx = width / 2;
  const cy = height / 2;

  // Repulsion between all nodes -- skip domain-to-domain (too many)
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].type === "domain") continue;
    for (let j = i + 1; j < nodes.length; j++) {
      if (nodes[j].type === "domain") continue;
      const dx = nodes[i].x - nodes[j].x;
      const dy = nodes[i].y - nodes[j].y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = REPULSION / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      nodes[i].vx += fx;
      nodes[i].vy += fy;
      nodes[j].vx -= fx;
      nodes[j].vy -= fy;
    }
  }

  // Attraction along edges
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  for (const edge of edges) {
    const source = nodeMap.get(edge.source);
    const target = nodeMap.get(edge.target);
    if (!source || !target) continue;
    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
    const force = dist * ATTRACTION;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;
    source.vx += fx;
    source.vy += fy;
    target.vx -= fx;
    target.vy -= fy;
  }

  for (const node of nodes) {
    node.vx += (cx - node.x) * CENTER_GRAVITY;
    node.vy += (cy - node.y) * CENTER_GRAVITY;
    node.vx *= DAMPING;
    node.vy *= DAMPING;
    node.x += node.vx;
    node.y += node.vy;
    node.x = Math.max(node.radius + 4, Math.min(width - node.radius - 4, node.x));
    node.y = Math.max(node.radius + 4, Math.min(height - node.radius - 4, node.y));
  }
}

interface NetworkGraphProps {
  groups: AsnGroup[];
  onSelectGroup: (group: AsnGroup | null) => void;
}

export function NetworkGraph({ groups, onSelectGroup }: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const edgesRef = useRef<GraphEdge[]>([]);
  const animFrameRef = useRef<number>(0);
  const dragNodeRef = useRef<GraphNode | null>(null);
  const hoveredNodeRef = useRef<GraphNode | null>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 500 });

  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setCanvasSize({
          width: entry.contentRect.width,
          height: Math.max(entry.contentRect.height, 300),
        });
      }
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (groups.length === 0) {
      nodesRef.current = [];
      edgesRef.current = [];
      return;
    }
    const { nodes, edges } = buildGraph(groups, canvasSize.width, canvasSize.height);
    nodesRef.current = nodes;
    edgesRef.current = edges;
  }, [groups, canvasSize.width, canvasSize.height]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvasSize.width * dpr;
    canvas.height = canvasSize.height * dpr;
    ctx.scale(dpr, dpr);

    const nodes = nodesRef.current;
    const edges = edgesRef.current;

    if (nodes.length > 0) {
      simulateForces(nodes, edges, canvasSize.width, canvasSize.height);
    }

    ctx.clearRect(0, 0, canvasSize.width, canvasSize.height);

    // Subtle grid
    ctx.strokeStyle = "rgba(100, 120, 140, 0.04)";
    ctx.lineWidth = 1;
    for (let x = 0; x < canvasSize.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvasSize.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvasSize.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvasSize.width, y);
      ctx.stroke();
    }

    // Edges
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    for (const edge of edges) {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) continue;
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = edge.color + "30";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    const hovered = hoveredNodeRef.current;

    // Nodes
    for (const node of nodes) {
      const isHovered = hovered?.id === node.id;

      if (isHovered || node.type === "asn") {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered ? 8 : 4), 0, Math.PI * 2);
        ctx.fillStyle = node.color + (isHovered ? "25" : "10");
        ctx.fill();
      }

      // Risk ring for high-risk nodes
      if (node.riskScore >= 70) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 2, 0, Math.PI * 2);
        ctx.strokeStyle = "#f8717180";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle =
        node.type === "domain"
          ? node.color + "15"
          : node.type === "ip"
          ? node.color + "20"
          : node.color + "30";
      ctx.fill();
      ctx.strokeStyle = node.color;
      ctx.lineWidth = isHovered ? 2.5 : 1;
      ctx.stroke();

      // Inner label
      ctx.fillStyle = node.color;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      if (node.type === "asn") {
        ctx.font = `bold ${Math.max(8, node.radius * 0.45)}px Geist, sans-serif`;
        const parts = node.label.split(/[\s,]+/);
        ctx.fillText(parts[0].slice(0, 8), node.x, node.y);
      } else if (node.type === "ip") {
        ctx.font = "bold 6px Geist Mono, monospace";
        const parts = node.label.split(".");
        ctx.fillText(parts[2] + "." + parts[3], node.x, node.y);
      }
      // domains are too small for labels inside

      // Label below ASN nodes only (to avoid clutter)
      if (node.type === "asn") {
        ctx.fillStyle = node.color + "bb";
        ctx.font = "10px Geist, sans-serif";
        ctx.fillText(
          `AS${node.asnGroup?.asn || "?"}`,
          node.x,
          node.y + node.radius + 12
        );
      }

      // Show IP label on hover
      if (isHovered && node.type !== "asn") {
        ctx.fillStyle = "#e2e8f0";
        ctx.font = "bold 10px Geist Mono, monospace";
        const labelWidth = ctx.measureText(node.label).width + 12;
        const lx = node.x - labelWidth / 2;
        const ly = node.y - node.radius - 22;
        ctx.fillStyle = "rgba(15, 15, 30, 0.9)";
        ctx.beginPath();
        ctx.roundRect(lx, ly, labelWidth, 18, 4);
        ctx.fill();
        ctx.strokeStyle = node.color + "80";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = "#e2e8f0";
        ctx.fillText(node.label, node.x, ly + 9);
      }
    }

    animFrameRef.current = requestAnimationFrame(draw);
  }, [canvasSize]);

  useEffect(() => {
    animFrameRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [draw]);

  const getNodeAt = useCallback(
    (x: number, y: number): GraphNode | null => {
      const nodes = nodesRef.current;
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i];
        const dx = x - n.x;
        const dy = y - n.y;
        if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
          return n;
        }
      }
      return null;
    },
    []
  );

  const getCanvasCoords = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      const canvas = canvasRef.current;
      if (!canvas) return { x: 0, y: 0 };
      const rect = canvas.getBoundingClientRect();
      if ("touches" in e) {
        return {
          x: e.touches[0].clientX - rect.left,
          y: e.touches[0].clientY - rect.top,
        };
      }
      return {
        x: (e as React.MouseEvent).clientX - rect.left,
        y: (e as React.MouseEvent).clientY - rect.top,
      };
    },
    []
  );

  const handlePointerDown = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      const coords = getCanvasCoords(e);
      const node = getNodeAt(coords.x, coords.y);
      if (node) {
        dragNodeRef.current = node;
        if (node.type === "asn" && node.asnGroup) {
          onSelectGroup(node.asnGroup);
        }
      }
    },
    [getCanvasCoords, getNodeAt, onSelectGroup]
  );

  const handlePointerMove = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      const coords = getCanvasCoords(e);
      const node = getNodeAt(coords.x, coords.y);
      hoveredNodeRef.current = node;

      if (dragNodeRef.current) {
        dragNodeRef.current.x = coords.x;
        dragNodeRef.current.y = coords.y;
        dragNodeRef.current.vx = 0;
        dragNodeRef.current.vy = 0;
      }

      const canvas = canvasRef.current;
      if (canvas) {
        canvas.style.cursor = node ? "pointer" : "default";
      }
    },
    [getCanvasCoords, getNodeAt]
  );

  const handlePointerUp = useCallback(() => {
    dragNodeRef.current = null;
  }, []);

  if (groups.length === 0) {
    return (
      <div
        ref={containerRef}
        className="flex flex-1 items-center justify-center rounded-lg border border-border bg-card"
      >
        <div className="flex flex-col items-center gap-3 p-8 text-center">
          <svg
            width="48"
            height="48"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            className="text-muted-foreground"
          >
            <circle cx="12" cy="12" r="3" />
            <circle cx="5" cy="5" r="2" />
            <circle cx="19" cy="5" r="2" />
            <circle cx="5" cy="19" r="2" />
            <circle cx="19" cy="19" r="2" />
            <line x1="9.5" y1="9.5" x2="6.5" y2="6.5" />
            <line x1="14.5" y1="9.5" x2="17.5" y2="6.5" />
            <line x1="9.5" y1="14.5" x2="6.5" y2="17.5" />
            <line x1="14.5" y1="14.5" x2="17.5" y2="17.5" />
          </svg>
          <p className="text-muted-foreground text-sm">
            Upload INFRARUN or passive DNS data to map infrastructure
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="relative flex-1 overflow-hidden rounded-lg border border-border bg-card"
    >
      <canvas
        ref={canvasRef}
        style={{ width: canvasSize.width, height: canvasSize.height }}
        onMouseDown={handlePointerDown}
        onMouseMove={handlePointerMove}
        onMouseUp={handlePointerUp}
        onMouseLeave={handlePointerUp}
        onTouchStart={handlePointerDown}
        onTouchMove={handlePointerMove}
        onTouchEnd={handlePointerUp}
        className="touch-none"
      />
      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap gap-3 rounded-md border border-border bg-card/90 px-3 py-2 text-xs backdrop-blur-sm">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-3.5 w-3.5 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">ASN / Org</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">IP</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">Domain</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-[#f87171]" />
          <span className="text-muted-foreground">High Risk</span>
        </span>
      </div>
    </div>
  );
}
