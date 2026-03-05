"use client";

import { useRef, useEffect, useCallback, useState } from "react";
import type { GraphNode, GraphEdge, LookupResult, NetworkGroup } from "@/lib/network-types";

const GROUP_COLORS = [
  "#22d3ee", // cyan
  "#34d399", // emerald
  "#f59e0b", // amber
  "#f472b6", // pink
  "#a78bfa", // violet
  "#fb923c", // orange
  "#38bdf8", // sky
  "#4ade80", // green
];

function buildGraph(results: LookupResult[]): {
  nodes: GraphNode[];
  edges: GraphEdge[];
  groups: NetworkGroup[];
} {
  const orgMap = new Map<string, LookupResult[]>();

  for (const r of results) {
    if (r.error) continue;
    const key = r.org || r.isp || "Unknown";
    if (!orgMap.has(key)) orgMap.set(key, []);
    orgMap.get(key)!.push(r);
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const groups: NetworkGroup[] = [];
  let colorIndex = 0;

  for (const [org, ips] of orgMap) {
    const color = GROUP_COLORS[colorIndex % GROUP_COLORS.length];
    colorIndex++;

    const cidrSet = new Set(ips.map((ip) => ip.cidr));

    // Org node
    const orgId = `org-${org}`;
    nodes.push({
      id: orgId,
      label: org.length > 20 ? org.slice(0, 20) + "..." : org,
      type: "org",
      x: Math.random() * 600 + 100,
      y: Math.random() * 400 + 100,
      vx: 0,
      vy: 0,
      radius: 28,
      color,
    });

    for (const cidr of cidrSet) {
      if (!cidr) continue;
      const cidrId = `cidr-${cidr}`;
      if (!nodes.find((n) => n.id === cidrId)) {
        nodes.push({
          id: cidrId,
          label: cidr,
          type: "cidr",
          x: Math.random() * 600 + 100,
          y: Math.random() * 400 + 100,
          vx: 0,
          vy: 0,
          radius: 20,
          color,
        });
        edges.push({ source: orgId, target: cidrId, color });
      }
    }

    for (const ip of ips) {
      const ipId = `ip-${ip.ip}`;
      nodes.push({
        id: ipId,
        label: ip.ip,
        type: "ip",
        x: Math.random() * 600 + 100,
        y: Math.random() * 400 + 100,
        vx: 0,
        vy: 0,
        radius: 12,
        color,
        data: ip,
      });
      const cidrId = `cidr-${ip.cidr}`;
      if (nodes.find((n) => n.id === cidrId)) {
        edges.push({ source: cidrId, target: ipId, color });
      } else {
        edges.push({ source: orgId, target: ipId, color });
      }
    }

    groups.push({
      org,
      asn: ips[0]?.asn || "",
      cidr: Array.from(cidrSet).join(", "),
      ips,
      color,
    });
  }

  return { nodes, edges, groups };
}

function simulateForces(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number) {
  const REPULSION = 3000;
  const ATTRACTION = 0.005;
  const DAMPING = 0.85;
  const CENTER_GRAVITY = 0.01;

  const cx = width / 2;
  const cy = height / 2;

  // Repulsion between all nodes
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
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
    const dist = Math.sqrt(dx * dx + dy * dy);
    const force = dist * ATTRACTION;
    const fx = (dx / Math.max(dist, 1)) * force;
    const fy = (dy / Math.max(dist, 1)) * force;
    source.vx += fx;
    source.vy += fy;
    target.vx -= fx;
    target.vy -= fy;
  }

  // Center gravity + update positions
  for (const node of nodes) {
    node.vx += (cx - node.x) * CENTER_GRAVITY;
    node.vy += (cy - node.y) * CENTER_GRAVITY;
    node.vx *= DAMPING;
    node.vy *= DAMPING;
    node.x += node.vx;
    node.y += node.vy;
    // Keep in bounds
    node.x = Math.max(node.radius, Math.min(width - node.radius, node.x));
    node.y = Math.max(node.radius, Math.min(height - node.radius, node.y));
  }
}

interface NetworkGraphProps {
  results: LookupResult[];
  onNodeSelect: (result: LookupResult | null) => void;
  onGroupsUpdate: (groups: NetworkGroup[]) => void;
}

export function NetworkGraph({ results, onNodeSelect, onGroupsUpdate }: NetworkGraphProps) {
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
    if (results.length === 0) {
      nodesRef.current = [];
      edgesRef.current = [];
      return;
    }
    const { nodes, edges, groups } = buildGraph(results);
    // Scatter around center
    for (const node of nodes) {
      node.x = canvasSize.width / 2 + (Math.random() - 0.5) * canvasSize.width * 0.6;
      node.y = canvasSize.height / 2 + (Math.random() - 0.5) * canvasSize.height * 0.6;
    }
    nodesRef.current = nodes;
    edgesRef.current = edges;
    onGroupsUpdate(groups);
  }, [results, canvasSize.width, canvasSize.height, onGroupsUpdate]);

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

    simulateForces(nodes, edges, canvasSize.width, canvasSize.height);

    ctx.clearRect(0, 0, canvasSize.width, canvasSize.height);

    // Grid
    ctx.strokeStyle = "rgba(100, 120, 140, 0.06)";
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
      ctx.strokeStyle = edge.color + "40";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // Nodes
    const hovered = hoveredNodeRef.current;
    for (const node of nodes) {
      const isHovered = hovered?.id === node.id;

      // Glow
      if (isHovered || node.type === "org") {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered ? 8 : 4), 0, Math.PI * 2);
        ctx.fillStyle = node.color + (isHovered ? "30" : "15");
        ctx.fill();
      }

      // Circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = node.type === "ip" ? node.color + "20" : node.color + "30";
      ctx.fill();
      ctx.strokeStyle = node.color;
      ctx.lineWidth = isHovered ? 2.5 : 1.5;
      ctx.stroke();

      // Icon/text inside
      ctx.fillStyle = node.color;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      if (node.type === "org") {
        ctx.font = "bold 10px Geist, sans-serif";
        // Draw building icon (simple)
        const s = 8;
        ctx.fillRect(node.x - s / 2, node.y - s / 2 - 2, s, s + 2);
        ctx.fillStyle = node.color + "30";
        ctx.fillRect(node.x - s / 2 + 2, node.y - s / 2, 2, 2);
        ctx.fillRect(node.x + s / 2 - 4, node.y - s / 2, 2, 2);
        ctx.fillRect(node.x - s / 2 + 2, node.y + 1, 2, 2);
        ctx.fillRect(node.x + s / 2 - 4, node.y + 1, 2, 2);
      } else if (node.type === "cidr") {
        ctx.font = "bold 8px Geist Mono, monospace";
        const parts = node.label.split("/");
        ctx.fillText("/" + (parts[1] || "24"), node.x, node.y);
      } else {
        ctx.font = "7px Geist Mono, monospace";
        const parts = node.label.split(".");
        ctx.fillText(parts[2] + "." + parts[3], node.x, node.y);
      }

      // Label below node
      ctx.fillStyle = node.color + "cc";
      ctx.font = node.type === "org" ? "bold 11px Geist, sans-serif" : "9px Geist Mono, monospace";
      ctx.fillText(
        node.label.length > 24 ? node.label.slice(0, 24) + "..." : node.label,
        node.x,
        node.y + node.radius + 12
      );
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
        if (dx * dx + dy * dy <= (n.radius + 4) * (n.radius + 4)) {
          return n;
        }
      }
      return null;
    },
    []
  );

  const getCanvasCoords = useCallback((e: React.MouseEvent | React.TouchEvent) => {
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
  }, []);

  const handlePointerDown = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      const coords = getCanvasCoords(e);
      const node = getNodeAt(coords.x, coords.y);
      if (node) {
        dragNodeRef.current = node;
        if (node.type === "ip" && node.data) {
          onNodeSelect(node.data);
        }
      }
    },
    [getCanvasCoords, getNodeAt, onNodeSelect]
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

  if (results.length === 0) {
    return (
      <div
        ref={containerRef}
        className="flex flex-1 items-center justify-center rounded-lg border border-border bg-card"
      >
        <div className="flex flex-col items-center gap-3 p-8 text-center">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-muted-foreground">
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
          <p className="text-muted-foreground text-sm">Enter IP addresses to map the network</p>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative flex-1 overflow-hidden rounded-lg border border-border bg-card">
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
          <span className="inline-block h-3 w-3 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">Organization</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">CIDR Block</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full border-2 border-primary bg-primary/20" />
          <span className="text-muted-foreground">IP Address</span>
        </span>
      </div>
    </div>
  );
}
