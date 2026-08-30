"use client";

import { useRef, useEffect, useCallback, useState, forwardRef, useImperativeHandle } from "react";
import type { GraphNode, GraphEdge, AsnGroup } from "@/lib/network-types";

export interface NetworkGraphHandle {
  getCanvas: () => HTMLCanvasElement | null;
}

function riskColor(score: number): string {
  if (score >= 70) return "#f87171";
  if (score >= 40) return "#fbbf24";
  if (score >= 20) return "#38bdf8";
  return "#4ade80";
}

function buildGraph(
  groups: AsnGroup[],
  width: number,
  height: number,
  selectedAsn: string | null
): {
  nodes: GraphNode[];
  edges: GraphEdge[];
} {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const n = groups.length;
  if (n === 0) return { nodes, edges };

  // Lay ASN clusters out on a grid that fills the canvas, so clusters stay
  // separated instead of collapsing into one blob.
  const cols = Math.ceil(Math.sqrt(n * (width / Math.max(height, 1))));
  const rows = Math.ceil(n / cols);
  const cellW = width / cols;
  const cellH = height / rows;
  // Radius available for a cluster's IP rings within its cell
  const clusterRadius = Math.min(cellW, cellH) * 0.34;

  for (let gi = 0; gi < groups.length; gi++) {
    const group = groups[gi];
    const col = gi % cols;
    const row = Math.floor(gi / cols);
    const hubX = cellW * (col + 0.5);
    const hubY = cellH * (row + 0.5);

    const asnId = `asn-${group.asn}`;
    nodes.push({
      id: asnId,
      label: group.asName.length > 24 ? group.asName.slice(0, 22) + "..." : group.asName,
      type: "asn",
      x: hubX,
      y: hubY,
      vx: 0,
      vy: 0,
      homeX: hubX,
      homeY: hubY,
      radius: Math.min(12 + Math.sqrt(group.ips.length) * 3, 30),
      color: group.color,
      riskScore: group.maxRiskScore,
      asnGroup: group,
    });

    const isSelected = selectedAsn === group.asn;

    // IP nodes arranged in concentric rings around the hub
    const ipCount = group.ips.length;
    const perRing = Math.max(6, Math.ceil(Math.sqrt(ipCount) * 2));
    for (let i = 0; i < ipCount; i++) {
      const ip = group.ips[i];
      const ipId = `ip-${ip}`;
      const ring = Math.floor(i / perRing) + 1;
      const idxInRing = i % perRing;
      const ringRadius = (clusterRadius * ring) / (Math.ceil(ipCount / perRing) + 0.5);
      const ipAngle = (idxInRing / perRing) * Math.PI * 2 + ring * 0.6;
      const ix = hubX + Math.cos(ipAngle) * ringRadius;
      const iy = hubY + Math.sin(ipAngle) * ringRadius;

      const ipRecords = group.records.filter((r) => r.answer === ip);
      const ipRisk = ipRecords.length > 0 ? Math.max(...ipRecords.map((r) => r.answer_risk_score)) : 0;

      nodes.push({
        id: ipId,
        label: ip,
        type: "ip",
        x: ix,
        y: iy,
        vx: 0,
        vy: 0,
        homeX: ix,
        homeY: iy,
        radius: 6,
        color: group.color,
        riskScore: ipRisk,
        parentId: asnId,
      });

      edges.push({ source: asnId, target: ipId, color: group.color });

      // Domain nodes only for the SELECTED cluster (keeps the map readable)
      if (isSelected) {
        const uniqueDomains = [...new Set(ipRecords.map((r) => r.query).filter(Boolean))].slice(0, 4);
        for (let d = 0; d < uniqueDomains.length; d++) {
          const domain = uniqueDomains[d];
          const domainId = `dom-${domain}-${ip}`;
          const domAngle = ipAngle + (d - uniqueDomains.length / 2) * 0.5;
          const domDist = 22;
          const dx = ix + Math.cos(domAngle) * domDist;
          const dy = iy + Math.sin(domAngle) * domDist;
          const domRecord = ipRecords.find((r) => r.query === domain);
          const domRisk = domRecord?.query_risk_score ?? 0;

          nodes.push({
            id: domainId,
            label: domain.length > 20 ? domain.slice(0, 18) + "..." : domain,
            type: "domain",
            x: dx,
            y: dy,
            vx: 0,
            vy: 0,
            homeX: dx,
            homeY: dy,
            radius: 4,
            color: riskColor(domRisk),
            riskScore: domRisk,
            parentId: ipId,
            data: domRecord,
          });

          edges.push({ source: ipId, target: domainId, color: group.color + "60" });
        }
      }
    }
  }

  return { nodes, edges };
}

// Simulation state -- temperature cools the sim so it settles
let simTemperature = 1.0;
const SIM_COOL_RATE = 0.97; // multiply each tick
const SIM_MIN_TEMP = 0.001; // below this, sim is frozen

function resetSimTemperature() {
  simTemperature = 1.0;
}

function isSimSettled() {
  return simTemperature < SIM_MIN_TEMP;
}

function simulateForces(
  nodes: GraphNode[],
  _edges: GraphEdge[],
  width: number,
  height: number
) {
  if (simTemperature < SIM_MIN_TEMP) return;

  const HOME_SPRING = 0.08; // pull each node toward its computed home
  const COLLISION = 0.5; // how hard overlapping nodes push apart
  const DAMPING = 0.75;
  const temp = simTemperature;

  // Short-range collision resolution so nodes don't overlap.
  // Skip domains against domains to keep it cheap on large graphs.
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      if (a.type === "domain" && b.type === "domain") continue;
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const minDist = a.radius + b.radius + 4;
      const distSq = dx * dx + dy * dy;
      if (distSq >= minDist * minDist || distSq === 0) continue;
      const dist = Math.sqrt(distSq) || 1;
      const overlap = (minDist - dist) / dist;
      const fx = dx * overlap * COLLISION;
      const fy = dy * overlap * COLLISION;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }
  }

  for (const node of nodes) {
    // Spring back toward home anchor
    node.vx += (node.homeX - node.x) * HOME_SPRING;
    node.vy += (node.homeY - node.y) * HOME_SPRING;
    node.vx *= DAMPING;
    node.vy *= DAMPING;
    node.x += node.vx;
    node.y += node.vy;
    node.x = Math.max(node.radius + 4, Math.min(width - node.radius - 4, node.x));
    node.y = Math.max(node.radius + 4, Math.min(height - node.radius - 4, node.y));
  }

  simTemperature *= SIM_COOL_RATE;
}

interface NetworkGraphProps {
  groups: AsnGroup[];
  onSelectGroup: (group: AsnGroup | null) => void;
  selectedAsn?: string | null;
}

export const NetworkGraph = forwardRef<NetworkGraphHandle, NetworkGraphProps>(
  function NetworkGraph({ groups, onSelectGroup, selectedAsn = null }, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const edgesRef = useRef<GraphEdge[]>([]);
  const animFrameRef = useRef<number>(0);
  const dragNodeRef = useRef<GraphNode | null>(null);
  const hoveredNodeRef = useRef<GraphNode | null>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 500 });

  useImperativeHandle(ref, () => ({
    getCanvas: () => canvasRef.current,
  }), []);

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

  const needsRedrawRef = useRef(true);

  useEffect(() => {
    if (groups.length === 0) {
      nodesRef.current = [];
      edgesRef.current = [];
      return;
    }
    const { nodes, edges } = buildGraph(groups, canvasSize.width, canvasSize.height, selectedAsn);
    nodesRef.current = nodes;
    edgesRef.current = edges;
    resetSimTemperature();
    needsRedrawRef.current = true;
  }, [groups, canvasSize.width, canvasSize.height, selectedAsn]);

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

    const simActive = !isSimSettled();
    if (nodes.length > 0 && simActive) {
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

    // Only keep looping if sim is still cooling or user is dragging
    if (simActive || dragNodeRef.current || needsRedrawRef.current) {
      needsRedrawRef.current = false;
      animFrameRef.current = requestAnimationFrame(draw);
    }
  }, [canvasSize]);

  // Kick off the loop whenever draw changes or we need a redraw
  const startLoop = useCallback(() => {
    cancelAnimationFrame(animFrameRef.current);
    animFrameRef.current = requestAnimationFrame(draw);
  }, [draw]);

  useEffect(() => {
    startLoop();
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [startLoop]);

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
        // Gently reheat so neighbors settle around dragged node
        simTemperature = Math.max(simTemperature, 0.15);
        startLoop();
        if (node.type === "asn" && node.asnGroup) {
          onSelectGroup(node.asnGroup);
        }
      }
    },
    [getCanvasCoords, getNodeAt, onSelectGroup, startLoop]
  );

  const handlePointerMove = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      const coords = getCanvasCoords(e);
      const node = getNodeAt(coords.x, coords.y);
      const prevHovered = hoveredNodeRef.current;
      hoveredNodeRef.current = node;

      if (dragNodeRef.current) {
        dragNodeRef.current.x = coords.x;
        dragNodeRef.current.y = coords.y;
        dragNodeRef.current.vx = 0;
        dragNodeRef.current.vy = 0;
      }

      // Redraw for hover tooltip changes (even when sim is settled)
      if (prevHovered?.id !== node?.id || dragNodeRef.current) {
        needsRedrawRef.current = true;
        startLoop();
      }

      const canvas = canvasRef.current;
      if (canvas) {
        canvas.style.cursor = node ? "pointer" : "default";
      }
    },
    [getCanvasCoords, getNodeAt, startLoop]
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
});
