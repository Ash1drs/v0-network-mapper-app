"use client";

import {
  useRef,
  useEffect,
  useCallback,
  useState,
  forwardRef,
  useImperativeHandle,
} from "react";
import {
  entityColor,
  zoneColor,
  categoryOf,
  categoryColor,
  confidenceColor,
  CATEGORY_COLOR,
  CATEGORY_LABEL,
  CATEGORY_ORDER,
  MATCH_COLOR,
  BRIDGE_COLOR,
  EDGE_KIND_LABEL,
  ZONE_COLOR,
  ZONE_LABEL,
  ZONE_ORDER,
  type EntityKind,
  type ThreatGraph,
  type Entity,
} from "@/lib/network-types";
import type { ColorMode } from "@/app/page";

// A rendered node carries live simulation state alongside its entity.
interface RNode {
  id: string;
  entity: Entity;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  degree: number;
}

interface REdge {
  source: string;
  target: string;
  kind: string;
  color: string;
  matched: boolean;
  crossZone: boolean;
  confidence: number;
}

const KIND_RADIUS: Record<EntityKind, number> = {
  asn: 13,
  ip: 9,
  domain: 7,
  url: 7,
  hash: 6,
};

// Cap the rendered graph so large feeds stay legible + performant.
const MAX_NODES = 350;

function buildRenderGraph(
  graph: ThreatGraph,
  feedOrder: string[],
  colorMode: ColorMode,
  width: number,
  height: number,
): { nodes: RNode[]; edges: REdge[] } {
  // Degree map for sizing + capping.
  const degree = new Map<string, number>();
  for (const r of graph.relationships) {
    degree.set(r.source, (degree.get(r.source) || 0) + 1);
    degree.set(r.target, (degree.get(r.target) || 0) + 1);
  }

  let entities = graph.entities;
  if (entities.length > MAX_NODES) {
    entities = [...entities]
      .sort((a, b) => {
        // Keep matches and high-degree nodes first.
        const am = a.matched ? 1 : 0;
        const bm = b.matched ? 1 : 0;
        if (am !== bm) return bm - am;
        return (degree.get(b.id) || 0) - (degree.get(a.id) || 0);
      })
      .slice(0, MAX_NODES);
  }
  const keep = new Set(entities.map((e) => e.id));

  const cx = width / 2;
  const cy = height / 2;
  const ringRadius = Math.min(width, height) * 0.38;

  const nodes: RNode[] = entities.map((e, i) => {
    const deg = degree.get(e.id) || 0;
    const angle = (i / entities.length) * Math.PI * 2;
    // Matched nodes start near the center so overlaps are visually central.
    const dist = (e.matched ? ringRadius * 0.35 : ringRadius) + (Math.random() - 0.5) * 60;
    return {
      id: e.id,
      entity: e,
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      vx: 0,
      vy: 0,
      // Node size grows with relationship count (spec: size = degree).
      radius: KIND_RADIUS[e.kind] + Math.min(deg, 10),
      color:
        colorMode === "zone"
          ? zoneColor(e.zone)
          : colorMode === "category"
            ? categoryColor(categoryOf(e))
            : entityColor(e, feedOrder),
      degree: deg,
    };
  });

  const zoneById = new Map(entities.map((e) => [e.id, e.zone]));

  const edges: REdge[] = graph.relationships
    .filter((r) => keep.has(r.source) && keep.has(r.target))
    .map((r) => {
      const confidence = r.confidence ?? 0;
      let color: string;
      if (colorMode === "zone") {
        color = r.crossZone ? BRIDGE_COLOR : zoneColor(zoneById.get(r.source));
      } else if (colorMode === "category") {
        // Edge hue follows confidence band so link strength reads at a glance.
        color = confidenceColor(confidence);
      } else {
        color = r.matched ? MATCH_COLOR : entityColor({ feeds: r.feeds }, feedOrder);
      }
      return {
        source: r.source,
        target: r.target,
        kind: r.kind,
        matched: !!r.matched,
        crossZone: !!r.crossZone,
        confidence,
        color,
      };
    });

  return { nodes, edges };
}

// ---- force simulation (module-level cooling temperature) ----
let simTemperature = 1.0;
const SIM_COOL_RATE = 0.985;
const SIM_MIN_TEMP = 0.001;

function resetSim() {
  simTemperature = 1.0;
}
function simSettled() {
  return simTemperature < SIM_MIN_TEMP;
}

function simulate(nodes: RNode[], edges: REdge[], width: number, height: number) {
  if (simSettled()) return;
  const REPULSION = 1600;
  const ATTRACTION = 0.012;
  const DAMPING = 0.6;
  const GRAVITY = 0.01;
  const temp = simTemperature;
  const cx = width / 2;
  const cy = height / 2;

  const n = nodes.length;
  // Repulsion (skip when huge to stay responsive).
  const doAllPairs = n <= 250;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (!doAllPairs && Math.random() > 0.5) continue;
      const dx = nodes[i].x - nodes[j].x;
      const dy = nodes[i].y - nodes[j].y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (REPULSION * temp) / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      nodes[i].vx += fx;
      nodes[i].vy += fy;
      nodes[j].vx -= fx;
      nodes[j].vy -= fy;
    }
  }

  const map = new Map(nodes.map((nd) => [nd.id, nd]));
  for (const e of edges) {
    const s = map.get(e.source);
    const t = map.get(e.target);
    if (!s || !t) continue;
    const dx = t.x - s.x;
    const dy = t.y - s.y;
    const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
    const force = (dist - 70) * ATTRACTION * temp;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;
    s.vx += fx;
    s.vy += fy;
    t.vx -= fx;
    t.vy -= fy;
  }

  for (const nd of nodes) {
    nd.vx += (cx - nd.x) * GRAVITY * temp;
    nd.vy += (cy - nd.y) * GRAVITY * temp;
    nd.vx *= DAMPING;
    nd.vy *= DAMPING;
    nd.x += nd.vx;
    nd.y += nd.vy;
    nd.x = Math.max(nd.radius + 4, Math.min(width - nd.radius - 4, nd.x));
    nd.y = Math.max(nd.radius + 4, Math.min(height - nd.radius - 4, nd.y));
  }
  simTemperature *= SIM_COOL_RATE;
}

function drawShape(
  ctx: CanvasRenderingContext2D,
  kind: EntityKind,
  x: number,
  y: number,
  r: number,
) {
  ctx.beginPath();
  switch (kind) {
    case "ip": // square
      ctx.rect(x - r, y - r, r * 2, r * 2);
      break;
    case "url": // triangle
      ctx.moveTo(x, y - r);
      ctx.lineTo(x + r, y + r);
      ctx.lineTo(x - r, y + r);
      ctx.closePath();
      break;
    case "hash": // diamond
      ctx.moveTo(x, y - r);
      ctx.lineTo(x + r, y);
      ctx.lineTo(x, y + r);
      ctx.lineTo(x - r, y);
      ctx.closePath();
      break;
    case "asn": // hexagon
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        const px = x + Math.cos(a) * r;
        const py = y + Math.sin(a) * r;
        i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
      }
      ctx.closePath();
      break;
    default: // domain -> circle
      ctx.arc(x, y, r, 0, Math.PI * 2);
  }
}

interface NetworkGraphProps {
  graph: ThreatGraph;
  feedOrder: string[];
  colorMode: ColorMode;
  selectedId: string | null;
  onSelectEntity: (entity: Entity | null) => void;
}

export interface NetworkGraphHandle {
  // Returns the live canvas element so callers can snapshot it (PNG/PDF export).
  getCanvas: () => HTMLCanvasElement | null;
}

export const NetworkGraph = forwardRef<NetworkGraphHandle, NetworkGraphProps>(
  function NetworkGraph({ graph, feedOrder, colorMode, selectedId, onSelectEntity }, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useImperativeHandle(ref, () => ({ getCanvas: () => canvasRef.current }), []);
  const nodesRef = useRef<RNode[]>([]);
  const edgesRef = useRef<REdge[]>([]);
  const animRef = useRef<number>(0);
  const dragRef = useRef<RNode | null>(null);
  const hoverRef = useRef<RNode | null>(null);
  const needsRedraw = useRef(true);
  const [size, setSize] = useState({ width: 800, height: 500 });

  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver((entries) => {
      const e = entries[0];
      if (e) setSize({ width: e.contentRect.width, height: Math.max(e.contentRect.height, 300) });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (graph.entities.length === 0) {
      nodesRef.current = [];
      edgesRef.current = [];
      return;
    }
    const { nodes, edges } = buildRenderGraph(graph, feedOrder, colorMode, size.width, size.height);
    nodesRef.current = nodes;
    edgesRef.current = edges;
    resetSim();
    needsRedraw.current = true;
  }, [graph, feedOrder, colorMode, size.width, size.height]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size.width * dpr;
    canvas.height = size.height * dpr;
    ctx.scale(dpr, dpr);

    const nodes = nodesRef.current;
    const edges = edgesRef.current;
    const active = !simSettled();
    if (nodes.length && active) simulate(nodes, edges, size.width, size.height);

    ctx.clearRect(0, 0, size.width, size.height);

    // grid
    ctx.strokeStyle = "rgba(100, 120, 140, 0.05)";
    ctx.lineWidth = 1;
    for (let x = 0; x < size.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, size.height);
      ctx.stroke();
    }
    for (let y = 0; y < size.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(size.width, y);
      ctx.stroke();
    }

    const map = new Map(nodes.map((n) => [n.id, n]));
    const hovered = hoverRef.current;
    const focusId = hovered?.id || selectedId;
    const neighborIds = new Set<string>();
    if (focusId) {
      for (const e of edges) {
        if (e.source === focusId) neighborIds.add(e.target);
        if (e.target === focusId) neighborIds.add(e.source);
      }
    }

    // edges
    for (const e of edges) {
      const s = map.get(e.source);
      const t = map.get(e.target);
      if (!s || !t) continue;
      const focused = focusId && (e.source === focusId || e.target === focusId);
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);
      // Cross-zone (pivot) edges are dashed + brighter so the crossover paths
      // between environments stand out from same-zone links.
      if (e.crossZone) ctx.setLineDash([5, 3]);
      ctx.strokeStyle =
        e.color + (focused ? "" : focusId ? "18" : e.crossZone ? "cc" : e.matched ? "70" : "40");
      // Edge thickness encodes confidence (spec): stronger links draw heavier.
      const confWidth = 0.75 + (e.confidence / 100) * 2.75; // 0.75 .. 3.5
      ctx.lineWidth = e.crossZone ? Math.max(2, confWidth) : confWidth;
      ctx.stroke();
      ctx.setLineDash([]);

      // edge label when connected to focused node
      if (focused) {
        const mx = (s.x + t.x) / 2;
        const my = (s.y + t.y) / 2;
        ctx.fillStyle = "rgba(15,18,30,0.85)";
        const label = EDGE_KIND_LABEL[e.kind as keyof typeof EDGE_KIND_LABEL] || e.kind;
        ctx.font = "9px Geist, sans-serif";
        const w = ctx.measureText(label).width + 8;
        ctx.beginPath();
        ctx.roundRect(mx - w / 2, my - 7, w, 14, 3);
        ctx.fill();
        ctx.fillStyle = e.color;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(label, mx, my);
      }
    }

    // nodes
    for (const node of nodes) {
      const isHovered = hovered?.id === node.id;
      const isSelected = selectedId === node.id;
      const dim = focusId && !isHovered && !isSelected && !neighborIds.has(node.id);
      const e = node.entity;

      ctx.globalAlpha = dim ? 0.28 : 1;

      // pivot/bridge halo — a dashed near-white outer ring. These nodes connect
      // two different environments and are the crossover points of the attack.
      if (e.isBridge) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 9, 0, Math.PI * 2);
        ctx.setLineDash([3, 3]);
        ctx.strokeStyle = BRIDGE_COLOR + "dd";
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // case seed-anchor marker — a solid gold outer ring so investigation
      // anchor nodes are unmistakable in any color mode.
      if (e.isAnchor) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 7, 0, Math.PI * 2);
        ctx.strokeStyle = "#fbbf24";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // match glow ring
      if (e.matched) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
        ctx.fillStyle = MATCH_COLOR + "22";
        ctx.fill();
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 4, 0, Math.PI * 2);
        ctx.strokeStyle = MATCH_COLOR;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // high-risk secondary ring
      if (e.riskScore >= 70 && !e.matched) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
        ctx.strokeStyle = "#f8717199";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // shape body
      drawShape(ctx, e.kind, node.x, node.y, node.radius);
      ctx.fillStyle = node.color + "26";
      ctx.fill();
      ctx.strokeStyle = node.color;
      ctx.lineWidth = isHovered || isSelected ? 2.5 : 1.25;
      ctx.stroke();

      // asn label inside
      if (e.kind === "asn") {
        ctx.fillStyle = node.color;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.font = "bold 7px Geist Mono, monospace";
        ctx.fillText(e.value.replace(/^AS/, "").slice(0, 6), node.x, node.y);
      }

      ctx.globalAlpha = 1;

      // hover/selected tooltip
      if (isHovered || isSelected) {
        const label = e.value.length > 32 ? e.value.slice(0, 30) + "…" : e.value;
        ctx.font = "bold 10px Geist Mono, monospace";
        const w = ctx.measureText(label).width + 14;
        const lx = node.x - w / 2;
        const ly = node.y - node.radius - 24;
        ctx.fillStyle = "rgba(12,14,24,0.94)";
        ctx.beginPath();
        ctx.roundRect(lx, ly, w, 18, 4);
        ctx.fill();
        ctx.strokeStyle = node.color + "cc";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = "#e2e8f0";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(label, node.x, ly + 9);
      }
    }

    if (active || dragRef.current || needsRedraw.current) {
      needsRedraw.current = false;
      animRef.current = requestAnimationFrame(draw);
    }
  }, [size, selectedId]);

  const startLoop = useCallback(() => {
    cancelAnimationFrame(animRef.current);
    animRef.current = requestAnimationFrame(draw);
  }, [draw]);

  // Restart the animation loop whenever the render inputs change. This must
  // include `graph`/`feedOrder` because the loop halts once the simulation
  // settles (and while the empty-state placeholder has no canvas), so new data
  // needs to explicitly kick it back off.
  useEffect(() => {
    startLoop();
    return () => cancelAnimationFrame(animRef.current);
  }, [startLoop, graph, feedOrder, colorMode]);

  const coords = useCallback((ev: React.MouseEvent | React.TouchEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    if ("touches" in ev)
      return { x: ev.touches[0].clientX - rect.left, y: ev.touches[0].clientY - rect.top };
    return {
      x: (ev as React.MouseEvent).clientX - rect.left,
      y: (ev as React.MouseEvent).clientY - rect.top,
    };
  }, []);

  const nodeAt = useCallback((x: number, y: number): RNode | null => {
    const nodes = nodesRef.current;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = x - n.x;
      const dy = y - n.y;
      if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) return n;
    }
    return null;
  }, []);

  const onDown = useCallback(
    (ev: React.MouseEvent | React.TouchEvent) => {
      const c = coords(ev);
      const node = nodeAt(c.x, c.y);
      if (node) {
        dragRef.current = node;
        simTemperature = Math.max(simTemperature, 0.12);
        onSelectEntity(node.entity);
        needsRedraw.current = true;
        startLoop();
      } else {
        onSelectEntity(null);
        needsRedraw.current = true;
        startLoop();
      }
    },
    [coords, nodeAt, onSelectEntity, startLoop],
  );

  const onMove = useCallback(
    (ev: React.MouseEvent | React.TouchEvent) => {
      const c = coords(ev);
      const node = nodeAt(c.x, c.y);
      const prev = hoverRef.current;
      hoverRef.current = node;
      if (dragRef.current) {
        dragRef.current.x = c.x;
        dragRef.current.y = c.y;
        dragRef.current.vx = 0;
        dragRef.current.vy = 0;
      }
      if (prev?.id !== node?.id || dragRef.current) {
        needsRedraw.current = true;
        startLoop();
      }
      const canvas = canvasRef.current;
      if (canvas) canvas.style.cursor = node ? "pointer" : "default";
    },
    [coords, nodeAt, startLoop],
  );

  const onUp = useCallback(() => {
    dragRef.current = null;
  }, []);

  if (graph.entities.length === 0) {
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
          <p className="text-muted-foreground text-sm max-w-xs text-pretty">
            Upload STIX, MISP/VirusTotal, OpenIOC (AlienVault), passive DNS, or CSV to map the relationship graph
          </p>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative flex-1 overflow-hidden rounded-lg border border-border bg-card">
      <canvas
        ref={canvasRef}
        style={{ width: size.width, height: size.height }}
        onMouseDown={onDown}
        onMouseMove={onMove}
        onMouseUp={onUp}
        onMouseLeave={onUp}
        onTouchStart={onDown}
        onTouchMove={onMove}
        onTouchEnd={onUp}
        className="touch-none"
      />
      <GraphLegend colorMode={colorMode} />
    </div>
  );
});

function GraphLegend({ colorMode }: { colorMode: ColorMode }) {
  const shapes: { kind: EntityKind; label: string }[] = [
    { kind: "domain", label: "Domain" },
    { kind: "ip", label: "IP" },
    { kind: "url", label: "URL" },
    { kind: "hash", label: "Hash" },
    { kind: "asn", label: "ASN" },
  ];
  return (
    <div className="absolute bottom-3 left-3 flex max-w-[calc(100%-1.5rem)] flex-wrap items-center gap-x-3 gap-y-1.5 rounded-md border border-border bg-card/90 px-3 py-2 text-xs backdrop-blur-sm">
      {colorMode === "category" ? (
        <>
          {CATEGORY_ORDER.map((c) => (
            <span key={c} className="flex items-center gap-1.5 text-muted-foreground">
              <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: CATEGORY_COLOR[c] }} />
              {CATEGORY_LABEL[c]}
            </span>
          ))}
          <span className="text-muted-foreground/50">|</span>
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="inline-block h-0.5 w-4 rounded-full bg-foreground" />
            <span>Edge weight = confidence</span>
          </span>
        </>
      ) : colorMode === "zone" ? (
        <>
          {ZONE_ORDER.map((z) => (
            <span key={z} className="flex items-center gap-1.5 text-muted-foreground">
              <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: ZONE_COLOR[z] }} />
              {ZONE_LABEL[z]}
            </span>
          ))}
          <span className="text-muted-foreground/50">|</span>
          <span className="flex items-center gap-1.5">
            <span
              className="inline-block h-3 w-3 rounded-full border-2 border-dashed"
              style={{ borderColor: BRIDGE_COLOR }}
            />
            <span className="text-foreground font-medium">Pivot (bridges zones)</span>
          </span>
        </>
      ) : (
        <>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: MATCH_COLOR }} />
            <span className="text-foreground font-medium">Match (multi-feed)</span>
          </span>
          <span className="text-muted-foreground/50">|</span>
          {shapes.map((s) => (
            <span key={s.kind} className="flex items-center gap-1.5 text-muted-foreground">
              <ShapeIcon kind={s.kind} />
              {s.label}
            </span>
          ))}
        </>
      )}
    </div>
  );
}

function ShapeIcon({ kind }: { kind: EntityKind }) {
  const c = "var(--color-muted-foreground)";
  if (kind === "ip")
    return <span className="inline-block h-2.5 w-2.5 border" style={{ borderColor: c }} />;
  if (kind === "hash")
    return <span className="inline-block h-2.5 w-2.5 rotate-45 border" style={{ borderColor: c }} />;
  if (kind === "url")
    return (
      <span
        className="inline-block h-0 w-0"
        style={{ borderLeft: "5px solid transparent", borderRight: "5px solid transparent", borderBottom: `9px solid ${c}` }}
      />
    );
  if (kind === "asn")
    return <span className="inline-block h-2.5 w-2.5 border" style={{ borderColor: c, clipPath: "polygon(25% 0, 75% 0, 100% 50%, 75% 100%, 25% 100%, 0 50%)" }} />;
  return <span className="inline-block h-2.5 w-2.5 rounded-full border" style={{ borderColor: c }} />;
}
