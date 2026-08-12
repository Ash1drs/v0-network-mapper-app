"use client";

// Client-side PDF text extraction using pdfjs-dist.
// Real PDF exports (VirusTotal Graph, AlienVault OTX reports, threat-intel
// briefings) are binary, so FileReader.readAsText produces garbage. We instead
// parse the PDF and concatenate the text content of every page, which the
// free-text IOC extractor in lib/ingest.ts can then scan.

// pdfjs-dist references browser globals (DOMMatrix, etc.) at module-evaluation
// time, so importing it at the top level crashes during server-side rendering.
// We load it lazily on first use — which only ever happens in the browser when
// a user actually parses a PDF — and cache the module.
type PdfjsModule = typeof import("pdfjs-dist");
let pdfjsPromise: Promise<PdfjsModule> | null = null;

async function loadPdfjs(): Promise<PdfjsModule> {
  if (!pdfjsPromise) {
    pdfjsPromise = import("pdfjs-dist").then((pdfjsLib) => {
      // Point pdf.js at its worker. The `new URL(..., import.meta.url)` form is
      // resolved and bundled by the app's bundler (Turbopack/webpack).
      pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
        "pdfjs-dist/build/pdf.worker.min.mjs",
        import.meta.url,
      ).toString();
      return pdfjsLib;
    });
  }
  return pdfjsPromise;
}

export async function isPdf(file: File): Promise<boolean> {
  if (file.type === "application/pdf") return true;
  if (/\.pdf$/i.test(file.name)) {
    // Confirm with the magic header so JSON/XML mislabeled as .pdf isn't
    // routed through the PDF path.
    const head = await file.slice(0, 5).text();
    return head.startsWith("%PDF-");
  }
  // Some files carry no extension/type but are still PDFs.
  const head = await file.slice(0, 5).text();
  return head.startsWith("%PDF-");
}

export async function extractPdfText(file: File): Promise<string> {
  const pdfjsLib = await loadPdfjs();
  const data = new Uint8Array(await file.arrayBuffer());
  const loadingTask = pdfjsLib.getDocument({ data });
  const doc = await loadingTask.promise;
  const parts: string[] = [];
  try {
    for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
      const page = await doc.getPage(pageNum);
      const content = await page.getTextContent();
      // Join text items; insert newlines between rows so tables stay readable.
      let lastY: number | null = null;
      let line = "";
      for (const item of content.items as Array<{ str: string; transform: number[] }>) {
        const y = item.transform?.[5] ?? null;
        if (lastY !== null && y !== null && Math.abs(y - lastY) > 2) {
          parts.push(line);
          line = "";
        }
        line += (line && !line.endsWith(" ") ? " " : "") + item.str;
        lastY = y;
      }
      if (line) parts.push(line);
      page.cleanup();
    }
  } finally {
    await loadingTask.destroy();
  }
  return parts.join("\n");
}
