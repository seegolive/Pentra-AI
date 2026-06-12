import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import {
  RefreshCw,
  Copy,
  Check,
  FileText,
  FileCode,
  ShieldAlert,
  Loader2,
  AlertCircle,
  Eye,
  Code2,
} from "lucide-react";
import { useEngagementReport } from "../../lib/api";
import { useAuthStore } from "../../lib/authStore";
import { cn } from "../../lib/utils";

// ── Markdown component renderers ──────────────────────────────────────────────

const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="text-xl font-bold text-foreground mt-6 mb-3 pb-2 border-b border-border">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="text-base font-semibold text-foreground mt-5 mb-2 pb-1 border-b border-border/50">
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-sm font-semibold text-foreground mt-4 mb-1.5">{children}</h3>
  ),
  h4: ({ children }) => (
    <h4 className="text-xs font-semibold text-foreground/90 uppercase tracking-wide mt-3 mb-1">
      {children}
    </h4>
  ),
  p: ({ children }) => (
    <p className="text-sm text-foreground/80 leading-relaxed mb-3">{children}</p>
  ),
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-primary underline underline-offset-2 hover:text-primary/80"
    >
      {children}
    </a>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-inside mb-3 space-y-1 text-sm text-foreground/80 pl-2">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-inside mb-3 space-y-1 text-sm text-foreground/80 pl-2">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-primary/40 pl-3 py-0.5 my-3 text-sm text-muted-foreground italic bg-muted/20 rounded-r">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="border-border my-5" />,
  strong: ({ children }) => (
    <strong className="font-semibold text-foreground">{children}</strong>
  ),
  em: ({ children }) => <em className="italic text-foreground/80">{children}</em>,
  code: ({ children, className }) => {
    // Inline code (no className) vs block code (has language-* className)
    const isBlock = !!className;
    if (isBlock) return <code className={className}>{children}</code>;
    return (
      <code className="text-xs font-mono bg-muted/60 border border-border/50 rounded px-1 py-0.5 text-primary/90">
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="bg-muted/40 border border-border rounded-md p-3 my-3 overflow-x-auto text-xs font-mono text-foreground/85 leading-relaxed">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-md border border-border">
      <table className="w-full text-xs border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-muted/40 text-muted-foreground">{children}</thead>
  ),
  tbody: ({ children }) => <tbody className="divide-y divide-border/50">{children}</tbody>,
  tr: ({ children }) => (
    <tr className="hover:bg-muted/10 transition-colors">{children}</tr>
  ),
  th: ({ children }) => (
    <th className="px-3 py-2 text-left font-medium text-[11px] uppercase tracking-wide border-b border-border">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 text-foreground/80">{children}</td>
  ),
};

// ── Download helpers ──────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const DOWNLOAD_FORMATS = [
  {
    format: "markdown",
    label: "Markdown",
    ext: "md",
    icon: FileText,
    iconColor: "text-blue-400",
  },
  {
    format: "html",
    label: "HTML",
    ext: "html",
    icon: FileCode,
    iconColor: "text-orange-400",
  },
  {
    format: "pdf",
    label: "PDF",
    ext: "pdf",
    icon: FileText,
    iconColor: "text-red-400",
  },
  {
    format: "h1",
    label: "HackerOne",
    ext: "md",
    icon: ShieldAlert,
    iconColor: "text-green-400",
  },
  {
    format: "h1-summary",
    label: "H1 Executive",
    ext: "md",
    icon: ShieldAlert,
    iconColor: "text-yellow-400",
  },
] as const;

// ── Main component ─────────────────────────────────────────────────────────────

interface ReportViewerProps {
  engagementId: string;
}

export function ReportViewer({ engagementId }: ReportViewerProps) {
  const [view, setView] = useState<"preview" | "raw">("preview");
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const { data: markdown, isLoading, isError, error, refetch, isFetching } =
    useEngagementReport(engagementId);

  const copy = () => {
    if (!markdown) return;
    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const download = async (format: string, ext: string) => {
    setDownloading(format);
    try {
      const token = useAuthStore.getState().accessToken;
      // H1 Executive Summary uses a different endpoint (Task 19.5)
      const reportUrl = format === "h1-summary"
        ? `${API_BASE}/api/v1/engagements/${engagementId}/report/h1-summary`
        : `${API_BASE}/api/v1/engagements/${engagementId}/report?format=${format}`;
      const res = await fetch(reportUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `pentra-report-${engagementId.slice(0, 8)}.${ext}`;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch {
      // silently fail — user sees no download
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="flex flex-col h-full gap-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* View toggle */}
        <div className="flex rounded-md border border-border overflow-hidden text-xs">
          <button
            onClick={() => setView("preview")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 transition-colors",
              view === "preview"
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/40",
            )}
          >
            <Eye className="h-3 w-3" />
            Preview
          </button>
          <button
            onClick={() => setView("raw")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 border-l border-border transition-colors",
              view === "raw"
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/40",
            )}
          >
            <Code2 className="h-3 w-3" />
            Raw
          </button>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {/* Copy */}
          <button
            onClick={copy}
            disabled={!markdown || isFetching}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs border border-border rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/40 disabled:opacity-40 transition-colors"
          >
            {copied ? (
              <Check className="h-3 w-3 text-green-500" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
            {copied ? "Copied" : "Copy MD"}
          </button>

          {/* Refresh */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs border border-border rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/40 disabled:opacity-40 transition-colors"
          >
            <RefreshCw className={cn("h-3 w-3", isFetching && "animate-spin")} />
            Refresh
          </button>
        </div>
      </div>

      {/* Content area */}
      <div className="flex-1 min-h-0 rounded-md border border-border overflow-hidden flex flex-col">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground py-16">
            <Loader2 className="h-6 w-6 animate-spin" />
            <p className="text-sm">Generating report…</p>
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center flex-1 gap-3 text-muted-foreground py-16">
            <AlertCircle className="h-6 w-6 text-red-400" />
            <p className="text-sm text-red-400">{error?.message ?? "Failed to load report"}</p>
            <button
              onClick={() => refetch()}
              className="mt-1 px-3 py-1.5 text-xs border border-border rounded-md hover:bg-muted/40 transition-colors"
            >
              Try again
            </button>
          </div>
        ) : !markdown ? (
          <div className="flex flex-col items-center justify-center flex-1 gap-2 text-muted-foreground py-16">
            <FileText className="h-8 w-8 opacity-30" />
            <p className="text-sm">No report yet — run the agent to completion first</p>
          </div>
        ) : view === "preview" ? (
          <div className="overflow-y-auto flex-1 p-5">
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
              {markdown}
            </ReactMarkdown>
          </div>
        ) : (
          <pre className="overflow-auto flex-1 p-4 text-xs font-mono text-foreground/80 leading-relaxed bg-muted/20 whitespace-pre-wrap break-words">
            {markdown}
          </pre>
        )}
      </div>

      {/* Download strip */}
      <div className="flex items-center gap-2 flex-wrap border-t border-border pt-3">
        <span className="text-xs text-muted-foreground">Download:</span>
        {DOWNLOAD_FORMATS.map(({ format, label, ext, icon: Icon, iconColor }) => (
          <button
            key={format}
            onClick={() => download(format, ext)}
            disabled={downloading === format || isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-border rounded-md bg-background/50 hover:bg-muted/40 disabled:opacity-50 transition-colors"
          >
            {downloading === format ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Icon className={cn("h-3 w-3", iconColor)} />
            )}
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
