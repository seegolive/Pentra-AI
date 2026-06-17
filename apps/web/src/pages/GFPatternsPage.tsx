import { useState, useEffect } from "react";
import {
  Filter,
  ChevronDown,
  ChevronRight,
  Upload,
  Edit3,
  X,
  CheckCircle2,
} from "lucide-react";
import { cn } from "../lib/utils";
import { toastSuccess, toastError } from "../lib/toast";

// ── Types & Defaults ──────────────────────────────────────────────────────────

interface GFPattern {
  name: string;
  description: string;
  regexes: string[];
  enabled: boolean;
}

const DEFAULT_PATTERNS: GFPattern[] = [
  { name: "xss", description: "Cross-site scripting sinks", regexes: ["=[^&]*<script", "=[^&]*onerror", "=[^&]*alert", "=[^&]*prompt", "=[^&]*confirm"], enabled: true },
  { name: "sqli", description: "SQL injection parameters", regexes: ["id=", "user=", "item=", "cat=", "product=", "page=", "search="], enabled: true },
  { name: "ssrf", description: "Server-side request forgery", regexes: ["url=", "uri=", "path=", "redirect=", "dest=", "feed=", "src="], enabled: true },
  { name: "open-redirect", description: "Open redirect parameters", regexes: ["next=", "return=", "returnUrl=", "redirect_uri=", "goto=", "continue="], enabled: true },
  { name: "idor", description: "Insecure direct object reference", regexes: ["id=", "user_id=", "account=", "profile=", "order=", "invoice="], enabled: true },
  { name: "debug", description: "Debug/testing parameters", regexes: ["debug=", "test=", "admin=", "dev=", "verbose=", "trace="], enabled: true },
  { name: "lfi", description: "Local file inclusion", regexes: ["file=", "path=", "template=", "include=", "page=", "document="], enabled: true },
  { name: "xxe", description: "XML external entity", regexes: ["\\.xml", "format=xml", "type=xml", "content-type.*xml"], enabled: true },
  { name: "cors", description: "CORS misconfiguration test", regexes: ["Access-Control-Allow-Origin", "origin=", "host="], enabled: false },
  { name: "rce", description: "Remote code execution", regexes: ["cmd=", "exec=", "command=", "ping=", "query=", "shell="], enabled: true },
  { name: "ssti", description: "Server-side template injection", regexes: ["template=", "view=", "name=", "preview=", "render="], enabled: false },
  { name: "upload", description: "File upload parameters", regexes: ["file=", "upload=", "image=", "photo=", "avatar=", "attachment="], enabled: true },
];

const STORAGE_KEY = "pentra-gf-patterns";

function loadPatterns(): GFPattern[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return JSON.parse(stored) as GFPattern[];
  } catch {
    // ignore
  }
  return DEFAULT_PATTERNS;
}

function savePatterns(patterns: GFPattern[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(patterns));
}

// ── URL Tester ────────────────────────────────────────────────────────────────

function UrlTester({ patterns }: { patterns: GFPattern[] }) {
  const [url, setUrl] = useState("");

  const enabledPatterns = patterns.filter((p) => p.enabled);

  const matches = url
    ? enabledPatterns.filter((p) =>
        p.regexes.some((re) => {
          try {
            return new RegExp(re, "i").test(url);
          } catch {
            return false;
          }
        })
      )
    : [];

  return (
    <div className="rounded-ds-md border border-pentra-border bg-pentra-bg-card p-4 space-y-3">
      <h3 className="text-[13px] font-semibold text-pentra-text-primary">URL Tester</h3>
      <input
        type="text"
        placeholder="https://example.com/api?id=123&redirect=..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[12px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
      />
      {url && (
        <div>
          {matches.length === 0 ? (
            <p className="text-[12px] text-pentra-text-muted">No patterns matched</p>
          ) : (
            <div className="space-y-1">
              <p className="text-[11px] font-semibold text-pentra-status-waiting mb-1">
                {matches.length} pattern(s) matched:
              </p>
              {matches.map((p) => (
                <div key={p.name} className="flex items-center gap-2">
                  <span className="text-[10px] font-mono bg-pentra-bg-hover px-1.5 py-0.5 rounded text-pentra-accent-light">
                    {p.name}
                  </span>
                  <span className="text-[11px] text-pentra-text-secondary">{p.description}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Edit Pattern Modal ────────────────────────────────────────────────────────

interface EditModalProps {
  pattern: GFPattern;
  onSave: (updated: GFPattern) => void;
  onClose: () => void;
}

function EditPatternModal({ pattern, onSave, onClose }: EditModalProps) {
  const [regexText, setRegexText] = useState(pattern.regexes.join("\n"));

  const handleSave = () => {
    const regexes = regexText.split("\n").map((s) => s.trim()).filter(Boolean);
    if (regexes.length === 0) {
      toastError("Validation", "At least one regex is required");
      return;
    }
    onSave({ ...pattern, regexes });
    toastSuccess("Pattern updated", pattern.name);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[480px] rounded-ds-lg border border-pentra-border bg-pentra-bg-panel shadow-2xl">
        <div className="flex items-center justify-between border-b border-pentra-border px-4 py-3.5">
          <h2 className="text-[15px] font-semibold text-pentra-text-primary">Edit Pattern: {pattern.name}</h2>
          <button type="button" onClick={onClose} className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="p-4">
          <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">
            Regexes (one per line)
          </label>
          <textarea
            rows={10}
            value={regexText}
            onChange={(e) => setRegexText(e.target.value)}
            className="w-full resize-none rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[12px] font-mono text-pentra-text-primary outline-none focus:border-pentra-border-focus"
          />
        </div>
        <div className="flex justify-end gap-2 border-t border-pentra-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-ds-md border border-pentra-border px-3 py-1.5 text-[13px] text-pentra-text-secondary hover:bg-pentra-bg-hover">
            Cancel
          </button>
          <button type="button" onClick={handleSave} className="flex items-center gap-1.5 rounded-ds-md bg-pentra-accent px-3 py-1.5 text-[13px] font-medium text-white hover:opacity-80">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Pattern Row ────────────────────────────────────────────────────────────────

interface PatternRowProps {
  pattern: GFPattern;
  onToggle: () => void;
  onEdit: () => void;
}

function PatternRow({ pattern, onToggle, onEdit }: PatternRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={cn("rounded-ds-md border transition-colors", pattern.enabled ? "border-pentra-border" : "border-pentra-border/50 opacity-60")}>
      <div className="flex items-center gap-3 px-4 py-2.5">
        {/* Toggle */}
        <button
          type="button"
          role="switch"
          aria-checked={pattern.enabled}
          onClick={onToggle}
          className={cn(
            "relative h-4 w-8 flex-shrink-0 rounded-full transition-colors",
            pattern.enabled ? "bg-pentra-accent" : "bg-pentra-border"
          )}
        >
          <span
            className={cn(
              "absolute top-0.5 h-3 w-3 rounded-full bg-white shadow transition-transform",
              pattern.enabled ? "left-[18px]" : "left-0.5"
            )}
          />
        </button>

        {/* Name */}
        <span className="font-mono text-[12px] font-semibold text-pentra-accent-light w-28 flex-shrink-0">
          {pattern.name}
        </span>
        <span className="flex-1 text-[12px] text-pentra-text-secondary">{pattern.description}</span>
        <span className="text-[11px] text-pentra-text-muted">{pattern.regexes.length} regex{pattern.regexes.length !== 1 ? "es" : ""}</span>

        <button
          type="button"
          onClick={onEdit}
          className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
          title="Edit"
        >
          <Edit3 className="h-3.5 w-3.5" />
        </button>

        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
        >
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </button>
      </div>

      {expanded && (
        <div className="border-t border-pentra-border px-4 py-2 bg-pentra-bg-card rounded-b-ds-md">
          <div className="flex flex-wrap gap-1.5">
            {pattern.regexes.map((re, i) => (
              <code key={i} className="rounded bg-pentra-bg-hover px-2 py-0.5 text-[10px] font-mono text-pentra-text-code">
                {re}
              </code>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function GFPatternsPage() {
  const [patterns, setPatterns] = useState<GFPattern[]>(() => loadPatterns());
  const [editPattern, setEditPattern] = useState<GFPattern | null>(null);

  useEffect(() => {
    savePatterns(patterns);
  }, [patterns]);

  const toggle = (name: string) => {
    setPatterns((prev) =>
      prev.map((p) => (p.name === name ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const update = (updated: GFPattern) => {
    setPatterns((prev) =>
      prev.map((p) => (p.name === updated.name ? updated : p))
    );
  };

  const handleUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const parsed = JSON.parse(ev.target?.result as string) as unknown;
        if (!Array.isArray(parsed)) throw new Error("Expected array");
        const validated = (parsed as GFPattern[]).filter(
          (p) => typeof p.name === "string" && Array.isArray(p.regexes)
        );
        // Merge: update existing + add new
        setPatterns((prev) => {
          const map = new Map(prev.map((p) => [p.name, p]));
          for (const p of validated) {
            const existing = map.get(p.name);
            map.set(p.name, {
              enabled: existing?.enabled ?? true,
              description: p.description ?? existing?.description ?? "",
              name: p.name,
              regexes: p.regexes,
            });
          }
          return Array.from(map.values());
        });
        toastSuccess("Patterns imported", `${validated.length} pattern(s) merged`);
      } catch {
        toastError("Invalid file", "Expected JSON array of {name, regexes}");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const enabledCount = patterns.filter((p) => p.enabled).length;

  return (
    <div className="flex min-h-full gap-6 p-6">
      {/* Left: Pattern List */}
      <div className="flex flex-col flex-1 gap-4 min-w-0">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-[20px] font-bold text-pentra-text-primary flex items-center gap-2">
              <Filter className="h-5 w-5 text-pentra-accent" />
              GF Patterns
            </h1>
            <p className="text-[13px] text-pentra-text-secondary mt-0.5">
              {enabledCount}/{patterns.length} patterns active
            </p>
          </div>

          <label className="flex cursor-pointer items-center gap-2 rounded-ds-md border border-pentra-border px-3 py-2 text-[13px] text-pentra-text-secondary transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-primary">
            <Upload className="h-4 w-4" />
            Import .json
            <input type="file" accept=".json" className="hidden" onChange={handleUpload} />
          </label>
        </div>

        <div className="space-y-2">
          {patterns.map((p) => (
            <PatternRow
              key={p.name}
              pattern={p}
              onToggle={() => toggle(p.name)}
              onEdit={() => setEditPattern(p)}
            />
          ))}
        </div>
      </div>

      {/* Right: URL Tester */}
      <div className="w-72 flex-shrink-0">
        <UrlTester patterns={patterns} />
      </div>

      {editPattern && (
        <EditPatternModal
          pattern={editPattern}
          onSave={update}
          onClose={() => setEditPattern(null)}
        />
      )}
    </div>
  );
}
