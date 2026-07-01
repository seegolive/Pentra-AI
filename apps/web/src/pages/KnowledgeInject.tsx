/**
 * KnowledgeInject — full-page KB inject with 3 input tabs.
 *
 *  Tab 1 "URL"     — paste a write-up/blog URL → backend fetches + parses
 *  Tab 2 "File"    — upload Markdown / PDF → backend extracts text
 *  Tab 3 "Manual"  — fill-in form directly
 *
 * Route: /knowledge/inject
 */

import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Link2,
  Upload,
  PenLine,
  Loader2,
  CheckCircle2,
  ArrowLeft,
  Database,
} from "lucide-react";
import {
  useKBInjectFromUrl,
  useKBInjectFromFile,
  useKBManualInject,
  type KBManualInjectRequest,
} from "../lib/api";
import { cn } from "../lib/utils";
import type { Severity, VulnClass } from "../lib/types";

const VULN_CLASSES: VulnClass[] = [
  "sqli", "xss", "ssrf", "idor", "rce", "lfi", "xxe", "auth_bypass",
  "privilege_escalation", "info_disclosure", "csrf", "open_redirect",
  "ssti", "path_traversal", "race_condition", "business_logic", "misconfig",
  "dos", "other",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

type Tab = "url" | "file" | "manual";

const inputCls =
  "w-full rounded-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-sm text-pentra-text-primary placeholder:text-pentra-text-muted focus:outline-none focus:ring-1 focus:ring-pentra-border-focus focus:border-transparent";

// ── Success state ─────────────────────────────────────────────────────────────

function SuccessPanel({ id, message, onReset }: { id: string; message: string; onReset: () => void }) {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
      <CheckCircle2 className="h-12 w-12 text-green-500" />
      <p className="text-base font-semibold text-pentra-text-primary">{message}</p>
      <p className="text-xs text-pentra-text-muted font-mono">Record ID: {id}</p>
      <p className="text-xs text-pentra-text-muted">
        The worker will embed and index this record within the next hourly cycle.
      </p>
      <div className="flex gap-3 mt-2">
        <button
          onClick={onReset}
          className="px-4 py-2 rounded-md border border-pentra-border text-sm text-pentra-text-muted hover:text-pentra-text-primary hover:bg-pentra-bg-hover transition-colors"
        >
          Inject another
        </button>
        <button
          onClick={() => navigate("/knowledge")}
          className="px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm hover:bg-primary/90 transition-colors"
        >
          Back to Knowledge Browser
        </button>
      </div>
    </div>
  );
}

// ── Tab 1: URL ────────────────────────────────────────────────────────────────

function UrlTab() {
  const [url, setUrl] = useState("");
  const [vulnClass, setVulnClass] = useState<string>("other");
  const [tags, setTags] = useState("");
  const { mutate, isPending, isSuccess, data, error, reset } = useKBInjectFromUrl();

  if (isSuccess && data) return <SuccessPanel id={data.knowledge_record_id} message={data.message} onReset={reset} />;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        mutate({
          url: url.trim(),
          vuln_class: vulnClass,
          tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        });
      }}
      className="space-y-4"
    >
      <p className="text-sm text-pentra-text-muted">
        Paste the URL of a write-up, blog post, or H1 disclosure. Pentra AI will fetch and extract its content.
      </p>
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">
          URL <span className="text-red-400">*</span>
        </label>
        <input
          required
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://hackerone.com/reports/123456"
          className={inputCls}
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Vuln Class</label>
          <select value={vulnClass} onChange={(e) => setVulnClass(e.target.value)} className={inputCls}>
            {VULN_CLASSES.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">
            Tags <span className="text-pentra-text-muted/50">(comma-separated)</span>
          </label>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="api, rails, bypass"
            className={inputCls}
          />
        </div>
      </div>
      {error && <p className="text-xs text-red-400 rounded-md border border-red-500/20 bg-red-500/10 p-3">{error.message}</p>}
      <button
        type="submit"
        disabled={isPending || !url.trim()}
        className={cn(
          "w-full py-2.5 rounded-md font-medium text-sm transition-colors flex items-center justify-center gap-2",
          "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed",
        )}
      >
        {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
        {isPending ? "Fetching…" : "Fetch & Inject"}
      </button>
    </form>
  );
}

// ── Tab 2: File ───────────────────────────────────────────────────────────────

function FileTab() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [vulnClass, setVulnClass] = useState<string>("other");
  const [tags, setTags] = useState("");
  const { mutate, isPending, isSuccess, data, error, reset } = useKBInjectFromFile();

  if (isSuccess && data) return <SuccessPanel id={data.knowledge_record_id} message={data.message} onReset={() => { reset(); setSelectedFile(null); }} />;

  function handleFile(f: File) {
    setSelectedFile(f);
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedFile) return;
    const form = new FormData();
    form.append("file", selectedFile);
    form.append("vuln_class", vulnClass);
    form.append("tags", tags);
    mutate(form);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <p className="text-sm text-pentra-text-muted">
        Upload a Markdown or plain-text write-up (max 5 MB). PDF support requires <code>pypdf</code> installed.
      </p>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
        className={cn(
          "border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors",
          dragOver ? "border-pentra-accent bg-pentra-accent/5" : "border-pentra-border hover:border-pentra-border-light",
        )}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".md,.txt,.pdf,.markdown"
          className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
        />
        {selectedFile ? (
          <div className="text-sm text-pentra-text-primary">
            <p className="font-medium">{selectedFile.name}</p>
            <p className="text-xs text-pentra-text-muted mt-1">{(selectedFile.size / 1024).toFixed(1)} KB</p>
          </div>
        ) : (
          <div className="text-pentra-text-muted">
            <Upload className="h-8 w-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm">Drop file here or click to browse</p>
            <p className="text-xs mt-1 opacity-60">.md, .txt, .pdf</p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Vuln Class</label>
          <select value={vulnClass} onChange={(e) => setVulnClass(e.target.value)} className={inputCls}>
            {VULN_CLASSES.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">
            Tags <span className="text-pentra-text-muted/50">(comma-separated)</span>
          </label>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="writeup, api"
            className={inputCls}
          />
        </div>
      </div>

      {error && <p className="text-xs text-red-400 rounded-md border border-red-500/20 bg-red-500/10 p-3">{error.message}</p>}
      <button
        type="submit"
        disabled={isPending || !selectedFile}
        className={cn(
          "w-full py-2.5 rounded-md font-medium text-sm transition-colors flex items-center justify-center gap-2",
          "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed",
        )}
      >
        {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
        {isPending ? "Uploading…" : "Upload & Inject"}
      </button>
    </form>
  );
}

// ── Tab 3: Manual ─────────────────────────────────────────────────────────────

function ManualTab() {
  const [title, setTitle] = useState("");
  const [vulnClass, setVulnClass] = useState<VulnClass>("other");
  const [severity, setSeverity] = useState<Severity>("info");
  const [rawText, setRawText] = useState("");
  const [keyInsight, setKeyInsight] = useState("");
  const [technique, setTechnique] = useState("");
  const [techStack, setTechStack] = useState("");
  const [tags, setTags] = useState("");
  const [url, setUrl] = useState("");
  const { mutate, isPending, isSuccess, data, error, reset } = useKBManualInject();

  if (isSuccess && data) return (
    <SuccessPanel
      id={data.knowledge_record_id}
      message={data.message}
      onReset={() => {
        reset();
        setTitle(""); setRawText(""); setKeyInsight(""); setTechnique("");
        setTechStack(""); setTags(""); setUrl("");
      }}
    />
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const body: KBManualInjectRequest = {
      title: title.trim(),
      vuln_class: vulnClass,
      severity,
      raw_text: rawText.trim(),
      key_insight: keyInsight.trim() || undefined,
      technique: technique.trim() || undefined,
      tech_stack: techStack.split(",").map((s) => s.trim()).filter(Boolean),
      tags: tags.split(",").map((s) => s.trim()).filter(Boolean),
      url: url.trim() || undefined,
    };
    mutate(body);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">Title <span className="text-red-400">*</span></label>
        <input required value={title} onChange={(e) => setTitle(e.target.value)}
          placeholder="e.g. IDOR on HackerOne via user_id parameter"
          className={inputCls} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Vuln Class</label>
          <select value={vulnClass} onChange={(e) => setVulnClass(e.target.value as VulnClass)} className={inputCls}>
            {VULN_CLASSES.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={inputCls}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">Write-up / Raw Text <span className="text-red-400">*</span></label>
        <textarea required rows={5} value={rawText} onChange={(e) => setRawText(e.target.value)}
          placeholder="Paste the full vulnerability description, steps, or write-up…"
          className={cn(inputCls, "resize-y")} />
      </div>
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">Key Insight <span className="opacity-50 text-[10px]">(optional — LLM fills if empty)</span></label>
        <input value={keyInsight} onChange={(e) => setKeyInsight(e.target.value)}
          placeholder="What makes this non-obvious?" className={inputCls} />
      </div>
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">Attack Technique</label>
        <input value={technique} onChange={(e) => setTechnique(e.target.value)}
          placeholder="e.g. Horizontal privilege escalation via predictable UUID" className={inputCls} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Tech Stack</label>
          <input value={techStack} onChange={(e) => setTechStack(e.target.value)} placeholder="rails, postgresql" className={inputCls} />
        </div>
        <div>
          <label className="block text-xs font-medium text-pentra-text-muted mb-1">Tags</label>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="api, jwt, bypass" className={inputCls} />
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-pentra-text-muted mb-1">Source URL</label>
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://hackerone.com/reports/123456" className={inputCls} />
      </div>
      {error && <p className="text-xs text-red-400 rounded-md border border-red-500/20 bg-red-500/10 p-3">{error.message}</p>}
      <button
        type="submit"
        disabled={isPending || !title.trim() || !rawText.trim()}
        className={cn(
          "w-full py-2.5 rounded-md font-medium text-sm transition-colors flex items-center justify-center gap-2",
          "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed",
        )}
      >
        {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <PenLine className="h-4 w-4" />}
        {isPending ? "Injecting…" : "Inject Record"}
      </button>
    </form>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  { key: "url", label: "Paste URL", icon: <Link2 className="h-3.5 w-3.5" /> },
  { key: "file", label: "Upload File", icon: <Upload className="h-3.5 w-3.5" /> },
  { key: "manual", label: "Manual Form", icon: <PenLine className="h-3.5 w-3.5" /> },
];

export default function KnowledgeInject() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>("url");

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-pentra-bg-void">
      {/* Header */}
      <header className="shrink-0 border-b border-pentra-border bg-pentra-bg-card/50 backdrop-blur px-6 py-3 flex items-center gap-3">
        <button
          onClick={() => navigate("/knowledge")}
          className="text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <Database className="h-5 w-5 text-pentra-accent shrink-0" />
        <span className="font-semibold text-pentra-text-primary text-sm">Inject Knowledge Record</span>
        <span className="text-pentra-text-muted text-xs hidden sm:block">
          — Add write-ups, techniques, and CVEs to the knowledge base
        </span>
      </header>

      {/* Body */}
      <div className="flex-1 overflow-y-auto flex justify-center py-8 px-4">
        <div className="w-full max-w-2xl">
          {/* Tab switcher */}
          <div className="flex gap-1 bg-pentra-bg-panel rounded-lg p-1 mb-6">
            {TABS.map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => setActiveTab(t.key)}
                className={cn(
                  "flex-1 flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  activeTab === t.key
                    ? "bg-pentra-bg-card text-pentra-text-primary shadow-sm"
                    : "text-pentra-text-muted hover:text-pentra-text-secondary",
                )}
              >
                {t.icon}
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="bg-pentra-bg-card border border-pentra-border rounded-xl p-6">
            {activeTab === "url" && <UrlTab />}
            {activeTab === "file" && <FileTab />}
            {activeTab === "manual" && <ManualTab />}
          </div>
        </div>
      </div>
    </div>
  );
}
