/**
 * KBInjectDialog — modal form for manually injecting a knowledge record.
 *
 * Opens when user clicks "+ Inject" in the Knowledge Browser header.
 */

import { useState } from "react";
import { X, Loader2, CheckCircle2 } from "lucide-react";
import { cn } from "../lib/utils";
import { useKBManualInject } from "../lib/api";
import type { Severity, VulnClass } from "../lib/types";

const VULN_CLASSES: VulnClass[] = [
  "sqli", "xss", "ssrf", "idor", "rce", "lfi", "xxe", "auth_bypass",
  "privilege_escalation", "info_disclosure", "csrf", "open_redirect",
  "ssti", "path_traversal", "race_condition", "business_logic", "misconfig",
  "dos", "other",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface Props {
  open: boolean;
  onClose: () => void;
}

export function KBInjectDialog({ open, onClose }: Props) {
  const [title, setTitle] = useState("");
  const [vulnClass, setVulnClass] = useState<VulnClass>("other");
  const [severity, setSeverity] = useState<Severity>("info");
  const [rawText, setRawText] = useState("");
  const [keyInsight, setKeyInsight] = useState("");
  const [technique, setTechnique] = useState("");
  const [techStack, setTechStack] = useState("");
  const [tags, setTags] = useState("");
  const [url, setUrl] = useState("");

  const { mutate, isPending, isSuccess, error, reset } = useKBManualInject();

  if (!open) return null;

  function handleClose() {
    reset();
    setTitle(""); setRawText(""); setKeyInsight(""); setTechnique("");
    setTechStack(""); setTags(""); setUrl("");
    onClose();
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    mutate({
      title: title.trim(),
      vuln_class: vulnClass,
      severity,
      raw_text: rawText.trim(),
      key_insight: keyInsight.trim() || undefined,
      technique: technique.trim() || undefined,
      tech_stack: techStack.split(",").map((s) => s.trim()).filter(Boolean),
      tags: tags.split(",").map((s) => s.trim()).filter(Boolean),
      url: url.trim() || undefined,
    });
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Inject knowledge record"
    >
      <div className="relative w-full max-w-2xl mx-4 bg-card border border-border rounded-xl shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
          <span className="font-semibold text-sm text-foreground">Inject Knowledge Record</span>
          <button
            type="button"
            onClick={handleClose}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Success state */}
        {isSuccess ? (
          <div className="flex flex-col items-center justify-center gap-3 p-10 text-center">
            <CheckCircle2 className="h-10 w-10 text-green-500" />
            <p className="text-sm text-foreground font-medium">Record injected successfully</p>
            <button
              type="button"
              onClick={handleClose}
              className="mt-2 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm"
            >
              Close
            </button>
          </div>
        ) : (
          /* Form */
          <form onSubmit={handleSubmit} className="flex flex-col overflow-hidden">
            <div className="overflow-y-auto p-5 space-y-4">
              {/* Title */}
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">
                  Title <span className="text-red-400">*</span>
                </label>
                <input
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. IDOR on HackerOne via user_id parameter"
                  className={inputCls}
                />
              </div>

              {/* Vuln class + Severity */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Vuln Class</label>
                  <select value={vulnClass} onChange={(e) => setVulnClass(e.target.value as VulnClass)} className={inputCls}>
                    {VULN_CLASSES.map((v) => <option key={v} value={v}>{v}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Severity</label>
                  <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={inputCls}>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>

              {/* Raw text / write-up */}
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">
                  Write-up / Raw Text <span className="text-red-400">*</span>
                </label>
                <textarea
                  required
                  rows={5}
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  placeholder="Paste the vulnerability description, exploit steps, or full write-up…"
                  className={cn(inputCls, "resize-y")}
                />
              </div>

              {/* Key insight */}
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Key Insight</label>
                <input
                  value={keyInsight}
                  onChange={(e) => setKeyInsight(e.target.value)}
                  placeholder="One-liner: what makes this finding interesting?"
                  className={inputCls}
                />
              </div>

              {/* Technique */}
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Attack Technique</label>
                <input
                  value={technique}
                  onChange={(e) => setTechnique(e.target.value)}
                  placeholder="e.g. Horizontal privilege escalation via predictable UUID"
                  className={inputCls}
                />
              </div>

              {/* Tech stack + tags */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">
                    Tech Stack <span className="text-muted-foreground/50">(comma-separated)</span>
                  </label>
                  <input
                    value={techStack}
                    onChange={(e) => setTechStack(e.target.value)}
                    placeholder="rails, postgresql"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">
                    Tags <span className="text-muted-foreground/50">(comma-separated)</span>
                  </label>
                  <input
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    placeholder="api, jwt, bypass"
                    className={inputCls}
                  />
                </div>
              </div>

              {/* Source URL */}
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Source URL</label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://hackerone.com/reports/123456"
                  className={inputCls}
                />
              </div>

              {/* Error */}
              {error && (
                <div className="rounded-md border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
                  {error.message}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-border shrink-0">
              <button
                type="button"
                onClick={handleClose}
                disabled={isPending}
                className="px-4 py-2 rounded-md border border-border text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isPending || !title.trim() || !rawText.trim()}
                className={cn(
                  "px-4 py-2 rounded-md text-sm font-medium transition-colors",
                  "bg-primary text-primary-foreground hover:bg-primary/90",
                  "disabled:opacity-50 disabled:cursor-not-allowed",
                )}
              >
                {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Inject"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

const inputCls =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent";
