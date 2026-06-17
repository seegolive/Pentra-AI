import { useState, useEffect, useRef } from "react";
import {
  KeyRound,
  Plus,
  Eye,
  EyeOff,
  Trash2,
  Copy,
  Loader2,
  CheckCircle2,
  X,
} from "lucide-react";
import { cn } from "../lib/utils";
import { toastSuccess, toastError } from "../lib/toast";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ApiKey {
  id: string;
  name: string;
  key: string;
  added_at: string;
}

const STORAGE_KEY = "pentra-api-vault";

function loadKeys(): ApiKey[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]") as ApiKey[];
  } catch {
    return [];
  }
}

function saveKeys(keys: ApiKey[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

// ── Add Key Modal ─────────────────────────────────────────────────────────────

interface AddKeyModalProps {
  onAdd: (key: ApiKey) => void;
  onClose: () => void;
}

function AddKeyModal({ onAdd, onClose }: AddKeyModalProps) {
  const [name, setName] = useState("");
  const [keyValue, setKeyValue] = useState("");
  const [showKey, setShowKey] = useState(false);

  const handleAdd = () => {
    if (!name.trim() || !keyValue.trim()) {
      toastError("Validation error", "Name and key are required");
      return;
    }
    const newKey: ApiKey = {
      id: crypto.randomUUID(),
      name: name.trim(),
      key: keyValue.trim(),
      added_at: new Date().toISOString(),
    };
    onAdd(newKey);
    toastSuccess("Key added", name);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[400px] rounded-ds-lg border border-pentra-border bg-pentra-bg-panel shadow-2xl">
        <div className="flex items-center justify-between border-b border-pentra-border px-4 py-3.5">
          <h2 className="text-[15px] font-semibold text-pentra-text-primary">Add New Key</h2>
          <button
            type="button"
            onClick={onClose}
            className="flex h-6 w-6 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">Name</label>
            <input
              type="text"
              placeholder="My API Key"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 text-[13px] text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold text-pentra-text-secondary mb-1.5">API Key</label>
            <div className="relative">
              <input
                type={showKey ? "text" : "password"}
                placeholder="sk-..."
                value={keyValue}
                onChange={(e) => setKeyValue(e.target.value)}
                className="w-full rounded-ds-md border border-pentra-border bg-pentra-bg-input px-3 py-2 pr-9 text-[13px] font-mono text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-pentra-text-muted hover:text-pentra-text-secondary"
              >
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-pentra-border px-4 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-ds-md border border-pentra-border px-3 py-1.5 text-[13px] text-pentra-text-secondary hover:bg-pentra-bg-hover"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleAdd}
            className="flex items-center gap-1.5 rounded-ds-md bg-pentra-accent px-3 py-1.5 text-[13px] font-medium text-white hover:opacity-80"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Key
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Key Row ───────────────────────────────────────────────────────────────────

function KeyRow({ apiKey, onDelete }: { apiKey: ApiKey; onDelete: () => void }) {
  const [revealed, setRevealed] = useState(false);
  const [countdown, setCountdown] = useState(30);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const reveal = () => {
    setRevealed(true);
    setCountdown(30);
    timerRef.current = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          clearInterval(timerRef.current!);
          setRevealed(false);
          return 30;
        }
        return c - 1;
      });
    }, 1000);
  };

  const mask = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    setRevealed(false);
  };

  const copyKey = () => {
    navigator.clipboard.writeText(apiKey.key);
    toastSuccess("Copied", apiKey.name);
  };

  const testKey = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_URL ?? "http://localhost:8000"}/api/v1/auth/me`,
        {
          headers: { Authorization: `Bearer ${apiKey.key}` },
        }
      );
      setTestResult(`HTTP ${res.status} ${res.statusText}`);
    } catch {
      setTestResult("Connection failed");
    } finally {
      setTesting(false);
    }
  };

  const displayKey = revealed
    ? apiKey.key
    : `${apiKey.key.slice(0, 8)}${"*".repeat(Math.min(20, apiKey.key.length - 8))}`;

  return (
    <div className="flex items-center gap-3 rounded-ds-md border border-pentra-border bg-pentra-bg-card px-4 py-3">
      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-ds-sm bg-pentra-accent-dim text-pentra-accent-light">
        <KeyRound className="h-4 w-4" />
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-semibold text-pentra-text-primary">{apiKey.name}</p>
        <p className={cn("text-[11px] font-mono mt-0.5", revealed ? "text-pentra-text-code" : "text-pentra-text-muted")}>
          {displayKey}
          {revealed && (
            <span className="ml-2 text-[10px] text-pentra-status-waiting">({countdown}s)</span>
          )}
        </p>
        {testResult && (
          <p className={cn(
            "text-[10px] mt-0.5",
            testResult.startsWith("HTTP 200") ? "text-pentra-status-complete" : "text-pentra-severity-critical"
          )}>
            {testResult}
          </p>
        )}
        <p className="text-[10px] text-pentra-text-muted mt-0.5">
          Added {new Date(apiKey.added_at).toLocaleDateString()}
        </p>
      </div>

      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={revealed ? mask : reveal}
          title={revealed ? "Hide" : "Reveal"}
          className="flex h-7 w-7 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
        >
          {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
        </button>

        <button
          type="button"
          onClick={copyKey}
          title="Copy"
          className="flex h-7 w-7 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
        >
          <Copy className="h-3.5 w-3.5" />
        </button>

        <button
          type="button"
          onClick={testKey}
          disabled={testing}
          title="Test key"
          className="flex h-7 items-center gap-1 rounded-ds-sm border border-pentra-border px-2 text-[11px] text-pentra-text-secondary hover:bg-pentra-bg-hover disabled:opacity-50"
        >
          {testing ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <CheckCircle2 className="h-3 w-3" />
          )}
          Test
        </button>

        <button
          type="button"
          onClick={onDelete}
          title="Delete"
          className="flex h-7 w-7 items-center justify-center rounded-ds-sm text-pentra-text-muted hover:bg-pentra-severity-critical/10 hover:text-pentra-severity-critical"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ApiVaultPage() {
  const [keys, setKeys] = useState<ApiKey[]>(() => loadKeys());
  const [showAdd, setShowAdd] = useState(false);

  useEffect(() => {
    saveKeys(keys);
  }, [keys]);

  const handleAdd = (key: ApiKey) => {
    setKeys((prev) => [...prev, key]);
  };

  const handleDelete = (id: string) => {
    setKeys((prev) => prev.filter((k) => k.id !== id));
    toastSuccess("Key deleted");
  };

  return (
    <div className="flex min-h-full flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[20px] font-bold text-pentra-text-primary flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-pentra-accent" />
            API Vault
          </h1>
          <p className="text-[13px] text-pentra-text-secondary mt-0.5">
            Securely store API keys locally (localStorage, never sent to server)
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 rounded-ds-md bg-pentra-accent px-3 py-2 text-[13px] font-medium text-white hover:opacity-80"
        >
          <Plus className="h-4 w-4" />
          Add New Key
        </button>
      </div>

      {keys.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-ds-lg border border-pentra-border bg-pentra-bg-card">
          <KeyRound className="h-12 w-12 text-pentra-text-muted opacity-30" />
          <p className="text-[13px] text-pentra-text-muted">No API keys stored yet</p>
          <button
            type="button"
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 rounded-ds-md border border-pentra-accent/40 px-3 py-1.5 text-[13px] text-pentra-accent hover:bg-pentra-accent/10"
          >
            <Plus className="h-3.5 w-3.5" />
            Add your first key
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {keys.map((key) => (
            <KeyRow key={key.id} apiKey={key} onDelete={() => handleDelete(key.id)} />
          ))}
        </div>
      )}

      {showAdd && <AddKeyModal onAdd={handleAdd} onClose={() => setShowAdd(false)} />}
    </div>
  );
}
