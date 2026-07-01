import { useState, useCallback, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Search, Database, Loader2, Plus, X } from "lucide-react";
import { useKnowledgeSearch } from "../lib/api";
import { cn } from "../lib/utils";
import type { SearchFilters } from "../lib/types";
import { KnowledgeCard } from "../components/KnowledgeCard";
import { KnowledgeDrawer } from "../components/KnowledgeDrawer";
import { FilterPanel } from "../components/FilterPanel";

const DEFAULT_FILTERS: SearchFilters = {
  severity: [],
  vuln_class: [],
  tech_stack: [],
};

const QUICK_SEARCHES = [
  "IDOR on Rails API",
  "XSS via file upload",
  "SSRF bypass AWS metadata",
  "JWT auth bypass",
  "SQL injection WAF bypass",
  "RCE via deserialization",
];

export default function KnowledgeBrowser() {
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [filters, setFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: results, isLoading, isError, error } = useKnowledgeSearch(
    { q: submittedQuery, ...filters },
    submittedQuery.trim().length > 0,
  );

  // Debounced live search — fires 400 ms after user stops typing (≥2 chars)
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const trimmed = query.trim();
    if (trimmed.length >= 2) {
      debounceRef.current = setTimeout(() => setSubmittedQuery(trimmed), 400);
    } else if (trimmed.length === 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSubmittedQuery("");
    }
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query]);

  const handleSearch = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const trimmed = query.trim();
    if (trimmed) setSubmittedQuery(trimmed);
  }, [query]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") handleSearch();
    },
    [handleSearch],
  );

  const handleFiltersChange = useCallback(
    (f: SearchFilters) => {
      setFilters(f);
      if (submittedQuery) setSubmittedQuery((q) => q);
    },
    [submittedQuery],
  );

  const handleClear = () => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setQuery("");
    setSubmittedQuery("");
    inputRef.current?.focus();
  };

  const handleQuickSearch = (s: string) => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setQuery(s);
    setSubmittedQuery(s);
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-pentra-bg-void">
      {/* Top bar */}
      <header className="shrink-0 border-b border-pentra-border bg-pentra-bg-card/50 backdrop-blur px-6 py-3 flex items-center gap-3">
        <Database className="h-5 w-5 text-pentra-accent shrink-0" />
        <span className="font-semibold text-pentra-text-primary text-sm">Knowledge Base</span>
        <span className="text-pentra-text-muted text-xs hidden sm:block">
          — HackerOne disclosures + manual injects
        </span>

        {/* Search bar */}
        <div className="ml-auto flex items-center gap-2 w-full max-w-lg">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-pentra-text-muted" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search by attack type, tech, CVE…"
              className={cn(
                "w-full rounded-md border border-pentra-border bg-pentra-bg-input pl-9 pr-8 py-2 text-sm",
                "text-pentra-text-primary placeholder:text-pentra-text-muted",
                "focus:outline-none focus:ring-1 focus:ring-pentra-border-focus focus:border-transparent",
              )}
            />
            {query && (
              <button
                type="button"
                onClick={handleClear}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
                aria-label="Clear search"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <button
            type="button"
            onClick={handleSearch}
            disabled={!query.trim() || isLoading}
            className={cn(
              "shrink-0 rounded-md px-4 py-2 text-sm font-medium transition-colors",
              "bg-primary text-primary-foreground hover:bg-primary/90",
              "disabled:opacity-50 disabled:cursor-not-allowed",
            )}
          >
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Search"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/knowledge/inject")}
            className={cn(
              "shrink-0 rounded-md px-3 py-2 text-sm font-medium transition-colors flex items-center gap-1.5",
              "border border-pentra-border bg-pentra-bg-card text-pentra-text-primary hover:bg-pentra-bg-hover",
            )}
            title="Manually inject a knowledge record"
          >
            <Plus className="h-3.5 w-3.5" />
            Inject
          </button>
        </div>
      </header>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="shrink-0 w-60 border-r border-pentra-border overflow-y-auto p-4 hidden md:block bg-pentra-bg-panel/30">
          <FilterPanel filters={filters} onChange={handleFiltersChange} />
        </aside>

        {/* Results area */}
        <main className="flex-1 overflow-y-auto p-4">
          {/* Initial empty state — no query yet */}
          {!query && (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-pentra-text-muted">
              <Search className="h-10 w-10 opacity-20" />
              <div className="text-center">
                <p className="text-sm text-pentra-text-secondary">Enter a query to search the knowledge base</p>
                <p className="text-xs opacity-60 mt-1">Hybrid semantic + lexical search</p>
              </div>
              <div className="flex flex-wrap justify-center gap-2 max-w-sm mt-1">
                {QUICK_SEARCHES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => handleQuickSearch(s)}
                    className="text-xs px-2.5 py-1 rounded border border-pentra-border bg-pentra-bg-card hover:bg-pentra-bg-hover hover:border-pentra-border-light text-pentra-text-muted hover:text-pentra-text-primary transition-colors"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Typing — fewer than 2 chars */}
          {query.trim().length > 0 && query.trim().length < 2 && !submittedQuery && (
            <div className="flex items-center justify-center h-40 text-pentra-text-muted text-sm opacity-60">
              Type at least 2 characters…
            </div>
          )}

          {/* Loading */}
          {isLoading && (
            <div className="flex items-center justify-center h-40 gap-2 text-pentra-text-muted text-sm">
              <Loader2 className="h-4 w-4 animate-spin" />
              Searching…
            </div>
          )}

          {/* Error */}
          {isError && (
            <div className="rounded-md border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-400">
              Search failed: {error?.message ?? "Unknown error"}
            </div>
          )}

          {/* Results */}
          {results && !isLoading && (
            <>
              <p className="mb-3 text-xs text-pentra-text-muted">
                {results.length === 0
                  ? `No results for "${submittedQuery}"`
                  : `${results.length} result${results.length !== 1 ? "s" : ""} for "${submittedQuery}"`}
              </p>
              {results.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-40 gap-2 text-pentra-text-muted">
                  <Database className="h-8 w-8 opacity-20" />
                  <p className="text-sm">No matching records found</p>
                  <p className="text-xs opacity-60">Try different keywords or remove filters</p>
                </div>
              ) : (
                <div className="grid gap-3 grid-cols-1 xl:grid-cols-2">
                  {results.map((record) => (
                    <KnowledgeCard
                      key={record.id}
                      record={record}
                      onClick={setSelectedId}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </main>
      </div>

      {/* Detail drawer */}
      <KnowledgeDrawer
        recordId={selectedId}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
