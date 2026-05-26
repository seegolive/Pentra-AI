import { useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Search, Database, Loader2, Plus } from "lucide-react";
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

export default function KnowledgeBrowser() {
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [filters, setFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const { data: results, isLoading, isError, error } = useKnowledgeSearch(
    { q: submittedQuery, ...filters },
    submittedQuery.trim().length > 0,
  );

  const handleSearch = useCallback(() => {
    const trimmed = query.trim();
    if (trimmed) setSubmittedQuery(trimmed);
  }, [query]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") handleSearch();
    },
    [handleSearch],
  );

  const handleFiltersChange = useCallback((f: SearchFilters) => {
    setFilters(f);
    // Re-fire search with new filters if there's an active query
    if (submittedQuery) setSubmittedQuery((q) => q);
  }, [submittedQuery]);

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-background">
      {/* Top bar */}
      <header className="shrink-0 border-b border-border bg-card/50 backdrop-blur px-6 py-3 flex items-center gap-3">
        <Database className="h-5 w-5 text-primary shrink-0" />
        <span className="font-semibold text-foreground text-sm">Knowledge Base</span>
        <span className="text-muted-foreground text-xs hidden sm:block">
          — HackerOne public disclosures + manual injects
        </span>

        {/* Search bar */}
        <div className="ml-auto flex items-center gap-2 w-full max-w-lg">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search by attack type, tech, CVE…"
              className={cn(
                "w-full rounded-md border border-input bg-background pl-9 pr-3 py-2 text-sm",
                "text-foreground placeholder:text-muted-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent",
              )}
            />
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
              "border border-border bg-card text-foreground hover:bg-muted",
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
        <aside className="shrink-0 w-60 border-r border-border overflow-y-auto p-4 hidden md:block">
          <FilterPanel filters={filters} onChange={handleFiltersChange} />
        </aside>

        {/* Results */}
        <main className="flex-1 overflow-y-auto p-4">
          {/* Empty / initial state */}
          {!submittedQuery && (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
              <Search className="h-10 w-10 opacity-20" />
              <p className="text-sm">Enter a query to search the knowledge base</p>
              <p className="text-xs opacity-60">
                Try: "IDOR on Rails", "XSS via file upload", "SSRF bypass AWS metadata"
              </p>
            </div>
          )}

          {/* Loading */}
          {isLoading && (
            <div className="flex items-center justify-center h-40 gap-2 text-muted-foreground text-sm">
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

          {/* Results list */}
          {results && !isLoading && (
            <>
              <p className="mb-3 text-xs text-muted-foreground">
                {results.length === 0
                  ? `No results for "${submittedQuery}"`
                  : `${results.length} result${results.length !== 1 ? "s" : ""} for "${submittedQuery}"`}
              </p>
              {results.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-40 gap-2 text-muted-foreground">
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
