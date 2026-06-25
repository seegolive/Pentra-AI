import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, FolderOpen, Loader2, ChevronRight } from "lucide-react";
import { useWorkspaces, useCreateWorkspace } from "../lib/api";
import type { Workspace } from "../lib/types";

export default function WorkspacesPage() {
  const navigate = useNavigate();
  const { data: workspaces, isLoading } = useWorkspaces();
  const createMutation = useCreateWorkspace();

  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await createMutation.mutateAsync({ name: name.trim(), description: description.trim() || undefined });
    setName("");
    setDescription("");
    setShowCreate(false);
  };

  return (
    <div className="flex-1 w-full p-6 lg:p-8">

      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-[22px] font-bold text-pentra-text-primary">Workspaces</h1>
          <p className="text-[13px] text-pentra-text-secondary mt-1">
            {workspaces?.length
              ? `${workspaces.length} workspace${workspaces.length !== 1 ? "s" : ""}`
              : "Organise your engagements by client or program"}
          </p>
        </div>
        <button
          onClick={() => setShowCreate((v) => !v)}
          className="flex items-center gap-2 px-4 py-2 bg-pentra-accent text-white rounded-ds-md text-[13px] font-medium hover:opacity-90 transition-opacity"
        >
          <Plus className="h-4 w-4" />
          New Workspace
        </button>
      </div>

      {/* Inline create form */}
      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="mb-6 rounded-ds-lg border border-pentra-border bg-pentra-bg-panel p-5 space-y-3"
        >
          <h2 className="text-[13px] font-semibold text-pentra-text-primary">Create Workspace</h2>
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Workspace name"
            className="w-full px-3 py-2 bg-pentra-bg-input border border-pentra-border rounded-ds-md text-[13px] text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
          />
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description (optional)"
            className="w-full px-3 py-2 bg-pentra-bg-input border border-pentra-border rounded-ds-md text-[13px] text-pentra-text-primary placeholder:text-pentra-text-muted outline-none focus:border-pentra-border-focus"
          />
          <div className="flex gap-2 pt-1">
            <button
              type="submit"
              disabled={createMutation.isPending || !name.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-pentra-accent text-white rounded-ds-md text-[13px] font-medium hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {createMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Create
            </button>
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 text-[13px] text-pentra-text-muted hover:text-pentra-text-secondary transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-40 text-pentra-text-muted gap-2">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-[13px]">Loading…</span>
        </div>
      ) : workspaces?.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-pentra-text-muted border border-dashed border-pentra-border rounded-ds-lg gap-3">
          <FolderOpen className="h-12 w-12 opacity-20" />
          <div className="text-center">
            <p className="text-[13px] font-medium">No workspaces yet</p>
            <p className="text-[12px] mt-1 opacity-60">Create one to organise your engagements</p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="mt-1 flex items-center gap-2 px-4 py-2 bg-pentra-accent text-white rounded-ds-md text-[13px] font-medium hover:opacity-90 transition-opacity"
          >
            <Plus className="h-4 w-4" />
            New Workspace
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
          {workspaces?.map((ws: Workspace) => (
            <button
              key={ws.id}
              onClick={() => navigate(`/workspaces/${ws.id}/engagements`)}
              className="group text-left p-5 border border-pentra-border rounded-ds-lg bg-pentra-bg-card hover:border-pentra-border-light hover:bg-pentra-bg-hover transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  <FolderOpen className="h-5 w-5 text-pentra-accent mt-0.5 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-[13px] font-semibold text-pentra-text-primary truncate">
                      {ws.name}
                    </p>
                    {ws.description && (
                      <p className="text-[12px] text-pentra-text-muted mt-1 line-clamp-2 leading-snug">
                        {ws.description}
                      </p>
                    )}
                    <p className="text-[11px] text-pentra-text-muted mt-2 opacity-60">
                      {new Date(ws.created_at).toLocaleDateString(undefined, {
                        day: "numeric", month: "short", year: "numeric",
                      })}
                    </p>
                  </div>
                </div>
                <ChevronRight className="h-4 w-4 text-pentra-text-muted flex-shrink-0 mt-0.5 group-hover:text-pentra-text-secondary transition-colors" />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
