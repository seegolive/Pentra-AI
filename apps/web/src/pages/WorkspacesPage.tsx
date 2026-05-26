import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, FolderOpen, Loader2 } from "lucide-react";
import { useWorkspaces, useCreateWorkspace } from "../lib/api";
import type { Workspace } from "../lib/types";
import { cn } from "../lib/utils";

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
    <div className="flex-1 p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Workspaces</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Organise your engagements by client or program
            </p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className="h-4 w-4" />
            New Workspace
          </button>
        </div>

        {/* Create Form */}
        {showCreate && (
          <form
            onSubmit={handleCreate}
            className="mb-6 p-4 border border-border rounded-lg bg-card space-y-3"
          >
            <h2 className="text-sm font-semibold text-foreground">Create Workspace</h2>
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Workspace name"
              className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              className="w-full px-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={createMutation.isPending || !name.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {createMutation.isPending && <Loader2 className="h-3 w-3 animate-spin" />}
                Create
              </button>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {/* List */}
        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading…
          </div>
        ) : workspaces?.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-60 text-muted-foreground border border-dashed border-border rounded-lg">
            <FolderOpen className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No workspaces yet</p>
            <p className="text-xs mt-1 opacity-60">Create one to get started</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {workspaces?.map((ws: Workspace) => (
              <button
                key={ws.id}
                onClick={() => navigate(`/workspaces/${ws.id}/engagements`)}
                className={cn(
                  "text-left p-5 border border-border rounded-lg bg-card",
                  "hover:border-primary/50 hover:bg-card/80 transition-colors group"
                )}
              >
                <div className="flex items-start gap-3">
                  <FolderOpen className="h-5 w-5 text-primary mt-0.5 group-hover:text-primary" />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-foreground truncate">{ws.name}</p>
                    {ws.description && (
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                        {ws.description}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground mt-2 opacity-60">
                      {new Date(ws.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
