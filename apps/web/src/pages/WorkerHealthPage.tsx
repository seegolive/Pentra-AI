import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  Loader2,
  RefreshCw,
  Server,
  Zap,
} from "lucide-react";
import { Navigate } from "react-router-dom";
import { useAuthStore } from "../lib/authStore";
import { cn } from "../lib/utils";

// ── API ────────────────────────────────────────────────────────────────────

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

function authHeaders() {
  const token = useAuthStore.getState().accessToken;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ── Types ──────────────────────────────────────────────────────────────────

interface WorkerStats {
  hostname: string;
  status: "online" | "offline";
  pid: number | null;
  concurrency: number | null;
  queues: string[];
  active_tasks: number;
  reserved_tasks: number;
  total_tasks_executed: number | null;
  pool: string | null;
}

interface ActiveTask {
  id: string;
  name: string;
  worker: string;
  started_at: string | null;
  kwargs: Record<string, unknown>;
}

interface WorkerHealthResponse {
  healthy: boolean;
  workers: WorkerStats[];
  active_tasks: ActiveTask[];
  scheduled_tasks: number;
  checked_at: string;
}

// ── Worker card ────────────────────────────────────────────────────────────

function WorkerCard({ worker }: { worker: WorkerStats }) {
  return (
    <div
      className={cn(
        "rounded-lg border p-4 space-y-3",
        worker.status === "online"
          ? "border-green-500/20 bg-green-500/5"
          : "border-red-500/20 bg-red-500/5"
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cn(
            "h-2 w-2 rounded-full",
            worker.status === "online" ? "bg-green-500" : "bg-red-500"
          )}
        />
        <p className="font-medium text-sm text-foreground truncate flex-1">
          {worker.hostname}
        </p>
        {worker.status === "online" ? (
          <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
        ) : (
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        {worker.pid && (
          <div>
            <p className="text-muted-foreground">PID</p>
            <p className="text-foreground font-mono">{worker.pid}</p>
          </div>
        )}
        {worker.concurrency && (
          <div>
            <p className="text-muted-foreground">Concurrency</p>
            <p className="text-foreground font-mono">{worker.concurrency}</p>
          </div>
        )}
        <div>
          <p className="text-muted-foreground">Active</p>
          <p className="text-foreground font-mono">{worker.active_tasks}</p>
        </div>
        <div>
          <p className="text-muted-foreground">Queued</p>
          <p className="text-foreground font-mono">{worker.reserved_tasks}</p>
        </div>
        {worker.total_tasks_executed != null && (
          <div className="col-span-2">
            <p className="text-muted-foreground">Total Executed</p>
            <p className="text-foreground font-mono">
              {worker.total_tasks_executed.toLocaleString()}
            </p>
          </div>
        )}
        {worker.pool && (
          <div className="col-span-2">
            <p className="text-muted-foreground">Pool</p>
            <p className="text-foreground font-mono">{worker.pool}</p>
          </div>
        )}
      </div>

      {worker.queues.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {worker.queues.map((q) => (
            <span
              key={q}
              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/20"
            >
              {q}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Active tasks table ─────────────────────────────────────────────────────

function taskShortName(fullName: string) {
  const parts = fullName.split(".");
  return parts[parts.length - 1] ?? fullName;
}

function ActiveTasksTable({ tasks }: { tasks: ActiveTask[] }) {
  if (tasks.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-24 text-muted-foreground text-sm gap-1">
        <Activity className="h-5 w-5 opacity-30" />
        <p>No active tasks</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th className="text-left py-2 pr-4 font-medium">Task</th>
            <th className="text-left py-2 pr-4 font-medium">Worker</th>
            <th className="text-left py-2 font-medium">Started</th>
          </tr>
        </thead>
        <tbody>
          {tasks.map((task) => (
            <tr key={task.id} className="border-b border-border/50 hover:bg-muted/30">
              <td className="py-2 pr-4">
                <p className="font-mono text-foreground">{taskShortName(task.name)}</p>
                <p className="text-muted-foreground truncate max-w-[160px]">{task.id}</p>
              </td>
              <td className="py-2 pr-4 text-muted-foreground truncate max-w-[140px]">
                {task.worker.split("@")[1] ?? task.worker}
              </td>
              <td className="py-2 text-muted-foreground whitespace-nowrap">
                {task.started_at
                  ? new Date(task.started_at).toLocaleTimeString()
                  : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export default function WorkerHealthPage() {
  const user = useAuthStore((s) => s.user);

  const { data, isLoading, isError, refetch, isFetching } =
    useQuery<WorkerHealthResponse>({
      queryKey: ["worker-health"],
      queryFn: async () => {
        const res = await axios.get(`${BASE}/api/v1/admin/worker/health`, {
          headers: authHeaders(),
        });
        return res.data;
      },
      refetchInterval: 10_000,
      retry: 1,
      enabled: !!user?.is_admin,
    });

  if (!user?.is_admin) return <Navigate to="/" replace />;

  return (
    <div className="flex-1 w-full p-8">
      <div className="w-full">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Server className="h-6 w-6 text-primary" />
              Worker Health
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Live Celery worker status — auto-refreshes every 10 s
            </p>
          </div>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-3 py-2 rounded-md border border-border text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
          >
            <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
            Refresh
          </button>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-muted-foreground gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Pinging workers…
          </div>
        ) : isError ? (
          <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-400">
            Could not reach the API. Make sure the backend is running.
          </div>
        ) : data ? (
          <div className="space-y-8">
            {/* Summary bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                {
                  label: "Workers Online",
                  value: data.workers.filter((w) => w.status === "online").length,
                  icon: <Cpu className="h-5 w-5" />,
                  color: data.healthy ? "text-green-400" : "text-red-400",
                },
                {
                  label: "Active Tasks",
                  value: data.active_tasks.length,
                  icon: <Zap className="h-5 w-5" />,
                  color: "text-yellow-400",
                },
                {
                  label: "Scheduled",
                  value: data.scheduled_tasks,
                  icon: <Clock className="h-5 w-5" />,
                  color: "text-blue-400",
                },
                {
                  label: "Status",
                  value: data.healthy ? "Healthy" : "Degraded",
                  icon: data.healthy ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : (
                    <AlertTriangle className="h-5 w-5" />
                  ),
                  color: data.healthy ? "text-green-400" : "text-red-400",
                },
              ].map(({ label, value, icon, color }) => (
                <div
                  key={label}
                  className="rounded-lg border border-border bg-card p-4 flex items-center gap-3"
                >
                  <span className={color}>{icon}</span>
                  <div>
                    <p className="text-xs text-muted-foreground">{label}</p>
                    <p className="text-lg font-semibold text-foreground">{value}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Workers grid */}
            <section>
              <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                Workers ({data.workers.length})
              </h2>
              {data.workers.length === 0 ? (
                <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
                  No workers connected. Start a Celery worker to see status here.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4 gap-4">
                  {data.workers.map((w) => (
                    <WorkerCard key={w.hostname} worker={w} />
                  ))}
                </div>
              )}
            </section>

            {/* Active tasks */}
            <section>
              <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                <Activity className="h-4 w-4 text-muted-foreground" />
                Active Tasks
              </h2>
              <div className="rounded-lg border border-border bg-card p-4">
                <ActiveTasksTable tasks={data.active_tasks} />
              </div>
            </section>

            {/* Footer */}
            <p className="text-xs text-muted-foreground text-right">
              Last checked: {new Date(data.checked_at).toLocaleString()}
            </p>
          </div>
        ) : null}
      </div>
    </div>
  );
}
