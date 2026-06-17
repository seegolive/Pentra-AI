import { NavLink, useNavigate, useLocation, Outlet } from "react-router-dom";
import {
  BookOpen,
  FolderOpen,
  Target,
  ShieldCheck,
  ChevronRight,
  LogOut,
  Settings,
  Users,
  Activity,
  LayoutDashboard,
} from "lucide-react";
import { cn } from "../lib/utils";
import { useAuthStore } from "../lib/authStore";
import { APP_VERSION } from "../lib/version";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  exact?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
  { to: "/workspaces", label: "Workspaces", icon: <FolderOpen className="h-4 w-4" /> },
  { to: "/engagements", label: "All Engagements", icon: <Target className="h-4 w-4" /> },
  { to: "/knowledge", label: "Knowledge Base", icon: <BookOpen className="h-4 w-4" /> },
  { to: "/settings", label: "Settings", icon: <Settings className="h-4 w-4" /> },
];

function isRouteActive(pathname: string, to: string) {
  return pathname === to || pathname.startsWith(`${to}/`);
}

export function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();

  const adminNav: NavItem[] = user?.is_admin
    ? [
        { to: "/admin", label: "Admin", icon: <Settings className="h-4 w-4" /> },
        { to: "/admin/users", label: "Users", icon: <Users className="h-4 w-4" /> },
        { to: "/admin/workers", label: "Workers", icon: <Activity className="h-4 w-4" /> },
      ]
    : [];

  const isEngagementDetail = location.pathname.startsWith("/engagements/");
  const allNav = [...NAV_ITEMS, ...adminNav];

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="grid h-screen grid-cols-shell overflow-hidden bg-pentra-bg-void font-ui text-pentra-text-primary">
      <nav
        aria-label="Primary navigation"
        className="flex min-w-icon-nav flex-col items-center border-r border-pentra-border bg-pentra-bg-panel px-ds-2 py-ds-3"
      >
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          className="mb-ds-4 flex h-9 w-9 items-center justify-center rounded-ds-md bg-pentra-accent text-white shadow-[0_0_0_1px_var(--accent-glow)] transition-colors hover:bg-pentra-accent-light"
          aria-label="Dashboard"
        >
          <ShieldCheck className="h-4 w-4" />
        </button>

        <div className="flex flex-1 flex-col items-center gap-ds-1">
          {allNav.map((item) => {
            const active = isRouteActive(location.pathname, item.to);
            return (
              <NavLink
                key={item.to}
                to={item.to}
                title={item.label}
                aria-label={item.label}
                className={cn(
                  "group relative flex h-9 w-9 items-center justify-center rounded-ds-md text-pentra-text-muted transition-colors",
                  "hover:bg-pentra-bg-hover hover:text-pentra-text-secondary",
                  active && "bg-pentra-accent-glow text-pentra-accent-light"
                )}
              >
                {item.icon}
                <span className="pointer-events-none absolute left-[calc(100%+10px)] top-1/2 z-50 -translate-y-1/2 whitespace-nowrap rounded-ds-sm border border-pentra-border-light bg-pentra-bg-card px-2.5 py-1 text-[11px] text-pentra-text-primary opacity-0 shadow-xl transition-opacity group-hover:opacity-100">
                  {item.label}
                </span>
              </NavLink>
            );
          })}
        </div>

        <button
          type="button"
          onClick={handleLogout}
          className="flex h-9 w-9 items-center justify-center rounded-ds-md text-pentra-text-muted transition-colors hover:bg-pentra-bg-hover hover:text-pentra-text-secondary"
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="h-4 w-4" />
        </button>
      </nav>

      <aside className="flex min-w-sidebar flex-col overflow-hidden border-r border-pentra-border bg-pentra-bg-base">
        <div className="border-b border-pentra-border px-ds-4 py-ds-4">
          <button
            type="button"
            onClick={() => navigate("/dashboard")}
            className="flex min-w-0 items-center gap-ds-2"
          >
            <span className="flex h-7 w-7 items-center justify-center rounded-ds-sm bg-pentra-accent text-sm font-bold text-white">
              P
            </span>
            <span className="truncate text-[15px] font-semibold tracking-normal text-pentra-text-primary">
              Pentra <span className="text-pentra-accent-light">AI</span>
            </span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-ds-2">
          <p className="px-ds-3 pb-ds-1 pt-ds-2 text-[10px] font-semibold uppercase tracking-[0.8px] text-pentra-text-muted">
            Workspace
          </p>
          <nav aria-label="Workspace navigation" className="space-y-0.5">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-ds-2 rounded-ds-md px-ds-3 py-ds-2 text-[13px] font-medium transition-colors",
                    isActive
                      ? "bg-pentra-bg-active text-pentra-text-primary"
                      : "text-pentra-text-secondary hover:bg-pentra-bg-card hover:text-pentra-text-primary"
                  )
                }
              >
                <span className="text-pentra-text-muted">{item.icon}</span>
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </nav>

          {adminNav.length > 0 && (
            <>
              <p className="px-ds-3 pb-ds-1 pt-ds-4 text-[10px] font-semibold uppercase tracking-[0.8px] text-pentra-text-muted">
                Admin
              </p>
              <nav aria-label="Admin navigation" className="space-y-0.5">
                {adminNav.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      cn(
                        "flex items-center gap-ds-2 rounded-ds-md px-ds-3 py-ds-2 text-[13px] font-medium transition-colors",
                        isActive
                          ? "bg-pentra-bg-active text-pentra-text-primary"
                          : "text-pentra-text-secondary hover:bg-pentra-bg-card hover:text-pentra-text-primary"
                      )
                    }
                  >
                    <span className="text-pentra-text-muted">{item.icon}</span>
                    <span className="truncate">{item.label}</span>
                  </NavLink>
                ))}
              </nav>
            </>
          )}
        </div>

        <div className="space-y-ds-2 border-t border-pentra-border px-ds-3 py-ds-3">
          {user && (
            <div className="flex min-w-0 items-center gap-ds-2 px-ds-1">
              <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full border border-pentra-border-light bg-pentra-accent-dim text-[11px] font-semibold text-pentra-accent-light">
                {user.username[0].toUpperCase()}
              </div>
              <span className="truncate text-xs text-pentra-text-secondary">{user.username}</span>
            </div>
          )}
          <div className="px-ds-1 pt-ds-1">
            <span className="font-mono text-[10px] text-pentra-text-muted">
              v{APP_VERSION}
            </span>
          </div>
        </div>
      </aside>

      <main className="flex min-w-0 flex-col overflow-hidden bg-pentra-bg-base">
        {isEngagementDetail && (
          <div className="flex h-9 shrink-0 items-center gap-ds-1 border-b border-pentra-border bg-pentra-bg-panel px-ds-4 text-xs text-pentra-text-secondary">
            <ChevronRight className="h-3 w-3 opacity-40" />
            <span>Engagement detail</span>
          </div>
        )}
        <div className="flex min-h-0 flex-1 flex-col overflow-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
