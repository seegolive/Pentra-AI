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

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-border flex flex-col bg-card">
        {/* Logo */}
        <div
          className="flex items-center gap-2.5 px-5 py-5 border-b border-border cursor-pointer"
          onClick={() => navigate("/dashboard")}
        >
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span className="font-bold text-foreground tracking-tight">Pentra AI</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 space-y-0.5 px-2">
          {[...NAV_ITEMS, ...adminNav].map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors",
                  isActive
                    ? "bg-primary/10 text-primary font-medium"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground"
                )
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Footer with user info + logout */}
        <div className="border-t border-border px-3 py-3 space-y-2">
          {user && (
            <div className="flex items-center gap-2 px-1">
              <div className="h-6 w-6 rounded-full bg-indigo-600 flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0">
                {user.username[0].toUpperCase()}
              </div>
              <span className="text-xs text-muted-foreground truncate">{user.username}</span>
            </div>
          )}
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-full px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>
          <div className="px-1 pt-1">
            <span className="text-[10px] text-muted-foreground/40 font-mono">
              v{APP_VERSION}
            </span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Breadcrumb strip if on engagement detail */}
        {isEngagementDetail && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground px-4 py-1.5 border-b border-border/50 bg-background/80">
            <ChevronRight className="h-3 w-3 opacity-40" />
            <span className="opacity-60">Engagement detail</span>
          </div>
        )}
        <div className="flex-1 overflow-auto flex flex-col">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
