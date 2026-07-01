import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import ProtectedRoute from "./components/ProtectedRoute";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Toaster } from "./components/Toaster";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import WorkspacesPage from "./pages/WorkspacesPage";
import EngagementsPage from "./pages/EngagementsPage";
import EngagementDetailPage from "./pages/EngagementDetailPage";
import FindingsPage from "./pages/FindingsPage";
import KnowledgeBrowser from "./pages/KnowledgeBrowser";
import KnowledgeInject from "./pages/KnowledgeInject";
import AdminPage from "./pages/AdminPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import WorkerHealthPage from "./pages/WorkerHealthPage";
import SetupPage from "./pages/SetupPage";
import SettingsPage from "./pages/SettingsPage";
import ScanWizard from "./pages/ScanWizard";
import AttackSurfacePage from "./pages/AttackSurfacePage";
import ApiVaultPage from "./pages/ApiVaultPage";
import GFPatternsPage from "./pages/GFPatternsPage";
import TrendsPage from "./pages/TrendsPage";

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/setup" element={<SetupPage />} />

          {/* Protected — all routes require authentication */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppShell />}>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/workspaces" element={<WorkspacesPage />} />
              <Route path="/workspaces/:workspaceId/engagements" element={<EngagementsPage />} />
              <Route path="/engagements" element={<EngagementsPage />} />
              <Route path="/engagements/:engagementId" element={<EngagementDetailPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/knowledge" element={<KnowledgeBrowser />} />
              <Route path="/knowledge/inject" element={<KnowledgeInject />} />
              <Route path="/admin" element={<AdminPage />} />
              <Route path="/admin/users" element={<AdminUsersPage />} />
              <Route path="/admin/workers" element={<WorkerHealthPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              {/* Sprint UI-2 new routes */}
              <Route path="/scan/new" element={<ScanWizard />} />
              <Route path="/attack-surface" element={<AttackSurfacePage />} />
              <Route path="/api-vault" element={<ApiVaultPage />} />
              <Route path="/gf-patterns" element={<GFPatternsPage />} />
              <Route path="/trends" element={<TrendsPage />} />
            </Route>
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster />
    </ErrorBoundary>
  );
}

export default App;
