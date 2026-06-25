import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { useLogin, getMeApi } from "../lib/api";
import { useAuthStore } from "../lib/authStore";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export default function LoginPage() {
  const navigate = useNavigate();
  const { setTokens, setUser, isAuthenticated } = useAuthStore();
  const login = useLogin();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Already logged in → go to app
  useEffect(() => {
    if (isAuthenticated()) {
      navigate("/workspaces", { replace: true });
      return;
    }
    // Check if first-run setup is needed
    axios
      .get<{ requires_setup: boolean }>(`${BASE}/api/v1/setup/status`)
      .then((r) => {
        if (r.data.requires_setup) navigate("/setup", { replace: true });
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const tokens = await login.mutateAsync({ username, password });
      setTokens(tokens.access_token, tokens.refresh_token);
      // Fetch user info now that token is set
      const me = await getMeApi();
      setUser(me);
      navigate("/workspaces");
    } catch (err) {
      setError((err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Login failed");
    }
  };

  return (
    <div className="min-h-screen bg-pentra-bg-base flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="text-3xl font-black tracking-tight text-pentra-text-primary">
            Pentra<span className="text-pentra-accent">AI</span>
          </div>
          <p className="mt-2 text-sm text-pentra-text-muted">
            Self-hosted AI Security Research Platform
          </p>
        </div>

        {/* Card */}
        <div className="bg-pentra-bg-panel border border-pentra-border rounded-ds-lg p-6 shadow-xl">
          <h1 className="text-lg font-semibold text-pentra-text-primary mb-6">Sign in</h1>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-xs font-medium text-pentra-text-muted mb-1.5">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                className="w-full bg-pentra-bg-card border border-pentra-border rounded-ds-md px-3 py-2
                           text-sm text-pentra-text-primary placeholder-pentra-text-muted/50
                           focus:outline-none focus:ring-1 focus:ring-pentra-accent focus:border-pentra-accent/60
                           transition-colors"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-medium text-pentra-text-muted mb-1.5">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                className="w-full bg-pentra-bg-card border border-pentra-border rounded-ds-md px-3 py-2
                           text-sm text-pentra-text-primary placeholder-pentra-text-muted/50
                           focus:outline-none focus:ring-1 focus:ring-pentra-accent focus:border-pentra-accent/60
                           transition-colors"
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 bg-red-950/60 border border-red-800/60 rounded-ds-md px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={login.isPending}
              className="w-full bg-pentra-accent hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed
                         text-white text-sm font-semibold rounded-ds-md px-4 py-2.5
                         transition-opacity"
            >
              {login.isPending ? "Signing in…" : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
