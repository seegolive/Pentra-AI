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
    } catch (err: any) {
      setError(err.response?.data?.detail ?? "Login failed");
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="text-3xl font-black tracking-tight text-white">
            Pentra<span className="text-indigo-400">AI</span>
          </div>
          <p className="mt-2 text-sm text-gray-400">
            Self-hosted AI Security Research Platform
          </p>
        </div>

        {/* Card */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl">
          <h1 className="text-lg font-semibold text-white mb-6">Sign in</h1>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-xs font-medium text-gray-400 mb-1">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2
                           text-sm text-white placeholder-gray-500
                           focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-medium text-gray-400 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2
                           text-sm text-white placeholder-gray-500
                           focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={login.isPending}
              className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed
                         text-white text-sm font-semibold rounded-lg px-4 py-2.5
                         transition-colors duration-150"
            >
              {login.isPending ? "Signing in…" : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
