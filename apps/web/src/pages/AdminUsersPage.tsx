import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import {
  Users,
  UserPlus,
  ShieldCheck,
  ToggleLeft,
  ToggleRight,
  Trash2,
  KeyRound,
  X,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
} from "lucide-react";
import { Navigate } from "react-router-dom";
import { useAuthStore } from "../lib/authStore";
import { cn } from "../lib/utils";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

function authHeaders() {
  const token = useAuthStore.getState().accessToken;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ── Types ──────────────────────────────────────────────────────────────────

interface AdminUser {
  id: string;
  username: string;
  email: string;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
}

// ── API helpers ────────────────────────────────────────────────────────────

async function fetchUsers(): Promise<AdminUser[]> {
  const r = await axios.get(`${BASE}/api/v1/admin/users`, { headers: authHeaders() });
  return r.data;
}

async function createUser(data: {
  username: string;
  email: string;
  password: string;
  is_admin: boolean;
}): Promise<AdminUser> {
  const r = await axios.post(`${BASE}/api/v1/admin/users`, data, { headers: authHeaders() });
  return r.data;
}

async function updateUser(id: string, data: { is_active?: boolean; is_admin?: boolean }): Promise<AdminUser> {
  const r = await axios.patch(`${BASE}/api/v1/admin/users/${id}`, data, { headers: authHeaders() });
  return r.data;
}

async function deleteUser(id: string): Promise<void> {
  await axios.delete(`${BASE}/api/v1/admin/users/${id}`, { headers: authHeaders() });
}

async function resetPassword(id: string): Promise<{ temporary_password: string }> {
  const r = await axios.post(`${BASE}/api/v1/admin/users/${id}/reset-password`, {}, { headers: authHeaders() });
  return r.data;
}

// ── Create User Modal ──────────────────────────────────────────────────────

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ username: "", email: "", password: "", is_admin: false });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");

  const mutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      onClose();
    },
    onError: (err: unknown) => {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Failed to create user";
      setError(detail);
    },
  });

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 shadow-xl">
        <div className="flex items-center justify-between mb-5">
          <h3 className="font-semibold text-foreground">Create User</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-3">
          {[
            { key: "username", label: "Username", type: "text" },
            { key: "email", label: "Email", type: "email" },
          ].map(({ key, label, type }) => (
            <div key={key}>
              <label className="block text-xs font-medium text-muted-foreground mb-1">{label}</label>
              <input
                type={type}
                value={form[key as keyof typeof form] as string}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          ))}

          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-1">Password</label>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                placeholder="Min. 8 characters"
                className="w-full bg-background border border-border rounded-md px-3 py-2 pr-9 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={form.is_admin}
              onChange={(e) => setForm((f) => ({ ...f, is_admin: e.target.checked }))}
              className="accent-primary"
            />
            <span className="text-sm text-foreground">Grant admin privileges</span>
          </label>
        </div>

        {error && (
          <p className="mt-3 text-xs text-red-400 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            {error}
          </p>
        )}

        <div className="flex gap-2 mt-5">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => mutation.mutate(form)}
            disabled={mutation.isPending}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
            Create User
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Reset Password Modal ───────────────────────────────────────────────────

function ResetPasswordModal({
  userId,
  username,
  onClose,
}: {
  userId: string;
  username: string;
  onClose: () => void;
}) {
  const [tempPw, setTempPw] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleReset = async () => {
    setLoading(true);
    setError("");
    try {
      const r = await resetPassword(userId);
      setTempPw(r.temporary_password);
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Reset failed";
      setError(detail);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-card border border-border rounded-xl w-full max-w-sm p-6 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-foreground">Reset Password — {username}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        {!tempPw ? (
          <>
            <p className="text-sm text-muted-foreground mb-4">
              A new random password will be generated. Share it with the user securely — it is shown only once.
            </p>
            {error && <p className="text-xs text-red-400 mb-3">{error}</p>}
            <div className="flex gap-2">
              <button onClick={onClose} className="px-4 py-2 border border-border rounded-md text-sm text-muted-foreground">
                Cancel
              </button>
              <button
                onClick={handleReset}
                disabled={loading}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-yellow-600 text-white rounded-md text-sm font-medium hover:bg-yellow-500 disabled:opacity-50 transition-colors"
              >
                {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <KeyRound className="h-3.5 w-3.5" />}
                Generate Password
              </button>
            </div>
          </>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-green-400 flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5" />
              Password reset successfully
            </p>
            <div className="bg-background border border-border rounded-md px-3 py-2">
              <p className="text-xs text-muted-foreground mb-1">Temporary password</p>
              <code className="text-sm font-mono text-foreground select-all">{tempPw}</code>
            </div>
            <p className="text-[10px] text-muted-foreground">
              This password will not be shown again. The user should change it immediately after login.
            </p>
            <button
              onClick={onClose}
              className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function AdminUsersPage() {
  const currentUser = useAuthStore((s) => s.user);
  const qc = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  if (!currentUser?.is_admin) return <Navigate to="/" replace />;

  const { data: users, isLoading } = useQuery<AdminUser[]>({
    queryKey: ["admin-users"],
    queryFn: fetchUsers,
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      updateUser(id, { is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-users"] }),
  });

  const toggleAdminMutation = useMutation({
    mutationFn: ({ id, is_admin }: { id: string; is_admin: boolean }) =>
      updateUser(id, { is_admin }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-users"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      setDeleteConfirm(null);
    },
  });

  return (
    <div className="flex-1 overflow-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
            <Users className="h-5 w-5 text-primary" />
            User Management
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {users?.length ?? 0} user{users?.length !== 1 ? "s" : ""} registered
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <UserPlus className="h-4 w-4" />
          Invite User
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading users…
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-background/50">
                {["User", "Email", "Role", "Status", "Actions"].map((h) => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users?.map((user) => (
                <tr key={user.id} className="border-b border-border/50 last:border-0 hover:bg-accent/20 transition-colors">
                  {/* User */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-7 w-7 rounded-full bg-indigo-600 flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0">
                        {user.username[0].toUpperCase()}
                      </div>
                      <span className="font-medium text-foreground">{user.username}</span>
                      {user.id === currentUser?.id && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary rounded">you</span>
                      )}
                    </div>
                  </td>

                  {/* Email */}
                  <td className="px-4 py-3 text-muted-foreground text-xs">{user.email}</td>

                  {/* Role toggle */}
                  <td className="px-4 py-3">
                    <button
                      onClick={() =>
                        user.id !== currentUser?.id &&
                        toggleAdminMutation.mutate({ id: user.id, is_admin: !user.is_admin })
                      }
                      disabled={user.id === currentUser?.id || toggleAdminMutation.isPending}
                      className={cn(
                        "flex items-center gap-1 text-xs px-2 py-0.5 rounded transition-colors",
                        user.is_admin
                          ? "bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20"
                          : "bg-muted text-muted-foreground hover:bg-accent",
                        user.id === currentUser?.id && "cursor-default opacity-70"
                      )}
                    >
                      <ShieldCheck className="h-3 w-3" />
                      {user.is_admin ? "admin" : "user"}
                    </button>
                  </td>

                  {/* Active toggle */}
                  <td className="px-4 py-3">
                    <button
                      onClick={() =>
                        user.id !== currentUser?.id &&
                        toggleMutation.mutate({ id: user.id, is_active: !user.is_active })
                      }
                      disabled={user.id === currentUser?.id || toggleMutation.isPending}
                      className={cn(
                        "flex items-center gap-1 text-xs transition-colors",
                        user.is_active ? "text-green-400" : "text-muted-foreground",
                        user.id === currentUser?.id && "cursor-default"
                      )}
                    >
                      {user.is_active ? (
                        <ToggleRight className="h-4 w-4" />
                      ) : (
                        <ToggleLeft className="h-4 w-4" />
                      )}
                      {user.is_active ? "active" : "inactive"}
                    </button>
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setResetTarget(user)}
                        disabled={user.id === currentUser?.id}
                        className="p-1.5 rounded text-muted-foreground hover:text-yellow-400 hover:bg-yellow-400/10 transition-colors disabled:opacity-40"
                        title="Reset password"
                      >
                        <KeyRound className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteConfirm(user.id)}
                        disabled={user.id === currentUser?.id}
                        className="p-1.5 rounded text-muted-foreground hover:text-red-400 hover:bg-red-400/10 transition-colors disabled:opacity-40"
                        title="Delete user"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Delete confirm */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-sm p-6 shadow-xl">
            <h3 className="font-semibold text-foreground mb-2">Delete user?</h3>
            <p className="text-sm text-muted-foreground mb-5">
              This action cannot be undone. All data owned by this user will remain but become unlinked.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="flex-1 px-4 py-2 border border-border rounded-md text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-red-600 text-white rounded-md text-sm font-medium hover:bg-red-500 disabled:opacity-50 transition-colors"
              >
                {deleteMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
      {resetTarget && (
        <ResetPasswordModal
          userId={resetTarget.id}
          username={resetTarget.username}
          onClose={() => setResetTarget(null)}
        />
      )}
    </div>
  );
}
