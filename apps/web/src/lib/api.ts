import axios from "axios";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type {
  KnowledgeRecord,
  KnowledgeSummary,
  SearchFilters,
  SearchResponse,
  Severity,
  VulnClass,
  Workspace,
  WorkspaceCreate,
  Engagement,
  EngagementCreate,
  Finding,
  FindingStatus,
  HitlDecision,
} from "./types";
import { useAuthStore } from "./authStore";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8000",
  timeout: 15_000,
});

// Inject JWT on every request
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-logout on 401
apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore.getState().logout();
    }
    return Promise.reject(err);
  }
);

// ── Auth ────────────────────────────────────────────────────────────────────

export interface LoginRequest { username: string; password: string; }
export interface RegisterRequest { username: string; email: string; password: string; }
export interface TokenResponse { access_token: string; refresh_token: string; token_type: string; }
export interface UserResponse { id: string; username: string; email: string; is_admin: boolean; }

export async function loginApi(data: LoginRequest): Promise<TokenResponse> {
  const res = await apiClient.post<TokenResponse>("/api/v1/auth/login", data);
  return res.data;
}

export async function registerApi(data: RegisterRequest): Promise<UserResponse> {
  const res = await apiClient.post<UserResponse>("/api/v1/auth/register", data);
  return res.data;
}

export async function getMeApi(): Promise<UserResponse> {
  const res = await apiClient.get<UserResponse>("/api/v1/auth/me");
  return res.data;
}

export function useLogin() {
  return useMutation<TokenResponse, Error, LoginRequest>({
    mutationFn: loginApi,
  });
}

export function useRegister() {
  return useMutation<UserResponse, Error, RegisterRequest>({
    mutationFn: registerApi,
  });
}

// ── Search ──────────────────────────────────────────────────────────────────

export interface SearchParams extends Partial<SearchFilters> {
  q: string;
  top_k?: number;
}

async function fetchSearch(params: SearchParams): Promise<SearchResponse> {
  const qp = new URLSearchParams({ q: params.q });
  if (params.top_k) qp.set("top_k", String(params.top_k));
  params.vuln_class?.forEach((v: VulnClass) => qp.append("vuln_class", v));
  params.severity?.forEach((s: Severity) => qp.append("severity", s));
  params.tech_stack?.forEach((t: string) => qp.append("tech_stack", t));
  const res = await apiClient.get<SearchResponse>(`/knowledge/search?${qp}`);
  return res.data;
}

export function useKnowledgeSearch(params: SearchParams, enabled = true) {
  return useQuery<SearchResponse, Error, KnowledgeSummary[]>({
    queryKey: ["knowledge", "search", params],
    queryFn: () => fetchSearch(params),
    enabled: enabled && params.q.trim().length > 0,
    staleTime: 30_000,
    select: (data) => data.results,
  });
}

// ── Single record ──────────────────────────────────────────────────────────

async function fetchRecord(id: string): Promise<KnowledgeRecord> {
  const res = await apiClient.get<KnowledgeRecord>(`/knowledge/${id}`);
  return res.data;
}

export function useKnowledgeRecord(id: string | null) {
  return useQuery<KnowledgeRecord, Error>({
    queryKey: ["knowledge", "record", id],
    queryFn: () => fetchRecord(id!),
    enabled: id != null,
    staleTime: 60_000,
  });
}

// ── KB Manual Inject ─────────────────────────────────────────────────────────

export interface KBManualInjectRequest {
  title: string;
  vuln_class: string;
  severity: string;
  raw_text: string;
  key_insight?: string;
  technique?: string;
  tech_stack?: string[];
  tags?: string[];
  url?: string;
}

export interface KBInjectResponse {
  knowledge_record_id: string;
  message: string;
}

export function useKBManualInject() {
  const qc = useQueryClient();
  return useMutation<KBInjectResponse, Error, KBManualInjectRequest>({
    mutationFn: async (body) => {
      const res = await apiClient.post<KBInjectResponse>("/api/v1/knowledge/inject", body);
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["knowledge"] });
    },
  });
}


export function useWorkspaces() {
  return useQuery<Workspace[], Error>({
    queryKey: ["workspaces"],
    queryFn: async () => {
      const res = await apiClient.get<Workspace[]>("/api/v1/workspaces/");
      return res.data;
    },
    staleTime: 30_000,
  });
}

export function useCreateWorkspace() {
  const qc = useQueryClient();
  return useMutation<Workspace, Error, WorkspaceCreate>({
    mutationFn: async (data) => {
      const res = await apiClient.post<Workspace>("/api/v1/workspaces/", data);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workspaces"] }),
  });
}

// ── Engagements ────────────────────────────────────────────────────────────────

export function useEngagements(workspaceId?: string) {
  return useQuery<Engagement[], Error>({
    queryKey: ["engagements", workspaceId],
    queryFn: async () => {
      const url = workspaceId
        ? `/api/v1/engagements/?workspace_id=${workspaceId}`
        : "/api/v1/engagements/";
      const res = await apiClient.get<Engagement[]>(url);
      return res.data;
    },
    staleTime: 10_000,
  });
}

export function useEngagement(id: string | undefined) {
  return useQuery<Engagement, Error>({
    queryKey: ["engagement", id],
    queryFn: async () => {
      const res = await apiClient.get<Engagement>(`/api/v1/engagements/${id}`);
      return res.data;
    },
    enabled: id != null,
    refetchInterval: 5_000,
  });
}

export function useCreateEngagement() {
  const qc = useQueryClient();
  return useMutation<Engagement, Error, EngagementCreate>({
    mutationFn: async (data) => {
      const res = await apiClient.post<Engagement>("/api/v1/engagements/", data);
      return res.data;
    },
    onSuccess: (eng) => {
      qc.invalidateQueries({ queryKey: ["engagements"] });
      qc.invalidateQueries({ queryKey: ["engagements", eng.workspace_id] });
    },
  });
}

export function useStartEngagement(id: string) {
  const qc = useQueryClient();
  return useMutation<{ status: string }, Error, void>({
    mutationFn: async () => {
      const res = await apiClient.post<{ status: string }>(`/api/v1/engagements/${id}/start`);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagement", id] }),
  });
}

export function useApproveAction(id: string) {
  const qc = useQueryClient();
  return useMutation<{ status: string }, Error, HitlDecision>({
    mutationFn: async (decision) => {
      const res = await apiClient.post<{ status: string }>(`/api/v1/engagements/${id}/approve`, decision);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagement", id] }),
  });
}

// ── Findings ───────────────────────────────────────────────────────────────────

export function useFindings(engagementId: string) {
  return useQuery<Finding[], Error>({
    queryKey: ["findings", engagementId],
    queryFn: async () => {
      const res = await apiClient.get<Finding[]>(`/api/v1/engagements/${engagementId}/findings`);
      return res.data;
    },
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}

export function useEngagementReport(engagementId: string, enabled = true) {
  return useQuery<string, Error>({
    queryKey: ["engagement-report", engagementId],
    queryFn: async () => {
      const res = await apiClient.get<string>(
        `/api/v1/engagements/${engagementId}/report?format=markdown`,
        { responseType: "text" },
      );
      return res.data;
    },
    enabled,
    staleTime: 60_000,
    retry: false,
  });
}

export interface SubmitFindingToKBRequest {
  key_insight?: string;
  technique?: string;
  tags?: string[];
}

export function useSubmitFindingToKB(findingId: string) {
  const qc = useQueryClient();
  return useMutation<KBInjectResponse, Error, SubmitFindingToKBRequest>({
    mutationFn: async (body) => {
      const res = await apiClient.post<KBInjectResponse>(
        `/api/v1/findings/${findingId}/submit-to-knowledge`,
        body,
      );
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["knowledge"] }),
  });
}

export function usePatchFinding(engagementId: string) {
  const qc = useQueryClient();
  return useMutation<Finding, Error, { id: string; status: FindingStatus }>({
    mutationFn: async ({ id, status }) => {
      const res = await apiClient.patch<Finding>(`/api/v1/findings/${id}`, { status });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", engagementId] }),
  });
}

// ── KB URL + File inject ───────────────────────────────────────────────────────

export interface KBUrlInjectRequest {
  url: string;
  vuln_class?: string;
  tags?: string[];
}

export function useKBInjectFromUrl() {
  const qc = useQueryClient();
  return useMutation<KBInjectResponse, Error, KBUrlInjectRequest>({
    mutationFn: async (body) => {
      const res = await apiClient.post<KBInjectResponse>("/api/v1/knowledge/inject/url", body);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["knowledge"] }),
  });
}

export function useKBInjectFromFile() {
  const qc = useQueryClient();
  return useMutation<KBInjectResponse, Error, FormData>({
    mutationFn: async (form) => {
      const res = await apiClient.post<KBInjectResponse>("/api/v1/knowledge/inject/file", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["knowledge"] }),
  });
}

// ── Payload Generator ─────────────────────────────────────────────────────────

export interface PayloadGenerateRequest {
  target_url: string;
  parameter_name: string;
  parameter_value?: string;
  parameter_position?: "path" | "query" | "body" | "header" | "cookie";
  http_method?: string;
  vuln_class: string;
  tech_stack?: string[];
  additional_context?: string;
  count?: number;
}

export interface GeneratedPayload {
  value: string;
  rationale: string;
  severity_hint: string;
  requires_encoding: boolean;
}

export interface PayloadGenerateResponse {
  payloads: GeneratedPayload[];
  knowledge_used: number;
  model_used: string;
}

export function useGeneratePayloads() {
  return useMutation<PayloadGenerateResponse, Error, PayloadGenerateRequest>({
    mutationFn: async (body) => {
      const res = await apiClient.post<PayloadGenerateResponse>("/api/v1/payloads/generate", body);
      return res.data;
    },
  });
}

// ── Engagement Export / Import ─────────────────────────────────────────────────

export async function downloadEngagementExport(engagementId: string): Promise<void> {
  const res = await apiClient.get(`/api/v1/engagements/${engagementId}/export`);
  const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `engagement-${engagementId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export interface ImportEngagementRequest {
  bundle: unknown;
  new_name?: string;
}

export function useImportEngagement(workspaceId: string) {
  const qc = useQueryClient();
  return useMutation<Engagement, Error, ImportEngagementRequest>({
    mutationFn: async (body) => {
      const res = await apiClient.post<Engagement>(
        `/api/v1/workspaces/${workspaceId}/engagements/import`,
        body,
      );
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engagements", workspaceId] });
      qc.invalidateQueries({ queryKey: ["engagements"] });
    },
  });
}

// ── Monitoring ──────────────────────────────────────────────────────────────

export interface MonitoringAlert {
  id: string;
  engagement_id: string;
  alert_type: "new_subdomain" | "new_port" | "new_endpoint" | "removed_subdomain";
  detail: Record<string, unknown>;
  is_read: boolean;
  created_at: string;
}

export interface ReconSnapshot {
  id: string;
  engagement_id: string;
  snapshot_at: string;
  subdomains: string[];
  open_ports: Record<string, number[]>;
  endpoints: string[];
  tech_stack: string[];
  raw_summary: string | null;
}

export interface SnapshotDiff {
  snapshot_a_id: string;
  snapshot_b_id: string;
  snapshot_a_at: string;
  snapshot_b_at: string;
  new_subdomains: string[];
  removed_subdomains: string[];
  new_ports: Record<string, number[]>;
  new_endpoints: string[];
  new_tech: string[];
}

export function useMonitoringAlerts(
  engagementId: string | undefined,
  filters?: { is_read?: boolean; alert_type?: string; limit?: number }
) {
  return useQuery<MonitoringAlert[]>({
    queryKey: ["monitoring-alerts", engagementId, filters],
    queryFn: async () => {
      const params: Record<string, string | number | boolean> = {};
      if (filters?.is_read !== undefined) params.is_read = filters.is_read;
      if (filters?.alert_type) params.alert_type = filters.alert_type;
      if (filters?.limit) params.limit = filters.limit;
      const res = await apiClient.get<MonitoringAlert[]>(
        `/api/v1/engagements/${engagementId}/monitoring/alerts`,
        { params }
      );
      return res.data;
    },
    enabled: !!engagementId,
    refetchInterval: 60_000, // poll every 60s
  });
}

export function useMarkAlertRead() {
  const qc = useQueryClient();
  return useMutation<MonitoringAlert, Error, { engagementId: string; alertId: string }>({
    mutationFn: async ({ engagementId, alertId }) => {
      const res = await apiClient.patch<MonitoringAlert>(
        `/api/v1/engagements/${engagementId}/monitoring/alerts/${alertId}/read`
      );
      return res.data;
    },
    onSuccess: (_, { engagementId }) => {
      qc.invalidateQueries({ queryKey: ["monitoring-alerts", engagementId] });
    },
  });
}

export function useMarkAllAlertsRead() {
  const qc = useQueryClient();
  return useMutation<void, Error, { engagementId: string }>({
    mutationFn: async ({ engagementId }) => {
      await apiClient.post(
        `/api/v1/engagements/${engagementId}/monitoring/alerts/read-all`
      );
    },
    onSuccess: (_, { engagementId }) => {
      qc.invalidateQueries({ queryKey: ["monitoring-alerts", engagementId] });
    },
  });
}

export function useReconSnapshots(engagementId: string | undefined, limit = 10) {
  return useQuery<ReconSnapshot[]>({
    queryKey: ["recon-snapshots", engagementId, limit],
    queryFn: async () => {
      const res = await apiClient.get<ReconSnapshot[]>(
        `/api/v1/engagements/${engagementId}/monitoring/snapshots`,
        { params: { limit } }
      );
      return res.data;
    },
    enabled: !!engagementId,
  });
}

export function useSnapshotDiff(
  engagementId: string | undefined,
  snapshotA: string | undefined,
  snapshotB: string | undefined
) {
  return useQuery<SnapshotDiff>({
    queryKey: ["snapshot-diff", engagementId, snapshotA, snapshotB],
    queryFn: async () => {
      const res = await apiClient.get<SnapshotDiff>(
        `/api/v1/engagements/${engagementId}/monitoring/snapshots/diff`,
        { params: { snapshot_a: snapshotA, snapshot_b: snapshotB } }
      );
      return res.data;
    },
    enabled: !!engagementId && !!snapshotA && !!snapshotB,
  });
}
