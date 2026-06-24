export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type VulnClass =
  | "sqli"
  | "xss"
  | "ssrf"
  | "idor"
  | "rce"
  | "lfi"
  | "xxe"
  | "idor"
  | "auth_bypass"
  | "privilege_escalation"
  | "info_disclosure"
  | "csrf"
  | "open_redirect"
  | "ssti"
  | "path_traversal"
  | "race_condition"
  | "business_logic"
  | "misconfig"
  | "dos"
  | "other";

export type KnowledgeSource = "h1_public" | "custom" | "nvd" | "exploit_db";

export interface KnowledgeSummary {
  id: string;
  title: string;
  vuln_class: VulnClass;
  severity: Severity;
  program: string;
  tech_stack: string[];
  key_insight: string;
  bounty_usd: number | null;
  source: KnowledgeSource;
  source_url: string | null;
}

export interface KnowledgeRecord extends KnowledgeSummary {
  vuln_subclass: string;
  endpoint_pattern: string;
  http_method: string[];
  auth_required: boolean;
  attack_technique: string;
  attack_steps: string[];
  payload_pattern: string | null;
  indicators: string[];
  prerequisites: string[];
  what_tools_missed: string | null;
  chained_with: string[];
  impact: string;
  impact_category: string[];
  platform_type: string[];
  source_id: string;
  created_at: string;
  updated_at: string;
}

export interface SearchResponse {
  results: KnowledgeSummary[];
  total: number;
  query: string;
}

export interface SearchFilters {
  vuln_class: VulnClass[];
  severity: Severity[];
  tech_stack: string[];
}

// ── Workspace ─────────────────────────────────────────────────────────────────

export interface Workspace {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceCreate {
  name: string;
  description?: string;
}

// ── Engagement ────────────────────────────────────────────────────────────────

export type EngagementMode = "semi_auto" | "agentic";
export type EngagementStatus = "planning" | "active" | "awaiting_approval" | "paused" | "completed" | "failed" | "cancelled";

export interface Engagement {
  id: string;
  workspace_id: string;
  name: string;
  description: string | null;
  mode: EngagementMode;
  status: EngagementStatus;
  in_scope: string[];
  out_of_scope: string[];
  llm_model: string;
  langgraph_thread_id: string;
  opsec_mode: boolean;
  request_jitter_ms: number;
  scan_sequential: boolean;
  auto_approve_exploit_validation: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface EngagementCreate {
  workspace_id: string;
  name: string;
  description?: string;
  mode: EngagementMode;
  in_scope: string[];
  out_of_scope: string[];
  llm_model: string;
  opsec_mode?: boolean;
  request_jitter_ms?: number;
  scan_sequential?: boolean;
  auto_approve_exploit_validation?: boolean;
}

// ── Finding ───────────────────────────────────────────────────────────────────

export type FindingStatus = "open" | "confirmed" | "false_positive" | "wont_fix" | "resolved";

export interface ChainInfo {
  name: string;
  scenario: string;
  upgraded_severity?: string | null;
  business_impact?: string | null;
  chain_size?: number | null;
}

export interface Finding {
  id: string;
  engagement_id: string;
  title: string;
  vuln_class: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector?: string | null;
  target_url: string;
  http_method: string;
  status: FindingStatus;
  discovered_by: string;
  discovered_at: string;
  description?: string | null;
  impact?: string | null;
  remediation?: string | null;
  cve_ids: string[];
  cve_data?: {
    cve_id: string;
    description: string;
    cvss_score: number | null;
    cvss_vector: string | null;
    severity: string;
    published: string;
    references: string[];
    cpe: string[];
  } | null;
  chains?: ChainInfo[] | null;
}

// ── Live Feed ─────────────────────────────────────────────────────────────────

export type FeedEventType =
  | "ping"
  // agent lifecycle
  | "agent_start"
  | "agent_step"
  | "agent_complete"
  | "agent_cancelled"
  | "agent_resumed"
  | "terminal_output"
  | "error"
  // structured backend events (service.py / worker)
  | "NODE_START"
  | "NODE_COMPLETE"
  | "AWAITING_APPROVAL"
  | "FINDINGS_UPDATED"
  | "ENGAGEMENT_COMPLETED"
  | "ENGAGEMENT_STARTED"
  | "AGENT_ERROR"
  | "AGENT_RESUMED"
  | "LLM_STREAM"
  // subscan events
  | "subscan_started"
  | "subscan_complete"
  | "subscan_error";

export interface FeedEvent {
  type: FeedEventType;
  /** Node name (present on NODE_* and LLM_STREAM events) */
  node?: string;
  /** Single LLM token (LLM_STREAM events) */
  token?: string;
  /** Finding count delta (FINDINGS_UPDATED events) */
  count?: number;
  data?: Record<string, unknown>;
  message?: string;
  timestamp?: string;
}

export interface ApprovalRequest {
  phase: string;
  summary: string;
  proposed_actions?: unknown[];
}

// ── HITL ──────────────────────────────────────────────────────────────────────

export interface HitlDecision {
  action: "approve" | "skip" | "modify";
  modified_data?: Record<string, unknown>;
}
