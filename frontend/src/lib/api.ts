// Tiny fetch wrapper. Injects the JWT and unwraps JSON.
// Kept hand-rolled (no axios despite installing it) — readers can see exactly
// what's happening and there's nothing to explain in interview.

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";

const TOKEN_KEY = "tenex_jwt";

// ApiError carries the HTTP status alongside the message so callers can
// branch on it (e.g., 404 = "expected, no cached briefing yet"; 503 = "AI
// not configured"). Avoids fragile substring sniffing of error messages.
// (We use explicit field declarations rather than the constructor-parameter
// shorthand because Vite's `erasableSyntaxOnly` tsconfig flag rejects the
// shorthand — it isn't pure-erasable TypeScript.)
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401) {
    clearToken();
    // Forces the protected-route guard to bounce to /login on next render.
    window.location.assign("/login");
    throw new ApiError(401, "unauthorized");
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {}
    throw new ApiError(res.status, msg);
  }
  // 204 No Content
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// --- API types (match the Go JSON shapes) ---

export type Upload = {
  id: string;
  filename: string;
  total_rows: number;
  parsed_rows: number;
  uploaded_at: string;
};

export type LogEntry = {
  id: number;
  upload_id: string;
  timestamp: string;
  username: string;
  src_ip: string;
  dst_ip: string;
  url: string;
  url_category: string;
  action: string;
  threat_name: string;
  threat_category: string;
  bytes_in: number;
  bytes_out: number;
  user_agent: string;
  referer: string;
};

export type Anomaly = {
  id: number;
  upload_id: string;
  log_entry_id: number;
  rule_name: string;
  explanation: string;
  confidence: number;
};

export type CountPair = { key: string; count: number };
export type TimelineBucket = {
  bucket_start: string;
  total_count: number;
  blocked_count: number;
  anomaly_count: number;
};

export type Summary = {
  total_entries: number;
  blocked_entries: number;
  unique_src_ips: number;
  anomaly_count: number;
  top_categories: CountPair[] | null;
  top_src_ips: CountPair[] | null;
  top_threats: CountPair[] | null;
  timeline: TimelineBucket[] | null;
};

// --- Endpoint helpers ---

export type Briefing = {
  markdown: string;
  generated_at: string;
  cached: boolean;
};

export type Explanation = {
  markdown: string;
  generated_at: string;
  cached: boolean;
};

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; username: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  me: () => request<{ username: string }>("/api/auth/me"),

  uploadFile: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<{
      upload_id: string;
      filename: string;
      total_rows: number;
      parsed_rows: number;
      skipped_rows: number;
      anomaly_count: number;
    }>("/api/uploads", { method: "POST", body: fd });
  },

  listUploads: () => request<Upload[]>("/api/uploads"),
  getUpload: (id: string) => request<Upload>(`/api/uploads/${id}`),
  listEntries: (id: string, opts: { anomalousOnly?: boolean; limit?: number; offset?: number } = {}) => {
    const params = new URLSearchParams();
    if (opts.anomalousOnly) params.set("anomalous", "true");
    if (opts.limit != null) params.set("limit", String(opts.limit));
    if (opts.offset != null) params.set("offset", String(opts.offset));
    const q = params.toString();
    return request<{ entries: LogEntry[]; total: number; limit: number; offset: number }>(
      `/api/uploads/${id}/entries${q ? `?${q}` : ""}`,
    );
  },
  listAnomalies: (id: string) => request<Anomaly[]>(`/api/uploads/${id}/anomalies`),
  summary: (id: string) => request<Summary>(`/api/uploads/${id}/summary`),

  // AI — cached on the backend; the GET returns 404 if no briefing has been
  // generated yet, the POST triggers generation (or returns cached unless
  // ?regenerate=true).
  getBriefing: (id: string) => request<Briefing>(`/api/uploads/${id}/briefing`),
  generateBriefing: (id: string, regenerate = false) =>
    request<Briefing>(`/api/uploads/${id}/briefing${regenerate ? "?regenerate=true" : ""}`, {
      method: "POST",
    }),
  explainAnomaly: (anomalyId: number, regenerate = false) =>
    request<Explanation>(`/api/anomalies/${anomalyId}/explain${regenerate ? "?regenerate=true" : ""}`, {
      method: "POST",
    }),
};
