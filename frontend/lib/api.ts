export interface Indicator {
  name: string;
  label: string;
  points: number;
}

export interface LogEntry {
  id: number;
  upload_id: string;
  source_file: string;
  timestamp: string | null;
  source_ip: string | null;
  username: string | null;
  event_type: string | null;
  status: string | null;
  message: string;
  severity_score: number;
  severity_label: string;
  indicators: Indicator[];
}

export interface LogsPage {
  items: LogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface Stats {
  total: number;
  severity_breakdown: Record<string, number>;
  top_source_ips: { source_ip: string; count: number; avg_score: number }[];
  top_usernames: { username: string; count: number; avg_score: number }[];
  avg_score: number;
}

export interface UploadResult {
  upload_id: string;
  filename: string;
  records_ingested: number;
  severity_breakdown: Record<string, number>;
}

export interface LogsQuery {
  q?: string;
  severity?: string[];
  sortBy?: string;
  sortDir?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `Request failed (${res.status})`);
  }
  return res.json();
}

export async function fetchLogs(query: LogsQuery): Promise<LogsPage> {
  const params = new URLSearchParams();
  if (query.q) params.set("q", query.q);
  if (query.severity?.length) params.set("severity", query.severity.join(","));
  if (query.sortBy) params.set("sort_by", query.sortBy);
  if (query.sortDir) params.set("sort_dir", query.sortDir);
  params.set("page", String(query.page ?? 1));
  params.set("page_size", String(query.pageSize ?? 25));
  return handle(await fetch(`/api/logs?${params}`, { cache: "no-store" }));
}

export async function fetchStats(): Promise<Stats> {
  return handle(await fetch("/api/stats", { cache: "no-store" }));
}

export async function uploadFile(file: File): Promise<UploadResult> {
  const form = new FormData();
  form.append("file", file);
  return handle(await fetch("/api/upload", { method: "POST", body: form }));
}

export async function clearLogs(): Promise<{ deleted: number }> {
  return handle(await fetch("/api/logs", { method: "DELETE" }));
}
