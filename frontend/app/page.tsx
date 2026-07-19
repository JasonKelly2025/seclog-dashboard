"use client";

import { useCallback, useEffect, useState } from "react";
import { clearLogs, fetchLogs, fetchStats, LogsPage, Stats } from "@/lib/api";
import LogTable from "@/components/LogTable";
import StatsCards from "@/components/StatsCards";
import UploadZone from "@/components/UploadZone";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export default function Dashboard() {
  const [logs, setLogs] = useState<LogsPage | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState("severity_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [search]);

  const refresh = useCallback(async () => {
    setLoading(true);
    setApiError(null);
    try {
      const [logsData, statsData] = await Promise.all([
        fetchLogs({
          q: debouncedSearch || undefined,
          severity: severityFilter,
          sortBy,
          sortDir,
          page,
        }),
        fetchStats(),
      ]);
      setLogs(logsData);
      setStats(statsData);
    } catch (e) {
      setApiError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, [debouncedSearch, severityFilter, sortBy, sortDir, page]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function toggleSeverity(label: string) {
    setPage(1);
    setSeverityFilter((prev) =>
      prev.includes(label) ? prev.filter((s) => s !== label) : [...prev, label]
    );
  }

  function handleSort(col: string) {
    if (sortBy === col) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
    setPage(1);
  }

  async function handleClear() {
    if (!confirm("Delete all ingested log entries?")) return;
    await clearLogs();
    setPage(1);
    refresh();
  }

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-6 py-8">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">
            <span className="text-cyan-400">SecLog</span> Dashboard
          </h1>
          <p className="text-sm text-slate-400">
            Upload raw security logs, search parsed events, and triage by severity score.
          </p>
        </div>
        <button
          onClick={handleClear}
          className="rounded-lg border border-red-500/40 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10"
        >
          Clear all
        </button>
      </header>

      {apiError && (
        <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {apiError} — make sure the FastAPI backend is running on port 8010.
        </p>
      )}

      <UploadZone onUploaded={() => refresh()} />

      <StatsCards stats={stats} />

      <div className="flex flex-wrap items-center gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search messages, IPs, users, events…"
          className="w-full max-w-md rounded-lg border border-edge bg-panel px-4 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/60"
        />
        <div className="flex gap-1.5">
          {SEVERITIES.map((label) => (
            <button
              key={label}
              onClick={() => toggleSeverity(label)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                severityFilter.includes(label)
                  ? "border-cyan-400 bg-cyan-400/10 text-cyan-300"
                  : "border-edge text-slate-400 hover:border-slate-500"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <LogTable
        page={logs}
        loading={loading}
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
        onPageChange={setPage}
      />
    </main>
  );
}
