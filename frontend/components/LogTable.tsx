"use client";

import { Fragment, useState } from "react";
import { LogEntry, LogsPage } from "@/lib/api";
import SeverityBadge from "./SeverityBadge";

interface Props {
  page: LogsPage | null;
  loading: boolean;
  sortBy: string;
  sortDir: "asc" | "desc";
  onSort: (col: string) => void;
  onPageChange: (page: number) => void;
}

const COLUMNS: { key: string; label: string; sortable: boolean }[] = [
  { key: "severity_score", label: "Score", sortable: true },
  { key: "severity_label", label: "Severity", sortable: false },
  { key: "timestamp", label: "Timestamp", sortable: true },
  { key: "source_ip", label: "Source IP", sortable: true },
  { key: "username", label: "User", sortable: true },
  { key: "event_type", label: "Event", sortable: false },
  { key: "message", label: "Message", sortable: false },
];

function formatTimestamp(ts: string | null): string {
  if (!ts) return "—";
  return ts.replace("T", " ").slice(0, 19);
}

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-yellow-500" : score >= 20 ? "bg-blue-500" : "bg-slate-600";
  return (
    <div className="flex items-center gap-2">
      <span className="w-8 text-right font-mono text-sm">{Math.round(score)}</span>
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full ${color}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

function ExpandedRow({ entry }: { entry: LogEntry }) {
  return (
    <tr className="bg-panel-light/50">
      <td colSpan={COLUMNS.length} className="px-6 py-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Triggered indicators
            </p>
            {entry.indicators.length === 0 ? (
              <p className="text-sm text-slate-500">None — benign event.</p>
            ) : (
              <ul className="space-y-1">
                {entry.indicators.map((ind, i) => (
                  <li key={i} className="flex justify-between gap-4 text-sm">
                    <span className="text-slate-300">{ind.label}</span>
                    <span className="font-mono text-red-400">+{ind.points}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Details
            </p>
            <dl className="space-y-1 text-sm">
              <div className="flex gap-2">
                <dt className="text-slate-500">File:</dt>
                <dd className="font-mono text-slate-300">{entry.source_file}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-slate-500">Status:</dt>
                <dd className="text-slate-300">{entry.status ?? "—"}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="shrink-0 text-slate-500">Message:</dt>
                <dd className="break-all font-mono text-xs text-slate-300">{entry.message}</dd>
              </div>
            </dl>
          </div>
        </div>
      </td>
    </tr>
  );
}

export default function LogTable({ page, loading, sortBy, sortDir, onSort, onPageChange }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.page_size)) : 1;

  return (
    <div className="overflow-hidden rounded-xl border border-edge bg-panel">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-edge bg-panel-light/60 text-xs uppercase tracking-wider text-slate-400">
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={`px-4 py-3 font-semibold ${col.sortable ? "cursor-pointer select-none hover:text-slate-200" : ""}`}
                  onClick={() => col.sortable && onSort(col.key)}
                >
                  {col.label}
                  {sortBy === col.key && <span className="ml-1">{sortDir === "desc" ? "▼" : "▲"}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-edge/60">
            {loading && (
              <tr>
                <td colSpan={COLUMNS.length} className="px-4 py-10 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && (!page || page.items.length === 0) && (
              <tr>
                <td colSpan={COLUMNS.length} className="px-4 py-10 text-center text-slate-500">
                  No log entries. Upload a file to get started.
                </td>
              </tr>
            )}
            {!loading &&
              page?.items.map((entry) => (
                <Fragment key={entry.id}>
                  <tr
                    className="cursor-pointer transition-colors hover:bg-panel-light/40"
                    onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                  >
                    <td className="px-4 py-2.5">
                      <ScoreBar score={entry.severity_score} />
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge label={entry.severity_label} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-slate-400">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-300">{entry.source_ip ?? "—"}</td>
                    <td className="px-4 py-2.5 text-slate-300">{entry.username ?? "—"}</td>
                    <td className="px-4 py-2.5 text-slate-400">{entry.event_type ?? "—"}</td>
                    <td className="max-w-md truncate px-4 py-2.5 text-slate-400" title={entry.message}>
                      {entry.message}
                    </td>
                  </tr>
                  {expanded === entry.id && <ExpandedRow entry={entry} />}
                </Fragment>
              ))}
          </tbody>
        </table>
      </div>

      {page && page.total > 0 && (
        <div className="flex items-center justify-between border-t border-edge px-4 py-3 text-sm text-slate-400">
          <span>
            {page.total.toLocaleString()} events · page {page.page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page.page <= 1}
              onClick={() => onPageChange(page.page - 1)}
              className="rounded-lg border border-edge px-3 py-1 hover:bg-panel-light disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={page.page >= totalPages}
              onClick={() => onPageChange(page.page + 1)}
              className="rounded-lg border border-edge px-3 py-1 hover:bg-panel-light disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
