import { Stats } from "@/lib/api";

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_COLORS: Record<string, string> = {
  Critical: "text-red-400",
  High: "text-orange-400",
  Medium: "text-yellow-300",
  Low: "text-blue-300",
  Info: "text-slate-400",
};

export default function StatsCards({ stats }: { stats: Stats | null }) {
  if (!stats) return null;

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <div className="rounded-xl border border-edge bg-panel p-4">
        <p className="text-xs uppercase tracking-wider text-slate-400">Total events</p>
        <p className="mt-1 text-3xl font-bold text-slate-100">{stats.total.toLocaleString()}</p>
        <p className="mt-1 text-xs text-slate-500">avg score {stats.avg_score}</p>
      </div>

      <div className="rounded-xl border border-edge bg-panel p-4">
        <p className="text-xs uppercase tracking-wider text-slate-400">By severity</p>
        <div className="mt-2 space-y-1">
          {SEVERITY_ORDER.map((label) => (
            <div key={label} className="flex justify-between text-sm">
              <span className={SEVERITY_COLORS[label]}>{label}</span>
              <span className="font-mono text-slate-300">
                {stats.severity_breakdown[label] ?? 0}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-edge bg-panel p-4">
        <p className="text-xs uppercase tracking-wider text-slate-400">Riskiest source IPs</p>
        <div className="mt-2 space-y-1">
          {stats.top_source_ips.length === 0 && (
            <p className="text-sm text-slate-500">No data yet</p>
          )}
          {stats.top_source_ips.map((row) => (
            <div key={row.source_ip} className="flex justify-between text-sm">
              <span className="font-mono text-slate-300">{row.source_ip}</span>
              <span className="text-slate-400">
                {row.count}× <span className="text-red-400">{row.avg_score}</span>
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-edge bg-panel p-4">
        <p className="text-xs uppercase tracking-wider text-slate-400">Riskiest accounts</p>
        <div className="mt-2 space-y-1">
          {stats.top_usernames.length === 0 && (
            <p className="text-sm text-slate-500">No data yet</p>
          )}
          {stats.top_usernames.map((row) => (
            <div key={row.username} className="flex justify-between text-sm">
              <span className="font-mono text-slate-300">{row.username}</span>
              <span className="text-slate-400">
                {row.count}× <span className="text-red-400">{row.avg_score}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
