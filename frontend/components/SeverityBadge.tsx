const STYLES: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-400 border-red-500/40",
  High: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  Medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
  Low: "bg-blue-500/15 text-blue-300 border-blue-500/40",
  Info: "bg-slate-500/15 text-slate-400 border-slate-500/40",
};

export default function SeverityBadge({ label }: { label: string }) {
  return (
    <span
      className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
        STYLES[label] ?? STYLES.Info
      }`}
    >
      {label}
    </span>
  );
}
