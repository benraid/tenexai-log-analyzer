import type { Summary } from "../lib/api";

function Card({ label, value, tone = "default" }: { label: string; value: number | string; tone?: "default" | "warn" | "alert" }) {
  const color =
    tone === "alert" ? "text-red-400" : tone === "warn" ? "text-amber-400" : "text-emerald-400";
  return (
    <div className="bg-slate-900 border border-slate-700 rounded p-4">
      <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

export function SummaryCards({ summary }: { summary: Summary }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card label="Total entries" value={summary.total_entries} />
      <Card label="Blocked" value={summary.blocked_entries} tone="warn" />
      <Card label="Unique source IPs" value={summary.unique_src_ips} />
      <Card label="Anomalies" value={summary.anomaly_count} tone="alert" />
    </div>
  );
}
