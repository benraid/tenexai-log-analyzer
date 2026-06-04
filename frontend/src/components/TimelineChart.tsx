import {
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";
import type { TimelineBucket } from "../lib/api";

export function TimelineChart({ timeline }: { timeline: TimelineBucket[] }) {
  const data = timeline.map((t) => ({
    bucket: new Date(t.bucket_start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    total: t.total_count,
    blocked: t.blocked_count,
    anomaly: t.anomaly_count,
  }));
  if (data.length === 0) return <div className="text-slate-500 text-sm">No data.</div>;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <ComposedChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="bucket" stroke="#94a3b8" fontSize={11} />
        <YAxis stroke="#94a3b8" fontSize={11} />
        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="total" fill="#10b981" name="Total" />
        <Bar dataKey="blocked" fill="#f59e0b" name="Blocked" />
        <Line type="monotone" dataKey="anomaly" stroke="#ef4444" name="Anomalies" />
      </ComposedChart>
    </ResponsiveContainer>
  );
}
