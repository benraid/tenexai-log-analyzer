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

const seriesColors: Record<string, string> = {
  Allowed: "#34d399",
  Blocked: "#fbbf24",
  Anomalies: "#ef4444",
};

function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number | null }>; label?: string }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div
      style={{
        background: "rgba(15, 23, 42, 0.95)",
        border: "1px solid #475569",
        borderRadius: 8,
        padding: "10px 12px",
        boxShadow: "0 10px 30px rgba(0,0,0,0.4)",
        fontSize: 13,
      }}
    >
      <div style={{ color: "#fff", fontWeight: 600, marginBottom: 6 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ color: seriesColors[p.name] ?? "#cbd5e1" }}>
          {p.name} : {p.value}
        </div>
      ))}
    </div>
  );
}

export function TimelineChart({ timeline }: { timeline: TimelineBucket[] }) {
  const data = timeline.map((t) => ({
    bucket: new Date(t.bucket_start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    allowed: t.total_count - t.blocked_count,
    blocked: t.blocked_count,
    anomaly: t.anomaly_count > 0 ? t.anomaly_count : null,
  }));
  if (data.length === 0) return <div className="text-slate-500 text-sm">No data.</div>;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <ComposedChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: -10 }}>
        <defs>
          <linearGradient id="allowedGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#34d399" stopOpacity={0.95} />
            <stop offset="100%" stopColor="#059669" stopOpacity={0.75} />
          </linearGradient>
          <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#fbbf24" stopOpacity={1} />
            <stop offset="100%" stopColor="#d97706" stopOpacity={0.85} />
          </linearGradient>
          <filter id="anomalyGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <CartesianGrid strokeDasharray="2 6" stroke="#334155" strokeOpacity={0.35} vertical={false} />
        <XAxis
          dataKey="bucket"
          stroke="#94a3b8"
          fontSize={11}
          tickLine={false}
          axisLine={{ stroke: "#334155" }}
        />
        <YAxis
          stroke="#94a3b8"
          fontSize={11}
          tickLine={false}
          axisLine={false}
          width={40}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(148, 163, 184, 0.08)" }} />
        <Legend
          wrapperStyle={{ fontSize: 12, paddingTop: 12 }}
          iconType="circle"
        />
        <Bar
          dataKey="allowed"
          stackId="bar"
          fill="url(#allowedGradient)"
          name="Allowed"
        />
        <Bar
          dataKey="blocked"
          stackId="bar"
          fill="url(#blockedGradient)"
          name="Blocked"
          radius={[6, 6, 0, 0]}
        />
        <Line
          type="linear"
          dataKey="anomaly"
          stroke="#ef4444"
          strokeWidth={2}
          name="Anomalies"
          connectNulls={false}
          dot={{ r: 4, fill: "#ef4444", stroke: "#fee2e2", strokeWidth: 1.5, filter: "url(#anomalyGlow)" }}
          activeDot={{ r: 7, fill: "#ef4444", stroke: "#fff", strokeWidth: 2 }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  );
}
