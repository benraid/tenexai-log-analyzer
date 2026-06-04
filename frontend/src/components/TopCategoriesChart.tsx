import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import type { CountPair } from "../lib/api";

export function TopCategoriesChart({ data }: { data: CountPair[] }) {
  if (!data.length) return <div className="text-slate-500 text-sm">No data.</div>;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ left: 30 }}>
        <XAxis type="number" stroke="#94a3b8" fontSize={11} />
        <YAxis type="category" dataKey="key" stroke="#94a3b8" fontSize={11} width={120} />
        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
        <Bar dataKey="count" fill="#34d399" />
      </BarChart>
    </ResponsiveContainer>
  );
}
