import type { Anomaly, LogEntry } from "../lib/api";

type Props = {
  entries: LogEntry[];
  total: number;
  anomalousOnly: boolean;
  setAnomalousOnly: (v: boolean) => void;
  offset: number;
  limit: number;
  setOffset: (v: number) => void;
  anomalyByEntry: Map<number, Anomaly[]>;
};

export function EntriesTable(p: Props) {
  const showing = p.entries.length;
  const end = p.offset + showing;
  return (
    <div className="bg-slate-900 border border-slate-700 rounded">
      <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="text-sm font-semibold">Log entries</div>
        <label className="text-sm text-slate-300 flex items-center gap-2">
          <input
            type="checkbox"
            checked={p.anomalousOnly}
            onChange={(e) => p.setAnomalousOnly(e.target.checked)}
          />
          Anomalous only
        </label>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-slate-800 text-slate-300">
            <tr>
              <th className="text-left px-3 py-2">Time</th>
              <th className="text-left px-3 py-2">User</th>
              <th className="text-left px-3 py-2">Src IP</th>
              <th className="text-left px-3 py-2">URL</th>
              <th className="text-left px-3 py-2">Category</th>
              <th className="text-left px-3 py-2">Action</th>
              <th className="text-left px-3 py-2">Threat</th>
              <th className="text-right px-3 py-2">In/Out</th>
            </tr>
          </thead>
          <tbody>
            {p.entries.map((e) => {
              const anoms = p.anomalyByEntry.get(e.id);
              return (
                <tr
                  key={e.id}
                  className={`border-t border-slate-800 ${
                    anoms ? "bg-red-500/10" : ""
                  }`}
                  title={anoms?.map((a) => `${a.rule_name}: ${a.explanation}`).join("\n")}
                >
                  <td className="px-3 py-2 text-slate-400 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString([], { hour12: false })}
                  </td>
                  <td className="px-3 py-2">{e.username}</td>
                  <td className="px-3 py-2 font-mono">{e.src_ip}</td>
                  <td className="px-3 py-2 truncate max-w-xs" title={e.url}>
                    {e.url}
                  </td>
                  <td className="px-3 py-2">{e.url_category}</td>
                  <td
                    className={`px-3 py-2 ${
                      e.action === "blocked" ? "text-amber-400" : "text-slate-300"
                    }`}
                  >
                    {e.action}
                  </td>
                  <td className="px-3 py-2 text-red-400">{e.threat_name}</td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">
                    {e.bytes_in}/{e.bytes_out}
                  </td>
                </tr>
              );
            })}
            {p.entries.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-4 text-center text-slate-500">
                  No rows.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="px-4 py-2 border-t border-slate-700 flex items-center justify-between text-xs text-slate-400">
        <div>
          {showing === 0 ? 0 : p.offset + 1}–{end} of {p.total}
        </div>
        <div className="space-x-2">
          <button
            disabled={p.offset === 0}
            onClick={() => p.setOffset(Math.max(0, p.offset - p.limit))}
            className="px-2 py-1 border border-slate-700 rounded disabled:opacity-30"
          >
            Prev
          </button>
          <button
            disabled={end >= p.total}
            onClick={() => p.setOffset(p.offset + p.limit)}
            className="px-2 py-1 border border-slate-700 rounded disabled:opacity-30"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
