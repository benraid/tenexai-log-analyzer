import { useState } from "react";
import type { Anomaly } from "../lib/api";
import { api, ApiError } from "../lib/api";
import { MarkdownBox } from "./MarkdownBox";

const ruleLabels: Record<string, string> = {
  threat_hit: "Vendor threat hit",
  malicious_category: "Malicious URL category",
  blocked_spike_per_ip: "Blocked-request spike",
  high_request_rate: "High request rate",
  data_exfiltration: "Possible data exfiltration",
  off_hours_activity: "Off-hours activity",
  rare_user_agent: "Rare user agent",
};

function confidenceTone(c: number) {
  if (c >= 0.85) return { bar: "bg-red-500", label: "text-red-400" };
  if (c >= 0.65) return { bar: "bg-amber-500", label: "text-amber-400" };
  return { bar: "bg-emerald-500", label: "text-emerald-400" };
}

type ExplainState = {
  markdown?: string;
  loading: boolean;
  error?: string;
};

function AnomalyRow({ a }: { a: Anomaly }) {
  const tone = confidenceTone(a.confidence);
  const [expanded, setExpanded] = useState(false);
  const [explain, setExplain] = useState<ExplainState>({ loading: false });

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && !explain.markdown && !explain.loading) {
      setExplain({ loading: true });
      try {
        const r = await api.explainAnomaly(a.id);
        setExplain({ loading: false, markdown: r.markdown });
      } catch (e: any) {
        const msg =
          e instanceof ApiError && e.status === 503
            ? "AI is not configured on this server."
            : String(e.message || e);
        setExplain({ loading: false, error: msg });
      }
    }
  }

  return (
    <li className="px-4 py-3">
      <div className="flex items-start gap-4">
        <div className="flex-1">
          <div className="text-xs text-slate-400">{ruleLabels[a.rule_name] ?? a.rule_name}</div>
          <div className="text-sm text-slate-200">{a.explanation}</div>
        </div>
        <div className="w-40">
          <div className={`text-xs ${tone.label} text-right`}>{(a.confidence * 100).toFixed(0)}% confidence</div>
          <div className="h-2 mt-1 rounded bg-slate-800 overflow-hidden">
            <div className={`h-full ${tone.bar}`} style={{ width: `${a.confidence * 100}%` }} />
          </div>
        </div>
        <button
          onClick={toggle}
          className="text-xs text-emerald-400 hover:text-emerald-300 self-center px-2 py-1 border border-slate-700 rounded"
          title="AI-generated explanation"
        >
          {expanded ? "Hide" : "Explain ▾"}
        </button>
      </div>
      {expanded && (
        <div className="mt-3 ml-1 pl-3 border-l-2 border-emerald-500/40 bg-slate-950/40 p-3 rounded">
          {explain.loading && <div className="text-slate-400 text-sm">Asking the model…</div>}
          {explain.error && <div className="text-amber-400 text-sm">{explain.error}</div>}
          {explain.markdown && <MarkdownBox>{explain.markdown}</MarkdownBox>}
        </div>
      )}
    </li>
  );
}

export function AnomaliesPanel({ anomalies }: { anomalies: Anomaly[] }) {
  return (
    <div className="bg-slate-900 border border-slate-700 rounded">
      <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="text-sm font-semibold">Detected anomalies</div>
        <div className="text-xs text-slate-400">{anomalies.length} total</div>
      </div>
      {anomalies.length === 0 ? (
        <div className="p-4 text-slate-500 text-sm">No anomalies detected.</div>
      ) : (
        <ul className="divide-y divide-slate-800">
          {anomalies.map((a) => (
            <AnomalyRow key={a.id} a={a} />
          ))}
        </ul>
      )}
    </div>
  );
}
