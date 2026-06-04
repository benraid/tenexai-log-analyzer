import { useEffect, useState } from "react";
import { api, ApiError, type Briefing } from "../lib/api";
import { MarkdownBox } from "./MarkdownBox";

type Props = { uploadId: string };

export function BriefingPanel({ uploadId }: Props) {
  const [briefing, setBriefing] = useState<Briefing | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [aiDisabled, setAiDisabled] = useState(false);

  // On mount, try to load a cached briefing. 404 just means none yet — any
  // other error (500, network, etc.) we surface so the user isn't presented
  // with a "Generate" button that will silently fail.
  useEffect(() => {
    let cancelled = false;
    api
      .getBriefing(uploadId)
      .then((b) => !cancelled && setBriefing(b))
      .catch((e) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 404) return;
        setErr(String(e.message || e));
      });
    return () => {
      cancelled = true;
    };
  }, [uploadId]);

  async function generate(regenerate = false) {
    setErr(null);
    setLoading(true);
    try {
      const b = await api.generateBriefing(uploadId, regenerate);
      setBriefing(b);
    } catch (e: any) {
      // Status-based dispatch beats string sniffing: rephrasing the server
      // message can't break the disabled-UX detection.
      if (e instanceof ApiError && e.status === 503) {
        setAiDisabled(true);
      } else {
        setErr(String(e.message || e));
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-gradient-to-br from-emerald-500/10 to-slate-900 border border-emerald-500/30 rounded p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-emerald-400 text-xs font-semibold uppercase tracking-wider">
            AI SOC Briefing
          </span>
          {briefing?.cached && (
            <span className="text-xs text-slate-500">
              cached {new Date(briefing.generated_at).toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="space-x-2">
          {briefing && (
            <button
              onClick={() => generate(true)}
              disabled={loading || aiDisabled}
              className="text-xs px-2 py-1 border border-slate-700 rounded hover:bg-slate-800 disabled:opacity-30"
            >
              {loading ? "…" : "Regenerate"}
            </button>
          )}
          {!briefing && (
            <button
              onClick={() => generate(false)}
              disabled={loading || aiDisabled}
              className="text-sm px-3 py-1 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-medium rounded"
            >
              {loading ? "Generating…" : "Generate briefing"}
            </button>
          )}
        </div>
      </div>
      {aiDisabled && (
        <div className="text-amber-400 text-sm">
          AI is not configured on this server. Set <code className="bg-slate-800 px-1 rounded">ANTHROPIC_API_KEY</code> to enable.
        </div>
      )}
      {err && <div className="text-red-400 text-sm">{err}</div>}
      {briefing && !err && <MarkdownBox>{briefing.markdown}</MarkdownBox>}
      {!briefing && !err && !aiDisabled && !loading && (
        <div className="text-slate-400 text-sm">
          Generate an AI-written SOC handover note that interprets the rule-based findings above and recommends actions.
        </div>
      )}
    </div>
  );
}
