import { useEffect, useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, type Anomaly, type LogEntry, type Summary, type Upload } from "../lib/api";
import { SummaryCards } from "../components/SummaryCards";
import { TimelineChart } from "../components/TimelineChart";
import { AnomaliesPanel } from "../components/AnomaliesPanel";
import { EntriesTable } from "../components/EntriesTable";
import { TopCategoriesChart } from "../components/TopCategoriesChart";
import { BriefingPanel } from "../components/BriefingPanel";

export function UploadDetailPage() {
  const { id = "" } = useParams();
  const [upload, setUpload] = useState<Upload | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [entriesTotal, setEntriesTotal] = useState(0);
  const [anomalousOnly, setAnomalousOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const limit = 50;

  // Anomalies keyed by log_entry_id so the entries table can mark rows.
  const anomalyByEntry = useMemo(() => {
    const m = new Map<number, Anomaly[]>();
    for (const a of anomalies) {
      if (!a.log_entry_id) continue;
      const arr = m.get(a.log_entry_id) ?? [];
      arr.push(a);
      m.set(a.log_entry_id, arr);
    }
    return m;
  }, [anomalies]);

  // Initial load: upload + summary + anomalies in parallel.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([api.getUpload(id), api.summary(id), api.listAnomalies(id)])
      .then(([u, s, a]) => {
        if (cancelled) return;
        setUpload(u);
        setSummary(s);
        setAnomalies(a ?? []);
      })
      .catch((e) => !cancelled && setErr(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

  // Entries refetch on filter / pagination change.
  useEffect(() => {
    let cancelled = false;
    api
      .listEntries(id, { anomalousOnly, limit, offset })
      .then((r) => {
        if (cancelled) return;
        setEntries(r.entries ?? []);
        setEntriesTotal(r.total);
      })
      .catch((e) => !cancelled && setErr(e.message));
    return () => {
      cancelled = true;
    };
  }, [id, anomalousOnly, offset]);

  if (loading) return <div className="text-slate-400">Loading…</div>;
  if (err) return <div className="text-red-400">{err}</div>;
  if (!upload || !summary) return null;

  return (
    <div className="space-y-6">
      <div>
        <Link to="/uploads" className="text-sm text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
          <span>←</span> Back to uploads
        </Link>
        <h1 className="text-2xl font-semibold font-mono mt-2">{upload.filename}</h1>
        <div className="text-sm text-slate-400">
          Uploaded {new Date(upload.uploaded_at).toLocaleString()} · {upload.parsed_rows} rows parsed
        </div>
      </div>

      <SummaryCards summary={summary} />

      <BriefingPanel uploadId={id} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-700 rounded p-4">
          <div className="text-sm text-slate-300 mb-2">Activity timeline (5-min buckets)</div>
          <TimelineChart timeline={summary.timeline ?? []} />
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded p-4">
          <div className="text-sm text-slate-300 mb-2">Top URL categories</div>
          <TopCategoriesChart data={summary.top_categories ?? []} />
        </div>
      </div>

      <AnomaliesPanel anomalies={anomalies} />

      <EntriesTable
        entries={entries}
        total={entriesTotal}
        anomalousOnly={anomalousOnly}
        setAnomalousOnly={(v) => {
          setOffset(0);
          setAnomalousOnly(v);
        }}
        offset={offset}
        limit={limit}
        setOffset={setOffset}
        anomalyByEntry={anomalyByEntry}
      />
    </div>
  );
}
